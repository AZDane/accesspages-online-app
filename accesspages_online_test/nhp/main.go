// Minimal CLI over the current upstream native agent. Secrets travel on stdin.
package main

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"net/url"
	"path/filepath"
	"syscall"
	"time"

	"github.com/OpenNHP/opennhp/endpoints/agent"
)

func main() {
	if err := run(); err != nil {
		json.NewEncoder(os.Stdout).Encode(map[string]any{"ok": false, "error": err.Error()})
		os.Exit(1)
	}
}
func run() error {
	var in map[string]any
	if err := json.NewDecoder(io.LimitReader(os.Stdin, 8192)).Decode(&in); err != nil {
		return fmt.Errorf("invalid input")
	}
 machineDir:=os.Getenv("MACHINE_DIR");if machineDir==""{machineDir="/machine"}
	// Separate Admin and supervisor processes can use the same installation key.
	// Serialize those native sessions, with a finite queue wait, before Agent.Start.
	// This identity file remains stable during normal operation, including on
	// read-only Control Plane mounts. No extra writable credential directory.
	lock,err:=os.Open(filepath.Join(machineDir,"etc","config.toml"))
	if err!=nil{return fmt.Errorf("native operation lock unavailable")}
	defer lock.Close()
	deadline:=time.Now().Add(12*time.Second)
	for {
		err=syscall.Flock(int(lock.Fd()),syscall.LOCK_EX|syscall.LOCK_NB)
		if err==nil{break}
		if err!=syscall.EWOULDBLOCK && err!=syscall.EAGAIN{return fmt.Errorf("native operation lock failed")}
		if time.Now().After(deadline){return fmt.Errorf("native operation busy; retry")}
		time.Sleep(50*time.Millisecond)
	}
	defer syscall.Flock(int(lock.Fd()),syscall.LOCK_UN)
	a := &agent.UdpAgent{}
	if err := a.Start(machineDir, 0); err != nil {
		return fmt.Errorf("agent start failed: %v", err)
	}
	defer a.Stop()
	a.SetDeviceId("machine")
	op, _ := in["op"].(string)
	resource := "gateway-mint"
	if os.Getenv("MACHINE_ROLE") == "control-plane" {
		resource = "control-provision"
	}
	if override, ok := in["nhp_resource"].(string); ok {
		resource = override
		delete(in, "nhp_resource")
	}
	target := a.FindKnockTarget("guest", resource)
	if target == nil {
		return fmt.Errorf("unknown control resource")
	}
	if op == "bind" {
		bootstrap, _ := in["bootstrap"].(string)
		gid, _ := in["gateway_id"].(string)
		registrationData,_:=in["registration_data"].(map[string]any)
		a.SetKnockUser(gid, "", registrationData)
		ack, err := a.RegisterPublicKey(bootstrap, target)
		if in["registration_diagnostics"]==true {
			result:=map[string]any{"ok":err==nil && ack!=nil && ack.ErrCode=="0","received_ack":ack!=nil}
			if ack!=nil {result["error_code"]=ack.ErrCode}
			return json.NewEncoder(os.Stdout).Encode(result)
		}
		if err != nil || ack == nil || ack.ErrCode != "0" {
			return fmt.Errorf("bind denied")
		}
		return json.NewEncoder(os.Stdout).Encode(map[string]any{"ok": true, "gateway_id": gid})
	}
	body, _ := json.Marshal(in)
	a.SetKnockUser("machine", "", map[string]any{"request": string(body)})
	ack, err := a.Knock(target)
	if err != nil || ack == nil || ack.ErrCode != "0" {
		if ack != nil {
			return fmt.Errorf("NHP control admission denied (code=%s message=%q resource=%s)", ack.ErrCode, ack.ErrMsg, resource)
		}
		return fmt.Errorf("NHP control admission denied (no ACK: %v; resource=%s)", err, resource)
	}
	if in["transport_only"] == true {
		return json.NewEncoder(os.Stdout).Encode(map[string]any{"ack": ack})
	}
	cert, err := os.ReadFile(machineDir+"/control.crt")
	if err != nil {
		return err
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(cert) {
		return fmt.Errorf("bad authority certificate")
	}
 client:=&http.Client{Timeout:10*time.Second,Transport:&http.Transport{TLSClientConfig:&tls.Config{RootCAs:roots,ServerName:"nhp-control",MinVersion:tls.VersionTLS12}},CheckRedirect:func(req *http.Request,via []*http.Request)error{return http.ErrUseLastResponse}}
 host:=ack.ResourceHost["control"]
 destination,err:=url.Parse("https://"+host+"/operate")
 if err!=nil || destination.Host!=host || destination.User!=nil || destination.Path!="/operate" || destination.RawQuery!="" || destination.Fragment!="" {return fmt.Errorf("invalid protected destination")}
	req, err := http.NewRequest("POST", destination.String(), bytes.NewReader(body))
 if err!=nil{return fmt.Errorf("invalid protected destination")}
	req.Header.Set("Authorization", "Bearer "+ack.AuthProviderToken)
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("protected API unavailable: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return fmt.Errorf("protected API denied (%d)", resp.StatusCode)
	}
	_, err = io.Copy(os.Stdout, io.LimitReader(resp.Body, 16384))
	return err
}
