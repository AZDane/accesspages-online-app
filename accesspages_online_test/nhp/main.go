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
	"net/url"
	"os"
	"path/filepath"
	"syscall"
	"time"

	"github.com/OpenNHP/opennhp/endpoints/agent"
)

func main() {
	if err := run(); err != nil {
		// Machine output crosses process and privilege boundaries. Expose only a
		// stable category; upstream errors can contain destinations, identifiers,
		// or other request data that must not become application diagnostics.
		json.NewEncoder(os.Stdout).Encode(map[string]any{"ok": false, "category": errorCategory(err)})
		os.Exit(1)
	}
}

type operationError struct {
	category string
	cause    error
}

func (e *operationError) Error() string { return e.category }
func (e *operationError) Unwrap() error { return e.cause }
func categorized(category string, cause error) error {
	return &operationError{category: category, cause: cause}
}
func errorCategory(err error) string {
	if value, ok := err.(*operationError); ok {
		return value.category
	}
	return "native_failure"
}

func protectedStatusCategory(status int) string {
	switch status {
	case http.StatusUnauthorized, http.StatusForbidden:
		return "authenticated_denial"
	case http.StatusConflict:
		return "revocation_owner_mismatch"
	default:
		return "protected_api_unavailable"
	}
}

func acquireOperationLock(machineDir string, wait time.Duration) (*os.File, error) {
	lock, err := os.Open(filepath.Join(machineDir, "etc", "config.toml"))
	if err != nil {
		return nil, categorized("local_lock_unavailable", err)
	}
	deadline := time.Now().Add(wait)
	for {
		err = syscall.Flock(int(lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
		if err == nil {
			return lock, nil
		}
		if err != syscall.EWOULDBLOCK && err != syscall.EAGAIN {
			lock.Close()
			return nil, categorized("local_lock_unavailable", err)
		}
		if time.Now().After(deadline) {
			lock.Close()
			return nil, categorized("local_lock_contention", err)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

func run() error {
	var in map[string]any
	if err := json.NewDecoder(io.LimitReader(os.Stdin, 8192)).Decode(&in); err != nil {
		return categorized("invalid_request", err)
	}
	machineDir := os.Getenv("MACHINE_DIR")
	if machineDir == "" {
		machineDir = "/machine"
	}
	// Separate Admin and supervisor processes can use the same installation key.
	// Serialize those native sessions, with a finite queue wait, before Agent.Start.
	// This identity file remains stable during normal operation, including on
	// read-only Control Plane mounts. No extra writable credential directory.
	lock, err := acquireOperationLock(machineDir, 12*time.Second)
	if err != nil {
		return err
	}
	defer lock.Close()
	defer syscall.Flock(int(lock.Fd()), syscall.LOCK_UN)
	a := &agent.UdpAgent{}
	if err := a.Start(machineDir, 0); err != nil {
		return categorized("native_start_unavailable", err)
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
		return categorized("local_configuration", fmt.Errorf("unknown control resource"))
	}
	if op == "bind" {
		bootstrap, _ := in["bootstrap"].(string)
		gid, _ := in["gateway_id"].(string)
		registrationData, _ := in["registration_data"].(map[string]any)
		a.SetKnockUser(gid, "", registrationData)
		ack, err := a.RegisterPublicKey(bootstrap, target)
		if in["registration_diagnostics"] == true {
			result := map[string]any{"ok": err == nil && ack != nil && ack.ErrCode == "0", "received_ack": ack != nil}
			if ack != nil {
				result["error_code"] = ack.ErrCode
			}
			return json.NewEncoder(os.Stdout).Encode(result)
		}
		if err != nil || ack == nil {
			return categorized("native_no_ack", err)
		}
		if ack.ErrCode != "0" {
			return categorized("authenticated_denial", fmt.Errorf("bind denied"))
		}
		return json.NewEncoder(os.Stdout).Encode(map[string]any{"ok": true, "gateway_id": gid})
	}
	body, _ := json.Marshal(in)
	a.SetKnockUser("machine", "", map[string]any{"request": string(body)})
	ack, err := a.Knock(target)
	if err != nil || ack == nil || ack.ErrCode != "0" {
		if ack != nil {
			return categorized("authenticated_denial", fmt.Errorf("control admission denied"))
		}
		return categorized("native_no_ack", err)
	}
	if in["transport_only"] == true {
		return json.NewEncoder(os.Stdout).Encode(map[string]any{"ack": ack})
	}
	cert, err := os.ReadFile(machineDir + "/control.crt")
	if err != nil {
		return categorized("local_configuration", err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(cert) {
		return categorized("local_configuration", fmt.Errorf("bad authority certificate"))
	}
	client := &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots, ServerName: "nhp-control", MinVersion: tls.VersionTLS12}}, CheckRedirect: func(req *http.Request, via []*http.Request) error { return http.ErrUseLastResponse }}
	host := ack.ResourceHost["control"]
	destination, err := url.Parse("https://" + host + "/operate")
	if err != nil || destination.Host != host || destination.User != nil || destination.Path != "/operate" || destination.RawQuery != "" || destination.Fragment != "" {
		return categorized("invalid_response", err)
	}
	req, err := http.NewRequest("POST", destination.String(), bytes.NewReader(body))
	if err != nil {
		return categorized("invalid_response", err)
	}
	req.Header.Set("Authorization", "Bearer "+ack.AuthProviderToken)
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return categorized("protected_api_unavailable", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return categorized(protectedStatusCategory(resp.StatusCode), fmt.Errorf("protected API status"))
	}
	_, err = io.Copy(os.Stdout, io.LimitReader(resp.Body, 16384))
	if err != nil {
		return categorized("invalid_response", err)
	}
	return nil
}
