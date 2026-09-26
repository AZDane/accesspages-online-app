# Access Pages Online beta app

An experimental Home Assistant app for the controlled Access Pages beta. Each HA installation runs its own Guest Gateway and connects outbound to OpenNHP Service. One installation can serve multiple guest pages with separate grants and sessions.

The app connects to Home Assistant and supports selected sensors, binary sensors and lights through the local broker. It requests Home Assistant API access, and only the local broker receives the HA credentials. Native enrollment, NHP admission, NHP-FRP, TLS, signed handoffs and page authorization protect guest access.

## Install on a dedicated HA test system

1. In Home Assistant, open **Settings → Apps → App store → Repositories** (older versions call these add-ons).
2. Add `https://github.com/AZDane/accesspages-online-app`.
3. Install **Access Pages Online test**, start it, and choose **Open web UI**.
4. Paste the private, single-use enrollment API token supplied by the beta operator. The hosted beta must be running before enrollment can complete. After connecting, select the entities and controls guests may use on each page. See [the app guide](DOCS.md) for discovery filters and resource isolation.

The initial installation builds pinned OpenNHP/NHP-FRP source and can take several minutes. Supported architectures are amd64 and aarch64. No router port forwarding or manually assembled keys, hostnames or tunnel credentials are required.

The app retains its own Gateway identity, separate connector identity, and TLS private key. Admin, device broker, customer TLS, outbound connector and each page's guest worker use separate local identities. The broker issues guest sessions and checks current authorization on every protected request. Pages and permitted sensor/light actions are configured through Home Assistant Ingress.

**Resource isolation** defaults to `page`: guests on one page share a site, with separate guest sessions. Select `guest` for a separate site per invitation. Both modes keep separate workers for each page. Changing modes and restarting revokes all invitations while keeping page settings. See [resource isolation](DOCS.md#resource-isolation) before changing this option.

This source update requires a coordinated operator cutover of OpenNHP Service and the app. Revoke existing invitations before cutover, preserve pages and app data, and create fresh invitations afterward. Existing invitations and sessions are not carried forward; see [the app guide](DOCS.md).

This is a beta for dedicated test installations. A successful container test does not establish that every HAOS/Supervisor/device combination works. Preserve app data; resetting or restoring older identities requires operator reconciliation.

See [the app guide](DOCS.md) and [changelog](CHANGELOG.md).
