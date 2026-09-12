# Access Pages Online beta app

An experimental Home Assistant app for the controlled Access Pages beta. Each HA installation runs its own Guest Gateway and connects outbound to OpenNHP Service. One installation can serve multiple guest pages with separate grants and sessions.

## Install on a dedicated HA test system

1. In Home Assistant, open **Settings → Apps → App store → Repositories** (older versions call these add-ons).
2. Add `https://github.com/AZDane/accesspages-online-test`.
3. Install **Access Pages Online test**, start it, and choose **Open web UI**.
4. Paste the private enrollment link supplied by the beta operator. The hosted beta must be running before enrollment can complete.

The initial installation builds pinned OpenNHP/NHP-FRP source and can take several minutes. Supported architectures are amd64 and aarch64. No router port forwarding or manually assembled keys, hostnames or tunnel credentials are required.

The app retains its own Gateway identity, separate connector identity, and TLS private key. Admin, Guest, HA broker, customer TLS and outbound connector processes use separate local identities. Pages and permitted HA actions are configured through Home Assistant Ingress.

This is a beta for dedicated test installations. A successful container test does not establish that every HAOS/Supervisor/device combination works. Hosted deployment and live-provider acceptance are tracked separately from app installation. Preserve app data; resetting or restoring older identities requires operator reconciliation.

See [the app guide](accesspages_online_test/DOCS.md) and [changelog](accesspages_online_test/CHANGELOG.md).
