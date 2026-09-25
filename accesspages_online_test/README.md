# Access Pages Online beta app

An experimental Home Assistant app for the controlled Access Pages beta. Each HA installation runs its own Guest Gateway and connects outbound to OpenNHP Service. One installation can serve multiple guest pages with separate grants and sessions.

The app supports selected Home Assistant sensors, binary sensors and lights through the local broker. It defaults to `review_required`; an owner must explicitly select `homeassistant` before activation. The app requests Home Assistant API access, and only the local broker receives the HA credentials. There is no built-in fake-device backend. Native enrollment, NHP admission, NHP-FRP, TLS, signed handoffs and page authorization remain real.

## Install on a dedicated HA test system

1. In Home Assistant, open **Settings → Apps → App store → Repositories** (older versions call these add-ons).
2. Add `https://github.com/AZDane/accesspages-online-app`.
3. Install **Access Pages Online test**, start it, and choose **Open web UI**.
4. Review [the activation and migration guidance](DOCS.md), select `device_mode: homeassistant`, and set NHP Server address to `nhp.beta.accesspages.app:62206` on the app’s Configuration page. Restart and open the app, then paste the one-use enrollment API token supplied by the beta operator. The hosted beta must be running before enrollment can complete.

The initial installation builds pinned OpenNHP/NHP-FRP source and can take several minutes. Supported architectures are amd64 and aarch64. No router port forwarding or manually assembled keys, hostnames or tunnel credentials are required.

The app retains its own Gateway identity, separate connector identity, and TLS private key. Admin, Guest, device broker, customer TLS and outbound connector processes use separate local identities. Pages and permitted sensor/light actions are configured through Home Assistant Ingress.

This is a beta for dedicated test installations. A successful container test does not establish that every HAOS/Supervisor/device combination works. Preserve app data; resetting or restoring older identities requires operator reconciliation.

See [the app guide](DOCS.md) and [changelog](CHANGELOG.md).
