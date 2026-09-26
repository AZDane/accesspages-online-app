# Access Pages Online beta app

An experimental Home Assistant app for the controlled Access Pages beta. Each HA installation runs its own Guest Gateway and connects outbound to OpenNHP Service. One installation can serve multiple guest pages with separate grants and sessions.

The app supports selected Home Assistant sensors, binary sensors and lights through the local broker. It defaults to `review_required`; an owner must explicitly select `homeassistant` before activation. The app requests Home Assistant API access, and only the local broker receives the HA credentials. There is no built-in fake-device backend. Native enrollment, NHP admission, NHP-FRP, TLS, signed handoffs and page authorization remain real.

## Install on a dedicated HA test system

1. In Home Assistant, open **Settings → Apps → App store → Repositories** (older versions call these add-ons).
2. Add `https://github.com/AZDane/accesspages-online-app`.
3. Install **Access Pages Online test**, start it, and choose **Open web UI**.
4. Review [the activation and migration guidance](accesspages_online_test/DOCS.md), select `device_mode: homeassistant` in Configuration, and restart the app. Then open the app and paste the private, single-use enrollment API token supplied by the beta operator. The hosted beta must be running before enrollment can complete.

The initial installation builds pinned OpenNHP/NHP-FRP source and can take several minutes. Supported architectures are amd64 and aarch64. No router port forwarding or manually assembled keys, hostnames or tunnel credentials are required.

The app retains its own Gateway identity, separate connector identity, and TLS private key. Admin, device broker, customer TLS, outbound connector and each page's guest worker use separate local identities. The broker issues guest sessions and checks current authorization on every protected request. Pages and permitted sensor/light actions are configured through Home Assistant Ingress.

**Resource isolation** defaults to `page`: guests on one page share a site, with separate guest sessions. Select `guest` for a separate site per invitation. Both modes keep separate workers for each page. Changing modes and restarting revokes all invitations while keeping page settings. See [resource isolation](accesspages_online_test/DOCS.md#resource-isolation) before changing this option.

This is a beta for dedicated test installations. A successful container test does not establish that every HAOS/Supervisor/device combination works. Preserve app data; resetting or restoring older identities requires operator reconciliation.

See [the app guide](accesspages_online_test/DOCS.md) and [changelog](accesspages_online_test/CHANGELOG.md).

## Updating

This source update requires a coordinated operator cutover of OpenNHP Service
and the app. It is not an automatic upgrade of existing route or session state.
Revoke all existing invitations before cutover, preserve page settings and app
data, and create fresh invitations after the matching service and app are ready.
Existing invitations and browser sessions are not carried forward. Follow
[the app guide](accesspages_online_test/DOCS.md); do not reset the connection or
edit stored state as an upgrade procedure.

The app returns to enrollment after a connection reset. During
enrollment, the credential input is replaced by a spinner showing certificate
and startup progress. Failed enrollment restores the input.

## Testing

The offline tests use synthetic data. Do not upload enrollment credentials, AccessLinks, guest
sessions or home test targets to GitHub secrets, workflow inputs, logs or artifacts.
