# Access Pages Online beta app

An experimental Home Assistant app for the controlled Access Pages beta. Each HA installation runs its own Guest Gateway and connects outbound to OpenNHP Service. One installation can serve multiple guest pages with separate grants and sessions.

This version tests NHP using a built-in demo lock, light and temperature sensor. It does not request Home Assistant API access or use HA credentials. Device actions change in-memory demo data only and reset when the app restarts. Native enrollment, NHP admission, NHP-FRP, TLS, signed handoffs and page authorization remain real.

## Install on a dedicated HA test system

1. In Home Assistant, open **Settings → Apps → App store → Repositories** (older versions call these add-ons).
2. Add `https://github.com/AZDane/accesspages-online-test`.
3. Install **Access Pages Online test**, start it, and choose **Open web UI**.
4. Paste the private, single-use enrollment API token supplied by the beta operator. The hosted beta must be running before enrollment can complete.

The initial installation builds pinned OpenNHP/NHP-FRP source and can take several minutes. Supported architectures are amd64 and aarch64. No router port forwarding or manually assembled keys, hostnames or tunnel credentials are required.

The app retains its own Gateway identity, separate connector identity, and TLS private key. Admin, Guest, device broker, customer TLS and outbound connector processes use separate local identities. Pages and permitted demo actions are configured through Home Assistant Ingress.

This is a beta for dedicated test installations. A successful container test does not establish that every HAOS/Supervisor/device combination works. Hosted deployment and live-provider acceptance are tracked separately from app installation. Preserve app data; resetting or restoring older identities requires operator reconciliation.

See [the app guide](accesspages_online_test/DOCS.md) and [changelog](accesspages_online_test/CHANGELOG.md).

## Updating to beta.10

Refresh the repository in Home Assistant and update **Access Pages Online test**.
Keep app data: enrollment, pages, guests and pending revocations are preserved.
Existing browser sessions need a fresh AccessLink handoff. If an old invitation
is expired or already consumed, create a new invitation after updating.

Beta.10 restores individual guest activity and optional invitation emailing with
your local SMTP provider. Hosted Google/email verification requires separate
operator setup and acceptance; this update does not enable real HA API access.
The owner account/signup website is separate and is not part of this app release.

## Testing

GitHub Actions is disabled for this repository. Live guest tests run from the
operator's laptop. Do not upload enrollment credentials, AccessLinks, guest
sessions or home test targets to GitHub secrets, workflow inputs, logs or artifacts.
The remaining offline test source uses synthetic data; the public repository
continues to provide the installable app.
