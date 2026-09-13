# Access Pages Online test

Install this experimental app only on an authorized beta Home Assistant system.
It is managed through HA Ingress and does not request Home Assistant API access.
It uses built-in demo devices so that NHP can be tested without HA credentials.

## Configuration

Set NHP Server address on the app's Configuration page to `nhp.beta.accesspages.app:62206`.
The app ships with the beta's public NHP bootstrap settings and does not fetch an
HTTPS discovery document. It enrolls through native REG/RAK, then obtains its route,
tunnel credentials and certificates through NHP-authorized operations.
Select the demo door, light or temperature sensor and permitted actions when
creating each page in Admin. Actions change only in-memory demo data; restarting
the app resets device states but preserves pages, identities and invitations.
Existing pages that reference real HA entities must be edited to use demo entities.

Cameras, HA location/proximity and HA mobile notifications are unavailable in this
version. Do not enable proximity verification for these tests. The Supervisor may
still inject its standard environment token; this app does not use it or pass it
to child processes. Supplying an HA token cannot enable live-device access.

## Enrollment

1. The beta operator provisions an installation in OpenNHP Service and supplies
   its owner with a private, expiring enrollment API token.
2. Start the app, open it through HA Ingress and paste that token.
3. The app generates its own Gateway identity and completes native REG/RAK. It
   registers a separate connector identity and receives its allocated route.
4. The app generates a private TLS key locally and submits only a CSR for its
   certificate. It then starts its outbound connector and local Admin interface.

Set the NHP Server address on the app’s Configuration page before enrollment. Keep enrollment API tokens private: they are one-use bootstrap credentials. The configured address must match the public trust settings shipped with this beta. Changing it does not transfer an identity to another service. The app
retains its keys in its private data directory and can recover an interrupted
enrollment using the saved identity. Deleting app data requires operator
revocation and enrollment of a replacement installation.

## Guest invitations

Create a page and select its demo entities and allowed actions. Create a guest
invitation with a lifetime and optional verification, then share the AccessLink
privately. The guest starts at the shared access website. OpenNHP admission is
followed by a signed, one-use handoff to the customer's Guest Gateway.

Guest invitations use `/#<token>` and reject the earlier named-parameter link
format. Beta.10 preserves enrollment, pages and guest records. Browser sessions
from an older app require a fresh AccessLink handoff; create a new invitation if
the previous link has expired or its one-time entry has already been consumed.
Beta.7 replaces HTTPS discovery with packaged public bootstrap settings. Update the
app and use NHP Server address `nhp.beta.accesspages.app:62206`. Keep app data; the
app preserves the enrolled identity only if all previously saved NHP/signing keys
and certificate authorities match. No new enrollment token is needed. The obsolete
Service address option is no longer used. Guest invitations still start at
`https://access.beta.accesspages.app`.

Bootstrap settings contain public keys and CA certificates, never private keys or
API credentials. Changing those bootstrap trust anchors requires a reviewed app
update. Customer routes, tunnel credentials, certificates and invitation creation
remain authenticated operations behind NHP admission.

All pages use one installation endpoint; their grants and sessions remain
separate. Revocation in Admin removes the local grant and revokes its hosted
AccessLink. The Guest process has no Supervisor token, Admin credential or native
management key; its device broker enforces page policy against the demo data.

Demo data replaces only the HA device backend. Native REG/RAK, NHP admission,
the outbound NHP-FRP tunnel, customer TLS, signed handoffs, GuestToken/AccessLink
handling, expiry and revocation still use the real implementation.

## Invitation email and guest activity

In **Configure email & alerts**, you can configure your own SMTP provider for
invitation emails and owner alerts. When creating a guest, select **Email
invitation using my SMTP** and supply the recipient. Sending an invitation is
optional and independent of requiring guest verification. If verification is
selected, its invited address and the invitation email recipient must match.

If email delivery cannot be confirmed, the guest invitation is still created.
Use the displayed AccessLink for manual sharing; avoid creating another guest
just to retry delivery. SMTP credentials stay in the app's private local data and
are not sent to OpenNHP Service. Protect app backups as secrets.

Google sign-in and email-code verification happen at OpenNHP Service. They
require the operator's hosted provider configuration and acceptance testing;
this app update does not activate those providers. Required verification fails
closed when unavailable. The Gateway does not issue or accept verification codes.

**View activity** records use of each local guest grant. First-access and selected
action alerts use owner-configured local delivery; an alert failure does not
repeat a device action. A possession-only link identifies the invitation used,
not the person holding it. HA Companion notifications remain unavailable in the
demo-only beta.

## Availability and recovery

The HA system, app, OpenNHP Service and outbound network must remain available.
The app retries transient connection failures. Its readiness check includes the
connected FRP guest tunnel; a full guest journey is verified separately by beta tests.

Preserve app data in an encrypted backup. Restoring older authorization state
requires operator reconciliation and invalidation of old invitations and sessions.
See the beta runbook and current completion report for validated recovery behavior
and remaining limitations.
