# Access Pages Online test

Install this experimental app only on an authorized beta Home Assistant system.
It is managed through HA Ingress and does not request Home Assistant API access.
It uses built-in demo devices so that NHP can be tested without HA credentials.

## Configuration

There are no entity, hostname, port, key or tunnel credential options to assemble.
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
   its owner with a private, expiring enrollment link.
2. Start the app, open it through HA Ingress and paste that link.
3. The app generates its own Gateway identity and completes native REG/RAK. It
   registers a separate connector identity and receives its allocated route.
4. The app generates a private TLS key locally and submits only a CSR for its
   certificate. It then starts its outbound connector and local Admin interface.

Keep enrollment links private: they are one-use bootstrap credentials. The app
retains its keys in its private data directory and can recover an interrupted
enrollment using the saved identity. Deleting app data requires operator
revocation and enrollment of a replacement installation.

## Guest invitations

Create a page and select its demo entities and allowed actions. Create a guest
invitation with a lifetime and optional verification, then share the AccessLink
privately. The guest starts at the shared access website. OpenNHP admission is
followed by a signed, one-use handoff to the customer's Guest Gateway.

All pages use one installation endpoint; their grants and sessions remain
separate. Revocation in Admin removes the local grant and revokes its hosted
AccessLink. The Guest process has no Supervisor token, Admin credential or native
management key; its device broker enforces page policy against the demo data.

Demo data replaces only the HA device backend. Native REG/RAK, NHP admission,
the outbound NHP-FRP tunnel, customer TLS, signed handoffs, GuestToken/AccessLink
handling, expiry and revocation still use the real implementation.

## Availability and recovery

The HA system, app, OpenNHP Service and outbound network must remain available.
The app retries transient connection failures. Its readiness check includes the
connected FRP guest tunnel; a full guest journey is verified separately by beta tests.

Preserve app data in an encrypted backup. Restoring older authorization state
requires operator reconciliation and invalidation of old invitations and sessions.
See the beta runbook and current completion report for validated recovery behavior
and remaining limitations.
