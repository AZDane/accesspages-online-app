## 0.1.0-beta.15

- Revoke guest authorization immediately, with a bounded status-notification window before native transport withdrawal.
- Clear guest controls on revocation or connection loss; bound requests to ten seconds and recover status on return.
- Preserve pending revocation across restart and deny stale concurrent requests.

# 0.1.0-beta.14

- Allow an invitation to permit Google or email verification when advertised by OpenNHP Service.
- Preserve single-method invitation policy and verify the actual signed proof against the permitted methods and invited identity.
- Preserve the existing signed handoff, enrollment, page, session and revocation contracts.

# 0.1.0-beta.13

- Refresh into enrollment after an OpenNHP Service connection reset completes.
- Hide the setup credential input during enrollment and show a spinner with the current preparation stage.
- Show certificate and startup progress after reloading an enrolled app; restore the input if enrollment fails.

# 0.1.0-beta.12

- Complete the OpenNHP Service reset handoff: stop the isolated Gateway processes, remove local connection identities, certificates and page capabilities, and return to one-use enrollment.
- Preserve page layouts and owner email/alert settings while rotating page capabilities and removing the old local connection state.

# 0.1.0-beta.11

- Add optional Home Assistant sensor, binary-sensor and light access through the isolated local broker; demo mode remains the default.
- Add include/exclude Configuration filters and enforce the same entity/action policy in discovery, reads and actions.
- Allow invitation lifetimes up to the fixed 30-day Access Pages maximum while retaining 24 hours as the default.
- Expose the existing OpenNHP Service connection reset so owners can revoke guest links, preserve page layouts and enroll again with a new one-use setup credential.
- Add supported HA Companion notification destinations and keep Home Assistant credentials out of Guest, browser and hosted-service processes.
- Retain pinned OpenNHP/NHP-FRP source and suppress native credential payload logging in the app build.

# 0.1.0-beta.10

- Restore individual guest activity and first-access/action alerts through the trusted local broker.
- Add optional invitation emailing using the owner's SMTP, independently of Google/email verification. If delivery fails, keep the created invitation available for manual sharing.
- Keep SMTP settings local for invitations and owner alerts; do not forward them to OpenNHP Service. Guest identity verification remains hosted and requires the operator's provider setup.
- Require the signed verification method and recipient to match the local guest policy. Reject simulated verification and invalidate sessions when that policy changes.
- Fix invitation-form validation and retry behavior, and use Access Pages/OpenNHP naming throughout the app.
- Preserve enrollment, pages, guests and queued revocations. Existing browser sessions require a fresh AccessLink handoff; a consumed one-time or expired link needs a new invitation.
- Continue using demo devices only. No Home Assistant API access, live-device controls or HA Companion notifications are enabled in this beta.

# 0.1.0-beta.9

- Keep the local administration page and guest list available through trusted HA Ingress when the remote tunnel is offline and local admin services are running.
- Let owners revoke guests and queue service-side withdrawal during an outage. Preserve the existing Ingress source and CSRF checks.
- Show a reconnecting page for an already-enrolled app waiting to start, instead of asking for another enrollment token.
- Keep beta.8's durable retry behavior and existing enrollment, pages and guests.

# 0.1.0-beta.8

- Keep failed guest revocations queued on disk and retry them after service outages or app restarts.
- Confirm both service-side revocation and the network admission update before clearing a queued request and deleting its stored invitation secret.
- Treat native request timeouts as retryable service errors. Local guest access is still disabled first.
- Preserve enrollment, pages and guests when upgrading from beta.7. Uses the matching hosted admission-withdrawal update.

# 0.1.0-beta.7

- Remove public HTTPS discovery. Start with the native NHP Server address and public trust settings shipped with the app.
- Use NHP Server address `nhp.beta.accesspages.app:62206`; the old HTTPS Service address option is no longer used.
- Keep registration on native REG/RAK and route, tunnel, certificate and invitation operations behind NHP admission.
- Preserve enrolled keys when the saved authority matches the packaged bootstrap settings. Keep app data; no new enrollment token is needed.
- Keep enrollment tokens one-use, remove them after confirmation, and retain `/#<token>` guest invitations.

# 0.1.0-beta.6

- Separate the Service discovery address from the guest AccessLink website.
- Use https://relay.beta.accesspages.app as the beta Service address. Update this option when upgrading an enrolled app.
- Preserve an existing beta identity across this address change only when every saved public key and CA matches.
- Keep enrollment tokens one-use and remove them after successful enrollment.

# 0.1.0-beta.5

- Generate shorter guest AccessLinks containing only `/#<token>`; the service resolves the assigned resource.
- Accept a one-use enrollment API token and configure the Service address on the app's Configuration page.
- Use the new opaque AccessLink and raw enrollment-token formats. Create fresh pages and guests when testing this beta. Enrolled identities remain bound to their original service address.
- Preserve demo-only device data, native NHP authentication and the separate management and connector identities.

# 0.1.0-beta.4

- Fix startup under the app's enforced AppArmor profile by allowing package-directory reads and data-directory setup. App code remains read-only under the profile.
- Remove Home Assistant API access. Use a built-in demo lock, light and temperature sensor for NHP tests, without HA credentials or live-device actions.
- Keep the real native enrollment, NHP admission, NHP-FRP, TLS and page authorization paths. Demo device states reset on restart; stored identities and pages are preserved.
- Add GitHub-hosted startup and demo-backend checks with networking isolated and AppArmor enforced.

# 0.1.0-beta.3

- Accept signed handoff issue timestamps up to five seconds ahead to accommodate clock differences. Signature, destination, replay and expiration checks remain enforced.

# 0.1.0-beta.2

- One enrollment action creates persistent native Gateway and separate connector identities.
- One assigned guest endpoint serves all pages, with isolated sessions and local HA permissions.
- Uses customer-owned TLS keys, outbound NHP-FRP, protected remote management, and signed handoffs.
- Adds connector recovery/status, identity-version session invalidation, and Home Assistant Ingress path support.
- Experimental beta for dedicated test HA installations. Hosted enrollment credentials are supplied privately.
