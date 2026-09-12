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
