# 0.1.0-beta.3

- Accept signed handoff issue timestamps up to five seconds ahead to accommodate clock differences. Signature, destination, replay and expiration checks remain enforced.

# 0.1.0-beta.2

- One enrollment action creates persistent native Gateway and separate connector identities.
- One assigned guest endpoint serves all pages, with isolated sessions and local HA permissions.
- Uses customer-owned TLS keys, outbound NHP-FRP, protected remote management, and signed handoffs.
- Adds connector recovery/status, identity-version session invalidation, and Home Assistant Ingress path support.
- Experimental beta for dedicated test HA installations. Hosted enrollment credentials are supplied privately.
