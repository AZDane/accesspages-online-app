# Access Pages Online — Home Assistant app

The current beta uses normal Home Assistant integration. It has no built-in fake device backend. Guest access continues through the existing NHP/AC/FRP architecture; only the local HA broker receives Home Assistant credentials.

## Resource isolation

In Configuration, **Resource isolation** accepts:

- `page` (default): one OpenNHP resource and site per page, shared by its guests.
- `guest`: one OpenNHP resource and site per invitation. Two invitations to the same page have different ResourceIDs and site hostnames.

The site's first hostname label is its ResourceID in both modes. ResourceID identifies the route; it is not a credential. Each guest has a separate browser session, and the broker checks that session's resource, invitation and current page permissions on every protected read or action. Revoking one guest denies that guest while other authorized guests can continue.

Both modes use a separate process and Linux identity per page. Admin remains accessible only through Home Assistant Ingress; page workers cannot read another page's private files or Home Assistant credentials. Guest mode adds separate network resources, not a process per guest.

After changing this setting, save and restart the app. **Changing modes revokes every existing invitation.** Page settings remain. Create fresh invitations when the app reconnects. Saving the same mode and ordinary restarts do not revoke invitations.

The current beta has a shared capacity of eight active resources across installations. Page mode uses one per page; guest mode uses one per invitation. Creating a guest invitation can take longer while its site becomes ready. Creating or retiring resources can briefly interrupt other guests while the installation tunnel reconnects. Capacity exhaustion does not fall back to a shared resource.

## Updating to resource isolation

Coordinate this source update with the matching OpenNHP Service deployment. The operator must revoke existing invitations and replace old route/session state during cutover, preserving page settings and app data. This package does not migrate old route or session schemas. Create new invitations only after the updated service and app are ready; old invitations and browser sessions are not retained. Do not reset the connection or edit stored state as an upgrade procedure.

## Before upgrading from beta.15

Use the established Admin UI to revoke existing invitations. In the app's Configuration select `device_mode: homeassistant` only for the intended Home Assistant installation. Discover its actual entity IDs and replace old `nhp_demo_*` references in saved pages. Do not create new invitations before the app's first activation.

The app defaults to `review_required`; legacy `demo` is accepted only as a blocked migration state. Until an owner explicitly selects `homeassistant`, no HA broker or guest transport is started. First activation also refuses existing grants, fake resource references or invalid page/activation records. The migration page explains the necessary review and leaves saved data untouched. After a successful empty-grant review, a private local approval marker allows ordinary restarts with newly created normal-HA invitations. If prerequisites were missed, preserve app data and contact support before continuing; never edit the database or files manually.

## Normal Home Assistant connection

The app uses its own Supervisor HA API at `http://supervisor/core`. No credential from another Home Assistant is needed. Missing credentials fail startup. Admin, guest, TLS and connector processes do not inherit the HA/Supervisor token. The guest receives only page-approved state and can invoke only allowed controls.

The current scope remains sensors, binary sensors and lights (on/off and validated brightness); cameras, proximity and other actionable domains remain disabled. Configure `include_domains`, `include_areas`, `exclude_domains` and `exclude_entities` to narrow discovery, then select exact entities/actions in Admin. The underlying HA token is not an entity-scoped token; page/broker policy enforces the guest boundary.

Guest revocation denies reads/actions immediately. The loaded page can show the explicit denial during the fixed 15-second transport grace, then NHP/AC withdraws transport. Normal polling remains about 3 seconds with a 10-second request deadline.
