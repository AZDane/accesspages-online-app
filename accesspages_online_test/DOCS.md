# Access Pages Online — Home Assistant app

The current beta uses normal Home Assistant integration. It has no built-in fake device backend. Guest access continues through the existing NHP/AC/FRP architecture; only the local HA broker receives Home Assistant credentials.

## Before upgrading from beta.15

Use the established Admin UI to revoke existing invitations. In the app's Configuration select `device_mode: homeassistant` only for the intended Home Assistant installation. Discover its actual entity IDs and replace old `nhp_demo_*` references in saved pages. Do not create new invitations before the app's first activation.

The app defaults to `review_required`; legacy `demo` is accepted only as a blocked migration state. Until an owner explicitly selects `homeassistant`, no HA broker or guest transport is started. First activation also refuses existing grants, fake resource references or invalid page/activation records. The migration page explains the necessary review and leaves saved data untouched. After a successful empty-grant review, a private local approval marker allows ordinary restarts with newly created normal-HA invitations. If prerequisites were missed, preserve app data and contact support before continuing; never edit the database or files manually.

## Normal Home Assistant connection

The app uses its own Supervisor HA API at `http://supervisor/core`. No credential from another Home Assistant is needed. Missing credentials fail startup. Admin, guest, TLS and connector processes do not inherit the HA/Supervisor token. The guest receives only page-approved state and can invoke only allowed controls.

The current scope remains sensors, binary sensors and lights (on/off and validated brightness); cameras, proximity and other actionable domains remain disabled. Configure `include_domains`, `include_areas`, `exclude_domains` and `exclude_entities` to narrow discovery, then select exact entities/actions in Admin. The underlying HA token is not an entity-scoped token; page/broker policy enforces the guest boundary.

Guest revocation denies reads/actions immediately. The loaded page can show the explicit denial during the fixed 15-second transport grace, then NHP/AC withdraws transport. Normal polling remains about 3 seconds with a 10-second request deadline.
