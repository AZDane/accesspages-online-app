# Access Pages Online — Home Assistant app

The app connects directly to its Home Assistant installation. Guest access uses the NHP/AC/FRP architecture; only the local HA broker receives Home Assistant credentials.

## Resource isolation

In Configuration, **Resource isolation** accepts:

- `page` (default): one OpenNHP resource and site per page, shared by its guests. Site provisioning starts in the background after the page is created, even before it has any guests. DNS and tunnel setup must finish before the site is ready; later invitations reuse that site.
- `guest`: one OpenNHP resource and site per invitation. Creating an invitation provisions its site and waits for DNS and tunnel readiness. Two invitations to the same page have different ResourceIDs and site hostnames, even if they are for the same person.

The site's first hostname label is its ResourceID in both modes. ResourceID identifies the route; it is not a credential. Each guest has a separate browser session, and the broker checks that session's resource, invitation and current page permissions on every protected read or action. Revoking one guest denies that guest while other authorized guests can continue.

Page mode already supports individual guest authorization and revocation. Guest mode adds a separate browser origin and host-only cookie scope for each invitation, plus an endpoint that can be withdrawn independently. Revoking a guest in page mode keeps the page's site for its other guests; in guest mode, it also retires that invitation's site.

Network admission uses the public source IP and destination IP/port, not the identity of a browser. Guests sharing a public IP can potentially reach another guest's open endpoint in either mode. A revoked guest cannot use their own session to access another guest's protected data or controls; that requires the other guest's valid session cookie. Withdrawing one endpoint does not block that person from reaching every other endpoint.

Both modes use a separate process and Linux identity per page. Admin remains accessible only through Home Assistant Ingress; page workers cannot read another page's private files or Home Assistant credentials. Guest mode adds separate network resources, not a process per guest.

After changing this setting, save and restart the app. **Changing modes revokes every existing invitation and invalidates its guest sessions.** Page settings remain. Create fresh invitations when the app reconnects. Saving the same mode and ordinary restarts do not revoke invitations.

The current beta has a shared capacity of eight active resources across installations. Page mode uses one per page; guest mode uses one per invitation. Creating a guest invitation can take longer while its site becomes ready. Creating or retiring resources can briefly interrupt other guests while the installation tunnel reconnects. Capacity exhaustion does not fall back to a shared resource.

## Updating to beta.24

When updating from beta.23, back up the app and install the update on the dedicated
HA test installation. Enrollment, pages, the selected isolation mode and guest
authorization are preserved. No connection reset or OpenNHP Service update is
required. Reload open Admin tabs after updating.

Supervisor applies the bundled AppArmor profile automatically; this app has no
selectable Protection mode toggle. This update adds separate network restrictions
for guest page processes. Check Admin, guest controls, activity and any configured
notifications, then individual guest revocation and an app restart.

This beta targets the standard Home Assistant Supervisor environment. Device
acceptance, including native ARM64 validation, is still required. If startup or a
normal operation fails, retain the app and Supervisor logs and restore the app
backup; do not loosen security settings to work around a failure.

## Updating to beta.23

When updating from beta.22, back up the app and install the update.
Enrollment, pages, the selected isolation mode and guest authorization
are preserved. No connection reset or service cutover is required. Reload open
Admin tabs after updating, then check Admin, guest controls and revocation.

The app logs a brief warning if a connection or size limit is reached. These
warnings contain a limit and event count, without request contents or credentials.

## Updating to beta.22

When updating from beta.21, back up the app and install the update.
The tighter AppArmor profile takes effect when the updated app
starts. Enrollment, page settings and the selected isolation mode are preserved.
No OpenNHP Service cutover, guest-state migration or connection reset is required.

Check Admin, guest controls and revocation after updating. If the app cannot start
or a normal operation fails, retain the logs and use the previous reviewed app
backup for recovery; do not loosen security settings to work around the failure.

The beta.22 profile restricts file access and executable paths. Separate guest
worker network restrictions are introduced in beta.24.

## Updating to resource isolation

Coordinate this source update with the matching OpenNHP Service deployment. The operator must revoke existing invitations and replace old route/session state during cutover, preserving page settings and app data. This package does not migrate old route or session schemas. Create new invitations only after the updated service and app are ready; old invitations and browser sessions are not retained. Do not reset the connection or edit stored state as an upgrade procedure.

## Normal Home Assistant connection

The app uses its own Supervisor HA API at `http://supervisor/core`. No credential from another Home Assistant is needed. Missing credentials fail startup. Admin, guest, TLS and connector processes do not inherit the HA/Supervisor token. The guest receives only page-approved state and can invoke only allowed controls.

The current scope remains sensors, binary sensors and lights (on/off and validated brightness); cameras, proximity and other actionable domains remain disabled. Configure `include_domains`, `include_areas`, `exclude_domains` and `exclude_entities` to narrow discovery, then select exact entities/actions in Admin. The underlying HA token is not an entity-scoped token; page/broker policy enforces the guest boundary.

Guest revocation denies reads/actions immediately. The loaded page can show the explicit denial during the fixed 15-second transport grace, then NHP/AC withdraws transport. Normal polling remains about 3 seconds with a 10-second request deadline.
