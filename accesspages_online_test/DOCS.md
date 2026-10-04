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

## Updating from beta.27 to beta.28

Beta.28 fixes guest access failing after an app restart following Finished
Sharing. Back up the app, install the update, and keep the existing enrollment,
app data and resource-isolation setting. Wait for the app to reconnect, then
reload the guest page. Existing unexpired grants, sessions and guest-held
invitations remain valid; the removed invitation stays unavailable in Admin.
No further hosted cutover or invitation replacement is needed for this update.

Confirm that a guest can still read states and operate a permitted safe light
after Finished Sharing and another app restart. Keep the guest active until the
operator finishes the remaining removal and revocation checks. An expired grant
still requires a fresh invitation through the normal Add Guest workflow.

For the first update from beta.26 or earlier, follow the Method Two cutover below.

## Updating to beta.27 (Method Two)

This is a coordinated protocol cutover with OpenNHP Service, including its landing
page. Do not install or start this version until the operator schedules the
cutover. There is no mixed-version invitation support. These steps take precedence
over the older version-specific update and rollback notes below.

1. Record the installed version, pages and intended guest policies. Make a private
   Home Assistant backup including this app. Keep enrollment, app data and pending
   revocations; do not reset the connection or edit stored state.
2. Stop sharing and admitting guests. In Admin, use the existing revoke controls
   to remove every old local guest grant. This immediately denies its sessions and
   preserves pending service revocations. Confirm each page has no legacy guest.
3. While the operator keeps the hosted authority stopped and prepares and validates
   its separate hash-only database candidate, update this app from GitHub. Keep it
   stopped until the operator coordinates startup of the updated Service, landing
   page and app. The operator preserves Gateway identities, resource ownership,
   epochs and pending work; do not manufacture replacement identifiers.
4. Start the updated app when instructed and reload Admin tabs. Confirm enrollment,
   pages, isolation mode and routes remain correct. First startup removes the old
   local credential-registry column and interrupted page-write files while keeping
   pending revocations and invitation-removal markers.
5. Create fresh invitations through Add Guest, selecting expiry and verification
   again. One-part invitations cannot be upgraded and must be replaced. Confirm
   admission, configured verification, permitted states/actions, activity, page
   isolation, revocation and restart with the operator before ending maintenance.
6. After acceptance, make a new customer backup paired with the operator's validated
   v2 hosted backup. These establish the oldest supported recovery baseline. Retire
   pre-v2 operational backups only after that succeeds. Never restore old active
   grants or enable the old protocol to work around a failed cutover; keep admission
   closed and contact the operator.

The Gateway creates a new random GuestToken and stores its hash in the local
grant. OpenNHP Service receives only that hash. The saved v2 invitation combines
an AccessLink admission credential and GuestToken; the browser uses AccessLink for
native enrollment and NHP knocks, then presents GuestToken separately to the
Guest Gateway along with the signed handoff. GuestToken stays in browser memory
through verification; reopening the original invitation is required if that
memory is lost. Both credentials must remain private.

### Finished Sharing

Copy, email, share or display the invitation QR as needed. These actions and closing
the dialog leave the saved invitation available. When finished distributing it,
choose **Finished Sharing** and confirm. The app removes both saved invitation
credentials and no longer offers its URL or QR, including after restart or stale
Admin edits. The guest's access, existing session, verification requirements,
expiry and activity remain intact. Revoke Guest still works through authenticated
identifier-based management, including durable retry after a service outage.

Finished Sharing does not remove guest-held copies, sent messages, clipboard
contents or older backups, and does not claim secure erasure. Use revocation to
end guest access.

### Security boundary

For fresh v2 grants, hosted database contents and the handoff signing key alone
cannot supply the missing random GuestToken required by the Gateway. A valid
signature and hash do not replace presenting GuestToken, and GuestToken alone
does not replace NHP admission. Hosted landing-page JavaScript remains trusted
because it reads the invitation credentials. Ordinary session cookies remain
bearer credentials. Keep backups and sharing channels private.

## Updating to beta.26

When updating from beta.25, back up the app and install the update on the dedicated
HA test installation. Enrollment, pages, the selected isolation mode and guest
authorization are preserved. No connection reset or OpenNHP Service update is
required. Reload open Admin and guest tabs after updating.

Beta.25 used a shared Home Assistant entity subscription. Beta.26 returns to
bounded REST state reads when guests poll their pages, with no background state
subscription. Only the broker contacts HA, and it rechecks guest authorization
before returning states. Normal browser polling, supported sensor/light controls
and fresh validation of actions remain in place. Failed reads keep controls
unavailable until a successful refresh.

Check Admin and two invited guests in the selected isolation mode: current states,
permitted controls and activity, then individual revocation and an app restart.
The bundled AppArmor profile and package options are unchanged. Supervisor applies
the profile automatically; there is no selectable Protection mode toggle.

## Updating to beta.25

When updating from beta.24, back up the app and install the update on the dedicated
HA test installation. Enrollment, pages, the selected isolation mode and guest
authorization are preserved. No connection reset or OpenNHP Service update is
required. Reload open Admin and guest tabs after updating.

Guest pages now share a Home Assistant state subscription for the entities needed
by active guests. The app stops the subscription after a short period without guest
activity. Normal browser polling and validation of each control operation remain
in place. This requires Home Assistant 2022.4 or later.

Check that two invited guests receive current demo states and can operate their
permitted controls, with activity recorded for each guest. Revoke one guest and
confirm the other continues, then restart the app and repeat those checks.
The bundled AppArmor profile is unchanged. Supervisor applies it automatically;
there is no selectable Protection mode toggle for this app.

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

Guest revocation reports **Access revoked** once the app has durably removed local access. Existing guest sessions, reads/actions and new handoffs are denied by the local grant checks. Remote cleanup continues through the existing durable worker, including after restart, without delaying that success message. A local storage failure is reported as an error. Connection reset retains its separate lifecycle behavior.

Remote transport withdrawal can lag local denial during an outage. The fixed 15-second transport grace starts when remote revocation is processed; the loaded guest page can show explicit denial while transport remains available. Normal polling remains about 3 seconds with a 10-second request deadline.
