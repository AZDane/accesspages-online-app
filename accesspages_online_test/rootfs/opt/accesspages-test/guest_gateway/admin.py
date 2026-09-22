"""Administrative HTTP routes using shared gateway runtime services."""


def handle_get(handler, parsed, path, runtime):
    if path == "/api/admin/verification-status":
        if not handler._require_admin():
            return
        try:
            handler._send_json(200, runtime.ACCESS_SERVICE_CLIENT.verification_status())
        except runtime.AccessServiceError:
            handler._send_json(503, {"error": "Hosted verification status is unavailable. Retry when the service reconnects."})
        return

    if path == "/api/admin/notification-options":
        if not handler._require_admin():
            return
        try:
            email = runtime.SMTP_CONFIG_STORE.public_view()
            available = runtime.HA_CLIENT.notification_targets()
            selected = [
                target for target in runtime.NOTIFICATION_TARGET_STORE.load()
                if target in available
            ]
            handler._send_json(200, {
                "email": {
                    "configured": bool(email.get("configured")),
                    "address": email.get("administrator_email", ""),
                },
                "mobile_targets": selected,
                "available_mobile_targets": available,
            })
        except runtime.HomeAssistantError as error:
            handler._send_ha_error(error)
        except (runtime.EmailConfigError, runtime.AccessServiceError, OSError) as error:
            handler._send_json(runtime.HTTPStatus.BAD_REQUEST, {"error": str(error)})
        return

    if path == "/api/admin/email/config":
        if not handler._require_admin():
            return
        handler._send_json(200, runtime.SMTP_CONFIG_STORE.public_view())
        return

    if path == "/api/admin/discovery":
        if not handler._require_admin():
            return

        try:
            handler._send_json(
                200,
                runtime.HA_CLIENT.discover_entities(
                    force=(
                        runtime.parse_qs(parsed.query)
                        .get("refresh", ["0"])[0]
                        == "1"
                    )
                ),
            )
        except runtime.HomeAssistantError as error:
            handler._send_ha_error(error)
        return

    if path == "/api/admin/pages":
        if not handler._require_admin():
            return

        pages = runtime.PAGE_STORE.list_pages()
        for item in pages:
            handler._cleanup_expired_grants(item["id"])
        handler._send_json(
            200,
            {
                "pages": runtime.PAGE_STORE.list_pages(),
                "access_service_api_configured": runtime.ACCESS_SERVICE_CLIENT.configured,
                "access_link_max_lifetime_days": runtime.ACCESS_LINK_MAX_LIFETIME_DAYS,
            },
        )
        return

    if path.startswith("/api/admin/pages/") and "/activity" in path:
        if not handler._require_admin():
            return
        remainder = path.removeprefix("/api/admin/pages/").strip("/")
        parts = remainder.split("/")
        if len(parts) not in (2, 3) or parts[1] != "activity":
            handler._send_json(404, {"error": "not found"})
            return
        page_id = parts[0]
        handler._cleanup_expired_grants(page_id)
        page = handler._load_page(page_id)
        if page is None:
            return
        try:
            for grant in page["access_grants"]:
                runtime.ACTIVITY_STORE.register_guest(page_id, grant)
            if len(parts) == 2:
                handler._send_json(
                    200,
                    {
                        "guests": runtime.ACTIVITY_STORE.page_guests(page_id),
                        "security_events": (
                            runtime.ACTIVITY_STORE.page_security_events(page_id)
                        ),
                    },
                )
            else:
                activity = runtime.ACTIVITY_STORE.guest_activity(
                    page_id,
                    parts[2],
                )
                if activity is None:
                    handler._send_json(
                        404,
                        {"error": "Guest activity not found"},
                    )
                else:
                    handler._send_json(200, activity)
        except (OSError, runtime.sqlite3.Error):
            handler._send_json(
                runtime.HTTPStatus.INTERNAL_SERVER_ERROR,
                {"error": "Could not load guest activity"},
            )
        return

    if path.startswith("/api/admin/pages/"):
        if not handler._require_admin():
            return

        page_id = path.removeprefix("/api/admin/pages/").strip("/")
        if not page_id or "/" in page_id:
            handler._send_json(404, {"error": "not found"})
            return

        page = handler._load_page(page_id)
        if page is not None:
            handler._send_json(200, runtime.page_admin_view(page))
        return
    handler._send_json(404, {"error": "not found"})


def handle_post(handler, path, payload, runtime):
    if path == "/api/admin/connection/reset":
        if not handler._require_admin():
            return
        handler._reset_service_connection(payload)
        return

    if path == "/api/admin/email/config":
        if not handler._require_admin():
            return
        try:
            runtime.SMTP_CONFIG_STORE.save(payload)
            handler._send_json(200, runtime.SMTP_CONFIG_STORE.public_view())
        except (runtime.EmailConfigError, runtime.AccessServiceError, OSError) as error:
            handler._send_json(runtime.HTTPStatus.BAD_REQUEST, {"error": str(error)})
        return

    if path == "/api/admin/alerts/config":
        if not handler._require_admin():
            return
        try:
            available = set(runtime.HA_CLIENT.notification_targets())
            selected = runtime.NOTIFICATION_TARGET_STORE.save(
                payload.get("mobile_targets"), available,
            )
            handler._send_json(200, {"mobile_targets": selected})
        except runtime.HomeAssistantError as error:
            handler._send_ha_error(error)
        except (runtime.EmailConfigError, runtime.AccessServiceError, OSError) as error:
            handler._send_json(runtime.HTTPStatus.BAD_REQUEST, {"error": str(error)})
        return

    if path == "/api/admin/alerts/test":
        if not handler._require_admin():
            return
        target = str(payload.get("target", "")).strip()
        try:
            if target not in runtime.NOTIFICATION_TARGET_STORE.load():
                raise runtime.EmailConfigError(
                    "Save this mobile alert destination before testing it"
                )
            runtime.HA_CLIENT.send_notification(
                target,
                "Access Pages test",
                "Mobile alert delivery from Access Pages is working.",
            )
            runtime.audit("mobile_notification_test_succeeded", target=target)
            handler._send_json(200, {"success": True})
        except (runtime.EmailConfigError, runtime.HomeAssistantError, OSError) as error:
            runtime.audit("mobile_notification_test_failed", target=target)
            handler._send_json(runtime.HTTPStatus.BAD_GATEWAY, {"error": str(error)})
        return

    if path == "/api/admin/email/test":
        if not handler._require_admin():
            return
        try:
            recipient = runtime.validate_email(
                payload.get("recipient"), "Test recipient",
            )
            runtime.send_email(
                runtime.SMTP_CONFIG_STORE.load(),
                recipient,
                "Access Pages email test",
                "Email delivery from Access Pages for Home Assistant is working.\n",
            )
            runtime.audit("smtp_test_succeeded")
            handler._send_json(200, {"success": True})
        except (runtime.EmailConfigError, runtime.AccessServiceError, OSError) as error:
            runtime.audit("smtp_test_failed")
            handler._send_json(runtime.HTTPStatus.BAD_GATEWAY, {"error": str(error)})
        return

    if path == "/api/admin/pages":
        if not handler._require_admin():
            return

        try:
            handler._validate_entity_policy(payload)
            page_id = str(payload.get("id", "")).strip()
            with runtime.page_action_lock(page_id):
                runtime.POLICY_PUBLISHER.prepare(page_id)
                page = runtime.PAGE_STORE.create(payload)
                try:
                    runtime.POLICY_PUBLISHER.publish(page)
                except runtime.PolicyPublishError:
                    runtime.PAGE_STORE.delete(page["id"])
                    raise
            handler._send_json(
                runtime.HTTPStatus.CREATED,
                runtime.page_admin_view(page),
            )
        except (runtime.PageConfigError, runtime.PageNotFoundError) as error:
            handler._send_page_error(error)
        except runtime.HomeAssistantError as error:
            handler._send_ha_error(error)
        except runtime.PolicyPublishError as error:
            handler._send_json(
                runtime.HTTPStatus.BAD_GATEWAY,
                {"error": str(error)},
            )
        return

    if path.startswith("/api/admin/pages/"):
        page_id = path.removeprefix("/api/admin/pages/").strip("/")
        if page_id and "/" not in page_id:
            if not handler._require_admin():
                return

            try:
                handler._validate_entity_policy(payload)
                with runtime.page_action_lock(page_id):
                    previous = runtime.PAGE_STORE.load(page_id)
                    runtime.POLICY_PUBLISHER.prepare(page_id)
                    page = runtime.PAGE_STORE.update(page_id, payload)
                    try:
                        runtime.POLICY_PUBLISHER.publish(page)
                    except runtime.PolicyPublishError:
                        runtime.PAGE_STORE.replace(page_id, previous)
                        raise
                handler._send_json(200, runtime.page_admin_view(page))
            except (runtime.PageConfigError, runtime.PageNotFoundError) as error:
                handler._send_page_error(error)
            except runtime.HomeAssistantError as error:
                handler._send_ha_error(error)
            except runtime.PolicyPublishError as error:
                handler._send_json(
                    runtime.HTTPStatus.BAD_GATEWAY,
                    {"error": str(error)},
                )
            return

    if path.startswith("/api/admin/pages/") and path.endswith("/preview"):
        if not handler._require_admin():
            return

        page_id = path.removeprefix("/api/admin/pages/")
        page_id = page_id.removesuffix("/preview").strip("/")
        if not page_id or "/" in page_id:
            handler._send_json(404, {"error": "not found"})
            return

        page = handler._load_page(page_id)
        if page is None:
            return

        expires_at = int((runtime.utc_now() + runtime.timedelta(minutes=15)).timestamp())
        preview_token = handler._preview_token(page_id, expires_at)
        handler._send_json(
            200,
            {
                "preview_url": (
                    f"access/{runtime.quote(page_id, safe='')}?"
                    f"{runtime.urlencode({'preview_token': preview_token})}"
                ),
                "expires_at": runtime.isoformat(runtime.datetime.fromtimestamp(expires_at, runtime.timezone.utc)),
            },
        )
        return

    if path.startswith("/api/admin/pages/") and path.endswith("/access-links"):
        if not handler._require_admin():
            return

        page_id = path.removeprefix("/api/admin/pages/")
        page_id = page_id.removesuffix("/access-links").strip("/")
        if not page_id or "/" in page_id:
            handler._send_json(404, {"error": "not found"})
            return

        with runtime.page_action_lock(page_id):
            handler._create_access_link(page_id, payload)
        return
    handler._send_json(404, {"error": "not found"})


def handle_put(handler, path, runtime):
    if not path.startswith("/api/admin/pages/"):
        handler._send_json(404, {"error": "not found"})
        return

    if not handler._require_admin():
        return

    page_id = path.removeprefix("/api/admin/pages/").strip("/")
    if not page_id or "/" in page_id:
        handler._send_json(404, {"error": "not found"})
        return

    try:
        payload = handler._read_json()
        handler._validate_entity_policy(payload)
        with runtime.page_action_lock(page_id):
            previous = runtime.PAGE_STORE.load(page_id)
            runtime.POLICY_PUBLISHER.prepare(page_id)
            page = runtime.PAGE_STORE.update(page_id, payload)
            try:
                runtime.POLICY_PUBLISHER.publish(page)
            except runtime.PolicyPublishError:
                runtime.PAGE_STORE.replace(page_id, previous)
                raise
        handler._send_json(200, runtime.page_admin_view(page))
    except ValueError as error:
        handler._send_json(
            runtime.HTTPStatus.BAD_REQUEST,
            {"error": str(error)},
        )
    except (runtime.PageConfigError, runtime.PageNotFoundError) as error:
        handler._send_page_error(error)
    except runtime.HomeAssistantError as error:
        handler._send_ha_error(error)
    except runtime.PolicyPublishError as error:
        handler._send_json(
            runtime.HTTPStatus.BAD_GATEWAY,
            {"error": str(error)},
        )


def handle_delete(handler, path, runtime):
    if not handler._require_admin():
        return

    if path.startswith("/api/admin/pages/") and "/activity/" in path:
        remainder = path.removeprefix("/api/admin/pages/").strip("/")
        parts = remainder.split("/")
        if len(parts) != 3 or parts[1] != "activity":
            handler._send_json(404, {"error": "not found"})
            return
        try:
            deleted = runtime.ACTIVITY_STORE.delete_revoked_guest(
                parts[0],
                parts[2],
            )
        except (OSError, runtime.sqlite3.Error):
            handler._send_json(
                runtime.HTTPStatus.INTERNAL_SERVER_ERROR,
                {"error": "Could not delete guest record"},
            )
            return
        if not deleted:
            handler._send_json(
                runtime.HTTPStatus.CONFLICT,
                {"error": "Only revoked guest records can be deleted"},
            )
            return
        runtime.audit(
            "guest_activity_deleted",
            page_id=parts[0],
            grant_id=parts[2],
        )
        handler._send_json(
            200,
            {"success": True, "guest_deleted": True},
        )
        return

    if path.startswith("/api/admin/pages/") and "/access-links/" in path:
        remainder = path.removeprefix("/api/admin/pages/").strip("/")
        parts = remainder.split("/")
        if len(parts) != 3 or parts[1] != "access-links":
            handler._send_json(404, {"error": "not found"})
            return
        page_id, _, grant_id = parts
        if not page_id or not grant_id:
            handler._send_json(404, {"error": "not found"})
            return
        handler._revoke_grant(page_id, grant_id)
        return

    if path.startswith("/api/admin/pages/") and path.endswith("/access-links"):
        page_id = path.removeprefix("/api/admin/pages/")
        page_id = page_id.removesuffix("/access-links").strip("/")
        if not page_id or "/" in page_id:
            handler._send_json(404, {"error": "not found"})
            return
        handler._revoke_all_grants(page_id)
        return

    if path.startswith("/api/admin/pages/"):
        page_id = path.removeprefix("/api/admin/pages/").strip("/")
        if not page_id or "/" in page_id:
            handler._send_json(404, {"error": "not found"})
            return

        try:
            with runtime.page_action_lock(page_id):
                page = runtime.PAGE_STORE.load(page_id)
                grants = list(page["access_grants"])
                runtime.POLICY_PUBLISHER.prepare(page_id)
                runtime.PAGE_STORE.delete(page_id)
                # Local denial and durable native intent are committed even
                # when policy publication fails; the marker owns recovery.
                runtime.POLICY_PUBLISHER.delete(page_id)
                for grant in grants:
                    try:
                        runtime.VERIFICATION_STORE.revoke(page_id, grant["id"])
                        runtime.VERIFICATION_RECIPIENTS.delete(page_id, grant["id"])
                    except (OSError, runtime.sqlite3.Error, runtime.EmailConfigError):
                        runtime.audit("verification_session_cleanup_failed", page_id=page_id, grant_id=grant["id"])
                    try:
                        runtime.ACTIVITY_STORE.mark_revoked(page_id, grant)
                    except (OSError, runtime.sqlite3.Error):
                        runtime.audit(
                            "guest_activity_storage_failed",
                            operation="revoke",
                            page_id=page_id,
                            grant_id=grant["id"],
                        )
                try:
                    runtime.ACTIVITY_STORE.delete_page(page_id)
                except (OSError, runtime.sqlite3.Error):
                    runtime.audit(
                        "guest_activity_storage_failed",
                        operation="delete_page",
                        page_id=page_id,
                    )
            remote_failures = []
            for grant in grants:
                access_link_id = grant.get("access_link_id", "")
                if not access_link_id:
                    remote_failures.append({"grant_id": grant["id"], "error": "Missing AccessLink ID"})
                    continue
                try:
                    runtime.ACCESS_SERVICE_CLIENT.delete_access_link(
                        resource_id=grant.get("resource_id", ""),
                        access_link_id=access_link_id,
                        page_id=page_id,
                        grant_id=grant["id"],
                    )
                except runtime.AccessServiceError as error:
                    remote_failures.append({"grant_id": grant["id"], "error": str(error)})
            runtime.audit("page_deleted", page_id=page_id, remote_failure_count=len(remote_failures))
            handler._send_json(
                runtime.HTTPStatus.BAD_GATEWAY if remote_failures else 200,
                {"success": not remote_failures, "page_deleted": True, "remote_failures": remote_failures},
            )
        except (runtime.PageConfigError, runtime.PageNotFoundError) as error:
            handler._send_page_error(error)
        except runtime.PolicyPublishError as error:
            handler._send_json(
                runtime.HTTPStatus.BAD_GATEWAY,
                {"error": str(error)},
            )
        return

    handler._send_json(404, {"error": "not found"})
