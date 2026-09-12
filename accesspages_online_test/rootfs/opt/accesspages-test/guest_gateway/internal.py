"""Narrowly scoped internal broker HTTP routes."""


def handle_post(handler, path, payload, runtime):
    if path == "/api/internal/guest-activity":
        page_id = str(payload.get("page_id", ""))
        if not handler._is_page_broker(page_id):
            handler._send_json(runtime.HTTPStatus.UNAUTHORIZED, {"error": "not found"})
            return
        page = handler._load_page(page_id)
        if page is None:
            return
        operation = str(payload.get("operation", ""))
        supplied_grant = payload.get("grant") or {}
        grant_id = str(payload.get("grant_id") or supplied_grant.get("id", ""))
        grant = next(
            (item for item in page["access_grants"] if item["id"] == grant_id), None,
        )
        if not grant:
            handler._send_json(runtime.HTTPStatus.NOT_FOUND, {"error": "not found"})
            return
        try:
            if operation == "register":
                runtime.ACTIVITY_STORE.register_guest(page_id, grant)
                result = {"success": True}
            elif operation == "initial_access":
                result = {
                    "success": True,
                    "first": runtime.ACTIVITY_STORE.record_initial_access(page_id, grant),
                }
            elif operation == "action":
                resource = next(
                    (item for item in page["resources"] if item["entity_id"] == str(payload.get("entity_id", ""))),
                    None,
                )
                action = next(
                    (item for item in (resource or {}).get("actions", []) if item["id"] == str(payload.get("action_id", ""))),
                    None,
                )
                outcome = str(payload.get("outcome", ""))
                if not resource or not action or outcome not in {"success", "failed"}:
                    raise ValueError("Invalid activity event")
                runtime.ACTIVITY_STORE.record_action(
                    grant_id=grant_id,
                    entity_id=resource["entity_id"],
                    entity_name=resource["name"],
                    action_id=action["id"],
                    parameters=payload.get("parameters") if isinstance(payload.get("parameters"), dict) else {},
                    outcome=outcome,
                    error=str(payload.get("error", "")),
                )
                result = {"success": True}
            elif operation == "security_event":
                event_type = str(payload.get("event_type", ""))
                if event_type not in {
                    "action_rate_limited", "unapproved_action_attempt",
                    "home_assistant_action_rejected", "verification_code_sent",
                    "guest_email_verified", "verification_failed",
                }:
                    raise ValueError("Invalid activity event")
                runtime.ACTIVITY_STORE.record_security_event(
                    page_id=page_id,
                    grant_id=grant_id,
                    event_type=event_type,
                    details=payload.get("details") if isinstance(payload.get("details"), dict) else {},
                )
                result = {"success": True}
            else:
                raise ValueError("Invalid activity operation")
            handler._send_json(200, result)
        except (ValueError, OSError, runtime.sqlite3.Error):
            handler._send_json(runtime.HTTPStatus.BAD_REQUEST, {"error": "Invalid activity event"})
        return

    if path == "/api/internal/guest-notification":
        page_id = str(payload.get("page_id", ""))
        if not handler._is_page_broker(page_id):
            handler._send_json(runtime.HTTPStatus.UNAUTHORIZED, {"error": "not found"})
            return
        grant_id = str(payload.get("grant_id", ""))
        event_type = str(payload.get("event_type", ""))
        page = handler._load_page(page_id)
        if page is None:
            return
        grant = next((item for item in page["access_grants"] if item["id"] == grant_id), None)
        if not grant:
            handler._send_json(runtime.HTTPStatus.NOT_FOUND, {"error": "not found"})
            return
        settings = grant.get("notifications") or {}
        event_key = (
            "successful_action"
            if event_type == "entity_action" and payload.get("outcome") == "success"
            else "failed_action"
            if event_type in {"entity_action", "blocked_action"}
            else event_type
        )
        if event_key not in settings.get("events", []):
            handler._send_json(200, {"success": True, "sent": 0})
            return
        guest = grant.get("label") or "A guest"
        title = "Access Pages activity"
        if event_type == "initial_login":
            message = f"{guest} opened {page['title']} for the first time."
        else:
            resource = next(
                (item for item in page["resources"] if item["id"] == str(payload.get("resource_id", ""))),
                None,
            )
            action = next(
                (item for item in (resource or {}).get("actions", []) if item["id"] == str(payload.get("action_id", ""))),
                None,
            )
            entity = (resource or {}).get("name") or "an unavailable entity"
            operation = (action or {}).get("name") or "an unapproved action"
            result = "succeeded" if event_key == "successful_action" else "failed or was blocked"
            message = f"{guest} used {entity}: {operation} {result}."
        try:
            sent = 0
            allowed_mobile_targets = set(runtime.NOTIFICATION_TARGET_STORE.load())
            for target in settings.get("targets", []):
                if target == "email":
                    config = runtime.SMTP_CONFIG_STORE.load()
                    runtime.send_email(config, config.administrator_email, title, message + "\n")
                else:
                    if target not in allowed_mobile_targets:
                        raise runtime.EmailConfigError(
                            "Mobile alert destination is not enabled"
                        )
                    runtime.HA_CLIENT.send_notification(target, title, message)
                sent += 1
            handler._send_json(200, {"success": True, "sent": sent})
        except (runtime.EmailConfigError, runtime.HomeAssistantError, OSError):
            handler._send_json(runtime.HTTPStatus.BAD_GATEWAY, {"error": "Notification delivery failed"})
        return

    if path == "/api/internal/email/verification":
        page_id = str(payload.get("page_id", ""))
        if not handler._is_page_broker(page_id):
            handler._send_json(runtime.HTTPStatus.UNAUTHORIZED, {"error": "not found"})
            return
        grant_id = str(payload.get("grant_id", ""))
        code = str(payload.get("code", ""))
        page = handler._load_page(page_id)
        if page is None:
            return
        grant = next((item for item in page["access_grants"] if item["id"] == grant_id), None)
        if not grant or not grant.get("verification_required") or not runtime.re.fullmatch(r"\d{6}", code):
            handler._send_json(runtime.HTTPStatus.NOT_FOUND, {"error": "not found"})
            return
        try:
            text, html = runtime.verification_email_content(code)
            runtime.send_email(
                runtime.SMTP_CONFIG_STORE.load(),
                runtime.VERIFICATION_RECIPIENTS.get(page_id, grant_id),
                "Your Access Pages verification code",
                text,
                html_body=html,
            )
            handler._send_json(200, {"success": True})
        except runtime.EmailConfigError as error:
            handler._send_json(runtime.HTTPStatus.BAD_GATEWAY, {"error": str(error)})
        return
    handler._send_json(404, {"error": "not found"})
