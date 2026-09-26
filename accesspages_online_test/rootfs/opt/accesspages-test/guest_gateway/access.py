"""Guest access HTTP routes and action entry points."""


def handle_get(handler, path, runtime):
    if path.startswith("/api/access/"):
        remainder = path.removeprefix("/api/access/").strip("/")
        parts = remainder.split("/")
        if len(parts) == 3 and parts[1] == "camera":
            page_id, _camera, resource_id = parts
            page = handler._load_page(page_id)
            if page is None:
                return
            if not handler._require_page_access(page):
                return
            handler._send_camera_image(page, resource_id)
            return
        page_id = remainder
        if not page_id or len(parts) != 1:
            handler._send_json(404, {"error": "not found"})
            return

        page = handler._load_page(page_id)
        if page is None:
            return
        if not handler._require_page_access(page):
            return

        try:
            handler._send_json(200, handler._public_page(page))
        except runtime.HomeAssistantError as error:
            handler._send_ha_error(error)
        return
    handler._send_json(404, {"error": "not found"})


def handle_post(handler, path, payload, runtime):
    if runtime.nhp.ENABLED:
        with runtime.page_action_lock(path.removeprefix("/api/access/").split("/")[0]):
            return _handle_post(handler,path,payload,runtime)
    return _handle_post(handler,path,payload,runtime)


def _handle_post(handler, path, payload, runtime):
    if path.startswith("/api/access/"):
        remainder = path.removeprefix("/api/access/").strip("/")
        parts = remainder.split("/")

        if len(parts) == 3 and parts[1] == "verification" and parts[2] in {"send", "verify"}:
            if runtime.nhp.ENABLED:
                handler._send_json(404, {"error": "not found"})
                return
            page_id = parts[0]
            page = handler._load_page(page_id)
            if page is None:
                return
            supplied = handler._query().get("access_token", [""])[0]
            grant, status = handler._active_grant_for_token(page, supplied)
            if not grant or status != "active" or not grant.get("verification_required"):
                handler._send_json(runtime.HTTPStatus.UNAUTHORIZED, {"error": "A valid verification-enabled access link is required"})
                return
            if parts[2] == "send":
                try:
                    code = runtime.VERIFICATION_STORE.issue_challenge(
                        page_id,
                        grant["id"],
                        replace=payload.get("replace") is True,
                    )
                    if code is None:
                        handler._send_json(200, {
                            "success": True,
                            "sent": False,
                            "pending": True,
                        })
                        return
                    handler._send_verification_email(page_id, grant, code)
                    handler._record_security_event(page_id, "verification_code_sent", grant_id=grant["id"])
                    handler._send_json(200, {
                        "success": True,
                        "sent": True,
                        "pending": True,
                    })
                except (
                    ValueError,
                    runtime.EmailConfigError,
                    OSError,
                    runtime.sqlite3.Error,
                ) as error:
                    if isinstance(error, runtime.EmailConfigError):
                        try:
                            runtime.VERIFICATION_STORE.cancel_challenge(
                                page_id, grant["id"],
                            )
                        except (OSError, runtime.sqlite3.Error):
                            pass
                    status = (
                        runtime.HTTPStatus.TOO_MANY_REQUESTS
                        if isinstance(error, ValueError)
                        else runtime.HTTPStatus.BAD_GATEWAY
                    )
                    message = (
                        str(error)
                        if isinstance(error, (ValueError, runtime.EmailConfigError))
                        else "Verification email could not be sent"
                    )
                    handler._send_json(status, {"error": message})
                return
            code = str(payload.get("code", "")).strip()
            try:
                if not runtime.re.fullmatch(r"\d{6}", code):
                    raise ValueError("The verification code is invalid or expired")
                session, expires_at = runtime.VERIFICATION_STORE.verify(
                    page_id, grant["id"], code, runtime.parse_time(grant["expires_at"]),
                )
                cookie = (
                    f"access_service_verified={session}; Path=/; HttpOnly; SameSite=Strict; "
                    f"Max-Age={max(0, expires_at - int(runtime.utc_now().timestamp()))}; Secure"
                )
                handler._record_security_event(page_id, "guest_email_verified", grant_id=grant["id"])
                handler._send_json(200, {"success": True}, {"Set-Cookie": cookie})
            except (ValueError, OSError, runtime.sqlite3.Error) as error:
                handler._record_security_event(page_id, "verification_failed", grant_id=grant["id"])
                message = (
                    str(error)
                    if isinstance(error, ValueError)
                    else "Guest verification is temporarily unavailable"
                )
                handler._send_json(
                    runtime.HTTPStatus.UNAUTHORIZED
                    if isinstance(error, ValueError)
                    else runtime.HTTPStatus.SERVICE_UNAVAILABLE,
                    {"error": message},
                )
            return

        if len(parts) != 3:
            handler._send_json(404, {"error": "not found"})
            return

        page_id, resource_id, action_id = parts
        with runtime.page_action_lock(page_id):
            page = handler._load_page(page_id)
            if page is None:
                return
            if not handler._require_page_access(
                page,
                record_invalid=True,
            ):
                return

            grant_id = getattr(
                handler,
                "active_grant",
                {},
            ).get("id", "preview")
            if getattr(handler, "page_attributed_access", False):
                grant_id = "page"
            rate_key = f"{page_id}:{grant_id}:{handler.client_address[0]}"
            if not runtime.ACTION_RATE_LIMITER.allow(rate_key):
                runtime.audit(
                    "action_rate_limited",
                    page_id=page_id,
                    grant_id=grant_id,
                    client_ip=handler.client_address[0],
                )
                handler._record_security_event(
                    page_id,
                    "action_rate_limited",
                    grant_id=(
                        getattr(handler, "active_grant", {}).get("id")
                    ),
                    details={
                        "resource_id": resource_id,
                        "action_id": action_id,
                        "reason": "request_limit_exceeded",
                    },
                )
                handler._send_json(
                    runtime.HTTPStatus.TOO_MANY_REQUESTS,
                    {
                        "error": (
                            "Too many action requests; "
                            "try again shortly"
                        )
                    },
                )
                return

            handler._execute_public_action(
                page,
                resource_id,
                action_id,
                payload,
            )
        return
    handler._send_json(404, {"error": "not found"})
