"""TLS-only SMTP configuration and delivery for guest verification email."""

from __future__ import annotations

from dataclasses import dataclass
from email.message import EmailMessage
from html import escape
from pathlib import Path
import json
import os
import re
import smtplib
import ssl
import tempfile
from threading import Lock


class EmailConfigError(ValueError):
    """A safe configuration or delivery error."""


EMAIL_RE = re.compile(r"^[^\s@]+@[^\s@]+\.[^\s@]+$")
MOBILE_NOTIFY_TARGET_RE = re.compile(r"^notify\.mobile_app_[a-z0-9_]+$")


class NotificationTargetStore:
    """Admin-selected Home Assistant notification destination allowlist."""

    def __init__(self, path: Path):
        self.path = Path(path)

    def load(self) -> list[str]:
        if not self.path.exists():
            return []
        try:
            payload = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as error:
            raise EmailConfigError("Alert destination configuration is invalid") from error
        targets = payload.get("mobile_targets", []) if isinstance(payload, dict) else []
        if not isinstance(targets, list):
            raise EmailConfigError("Alert destination configuration is invalid")
        normalized = sorted({str(item).strip() for item in targets})
        if any(not MOBILE_NOTIFY_TARGET_RE.fullmatch(item) for item in normalized):
            raise EmailConfigError("Alert destination configuration is invalid")
        return normalized

    def save(self, targets: object, available: set[str]) -> list[str]:
        if not isinstance(targets, list):
            raise EmailConfigError("Mobile alert destinations must be a list")
        normalized = sorted({str(item).strip() for item in targets})
        if any(
            not MOBILE_NOTIFY_TARGET_RE.fullmatch(item) or item not in available
            for item in normalized
        ):
            raise EmailConfigError("A mobile alert destination is not registered")
        self.path.parent.mkdir(parents=True, exist_ok=True)
        fd, name = tempfile.mkstemp(prefix=f".{self.path.name}.", dir=self.path.parent)
        temporary = Path(name)
        try:
            os.fchmod(fd, 0o600)
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                json.dump({"mobile_targets": normalized}, handle, separators=(",", ":"))
                handle.write("\n")
                handle.flush()
                os.fsync(handle.fileno())
            temporary.replace(self.path)
            self.path.chmod(0o600)
        except Exception:
            temporary.unlink(missing_ok=True)
            raise
        return normalized


@dataclass(frozen=True)
class SMTPConfig:
    host: str
    port: int
    security: str
    username: str
    password: str
    sender_email: str
    sender_name: str
    administrator_email: str


class SMTPConfigStore:
    def __init__(self, path: Path):
        self.path = Path(path)

    def configured(self) -> bool:
        try:
            self.load()
            return True
        except (EmailConfigError, OSError):
            return False

    def load(self) -> SMTPConfig:
        try:
            payload = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as error:
            raise EmailConfigError("Email delivery is not configured") from error
        return validate_smtp_config(payload, require_password=True)

    def public_view(self) -> dict:
        if not self.configured():
            return {"configured": False}
        config = self.load()
        return {
            "configured": True,
            "host": config.host,
            "port": config.port,
            "security": config.security,
            "username": config.username,
            "sender_email": config.sender_email,
            "sender_name": config.sender_name,
            "administrator_email": config.administrator_email,
            "password_configured": True,  # nosec B105 - status flag, not a secret
        }

    def save(self, payload: dict) -> SMTPConfig:
        existing_password = ""  # nosec B105 - empty placeholder, not a credential
        if self.path.exists():
            try:
                existing_password = self.load().password
            except EmailConfigError:
                pass
        candidate = dict(payload)
        if not str(candidate.get("password", "")):
            candidate["password"] = existing_password
        config = validate_smtp_config(candidate, require_password=True)
        content = json.dumps({
            "host": config.host,
            "port": config.port,
            "security": config.security,
            "username": config.username,
            "password": config.password,
            "sender_email": config.sender_email,
            "sender_name": config.sender_name,
            "administrator_email": config.administrator_email,
        }, indent=2) + "\n"
        self.path.parent.mkdir(parents=True, exist_ok=True)
        fd, temporary_name = tempfile.mkstemp(
            prefix=f".{self.path.name}.", dir=self.path.parent,
        )
        temporary = Path(temporary_name)
        try:
            os.fchmod(fd, 0o600)
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                handle.write(content)
                handle.flush()
                os.fsync(handle.fileno())
            temporary.replace(self.path)
            self.path.chmod(0o600)
        except Exception:
            temporary.unlink(missing_ok=True)
            raise
        return config

    def delete(self) -> None:
        self.path.unlink(missing_ok=True)


class VerificationRecipientStore:
    """Administrator-only mapping; public page files contain no addresses."""

    def __init__(self, path: Path):
        self.path = Path(path)
        self._lock = Lock()

    def _load(self) -> dict:
        if not self.path.exists():
            return {}
        try:
            value = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as error:
            raise EmailConfigError("Could not read verification recipients") from error
        if not isinstance(value, dict):
            raise EmailConfigError("Verification recipient storage is invalid")
        return value

    def _write(self, value: dict) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        fd, name = tempfile.mkstemp(prefix=f".{self.path.name}.", dir=self.path.parent)
        temporary = Path(name)
        try:
            os.fchmod(fd, 0o600)
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                json.dump(value, handle, separators=(",", ":"))
                handle.write("\n")
                handle.flush()
                os.fsync(handle.fileno())
            temporary.replace(self.path)
            self.path.chmod(0o600)
        except Exception:
            temporary.unlink(missing_ok=True)
            raise

    def set(self, page_id: str, grant_id: str, email: str) -> None:
        with self._lock:
            value = self._load()
            value[f"{page_id}:{grant_id}"] = validate_email(email, "Guest email")
            self._write(value)

    def get(self, page_id: str, grant_id: str) -> str:
        with self._lock:
            email = self._load().get(f"{page_id}:{grant_id}", "")
        return validate_email(email, "Guest email")

    def delete(self, page_id: str, grant_id: str) -> None:
        with self._lock:
            value = self._load()
            value.pop(f"{page_id}:{grant_id}", None)
            self._write(value)


def validate_email(value: object, field: str = "Email address") -> str:
    email = str(value or "").strip()
    if len(email) > 254 or not EMAIL_RE.fullmatch(email):
        raise EmailConfigError(f"{field} is invalid")
    return email


def validate_smtp_config(payload: object, *, require_password: bool) -> SMTPConfig:
    if not isinstance(payload, dict):
        raise EmailConfigError("SMTP configuration must be an object")
    host = str(payload.get("host", "")).strip().lower()
    if not host or len(host) > 253 or any(character.isspace() for character in host):
        raise EmailConfigError("SMTP host is invalid")
    try:
        port = int(payload.get("port", 587))
    except (TypeError, ValueError) as error:
        raise EmailConfigError("SMTP port must be a number") from error
    if not 1 <= port <= 65535 or port == 25:
        raise EmailConfigError("Use a TLS SMTP submission port such as 465 or 587")
    security = str(payload.get("security", "starttls")).strip().lower()
    if security not in {"starttls", "tls"}:
        raise EmailConfigError("SMTP security must be STARTTLS or implicit TLS")
    username = str(payload.get("username", "")).strip()
    password = str(payload.get("password", ""))
    if not username or len(username) > 320:
        raise EmailConfigError("SMTP username is required")
    if require_password and not password:
        raise EmailConfigError("SMTP password or app password is required")
    if len(password) > 4096:
        raise EmailConfigError("SMTP password is too long")
    sender_email = validate_email(
        payload.get("sender_email") or username, "Sender email",
    )
    sender_name = str(payload.get("sender_name", "Access Pages")).strip()
    if not sender_name or len(sender_name) > 80 or "\n" in sender_name or "\r" in sender_name:
        raise EmailConfigError("Sender name is invalid")
    administrator_email = validate_email(
        payload.get("administrator_email") or sender_email,
        "Administrator email",
    )
    return SMTPConfig(
        host, port, security, username, password, sender_email, sender_name,
        administrator_email,
    )


def _email_shell(title: str, content: str) -> str:
    return f"""<!doctype html>
<html lang="en">
  <body style="margin:0;padding:0;background:#f3f6fa;color:#172033;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;">
    <table role="presentation" width="100%" cellspacing="0" cellpadding="0" style="background:#f3f6fa;padding:28px 12px;">
      <tr><td align="center">
        <table role="presentation" width="100%" cellspacing="0" cellpadding="0" style="max-width:560px;background:#ffffff;border:1px solid #dfe6ef;border-radius:18px;overflow:hidden;">
          <tr><td style="padding:24px 30px;background:#10233f;color:#ffffff;">
            <div style="font-size:13px;letter-spacing:.12em;text-transform:uppercase;color:#9fc7ff;">Access Pages</div>
            <h1 style="margin:8px 0 0;font-size:25px;line-height:1.25;">{escape(title)}</h1>
          </td></tr>
          <tr><td style="padding:30px;">{content}</td></tr>
          <tr><td style="padding:18px 30px;border-top:1px solid #e6ebf2;color:#66758a;font-size:12px;line-height:1.5;">
            This message was sent by Access Pages for Home Assistant, powered by OpenNHP Service. If you were not expecting it, you can safely ignore it.
          </td></tr>
        </table>
      </td></tr>
    </table>
  </body>
</html>"""


def verification_email_content(code: str) -> tuple[str, str]:
    if not re.fullmatch(r"\d{6}", str(code)):
        raise EmailConfigError("Verification code is invalid")
    text = (
        "Your Access Pages verification code is:\n\n"
        f"{code}\n\n"
        "It expires in 10 minutes.\n"
    )
    content = f"""
      <p style="margin:0 0 20px;font-size:16px;line-height:1.6;">Enter this one-time code on your Access Page:</p>
      <div style="margin:0 0 20px;padding:18px 20px;border:1px solid #bed4f2;border-radius:12px;background:#f2f7ff;text-align:center;font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:32px;font-weight:700;letter-spacing:.24em;color:#10233f;">{code}</div>
      <p style="margin:0;color:#66758a;font-size:14px;line-height:1.6;">This code expires in 10 minutes and can be used only once. Do not forward it.</p>
    """
    return text, _email_shell("Your verification code", content)


def guest_invitation_email_content(
    access_link_url: str, access_url: str,
) -> tuple[str, str]:
    if not access_url:
        safe_access_link = escape(str(access_link_url), quote=True)
        button = (
            "display:inline-block;padding:13px 18px;border-radius:10px;"
            "background:#1769d2;color:#ffffff;text-decoration:none;"
            "font-size:15px;font-weight:700;"
        )
        text = (
            "You have been given temporary access through Access Pages.\n\n"
            "Open your private guest link:\n"
            f"{access_link_url}\n\n"
            "A separate one-time verification code will be sent to this "
            "email address when you open the guest controls.\n"
        )
        content = f"""
          <p style="margin:0 0 24px;font-size:16px;line-height:1.6;">You have been given temporary access to selected Home Assistant controls.</p>
          <a href="{safe_access_link}" style="{button}">Open Guest Controls</a>
          <div style="margin-top:12px;color:#7a8798;font-size:11px;line-height:1.4;overflow-wrap:anywhere;">{safe_access_link}</div>
          <p style="margin:24px 0 0;color:#66758a;font-size:13px;line-height:1.6;">A separate one-time verification code will be sent to this email address when you open the guest controls.</p>
        """
        return text, _email_shell("Your Access Page", content)
    text = (
        "You have been given temporary access through Access Pages.\n\n"
        "1. Activate OpenNHP Service access:\n"
        f"{access_link_url}\n\n"
        "2. Open your Access Page:\n"
        f"{access_url}\n\n"
        "When you open the access page, a separate one-time verification "
        "code will be sent to this email address.\n"
    )
    safe_access_link = escape(str(access_link_url), quote=True)
    safe_access = escape(str(access_url), quote=True)
    button = (
        "display:inline-block;padding:13px 18px;border-radius:10px;"
        "background:#1769d2;color:#ffffff;text-decoration:none;"
        "font-size:15px;font-weight:700;"
    )
    content = f"""
      <p style="margin:0 0 24px;font-size:16px;line-height:1.6;">You have been given temporary access to selected Home Assistant controls. Complete both steps below.</p>
      <div style="margin:0 0 24px;padding:20px;border:1px solid #dfe6ef;border-radius:12px;">
        <div style="margin-bottom:8px;color:#1769d2;font-size:13px;font-weight:700;text-transform:uppercase;letter-spacing:.08em;">Step 1</div>
        <h2 style="margin:0 0 10px;font-size:19px;">Activate OpenNHP Service access</h2>
        <p style="margin:0 0 16px;color:#526176;font-size:14px;line-height:1.5;">Authorize the secure OpenNHP Service connection for this invitation.</p>
        <a href="{safe_access_link}" style="{button}">Activate OpenNHP Service Access</a>
        <div style="margin-top:12px;color:#7a8798;font-size:11px;line-height:1.4;overflow-wrap:anywhere;">{safe_access_link}</div>
      </div>
      <div style="margin:0 0 24px;padding:20px;border:1px solid #dfe6ef;border-radius:12px;">
        <div style="margin-bottom:8px;color:#1769d2;font-size:13px;font-weight:700;text-transform:uppercase;letter-spacing:.08em;">Step 2</div>
        <h2 style="margin:0 0 10px;font-size:19px;">Open guest controls</h2>
        <p style="margin:0 0 16px;color:#526176;font-size:14px;line-height:1.5;">After activation, open the private controls assigned to you.</p>
        <a href="{safe_access}" style="{button}">Open Guest Controls</a>
        <div style="margin-top:12px;color:#7a8798;font-size:11px;line-height:1.4;overflow-wrap:anywhere;">{safe_access}</div>
      </div>
      <p style="margin:0;color:#66758a;font-size:13px;line-height:1.6;">A separate one-time verification code will be sent to this email address when you open the guest controls.</p>
    """
    return text, _email_shell("Your Access Page", content)


def send_email(
    config: SMTPConfig,
    recipient: str,
    subject: str,
    body: str,
    *,
    html_body: str | None = None,
) -> None:
    recipient = validate_email(recipient, "Recipient email")
    message = EmailMessage()
    message["From"] = f"{config.sender_name} <{config.sender_email}>"
    message["To"] = recipient
    message["Subject"] = subject
    message.set_content(body)
    if html_body:
        message.add_alternative(html_body, subtype="html")
    context = ssl.create_default_context()
    try:
        if config.security == "tls":
            client = smtplib.SMTP_SSL(
                config.host, config.port, timeout=15, context=context,
            )
        else:
            client = smtplib.SMTP(config.host, config.port, timeout=15)
        with client:
            if config.security == "starttls":
                client.ehlo()
                client.starttls(context=context)
                client.ehlo()
            client.login(config.username, config.password)
            client.send_message(message)
    except (OSError, smtplib.SMTPException) as error:
        raise EmailConfigError("The SMTP server could not send the test email") from error
