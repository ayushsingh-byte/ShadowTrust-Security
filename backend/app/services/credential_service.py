"""
Credential Management Service
==============================
Handles secure credential issuance, one-time token generation,
notification delivery (Email / WhatsApp), and audit logging.
"""

import os
import re
import uuid
import json
import string
import random
import smtplib
import logging
from datetime import datetime, timedelta
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from typing import Optional

from dotenv import load_dotenv
load_dotenv()

from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select

from app.models.all_models import (
    CredentialToken,
    CredentialAuditLog,
    AdminActivity,
    User,
)

logger = logging.getLogger("credential_service")

# ─── Configuration (from .env) ───────────────────────────────────────────────
SMTP_HOST     = os.getenv("SMTP_HOST", "")
SMTP_PORT     = int(os.getenv("SMTP_PORT", "587"))
SMTP_USER     = os.getenv("SMTP_USER", "")
SMTP_PASS     = os.getenv("SMTP_PASS", "")
SMTP_FROM     = os.getenv("SMTP_FROM", SMTP_USER)
SMTP_ENABLED  = bool(SMTP_HOST and SMTP_USER and SMTP_PASS)

TWILIO_SID    = os.getenv("TWILIO_ACCOUNT_SID", "")
TWILIO_TOKEN  = os.getenv("TWILIO_AUTH_TOKEN", "")
TWILIO_FROM   = os.getenv("TWILIO_FROM", "")
TWILIO_ENABLED = bool(TWILIO_SID and TWILIO_TOKEN and TWILIO_FROM)

PORTAL_BASE_URL = os.getenv("PORTAL_BASE_URL", "http://localhost:8001")

# Rate limit: max credential operations per admin per hour
RATE_LIMIT_MAX  = int(os.getenv("CRED_RATE_LIMIT", "20"))
RATE_LIMIT_WINDOW_HOURS = 1

# ─── Helpers ─────────────────────────────────────────────────────────────────

def generate_secure_token() -> str:
    """Generate a cryptographically random UUID4 token string."""
    return str(uuid.uuid4()).replace("-", "")


def generate_temp_password(length: int = 12) -> str:
    """Generate a strong temporary password."""
    alphabet = string.ascii_letters + string.digits + "!@#$%^&*"
    while True:
        pw = "".join(random.choices(alphabet, k=length))
        # Ensure at least one of each required character class
        if (any(c.isupper() for c in pw)
                and any(c.islower() for c in pw)
                and any(c.isdigit() for c in pw)
                and any(c in "!@#$%^&*" for c in pw)):
            return pw


def mask_password(pw: str) -> str:
    """Show first two characters then asterisks."""
    if not pw or len(pw) < 3:
        return "****"
    return pw[:2] + "*" * (len(pw) - 2)


def validate_email(email: str) -> bool:
    """Basic RFC 5322-like email validation."""
    pattern = re.compile(r"^[\w\.-]+@[\w\.-]+\.\w{2,}$")
    return bool(pattern.match(email))


def validate_phone(phone: str) -> bool:
    """E.164 format: +<country_code><number>, 7–15 digits."""
    pattern = re.compile(r"^\+\d{7,15}$")
    return bool(pattern.match(phone.replace(" ", "")))


# ─── Rate Limiting ────────────────────────────────────────────────────────────

async def rate_limit_check(admin_id: str, db: AsyncSession) -> bool:
    """
    Returns True if the admin is within the allowed rate limit.
    Checks AdminActivity within the last RATE_LIMIT_WINDOW_HOURS hours.
    """
    window_start = datetime.utcnow() - timedelta(hours=RATE_LIMIT_WINDOW_HOURS)
    result = await db.execute(
        select(AdminActivity).where(
            AdminActivity.admin_id == admin_id,
            AdminActivity.timestamp >= window_start,
            AdminActivity.action.in_([
                "ISSUE_CREDENTIALS", "RESET_PASSWORD", "RESEND_CREDENTIALS"
            ])
        )
    )
    recent = result.scalars().all()
    return len(recent) < RATE_LIMIT_MAX


# ─── Notification: Email ──────────────────────────────────────────────────────

def send_email_notification(
    recipients: list[str],
    subject: str,
    html_body: str,
    plain_body: str = "",
) -> str:
    """
    Send an HTML email to a list of recipients.
    Returns 'SENT' | 'FAILED' | 'SIMULATED'.
    """
    if not SMTP_ENABLED:
        logger.info("[EMAIL] SMTP not configured — simulating delivery to %s", recipients)
        return "SIMULATED"

    try:
        msg = MIMEMultipart("alternative")
        msg["Subject"] = subject
        msg["From"]    = SMTP_FROM
        msg["To"]      = ", ".join(recipients)
        if plain_body:
            msg.attach(MIMEText(plain_body, "plain"))
        msg.attach(MIMEText(html_body, "html"))

        with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=10) as server:
            server.ehlo()
            server.starttls()
            server.login(SMTP_USER, SMTP_PASS)
            server.sendmail(SMTP_FROM, recipients, msg.as_string())

        logger.info("[EMAIL] Successfully sent to %s", recipients)
        return "SENT"
    except Exception as exc:
        logger.error("[EMAIL] Delivery failed: %s", exc)
        return "FAILED"


# ─── Notification: WhatsApp (Twilio) ─────────────────────────────────────────

def send_whatsapp_notification(phone: str, message: str) -> str:
    """
    Send a WhatsApp message via Twilio.
    Returns 'SENT' | 'FAILED' | 'SIMULATED'.
    """
    if not TWILIO_ENABLED:
        logger.info("[WHATSAPP] Twilio not configured — simulating delivery to %s", phone)
        return "SIMULATED"

    try:
        from twilio.rest import Client  # type: ignore
        client = Client(TWILIO_SID, TWILIO_TOKEN)
        client.messages.create(
            body=message,
            from_=f"whatsapp:{TWILIO_FROM}",
            to=f"whatsapp:{phone}",
        )
        logger.info("[WHATSAPP] Successfully sent to %s", phone)
        return "SENT"
    except Exception as exc:
        logger.error("[WHATSAPP] Delivery failed: %s", exc)
        return "FAILED"


# ─── Message Templates ────────────────────────────────────────────────────────

def build_email_html(
    username: str,
    temp_password: str,
    token_link: str,
    admin_name: str,
    admin_message: str,
    expires_hours: int,
) -> str:
    # Use unmasked password per user request
    return f"""<!DOCTYPE html>
<html>
<head>
  <meta charset="UTF-8">
  <style>
    body {{ background-color:#f4f6f8; color:#333; font-family:-apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; margin:0; padding:0; }}
    .wrapper {{ max-width:600px; margin:40px auto; background:#ffffff; border-radius:8px; overflow:hidden; box-shadow: 0 4px 15px rgba(0,0,0,0.05); border-top: 4px solid #00c6ff; }}
    .header {{ padding:30px; text-align:center; border-bottom:1px solid #eef0f2; }}
    .header h1 {{ margin:0; color:#0f171e; font-size:24px; font-weight:700; letter-spacing: 0.5px; }}
    .header p  {{ margin:8px 0 0; color:#64748b; font-size:14px; text-transform:uppercase; letter-spacing: 1px; font-weight: 600; }}
    .body {{ padding:40px 30px; }}
    .welcome {{ font-size: 16px; line-height: 1.6; margin-bottom: 30px; color: #334155; }}
    .creds-box {{ background:#f8fafc; border:1px solid #e2e8f0; border-radius:6px; padding:20px; margin-bottom:30px; }}
    .field {{ margin-bottom:15px; }}
    .field:last-child {{ margin-bottom:0; }}
    .field .label {{ font-size:12px; color:#64748b; text-transform:uppercase; letter-spacing:1px; margin-bottom:4px; font-weight:700; }}
    .field .value {{ color:#0f171e; font-size:18px; font-weight:600; font-family: monospace; letter-spacing:0.5px; }}
    .msg-box {{ border-left: 4px solid #cbd5e1; padding-left: 15px; margin-bottom: 30px; }}
    .msg-box .label {{ font-size:13px; color:#64748b; font-weight:700; margin-bottom:6px; }}
    .msg-box .value {{ font-size:15px; color:#475569; font-style: italic; line-height: 1.5; }}
    .btn-wrap {{ text-align: center; margin: 40px 0 30px; }}
    .cta {{ display:inline-block; background:#00c6ff; color:#0f171e; padding:14px 28px; border-radius:4px; font-weight:700; text-decoration:none; font-size: 16px; letter-spacing: 0.5px; transition: background 0.2s; }}
    .cta:hover {{ background:#00aadd; }}
    .notice {{ background:#fff5f5; border:1px solid #fed7d7; border-radius:6px; padding:16px; font-size:14px; color:#c53030; line-height: 1.5; }}
    .notice strong {{ font-weight: 700; }}
    .footer {{ background:#0f171e; padding:24px; font-size:13px; color:#94a3b8; text-align:center; }}
  </style>
</head>
<body>
<div class="wrapper">
  <div class="header">
    <h1>SOC SENTINEL</h1>
    <p>Secure Credential Package</p>
  </div>
  <div class="body">
    <div class="welcome">
      Hello,<br><br>
      Your secure credentials and platform access portal have been generated by <strong>{admin_name}</strong>. Please use the information below to authenticate.
    </div>

    <div class="creds-box">
      <div class="field">
        <div class="label">Username</div>
        <div class="value">{username}</div>
      </div>
      <div class="field">
        <div class="label">Temporary Password</div>
        <div class="value">{temp_password}</div>
      </div>
    </div>

    <div class="msg-box">
      <div class="label">Administrator Message:</div>
      <div class="value">"{admin_message or 'No additional instructions provided.'}"</div>
    </div>

    <div class="btn-wrap">
      <a href="{token_link}" class="cta">Access Secure Portal</a>
    </div>

    <div class="notice">
      <strong>Security Notice:</strong> This secure login link expires in <strong>{expires_hours} hours</strong> and is valid for a single use only. You will be required to change your password immediately upon successful authentication. Never forward this email to anyone.
    </div>
  </div>
  <div class="footer">
    Issued on {datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")} &bull; SOC Sentinel Administration
  </div>
</div>
</body>
</html>"""


def build_whatsapp_message(
    username: str,
    temp_password: str,
    token_link: str,
    admin_name: str,
    admin_message: str,
    expires_hours: int,
) -> str:
    # Use unmasked password per user request
    return (
        f"🛡️ *SOC Sentinel — Credential Package*\n\n"
        f"Hello,\nYour secure credentials have been issued by *{admin_name}*.\n\n"
        f"*Username:* `{username}`\n"
        f"*Password:* `{temp_password}`\n\n"
        f"📝 *Message:* {admin_message or 'N/A'}\n\n"
        f"🔗 *Secure Login Portal (expires in {expires_hours}h):*\n{token_link}\n\n"
        f"⚠️ _Note: This link is single-use. You will be prompted to change your password on first login. Do not share this message._"
    )


# ─── Core Orchestration ───────────────────────────────────────────────────────

async def issue_credentials(
    db: AsyncSession,
    *,
    username: str,
    new_password: str,
    email: Optional[str],
    phone: Optional[str],
    delivery: list[str],          # ["email", "whatsapp", "both"]
    custom_message: str,
    token_expires_hours: int,
    force_password_change: bool,
    admin_id: str,
    admin_ip: str,
    admin_name: str,
    additional_recipients: Optional[list[dict]] = None,  # [{email, phone, delivery}]
) -> dict:
    """
    Main orchestration function for issuing credentials.
    Returns a result dict with token info and delivery statuses.
    """
    # 1. Rate limit check
    if not await rate_limit_check(admin_id, db):
        await _log_admin_activity(
            db, admin_id=admin_id, admin_name=admin_name,
            action="ISSUE_CREDENTIALS", affected_user=username,
            ip=admin_ip, result="RATE_LIMITED",
            details={"reason": "Rate limit exceeded"}
        )
        return {"success": False, "error": "Rate limit exceeded. Max 20 operations/hour."}

    # 2. Validate inputs
    if email and not validate_email(email):
        return {"success": False, "error": f"Invalid email address: {email}"}
    if phone and not validate_phone(phone):
        return {"success": False, "error": f"Invalid phone number: {phone}. Use E.164 format e.g. +911234567890"}

    # 3. Generate one-time token
    token_value = generate_secure_token()
    expires_at  = datetime.utcnow() + timedelta(hours=token_expires_hours)

    token_obj = CredentialToken(
        username=username,
        token=token_value,
        issued_by=admin_id,
        expires_at=expires_at,
        force_password_change=force_password_change,
    )
    db.add(token_obj)
    await db.flush()  # Get token_obj.id

    token_link = f"{PORTAL_BASE_URL}/frontend/login.html?token={token_value}"

    # 4. Normalize delivery list
    delivery_lower = [d.lower() for d in delivery]
    do_email     = "email" in delivery_lower or "both" in delivery_lower
    do_whatsapp  = "whatsapp" in delivery_lower or "both" in delivery_lower

    delivery_method = (
        "BOTH"      if do_email and do_whatsapp else
        "EMAIL"     if do_email else
        "WHATSAPP"  if do_whatsapp else "NONE"
    )

    # 5. Build messages
    email_html = build_email_html(
        username, new_password, token_link, admin_name, custom_message, token_expires_hours
    )
    wa_message = build_whatsapp_message(
        username, new_password, token_link, admin_name, custom_message, token_expires_hours
    )

    # 6. Collect all recipients (primary + additional)
    recipients = []
    if email or phone:
        recipients.append({
            "email": email,
            "phone": phone,
            "do_email": do_email,
            "do_whatsapp": do_whatsapp,
        })
    for extra in (additional_recipients or []):
        edl = [d.lower() for d in (extra.get("delivery") or delivery_lower)]
        recipients.append({
            "email": extra.get("email"),
            "phone": extra.get("phone"),
            "do_email": "email" in edl or "both" in edl,
            "do_whatsapp": "whatsapp" in edl or "both" in edl,
        })

    # 7. Send notifications & collect statuses
    audit_entries = []
    for r in recipients:
        r_email_status = "NOT_SENT"
        r_wa_status    = "NOT_SENT"

        if r["do_email"] and r.get("email"):
            r_email_status = send_email_notification(
                recipients=[r["email"]],
                subject=f"[SOC Sentinel] Your Temporary Credentials — {username}",
                html_body=email_html,
                plain_body=f"Username: {username}\nUse the secure link: {token_link}",
            )

        if r["do_whatsapp"] and r.get("phone"):
            r_wa_status = send_whatsapp_notification(r["phone"], wa_message)

        r_delivery_method = (
            "BOTH"      if r["do_email"] and r["do_whatsapp"] else
            "EMAIL"     if r["do_email"] else
            "WHATSAPP"  if r["do_whatsapp"] else "NONE"
        )

        audit = CredentialAuditLog(
            username=username,
            recipient_email=r.get("email"),
            recipient_phone=r.get("phone"),
            issued_by=admin_id,
            issuer_name=admin_name,
            delivery_method=r_delivery_method,
            email_status=r_email_status,
            whatsapp_status=r_wa_status,
            token_id=token_obj.id,
            token_status="GENERATED",
            custom_message=custom_message,
            admin_ip=admin_ip,
        )
        db.add(audit)
        audit_entries.append({
            "email": r.get("email"),
            "phone": r.get("phone"),
            "email_status": r_email_status,
            "whatsapp_status": r_wa_status,
        })

    # 8. Log admin activity
    await _log_admin_activity(
        db, admin_id=admin_id, admin_name=admin_name,
        action="ISSUE_CREDENTIALS", affected_user=username,
        ip=admin_ip, result="SUCCESS",
        details={
            "delivery_method": delivery_method,
            "token_expires_hours": token_expires_hours,
            "recipients_count": len(recipients),
        }
    )

    await db.commit()

    return {
        "success": True,
        "username": username,
        "token": token_value,
        "token_link": token_link,
        "expires_at": expires_at.isoformat() + "Z",
        "delivery_method": delivery_method,
        "recipients": audit_entries,
        "masked_password": mask_password(new_password),
    }


async def validate_one_time_token(db: AsyncSession, token: str) -> dict:
    """Validate a one-time login token. Marks it as used on success."""
    result = await db.execute(
        select(CredentialToken).where(CredentialToken.token == token)
    )
    token_obj = result.scalars().first()

    if not token_obj:
        return {"valid": False, "reason": "Token not found"}
    if token_obj.used:
        return {"valid": False, "reason": "Token already used", "used_at": token_obj.used_at.isoformat() if token_obj.used_at else None}
    if datetime.utcnow() > token_obj.expires_at:
        return {"valid": False, "reason": "Token expired", "expired_at": token_obj.expires_at.isoformat()}

    # Mark as used
    token_obj.used    = True
    token_obj.used_at = datetime.utcnow()

    # Update audit log
    audit_result = await db.execute(
        select(CredentialAuditLog).where(CredentialAuditLog.token_id == token_obj.id)
    )
    for audit in audit_result.scalars().all():
        audit.token_status = "USED"

    await db.commit()

    return {
        "valid": True,
        "username": token_obj.username,
        "force_password_change": token_obj.force_password_change,
        "expires_at": token_obj.expires_at.isoformat(),
    }


async def resend_credentials(
    db: AsyncSession,
    audit_id: str,
    admin_id: str,
    admin_ip: str,
    admin_name: str,
) -> dict:
    """Re-send notifications for a previous credential audit event."""
    result = await db.execute(
        select(CredentialAuditLog).where(CredentialAuditLog.id == audit_id)
    )
    audit = result.scalars().first()
    if not audit:
        return {"success": False, "error": "Audit log entry not found"}

    # Rate limit check
    if not await rate_limit_check(admin_id, db):
        return {"success": False, "error": "Rate limit exceeded."}

    # Fetch the token for the link
    token_link = f"{PORTAL_BASE_URL}/frontend/login.html"
    if audit.token_id:
        tok_result = await db.execute(
            select(CredentialToken).where(CredentialToken.id == audit.token_id)
        )
        tok = tok_result.scalars().first()
        if tok and not tok.used and datetime.utcnow() < tok.expires_at:
            token_link = f"{PORTAL_BASE_URL}/frontend/login.html?token={tok.token}"

    email_html = build_email_html(
        audit.username, "— Use token link —", token_link,
        admin_name, audit.custom_message or "", 0
    )
    wa_message = build_whatsapp_message(
        audit.username, "— Use token link —", token_link,
        admin_name, audit.custom_message or "", 0
    )

    new_email_status = audit.email_status
    new_wa_status    = audit.whatsapp_status

    if audit.recipient_email and audit.delivery_method in ("EMAIL", "BOTH"):
        new_email_status = send_email_notification(
            [audit.recipient_email],
            f"[SOC Sentinel] Re-issued Credentials — {audit.username}",
            email_html,
        )
    if audit.recipient_phone and audit.delivery_method in ("WHATSAPP", "BOTH"):
        new_wa_status = send_whatsapp_notification(audit.recipient_phone, wa_message)

    audit.email_status     = new_email_status
    audit.whatsapp_status  = new_wa_status

    await _log_admin_activity(
        db, admin_id=admin_id, admin_name=admin_name,
        action="RESEND_CREDENTIALS", affected_user=audit.username,
        ip=admin_ip, result="SUCCESS",
        details={"audit_id": audit_id}
    )
    await db.commit()

    return {
        "success": True,
        "email_status": new_email_status,
        "whatsapp_status": new_wa_status,
    }


# ─── Internal Helpers ─────────────────────────────────────────────────────────

async def _log_admin_activity(
    db: AsyncSession,
    *,
    admin_id: str,
    admin_name: str,
    action: str,
    affected_user: str,
    ip: str,
    result: str,
    details: dict,
):
    activity = AdminActivity(
        admin_id=admin_id,
        admin_username=admin_name,
        action=action,
        affected_user=affected_user,
        ip_address=ip,
        result=result,
        details=json.dumps(details),
    )
    db.add(activity)
