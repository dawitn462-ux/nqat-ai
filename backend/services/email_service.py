"""
Real Email Verification & SMTP Dispatch Service — NKAT AI Cyber Platform
-----------------------------------------------------------------------
Handles real email dispatch for user account email verification links, 6-digit OTP codes, and security alerts.
Supports real Gmail SMTP (smtp.gmail.com:587) or custom SMTP servers via .env configuration.
"""

import os
import smtplib
import logging
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime, timezone
from dotenv import load_dotenv

logger = logging.getLogger("nkat.email_service")


def get_smtp_config():
    load_dotenv(override=True)
    smtp_host = os.getenv("SMTP_HOST", "smtp.gmail.com")
    smtp_port = int(os.getenv("SMTP_PORT", "587"))
    smtp_user = os.getenv("SMTP_USER", "").strip()
    raw_pass = os.getenv("SMTP_PASS", "").strip()
    smtp_pass = raw_pass.replace(" ", "")  # Clean Google App Password spaces if present
    smtp_from = os.getenv("SMTP_FROM", "").strip() or smtp_user or "security-verify@nkat.ai"
    return smtp_host, smtp_port, smtp_user, smtp_pass, smtp_from



def send_verification_email(
    recipient_email: str,
    username: str,
    verification_code: str,
    verification_token: str,
    expires_in_minutes: int = 20
) -> dict:
    """
    Dispatches a real email verification message containing BOTH a direct clickable verification link
    and 6-digit OTP code to the user's registered email address via Gmail SMTP.
    """
    smtp_host, smtp_port, smtp_user, smtp_pass, smtp_from = get_smtp_config()
    clean_email = recipient_email.strip().lower()
    subject = f"🔐 [NKAT Security] Confirm Your Registered Email Address ({verification_code})"
    
    dashboard_verify_url = f"https://127.0.0.1:8443/?verify_token={verification_token}&email={clean_email}"
    backend_verify_url = f"http://127.0.0.1:8000/api/v1/auth/verify-link?token={verification_token}&email={clean_email}"
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    text_content = f"""
================================================================================
NKAT AI SECURITY PLATFORM — EMAIL VERIFICATION LINK & OTP CODE
================================================================================
Hello {username},

Thank you for registering your account on NKAT AI Threat Sentinel Console.
Please verify your registered email address ({clean_email}) to unlock your security dashboard.

Notice: This verification request will expire in {expires_in_minutes} minutes.

Option 1: Click the direct verification link below to verify automatically:
{dashboard_verify_url}
Direct API Link: {backend_verify_url}

Option 2: Use the 6-digit OTP verification code:
    VERIFICATION CODE: [  {verification_code}  ]

Registered Email: {clean_email}
Timestamp:        {timestamp}

If you did not request this registration, please ignore this email.
================================================================================
"""

    html_content = f"""
    <!DOCTYPE html>
    <html>
    <head>
      <meta charset="utf-8">
      <style>
        body {{ font-family: 'Segoe UI', Arial, sans-serif; background-color: #090d16; color: #e2e8f0; margin: 0; padding: 20px; }}
        .container {{ max-width: 600px; margin: 0 auto; background: #0f172a; border: 1px solid #1e293b; border-radius: 16px; padding: 35px; box-shadow: 0 15px 35px rgba(0,0,0,0.6); }}
        .header {{ text-align: center; padding-bottom: 25px; border-bottom: 1px solid #334155; }}
        .brand {{ color: #00f0ff; font-size: 24px; font-weight: 800; letter-spacing: 1.5px; margin: 0; }}
        .subbrand {{ color: #94a3b8; font-size: 13px; margin-top: 6px; font-weight: 600; }}
        .link-box {{ background: rgba(0, 240, 255, 0.06); border: 1px solid rgba(0, 240, 255, 0.3); border-radius: 12px; padding: 20px; margin: 25px 0; text-align: center; }}
        .btn {{ display: inline-block; padding: 15px 32px; background: linear-gradient(135deg, #00f0ff 0%, #3b82f6 100%); color: #000000 !important; text-align: center; text-decoration: none; font-weight: 800; font-size: 16px; border-radius: 10px; box-shadow: 0 4px 15px rgba(0, 240, 255, 0.4); }}
        .otp-box {{ background: #1e293b; border: 2px dashed #00f0ff; border-radius: 8px; font-size: 28px; font-weight: 800; letter-spacing: 6px; color: #38bdf8; text-align: center; padding: 15px; margin: 20px 0; }}
        .footer {{ font-size: 12px; color: #64748b; text-align: center; margin-top: 30px; border-top: 1px solid #334155; padding-top: 18px; line-height: 1.5; }}
      </style>
    </head>
    <body>
      <div class="container">
        <div class="header">
          <div class="brand">🛡️ NKAT AI SECURITY PLATFORM</div>
          <div class="subbrand">Mandatory Registered Email Verification</div>
        </div>
        
        <p style="font-size: 15px; margin-top: 20px;">Hello <strong>{username}</strong>,</p>
        <p style="color: #cbd5e1; font-size: 14px; line-height: 1.6;">
          Welcome to NKAT AI Security Sentinel. To complete your registration and access your security dashboard, please confirm ownership of your email address <strong>({clean_email})</strong>:
        </p>

        <p style="color: #fbbf24; font-size: 13px; font-weight: 600;">
          ⏳ <em>This verification link and OTP code expire in {expires_in_minutes} minutes.</em>
        </p>

        <div class="link-box">
          <p style="color: #38bdf8; font-weight: 700; margin-top: 0; font-size: 14px;">CLICK BELOW TO VERIFY EMAIL & LOGIN INSTANTLY:</p>
          <a href="{dashboard_verify_url}" class="btn" target="_blank">Verify Email Address Now</a>
          <p style="font-size: 11px; color: #64748b; margin-bottom: 0; margin-top: 12px;">
            Link URL: <a href="{dashboard_verify_url}" style="color: #00f0ff;">{dashboard_verify_url}</a>
          </p>
        </div>

        <p style="text-align: center; color: #94a3b8; font-size: 13px; margin-top: 20px;">Or enter this 6-digit OTP code on the verification screen:</p>
        <div class="otp-box">{verification_code}</div>

        <div class="footer">
          Dispatched on {timestamp} to registered email {clean_email}.<br/>
          NKAT Enterprise Threat Sentinel Platform &copy; 2026
        </div>
      </div>
    </body>
    </html>
    """

    msg = MIMEMultipart("alternative")
    msg["Subject"] = subject
    msg["From"] = smtp_from
    msg["To"] = clean_email
    msg.attach(MIMEText(text_content, "plain"))
    msg.attach(MIMEText(html_content, "html"))

    if smtp_user and smtp_pass and len(smtp_pass.strip()) > 3:
        try:
            with smtplib.SMTP(smtp_host, smtp_port, timeout=10) as server:
                server.ehlo()
                server.starttls()
                server.login(smtp_user, smtp_pass)
                server.sendmail(smtp_from, [clean_email], msg.as_string())
            logger.info(f"[+] [Real Email Dispatch SUCCESS] Real verification email delivered via Gmail SMTP ({smtp_host}:{smtp_port}) to '{clean_email}'")
            return {"status": "sent", "method": "smtp", "recipient": clean_email}
        except Exception as exc:
            logger.error(f"[!] [Gmail SMTP Auth Error] Failed to send email via SMTP ({exc})")
            print(f"[!] [Gmail SMTP Auth Error] {exc}")
            print(text_content)
            return {"status": "logged", "method": "console", "error": str(exc), "verify_url": dashboard_verify_url}
    else:
        logger.info(f"[+] [Email Verification Link Generated] Verify URL: '{dashboard_verify_url}' | Code: '{verification_code}'")
        print(text_content)
        return {"status": "logged", "method": "console", "verify_url": dashboard_verify_url}


