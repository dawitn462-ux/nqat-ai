# Future Work — External Email & SMS Notification Integration Architecture

> [!NOTE]
> **ENTERPRISE EXTENSION ARCHITECTURE DOCUMENTATION**
> While in-app security notifications are fully implemented, active, and integrated into the NKAT Sentinel platform via database persistence and real-time UI notification panels, external messaging delivery channels (SMTP/SendGrid Email, Twilio SMS, PagerDuty Webhooks, AWS SES/SNS) incur external financial costs and require production API credentials.
> This document details the complete extension specifications for integrating these third-party external delivery channels.

---

## 1. System Architecture & Dispatch Hooks

The NKAT Sentinel continuous monitoring daemon (`backend/services/continuous_monitoring_scheduler.py`) generates `InAppNotification` records upon detecting newly introduced vulnerabilities. 

To enable external channel delivery, an event listener / webhook dispatcher hook is attached to the notification creation lifecycle:

```
[ New Finding Detected ]
         │
         [ InAppNotification Record Persisted ]
         │
         ├──► Local UI Notification Panel (ACTIVE)
         │
         └──► External Notification Dispatcher (FUTURE WORK EXTENSION)
                ├──► Email Service (SMTP / SendGrid / AWS SES)
                ├──► SMS Service (Twilio / AWS SNS)
                └──► Incident Management (PagerDuty / Opsgenie / Slack Webhooks)
```

---

## 2. External Provider Integration Specifications

### A. SMTP / SendGrid Email Notifications

#### Configuration Environment Variables (`.env`)
```bash
EMAIL_NOTIFICATION_ENABLED=true
SMTP_HOST=smtp.sendgrid.net
SMTP_PORT=587
SMTP_USERNAME=apikey
SMTP_PASSWORD=your_sendgrid_api_key_here
SENDER_EMAIL=security-alerts@yourdomain.com
RECIPIENT_EMAILS=security-team@yourdomain.com,ciso@yourdomain.com
```

#### Code Implementation Blueprint
```python
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

def send_email_alert(recipient: str, title: str, html_body: str):
    msg = MIMEMultipart("alternative")
    msg["Subject"] = f"[NKAT ALERT] {title}"
    msg["From"] = SENDER_EMAIL
    msg["To"] = recipient
    msg.attach(MIMEText(html_body, "html"))

    with smtplib.SMTP(SMTP_HOST, SMTP_PORT) as server:
        server.starttls()
        server.login(SMTP_USERNAME, SMTP_PASSWORD)
        server.sendmail(SENDER_EMAIL, [recipient], msg.as_string())
```

---

### B. Twilio SMS Urgent Alerting

#### Configuration Environment Variables (`.env`)
```bash
SMS_NOTIFICATION_ENABLED=true
TWILIO_ACCOUNT_SID=ACXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
TWILIO_AUTH_TOKEN=your_twilio_auth_token
TWILIO_FROM_PHONE=+18005550199
ALERT_RECIPIENT_PHONES=+15550100123
```

#### Code Implementation Blueprint
```python
from twilio.rest import Client

def send_sms_alert(to_phone: str, message_body: str):
    client = Client(TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN)
    message = client.messages.create(
        body=f" NKAT CRITICAL: {message_body}",
        from_=TWILIO_FROM_PHONE,
        to=to_phone
    )
    return message.sid
```

---

### C. Webhook Integration (Slack / Teams / PagerDuty)

#### Configuration Environment Variables (`.env`)
```bash
SLACK_WEBHOOK_URL=https://hooks.slack.com/services/T000/B000/XXXX
PAGERDUTY_ROUTING_KEY=your_pagerduty_integration_key
```

#### Code Implementation Blueprint
```python
import httpx

def send_slack_webhook_alert(title: str, message: str, severity: str):
    color_map = {"CRITICAL": "#ef4444", "HIGH": "#f97316", "MEDIUM": "#eab308", "LOW": "#3b82f6"}
    payload = {
        "attachments": [{
            "color": color_map.get(severity.upper(), "#6b7280"),
            "title": f" {title}",
            "text": message,
            "footer": "NKAT Autonomous Threat Sentinel"
        }]
    }
    httpx.post(SLACK_WEBHOOK_URL, json=payload, timeout=5.0)
```

---

## 3. Rate Limiting & Digest Grouping

To prevent notification storms during bulk scans, future external notification integrations will enforce rate-limiting & digest grouping:

- **Digest Window**: Group low/medium severity alerts into a daily or hourly email summary.
- **Immediate Escalation**: Dispatch immediate SMS/PagerDuty alerts **only** for `CRITICAL` or `HIGH` severity findings with verified exploit vectors (CISA KEV listed).
- **Throttling**: Limit SMS alerts to maximum 5 messages per domain per hour.
