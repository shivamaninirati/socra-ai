"""
SOCRA AI — Email Service

Handles sending emails via SMTP for OTP verification and password resets.
Uses environment variables for SMTP configuration (never hardcodes credentials).
"""

import os
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

# Route through the SOCRA logger tree (console + rotating file handlers).
# Plain logging.getLogger(__name__) would target the bare root logger, which
# has no INFO handler under uvicorn - silently dropping the dev-mode OTP
# email bodies that make local registration usable without SMTP.
from app.core.logger import get_module_logger

logger = get_module_logger("services.email_service")


class EmailService:
    """SMTP email service for sending OTP emails."""

    def __init__(self):
        self.smtp_host = os.getenv("SMTP_HOST", "smtp.gmail.com")
        self.smtp_port = int(os.getenv("SMTP_PORT", "587"))
        self.smtp_username = os.getenv("SMTP_USERNAME", "")
        self.smtp_password = os.getenv("SMTP_PASSWORD", "")
        self.from_email = os.getenv("SMTP_FROM_EMAIL", "noreply@socra-ai.com")
        self.from_name = os.getenv("SMTP_FROM_NAME", "SOCRA AI")

    def _send_email(self, to_email: str, subject: str, html_body: str) -> bool:
        """Send an email via SMTP. Returns True on success."""
        if not self.smtp_username or not self.smtp_password:
            logger.warning("[EmailService] SMTP not configured - email not sent to %s", to_email)
            # In development, log the email content instead of sending
            logger.info("[EmailService] Subject: %s\nBody: %s", subject, html_body)
            return True  # Return True in dev mode to not block registration

        try:
            msg = MIMEMultipart("alternative")
            msg["From"] = f"{self.from_name} <{self.from_email}>"
            msg["To"] = to_email
            msg["Subject"] = subject

            msg.attach(MIMEText(html_body, "html"))

            with smtplib.SMTP(self.smtp_host, self.smtp_port, timeout=10) as server:
                server.starttls()
                server.login(self.smtp_username, self.smtp_password)
                server.sendmail(self.from_email, to_email, msg.as_string())

            logger.info("[EmailService] Email sent to %s", to_email)
            return True

        except Exception as e:
            logger.error("[EmailService] Failed to send email to %s: %s", to_email, e)
            return False

    def send_verification_otp(self, email: str, otp: str, full_name: str = "") -> bool:
        """Send email verification OTP."""
        name_part = f" {full_name}" if full_name else ""
        subject = "Verify your SOCRA AI account"
        html_body = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
        </head>
        <body style="margin:0; padding:0; background-color:#0f172a; font-family:'Segoe UI',Tahoma,Geneva,Verdana,sans-serif;">
            <div style="max-width:500px; margin:40px auto; background-color:#1e293b; border-radius:16px; border:1px solid #334155; overflow:hidden;">
                <div style="background:linear-gradient(135deg,#0891b2,#06b6d4); padding:30px; text-align:center;">
                    <h1 style="color:white; margin:0; font-size:24px; font-weight:700;">SOCRA AI</h1>
                    <p style="color:rgba(255,255,255,0.8); margin:5px 0 0; font-size:12px; text-transform:uppercase; letter-spacing:2px;">Security Investigation Platform</p>
                </div>
                <div style="padding:40px 30px;">
                    <h2 style="color:#e2e8f0; margin:0 0 15px; font-size:18px;">Welcome{name_part}!</h2>
                    <p style="color:#94a3b8; font-size:14px; line-height:1.6; margin:0 0 25px;">
                        Thank you for registering with SOCRA AI. Please use the following verification code to complete your registration.
                    </p>
                    <div style="background:#0f172a; border:1px solid #334155; border-radius:12px; padding:20px; text-align:center; margin:25px 0;">
                        <p style="color:#64748b; font-size:11px; text-transform:uppercase; letter-spacing:2px; margin:0 0 10px;">Your Verification Code</p>
                        <p style="color:#22d3ee; font-size:32px; font-weight:700; letter-spacing:8px; margin:0; font-family:monospace;">{otp}</p>
                    </div>
                    <p style="color:#94a3b8; font-size:12px; line-height:1.6; margin:0 0 15px;">
                        This code will expire in <strong style="color:#e2e8f0;">10 minutes</strong>.
                    </p>
                    <p style="color:#94a3b8; font-size:12px; line-height:1.6; margin:0;">
                        If you did not create an account, please ignore this email.
                    </p>
                </div>
                <div style="padding:20px 30px; border-top:1px solid #334155; text-align:center;">
                    <p style="color:#475569; font-size:11px; margin:0;">
                        This is an automated message from SOCRA AI. Do not reply to this email.
                    </p>
                </div>
            </div>
        </body>
        </html>
        """
        return self._send_email(email, subject, html_body)

    def send_password_reset_otp(self, email: str, otp: str, full_name: str = "") -> bool:
        """Send password reset OTP."""
        name_part = f" {full_name}" if full_name else ""
        subject = "SOCRA AI password reset code"
        html_body = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
        </head>
        <body style="margin:0; padding:0; background-color:#0f172a; font-family:'Segoe UI',Tahoma,Geneva,Verdana,sans-serif;">
            <div style="max-width:500px; margin:40px auto; background-color:#1e293b; border-radius:16px; border:1px solid #334155; overflow:hidden;">
                <div style="background:linear-gradient(135deg,#dc2626,#ef4444); padding:30px; text-align:center;">
                    <h1 style="color:white; margin:0; font-size:24px; font-weight:700;">SOCRA AI</h1>
                    <p style="color:rgba(255,255,255,0.8); margin:5px 0 0; font-size:12px; text-transform:uppercase; letter-spacing:2px;">Password Reset Request</p>
                </div>
                <div style="padding:40px 30px;">
                    <h2 style="color:#e2e8f0; margin:0 0 15px; font-size:18px;">Reset Your Password{name_part}</h2>
                    <p style="color:#94a3b8; font-size:14px; line-height:1.6; margin:0 0 25px;">
                        We received a request to reset your password. Please use the following code to create a new password.
                    </p>
                    <div style="background:#0f172a; border:1px solid #334155; border-radius:12px; padding:20px; text-align:center; margin:25px 0;">
                        <p style="color:#64748b; font-size:11px; text-transform:uppercase; letter-spacing:2px; margin:0 0 10px;">Your Reset Code</p>
                        <p style="color:#f87171; font-size:32px; font-weight:700; letter-spacing:8px; margin:0; font-family:monospace;">{otp}</p>
                    </div>
                    <p style="color:#94a3b8; font-size:12px; line-height:1.6; margin:0 0 15px;">
                        This code will expire in <strong style="color:#e2e8f0;">10 minutes</strong>.
                    </p>
                    <p style="color:#94a3b8; font-size:12px; line-height:1.6; margin:0;">
                        If you did not request a password reset, please ignore this email and your password will remain unchanged.
                    </p>
                </div>
                <div style="padding:20px 30px; border-top:1px solid #334155; text-align:center;">
                    <p style="color:#475569; font-size:11px; margin:0;">
                        This is an automated message from SOCRA AI. Do not reply to this email.
                    </p>
                </div>
            </div>
        </body>
        </html>
        """
        return self._send_email(email, subject, html_body)


email_service = EmailService()
