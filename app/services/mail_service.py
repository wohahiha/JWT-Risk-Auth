from dataclasses import dataclass
from email.message import EmailMessage
import smtplib

from app.core.config import Settings, get_settings


@dataclass(frozen=True)
class MailSendResult:
    sent: bool
    used_debug_fallback: bool
    error: str | None = None


class MailService:
    def __init__(self, settings: Settings | None = None) -> None:
        self.settings = settings or get_settings()

    def send_challenge_email(self, recipient: str, challenge_value: int) -> MailSendResult:
        if not self._is_smtp_configured:
            return self._fallback_or_failure("SMTP is not configured")

        message = EmailMessage()
        message["Subject"] = "JWT authentication challenge"
        message["From"] = self.settings.smtp_from_email or self.settings.smtp_username
        message["To"] = recipient
        message.set_content(
            "Use this value to complete your JWT authentication challenge: "
            f"{challenge_value}"
        )

        try:
            with smtplib.SMTP(self.settings.smtp_host, self.settings.smtp_port, timeout=10) as server:
                if self.settings.smtp_use_tls:
                    server.starttls()
                if self.settings.smtp_username and self.settings.smtp_password:
                    server.login(self.settings.smtp_username, self.settings.smtp_password)
                server.send_message(message)
        except Exception as exc:
            return self._fallback_or_failure(str(exc))

        return MailSendResult(sent=True, used_debug_fallback=False)

    @property
    def _is_smtp_configured(self) -> bool:
        return bool(
            self.settings.smtp_host
            and self.settings.smtp_port
            and (self.settings.smtp_from_email or self.settings.smtp_username)
        )

    def _fallback_or_failure(self, error: str) -> MailSendResult:
        debug_fallback = (
            self.settings.environment.lower() == "local"
            and self.settings.mail_debug_fallback_enabled
        )
        return MailSendResult(sent=False, used_debug_fallback=debug_fallback, error=error)


def get_mail_service() -> MailService:
    return MailService()
