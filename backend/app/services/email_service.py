import smtplib
import logging
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from app.config import settings

logger = logging.getLogger(__name__)


def send_verification_email(to_email: str, code: str) -> bool:
    """6자리 인증 코드를 Gmail SMTP로 발송. 성공 시 True, 실패 시 False."""
    if not settings.gmail_user or not settings.gmail_app_password:
        logger.warning("Gmail credentials not configured — skipping email send")
        return False

    subject = "[악성 사이트 탐지기] 이메일 인증 코드"
    body = f"""
안녕하세요!

악성 사이트 탐지기 회원가입을 위한 이메일 인증 코드입니다.

인증 코드: {code}

이 코드는 10분 동안 유효합니다.
본인이 요청하지 않은 경우 이 이메일을 무시하세요.
"""

    msg = MIMEMultipart("alternative")
    msg["Subject"] = subject
    msg["From"] = settings.gmail_user
    msg["To"] = to_email
    msg.attach(MIMEText(body.strip(), "plain", "utf-8"))

    try:
        with smtplib.SMTP_SSL("smtp.gmail.com", 465, timeout=10) as smtp:
            smtp.login(settings.gmail_user, settings.gmail_app_password)
            smtp.sendmail(settings.gmail_user, to_email, msg.as_string())
        return True
    except Exception as e:
        logger.error(f"Failed to send verification email to {to_email}: {e}")
        return False
