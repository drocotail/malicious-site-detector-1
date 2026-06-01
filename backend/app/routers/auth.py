import re
import random
from datetime import datetime, timezone, timedelta

from fastapi import APIRouter, Depends, HTTPException
from fastapi.security import OAuth2PasswordRequestForm
from pydantic import BaseModel, EmailStr
from sqlalchemy.orm import Session

from app.auth.jwt_handler import create_access_token, hash_password, verify_password
from app.database import get_db
from app.models.user import User
from app.models.email_verification import EmailVerification
from app.services.email_service import send_verification_email

router = APIRouter()

# 허용 특수문자: !@#%^*-_+=?~.,  (셸 간섭 문자 제외)
_ALLOWED_SPECIAL = r"!@#%\^*\-_+=?~.,"
_PW_ALLOWED = re.compile(r"^[A-Za-z0-9" + _ALLOWED_SPECIAL + r"]+$")
_PW_LETTER = re.compile(r"[A-Za-z]")
_PW_DIGIT = re.compile(r"[0-9]")
_PW_SPECIAL = re.compile(r"[" + _ALLOWED_SPECIAL + r"]")

_CODE_EXPIRY_MINUTES = 10


def _validate_password(pw: str) -> str | None:
    if len(pw) < 8:
        return "비밀번호는 8자 이상이어야 합니다."
    if not _PW_LETTER.search(pw):
        return "비밀번호에 영문자를 포함해야 합니다."
    if not _PW_DIGIT.search(pw):
        return "비밀번호에 숫자를 포함해야 합니다."
    if not _PW_SPECIAL.search(pw):
        return "비밀번호에 특수문자(!@#%^*-_+=?~.,)를 포함해야 합니다."
    if not _PW_ALLOWED.match(pw):
        return "비밀번호에 허용되지 않는 특수문자가 포함되어 있습니다."
    return None


def _issue_code(
    email: str,
    db: Session,
    password_hash: str | None = None,
    nickname: str | None = None,
) -> str:
    """기존 미사용 코드를 무효화하고 새 코드를 발급한다.
    password_hash/nickname이 None이면 기존 레코드의 값을 유지한다 (재발송 시).
    """
    existing = (
        db.query(EmailVerification)
        .filter(EmailVerification.email == email, EmailVerification.used == False)
        .first()
    )
    if existing:
        if password_hash is None:
            password_hash = existing.password_hash
        if nickname is None:
            nickname = existing.nickname
        db.delete(existing)
        db.flush()

    code = f"{random.randint(0, 999999):06d}"
    expires_at = datetime.now(timezone.utc) + timedelta(minutes=_CODE_EXPIRY_MINUTES)
    ev = EmailVerification(
        email=email,
        code=code,
        password_hash=password_hash,
        nickname=nickname,
        expires_at=expires_at,
    )
    db.add(ev)
    db.commit()
    return code


# ── 스키마 ────────────────────────────────────────────────────────────────────

class UserCreate(BaseModel):
    email: EmailStr
    password: str
    nickname: str | None = None


class LoginRequest(BaseModel):
    email: EmailStr
    password: str


class VerifyEmailRequest(BaseModel):
    email: EmailStr
    code: str


class ResendCodeRequest(BaseModel):
    email: EmailStr


class Token(BaseModel):
    access_token: str
    token_type: str


class RegisterResponse(BaseModel):
    email: str
    requires_verification: bool


# ── 엔드포인트 ─────────────────────────────────────────────────────────────────

@router.post("/auth/register", response_model=RegisterResponse)
def register(user_data: UserCreate, db: Session = Depends(get_db)):
    pw_error = _validate_password(user_data.password)
    if pw_error:
        raise HTTPException(status_code=400, detail=pw_error)

    # 이미 가입 완료된 이메일
    if db.query(User).filter(User.email == user_data.email).first():
        raise HTTPException(status_code=400, detail="이미 사용 중인 이메일입니다.")

    nickname = (user_data.nickname or "").strip() or user_data.email.split("@")[0]

    # 닉네임 중복 (가입 완료된 유저 기준)
    if db.query(User).filter(User.nickname == nickname).first():
        raise HTTPException(status_code=400, detail="이미 사용 중인 닉네임입니다.")

    # 코드 발급 (password_hash, nickname을 임시 보관)
    pw_hash = hash_password(user_data.password)
    code = _issue_code(user_data.email, db, password_hash=pw_hash, nickname=nickname)

    sent = send_verification_email(user_data.email, code)
    if not sent:
        print(f"[DEV] Email verification code for {user_data.email}: {code}")

    return {"email": user_data.email, "requires_verification": True}


@router.post("/auth/verify-email", response_model=Token)
def verify_email(req: VerifyEmailRequest, db: Session = Depends(get_db)):
    # 이미 가입 완료된 경우
    if db.query(User).filter(User.email == req.email).first():
        raise HTTPException(status_code=400, detail="이미 가입된 이메일입니다.")

    now = datetime.now(timezone.utc)
    ev = (
        db.query(EmailVerification)
        .filter(
            EmailVerification.email == req.email,
            EmailVerification.used == False,
            EmailVerification.expires_at > now,
        )
        .order_by(EmailVerification.created_at.desc())
        .first()
    )

    if not ev:
        raise HTTPException(status_code=400, detail="인증 코드가 만료되었거나 존재하지 않습니다.")
    if ev.code != req.code:
        raise HTTPException(status_code=400, detail="인증 코드가 올바르지 않습니다.")
    if not ev.password_hash or not ev.nickname:
        raise HTTPException(status_code=400, detail="회원가입 정보가 없습니다. 다시 시도해주세요.")

    # 인증 성공 → 유저 생성
    user = User(
        email=req.email,
        password_hash=ev.password_hash,
        nickname=ev.nickname,
        is_verified=True,
    )
    db.add(user)
    ev.used = True
    db.commit()
    db.refresh(user)

    return {
        "access_token": create_access_token({"sub": str(user.id), "nickname": user.nickname}),
        "token_type": "bearer",
    }


@router.post("/auth/resend-code")
def resend_code(req: ResendCodeRequest, db: Session = Depends(get_db)):
    if db.query(User).filter(User.email == req.email).first():
        raise HTTPException(status_code=400, detail="이미 가입된 이메일입니다.")

    # 기존 pending 레코드가 없으면 재발송 불가 (register를 먼저 해야 함)
    existing = (
        db.query(EmailVerification)
        .filter(EmailVerification.email == req.email, EmailVerification.used == False)
        .first()
    )
    if not existing:
        raise HTTPException(status_code=400, detail="회원가입을 먼저 진행해주세요.")

    code = _issue_code(req.email, db)  # password_hash/nickname은 기존 레코드에서 유지
    sent = send_verification_email(req.email, code)
    if not sent:
        print(f"[DEV] Resent verification code for {req.email}: {code}")

    return {"message": f"인증 코드를 {req.email}로 재발송했습니다."}


@router.post("/auth/login", response_model=Token)
def login_json(login_data: LoginRequest, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.email == login_data.email).first()
    if not user or not verify_password(login_data.password, user.password_hash):
        raise HTTPException(status_code=401, detail="이메일 또는 비밀번호가 올바르지 않습니다.")
    if not user.is_verified:
        raise HTTPException(status_code=403, detail="이메일 인증이 필요합니다.")
    if user.is_blocked:
        raise HTTPException(status_code=403, detail="차단된 계정입니다. 관리자에게 문의하세요.")

    return {"access_token": create_access_token({"sub": str(user.id), "nickname": user.nickname}), "token_type": "bearer"}


@router.post("/auth/token", response_model=Token)
def login_form(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    """Swagger용 OAuth2 form 로그인"""
    user = db.query(User).filter(User.email == form_data.username).first()
    if not user or not verify_password(form_data.password, user.password_hash):
        raise HTTPException(status_code=401, detail="이메일 또는 비밀번호가 올바르지 않습니다.")
    if not user.is_verified:
        raise HTTPException(status_code=403, detail="이메일 인증이 필요합니다.")
    if user.is_blocked:
        raise HTTPException(status_code=403, detail="차단된 계정입니다. 관리자에게 문의하세요.")

    return {"access_token": create_access_token({"sub": str(user.id), "nickname": user.nickname}), "token_type": "bearer"}
