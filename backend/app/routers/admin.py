from datetime import datetime, timedelta

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, EmailStr
from sqlalchemy.orm import Session

from app.auth.admin_auth import get_current_admin
from app.auth.jwt_handler import hash_password, verify_password
from app.config import settings
from app.database import get_db
from app.models.admin import Admin
from app.models.malicious_site import MaliciousSite
from app.models.post import Post
from app.models.report import Report
from app.models.scan import ScanHistory
from app.models.user import User
from app.services.domain_analyzer import extract_domain
from jose import jwt as jose_jwt

router = APIRouter(prefix="/api/admin", tags=["admin"])


# ── Schemas ───────────────────────────────────────────────────────────────────

class AdminLogin(BaseModel):
    email: EmailStr
    password: str


class AdminSetup(BaseModel):
    email: EmailStr
    password: str
    name: str


class SiteCreate(BaseModel):
    url: str
    domain: str
    category: str = "confirmed_phishing"
    threat_types: list[str] = []


class SiteUpdate(BaseModel):
    category: str | None = None
    threat_types: list[str] | None = None


class ReportReview(BaseModel):
    action: str  # "approve" | "reject"


def _make_admin_token(admin: Admin) -> str:
    payload = {
        "sub": str(admin.id),
        "role": "admin",
        "name": admin.name,
        "exp": datetime.utcnow() + timedelta(hours=8),
    }
    return jose_jwt.encode(payload, settings.secret_key, algorithm=settings.algorithm)


# ── 인증 ──────────────────────────────────────────────────────────────────────

@router.post("/login")
def admin_login(body: AdminLogin, db: Session = Depends(get_db)):
    admin = db.query(Admin).filter(Admin.email == body.email).first()
    if not admin or not verify_password(body.password, admin.password_hash):
        raise HTTPException(status_code=401, detail="이메일 또는 비밀번호가 올바르지 않습니다.")
    admin.last_login_at = datetime.utcnow()
    db.commit()
    return {"access_token": _make_admin_token(admin), "token_type": "bearer", "name": admin.name}


@router.post("/setup", status_code=status.HTTP_201_CREATED)
def admin_setup(body: AdminSetup, db: Session = Depends(get_db)):
    """최초 관리자 계정 생성 (관리자가 한 명도 없을 때만 허용)."""
    if db.query(Admin).count() > 0:
        raise HTTPException(status_code=403, detail="이미 관리자 계정이 존재합니다.")
    admin = Admin(
        email=body.email,
        password_hash=hash_password(body.password),
        name=body.name,
    )
    db.add(admin)
    db.commit()
    db.refresh(admin)
    return {"message": f"관리자 '{admin.name}' 계정이 생성되었습니다."}


# ── 통계 ──────────────────────────────────────────────────────────────────────

@router.get("/stats")
def admin_stats(db: Session = Depends(get_db), _: Admin = Depends(get_current_admin)):
    return {
        "total_scans": db.query(ScanHistory).count(),
        "dangerous": db.query(ScanHistory).filter(ScanHistory.verdict == "dangerous").count(),
        "suspicious": db.query(ScanHistory).filter(ScanHistory.verdict == "suspicious").count(),
        "safe": db.query(ScanHistory).filter(ScanHistory.verdict == "safe").count(),
        "total_sites": db.query(MaliciousSite).count(),
        "confirmed_phishing": db.query(MaliciousSite).filter(MaliciousSite.category == "confirmed_phishing").count(),
        "total_users": db.query(User).count(),
        "blocked_users": db.query(User).filter(User.is_blocked == True).count(),
        "pending_reports": db.query(Report).filter(Report.status == "pending").count(),
        "total_posts": db.query(Post).count(),
    }


# ── 제보 검토 ─────────────────────────────────────────────────────────────────

@router.get("/reports")
def admin_list_reports(
    status_filter: str = "pending",
    skip: int = 0,
    limit: int = 50,
    db: Session = Depends(get_db),
    _: Admin = Depends(get_current_admin),
):
    q = db.query(Report)
    if status_filter != "all":
        q = q.filter(Report.status == status_filter)
    reports = q.order_by(Report.created_at.desc()).offset(skip).limit(min(limit, 200)).all()

    return [
        {
            "id": r.id,
            "url": r.url,
            "domain": r.domain,
            "description": r.description,
            "user_id": r.user_id,
            "reporter_nickname": (
                db.query(User.nickname).filter(User.id == r.user_id).scalar()
                if r.user_id else None
            ),
            "status": r.status,
            "reviewed_at": r.reviewed_at.isoformat() if r.reviewed_at else None,
            "created_at": r.created_at.isoformat(),
        }
        for r in reports
    ]


@router.patch("/reports/{report_id}/review")
def admin_review_report(
    report_id: int,
    body: ReportReview,
    db: Session = Depends(get_db),
    admin: Admin = Depends(get_current_admin),
):
    if body.action not in ("approve", "reject"):
        raise HTTPException(status_code=400, detail="action은 'approve' 또는 'reject'여야 합니다.")

    report = db.query(Report).filter(Report.id == report_id).first()
    if not report:
        raise HTTPException(status_code=404, detail="제보를 찾을 수 없습니다.")
    if report.status != "pending":
        raise HTTPException(status_code=400, detail="이미 처리된 제보입니다.")

    report.status = "approved" if body.action == "approve" else "rejected"
    report.reviewed_by = admin.id
    report.reviewed_at = datetime.utcnow()
    db.commit()

    if body.action == "approve":
        existing = db.query(MaliciousSite).filter(MaliciousSite.domain == report.domain).first()
        if existing:
            existing.category = "confirmed_phishing"
            existing.source = "admin_approved"
        else:
            db.add(MaliciousSite(
                url=report.url,
                domain=report.domain,
                category="confirmed_phishing",
                source="admin_approved",
                threat_types=["USER_REPORTED"],
                confirmed_at=datetime.utcnow(),
            ))
        db.commit()
        return {"message": "제보가 승인되어 악성 사이트에 등록되었습니다."}

    return {"message": "제보가 거절되었습니다."}


# ── 사용자 차단 관리 ──────────────────────────────────────────────────────────

@router.get("/users")
def admin_users(
    skip: int = 0,
    limit: int = 50,
    db: Session = Depends(get_db),
    _: Admin = Depends(get_current_admin),
):
    users = (
        db.query(User)
        .order_by(User.created_at.desc())
        .offset(skip)
        .limit(min(limit, 200))
        .all()
    )
    return [
        {
            "id": u.id,
            "email": u.email,
            "nickname": u.nickname,
            "is_blocked": u.is_blocked,
            "scan_count": db.query(ScanHistory).filter(ScanHistory.user_id == u.id).count(),
            "created_at": u.created_at.isoformat(),
        }
        for u in users
    ]


@router.patch("/users/{user_id}/block")
def admin_block_user(
    user_id: int,
    db: Session = Depends(get_db),
    _: Admin = Depends(get_current_admin),
):
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="사용자를 찾을 수 없습니다.")
    if user.is_blocked:
        raise HTTPException(status_code=400, detail="이미 차단된 사용자입니다.")
    user.is_blocked = True
    db.commit()
    return {"message": f"'{user.nickname or user.email}' 사용자가 차단되었습니다."}


@router.patch("/users/{user_id}/unblock")
def admin_unblock_user(
    user_id: int,
    db: Session = Depends(get_db),
    _: Admin = Depends(get_current_admin),
):
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="사용자를 찾을 수 없습니다.")
    if not user.is_blocked:
        raise HTTPException(status_code=400, detail="차단되지 않은 사용자입니다.")
    user.is_blocked = False
    db.commit()
    return {"message": f"'{user.nickname or user.email}' 사용자의 차단이 해제되었습니다."}


# ── 악성 사이트 관리 (모니터링용) ─────────────────────────────────────────────

@router.get("/sites")
def admin_sites(
    skip: int = 0,
    limit: int = 50,
    db: Session = Depends(get_db),
    _: Admin = Depends(get_current_admin),
):
    sites = (
        db.query(MaliciousSite)
        .order_by(MaliciousSite.created_at.desc())
        .offset(skip)
        .limit(min(limit, 200))
        .all()
    )
    return [
        {
            "id": s.id,
            "url": s.url,
            "domain": s.domain,
            "category": s.category,
            "source": s.source,
            "threat_types": s.threat_types,
            "created_at": s.created_at.isoformat(),
            "confirmed_at": s.confirmed_at.isoformat() if s.confirmed_at else None,
        }
        for s in sites
    ]


@router.post("/sites", status_code=status.HTTP_201_CREATED)
def admin_add_site(
    body: SiteCreate,
    db: Session = Depends(get_db),
    _: Admin = Depends(get_current_admin),
):
    existing = db.query(MaliciousSite).filter(MaliciousSite.domain == body.domain).first()
    if existing:
        raise HTTPException(status_code=400, detail="이미 등록된 도메인입니다.")
    site = MaliciousSite(
        url=body.url,
        domain=body.domain,
        category=body.category,
        source="admin",
        threat_types=body.threat_types,
        confirmed_at=datetime.utcnow() if body.category == "confirmed_phishing" else None,
    )
    db.add(site)
    db.commit()
    db.refresh(site)
    return {"message": "사이트가 등록되었습니다.", "id": site.id}


@router.patch("/sites/{site_id}")
def admin_update_site(
    site_id: int,
    body: SiteUpdate,
    db: Session = Depends(get_db),
    _: Admin = Depends(get_current_admin),
):
    site = db.query(MaliciousSite).filter(MaliciousSite.id == site_id).first()
    if not site:
        raise HTTPException(status_code=404, detail="사이트를 찾을 수 없습니다.")
    if body.category is not None:
        site.category = body.category
        if body.category == "confirmed_phishing" and not site.confirmed_at:
            site.confirmed_at = datetime.utcnow()
    if body.threat_types is not None:
        site.threat_types = body.threat_types
    db.commit()
    return {"message": "업데이트되었습니다."}


@router.delete("/sites/{site_id}", status_code=status.HTTP_204_NO_CONTENT)
def admin_delete_site(
    site_id: int,
    db: Session = Depends(get_db),
    _: Admin = Depends(get_current_admin),
):
    site = db.query(MaliciousSite).filter(MaliciousSite.id == site_id).first()
    if not site:
        raise HTTPException(status_code=404, detail="사이트를 찾을 수 없습니다.")
    db.delete(site)
    db.commit()


# ── 스캔 이력 (모니터링용) ────────────────────────────────────────────────────

@router.get("/scans")
def admin_scans(
    skip: int = 0,
    limit: int = 50,
    db: Session = Depends(get_db),
    _: Admin = Depends(get_current_admin),
):
    records = (
        db.query(ScanHistory)
        .order_by(ScanHistory.created_at.desc())
        .offset(skip)
        .limit(min(limit, 100))
        .all()
    )
    return [
        {
            "id": r.id,
            "user_id": r.user_id,
            "url": r.url,
            "domain": r.domain,
            "verdict": r.verdict,
            "risk_score": r.risk_score,
            "threat_types": r.threat_types,
            "scanned_at": r.created_at.isoformat(),
        }
        for r in records
    ]


# ── 게시판 관리 ──────────────────────────────────────────────────────────────

@router.get("/posts")
def admin_list_posts(
    skip: int = 0,
    limit: int = 50,
    db: Session = Depends(get_db),
    _: Admin = Depends(get_current_admin),
):
    posts = (
        db.query(Post)
        .order_by(Post.created_at.desc())
        .offset(skip)
        .limit(min(limit, 200))
        .all()
    )
    return [
        {
            "id": p.id,
            "title": p.title,
            "user_id": p.user_id,
            "author_nickname": db.query(User.nickname).filter(User.id == p.user_id).scalar() or "탈퇴한 사용자",
            "view_count": p.view_count,
            "created_at": p.created_at.isoformat(),
        }
        for p in posts
    ]


@router.delete("/posts/{post_id}", status_code=status.HTTP_204_NO_CONTENT)
def admin_delete_post(
    post_id: int,
    db: Session = Depends(get_db),
    _: Admin = Depends(get_current_admin),
):
    post = db.query(Post).filter(Post.id == post_id).first()
    if not post:
        raise HTTPException(status_code=404, detail="게시글을 찾을 수 없습니다.")
    db.delete(post)
    db.commit()
