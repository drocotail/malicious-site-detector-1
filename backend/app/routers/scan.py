import re
from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, field_validator
from sqlalchemy.orm import Session
from slowapi import Limiter
from slowapi.util import get_remote_address

from app.auth.jwt_handler import get_optional_user
from app.database import get_db
from app.models.malicious_site import MaliciousSite
from app.models.report import Report
from app.models.scan import ScanHistory
from app.models.user import User
from app.services.domain_analyzer import extract_domain
from app.services.verdict_engine import scan_url as _engine_scan
from app.services.url_expander import expand_url

router = APIRouter()
limiter = Limiter(key_func=get_remote_address)

_URL_PATTERN = re.compile(
    r"^(https?://)?"
    r"(([a-zA-Z0-9\-]+\.)+[a-zA-Z]{2,})"
    r"(:\d+)?(/[^\s]*)?$"
)

VERDICT_TO_RISK = {"safe": "낮음", "suspicious": "주의", "dangerous": "위험"}


class UrlRequest(BaseModel):
    url: str

    @field_validator("url")
    @classmethod
    def validate_url(cls, v: str) -> str:
        v = v.strip()
        if not v:
            raise ValueError("URL을 입력해주세요.")
        if len(v) > 2048:
            raise ValueError("URL은 2048자를 초과할 수 없습니다.")
        test = v if v.startswith(("http://", "https://")) else f"http://{v}"
        if not _URL_PATTERN.match(test):
            raise ValueError("올바른 URL 형식이 아닙니다.")
        return v


def _normalize_url(url: str) -> str:
    url = url.strip()
    if not url.startswith(("http://", "https://")):
        url = f"https://{url}"
    return url


def _transform_response(
    url: str,
    normalized: str,
    result: dict,
    expanded_url: str | None = None,
) -> dict:
    """verdict_engine 결과를 프론트엔드가 기대하는 형식으로 변환."""
    verdict = result.get("verdict", "safe")
    details = result.get("details", {})
    domain_analysis = details.get("domain_analysis", {})
    domain_age = domain_analysis.get("domain_age", {})
    sb = details.get("safe_browsing", {})
    vt = details.get("virustotal", {})
    pt = details.get("phishtank", {})
    ml = details.get("ml") or {}
    url_flags = domain_analysis.get("url_structure_flags", [])
    threat_types = result.get("threat_types", [])

    triggered_rules = list(threat_types)
    rule_score = result.get("risk_score", 0)

    # final_reason 생성
    if details.get("source") == "whitelist":
        final_reason = f"공식 화이트리스트 도메인입니다: {details.get('domain', '')}"
    elif details.get("source") == "internal_db":
        final_reason = "자체 DB에 등록된 위협 사이트입니다."
    elif pt.get("is_phishing"):
        final_reason = "PhishTank에서 검증된 피싱 사이트입니다."
    elif triggered_rules:
        final_reason = "탐지된 위협: " + ", ".join(triggered_rules)
    else:
        final_reason = "알려진 위협이 탐지되지 않았습니다."

    # decision_type
    if details.get("source") == "whitelist":
        decision_type = "official_domain_allowlist"
    elif details.get("source") == "internal_db":
        decision_type = "internal_db"
    elif not sb.get("is_safe", True) or not vt.get("is_safe", True) or pt.get("is_phishing"):
        decision_type = "api_hard_positive"
    elif triggered_rules:
        decision_type = "hybrid_ai_rule_decision"
    else:
        decision_type = "safe"

    return {
        "input_url": url,
        "normalized_url": normalized,
        "is_shortened": expanded_url is not None,
        "expanded_url": expanded_url,
        "risk_level": VERDICT_TO_RISK.get(verdict, "낮음"),
        "risk_score": result.get("risk_score", 0),
        "decision_type": decision_type,
        "final_reason": final_reason,
        "features": {
            "domain_age_days": domain_age.get("age_days"),
            "ip_in_url": "IP_ADDRESS_URL" in url_flags,
            "at_sign": "AT_SIGN_IN_URL" in url_flags,
            "url_length": len(normalized),
            "subdomain_count": len(domain_analysis.get("domain", "").split(".")) - 2,
            "suspicious_tld": domain_analysis.get("suspicious_tld", False),
            "impersonation_patterns": domain_analysis.get("impersonation_patterns", []),
        },
        "rule_info": {
            "triggered_rules": triggered_rules,
            "score": rule_score,
        },
        "api_results": {
            "safe_browsing": {
                "skipped": sb.get("skipped", False),
                "is_safe": sb.get("is_safe", True),
            },
            "phishtank": {
                "skipped": pt.get("skipped", False),
                "available": pt.get("available", False),
                "in_database": pt.get("in_database", False),
                "verified": pt.get("verified", False),
                "valid": pt.get("valid", False),
                "is_phishing": pt.get("is_phishing", False),
            },
        },
        "ai_results": {
            "url_transformer": {
                "skipped": ml is None or not ml,
                "label": ml.get("ml_label", ""),
                "score": (ml.get("confidence") or 0),
            }
        },
    }


# ── /api/scan (프론트엔드 메인 스캔 엔드포인트) ──────────────────────────────
@router.post("/scan")
@limiter.limit("60/hour")
async def scan(
    request: Request,
    req: UrlRequest,
    db: Session = Depends(get_db),
    current_user: User | None = Depends(get_optional_user),
):
    url = req.url
    normalized = _normalize_url(url)

    # 리다이렉트를 따라가 최종 도메인이 다르면 단축링크로 판단
    final, is_shortened = await expand_url(normalized)
    expanded_url: str | None = final if is_shortened else None
    scan_target = final if is_shortened else normalized

    result = await _engine_scan(scan_target, db)

    db.add(
        ScanHistory(
            user_id=current_user.id if current_user else None,
            url=scan_target,
            domain=extract_domain(scan_target),
            verdict=result["verdict"],
            risk_score=result["risk_score"],
            threat_types=result["threat_types"],
            details=result["details"],
        )
    )
    db.commit()

    return _transform_response(url, normalized, result, expanded_url)


# ── /api/scan/check (기존 엔드포인트 유지) ───────────────────────────────────
@router.post("/scan/check")
@limiter.limit("60/hour")
async def check_url(
    request: Request,
    req: UrlRequest,
    db: Session = Depends(get_db),
    current_user: User | None = Depends(get_optional_user),
):
    normalized = _normalize_url(req.url)
    result = await _engine_scan(normalized, db)

    db.add(
        ScanHistory(
            user_id=current_user.id if current_user else None,
            url=normalized,
            domain=extract_domain(normalized),
            verdict=result["verdict"],
            risk_score=result["risk_score"],
            threat_types=result["threat_types"],
            details=result["details"],
        )
    )
    db.commit()

    return result


# ── /api/scan/stats ──────────────────────────────────────────────────────────
@router.get("/scan/stats")
def scan_stats(db: Session = Depends(get_db)):
    total = db.query(ScanHistory).count()
    dangerous = db.query(ScanHistory).filter(ScanHistory.verdict == "dangerous").count()
    suspicious = db.query(ScanHistory).filter(ScanHistory.verdict == "suspicious").count()
    db_entries = db.query(MaliciousSite).count()
    return {
        "total_scans": total,
        "dangerous_detected": dangerous,
        "suspicious_detected": suspicious,
        "db_entries": db_entries,
    }


# ── /api/scan/history ────────────────────────────────────────────────────────
@router.get("/scan/history")
def scan_history(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_optional_user),
):
    if not current_user:
        raise HTTPException(status_code=401, detail="로그인이 필요합니다.")
    records = (
        db.query(ScanHistory)
        .filter(ScanHistory.user_id == current_user.id)
        .order_by(ScanHistory.created_at.desc())
        .limit(50)
        .all()
    )
    return [
        {
            "id": r.id,
            "url": r.url,
            "domain": r.domain,
            "verdict": VERDICT_TO_RISK.get(r.verdict, r.verdict),
            "risk_score": r.risk_score,
            "reason": ", ".join(r.threat_types or []),
            "scanned_at": r.created_at.isoformat(),
        }
        for r in records
    ]


# ── /api/sites (최근 위협 목록, 프론트엔드 호환) ────────────────────────────
@router.get("/sites")
def recent_sites(limit: int = 10, db: Session = Depends(get_db)):
    sites = (
        db.query(MaliciousSite)
        .order_by(MaliciousSite.created_at.desc())
        .limit(min(limit, 50))
        .all()
    )
    return [
        {
            "id": s.id,
            "url": s.url,
            "domain": s.domain,
            "category": s.category,
            "notes": ", ".join(s.threat_types or []) if s.threat_types else None,
            "registered_at": s.created_at.isoformat(),
        }
        for s in sites
    ]


# ── /api/reports (사용자 제보) ──────────────────────────────────────────────
class ReportRequest(BaseModel):
    url: str
    title: str | None = None
    description: str | None = None

    @field_validator("url")
    @classmethod
    def validate_url(cls, v: str) -> str:
        v = v.strip()
        if not v:
            raise ValueError("URL을 입력해주세요.")
        return v


@router.post("/reports")
@limiter.limit("10/minute")
def report_url(
    request: Request,
    req: ReportRequest,
    db: Session = Depends(get_db),
    current_user: User | None = Depends(get_optional_user),
):
    normalized = _normalize_url(req.url)
    domain = extract_domain(normalized)

    # 이미 확정된 사이트는 제보 불필요
    confirmed = db.query(MaliciousSite).filter(
        MaliciousSite.domain == domain,
        MaliciousSite.category == "confirmed_phishing",
    ).first()
    if confirmed:
        return {"message": "이미 위협으로 등록된 사이트입니다."}

    # 동일 URL 중복 제보 방지
    duplicate = db.query(Report).filter(
        Report.domain == domain,
        Report.status == "pending",
    ).first()
    if duplicate:
        return {"message": "이미 검토 대기 중인 제보가 있습니다."}

    db.add(Report(
        url=normalized,
        domain=domain,
        description=req.description or req.title,
        user_id=current_user.id if current_user else None,
    ))
    db.commit()
    return {"message": "제보가 접수되었습니다. 관리자 검토 후 반영됩니다."}


# ── /api/scan/recent-threats (기존 엔드포인트 유지) ──────────────────────────
@router.get("/scan/recent-threats")
def recent_threats(limit: int = 10, db: Session = Depends(get_db)):
    sites = (
        db.query(MaliciousSite)
        .order_by(MaliciousSite.created_at.desc())
        .limit(min(limit, 50))
        .all()
    )
    return [
        {
            "domain": s.domain,
            "category": s.category,
            "source": s.source,
            "threat_types": s.threat_types,
            "detected_at": s.created_at.isoformat(),
        }
        for s in sites
    ]
