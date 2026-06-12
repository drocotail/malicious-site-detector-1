"""
판정 엔진 - URL 안전 여부를 결정하는 핵심 로직

판정 체계는 두 단계로 분리된다:

[API 직접 탐지 체계 — STEP 1~4]
  신뢰도 높은 외부 위협 인텔리전스(GSB·VT·PhishTank)가 탐지한 경우 즉시 위험 판정.
  임계값: VirusTotal 30% 이상 엔진 탐지, GSB 일치, PhishTank 검증 피싱

[ML + 도메인 합산 점수 체계 — STEP 5~8]
  외부 API를 통과한 미탐지(unknown) URL에 대해 도메인 분석과 ML 보조 신호로 판정.
  combined_risk 임계값: ≥ 70 → 위험, 25~69 → 의심, 0~24 → 안전

흐름:
  1. 화이트리스트 확인 (공식 도메인 → 즉시 안전 반환)
  2. 자체 DB 확인 (확정 피싱 → 즉시 위험 반환)
  3. Google Safe Browsing + VirusTotal + PhishTank + 도메인 분석 병렬 조회
  4. API 탐지 결과 종합 → 임계값 초과 시 위험 반환 (API 직접 탐지 체계)
  5. ML 모델 실행 (도메인 분석은 3단계에서 이미 완료)
  6. combined_risk ≥ 70 → 위험 반환 (ML+도메인 합산 체계)
  7. combined_risk ≥ 25 → 의심 반환 (ML+도메인 합산 체계)
  8. 모두 통과 → 안전 반환
"""

import asyncio
from datetime import datetime

from sqlalchemy.orm import Session

from app.models.malicious_site import MaliciousSite
from app.services.domain_analyzer import analyze_domain, extract_domain
from app.services.safe_browsing import check_safe_browsing
from app.services.virustotal import check_virustotal
from app.services.phishtank import check_phishtank
from app.ml.predictor import predict as ml_predict

# 글로벌 상위 도메인 및 국내 공공·금융·포털 화이트리스트
WHITELIST_DOMAINS = {
    "google.com", "youtube.com", "gmail.com",
    "microsoft.com", "office.com", "live.com", "outlook.com",
    "apple.com", "icloud.com",
    "amazon.com", "aws.amazon.com",
    "facebook.com", "instagram.com", "x.com", "twitter.com",
    "linkedin.com", "github.com", "wikipedia.org",
    "cloudflare.com", "openai.com", "netflix.com",
    "paypal.com", "stripe.com",
    "naver.com", "kakao.com", "daum.net", "kakaobank.com",
    "line.me", "toss.im",
    "shinhan.com", "kbstar.com", "ibk.co.kr", "hanabank.com",
    "nonghyup.com", "wooribank.com", "kebhana.com",
    "samsung.com", "lge.com", "hyundai.com",
    "go.kr", "or.kr", "ac.kr",
}

# ── API 직접 탐지 체계 임계값 ──────────────────────────────────────────────────
# GSB 탐지 시 부여하는 최소 위험 점수 (≥ VT_DANGER_THRESHOLD이면 위험 판정)
_GSB_HIT_SCORE = 70
# VirusTotal: 전체 엔진 대비 악성 판정 비율(%) 임계값. 30% 이상이면 위험 판정.
_VT_DANGER_THRESHOLD = 30
# PhishTank 검증 피싱 확정 점수
_PT_HIT_SCORE = 100
# API 체계 최종 위험 판정 임계값
_API_DANGER_CUTOFF = 30

# ── ML+도메인 합산 점수 체계 임계값 ───────────────────────────────────────────
_ML_DOMAIN_DANGER = 70   # combined_risk ≥ 이 값 → 위험
_ML_DOMAIN_SUSPICIOUS = 25  # combined_risk ≥ 이 값 → 의심


def _is_whitelisted(domain: str) -> bool:
    domain = domain.lower()
    for safe in WHITELIST_DOMAINS:
        if domain == safe or domain.endswith("." + safe):
            return True
    return False


async def scan_url(url: str, db: Session) -> dict:
    domain = extract_domain(url)

    # Step 1: 화이트리스트 확인
    if _is_whitelisted(domain):
        return _verdict(
            "safe", 5, [],
            {
                "source": "whitelist", "domain": domain,
                "safe_browsing": {"skipped": True},
                "phishtank": {"skipped": True},
                "virustotal": {"skipped": True},
            },
        )

    # Step 2: 자체 DB 확인
    db_entry = _lookup_db(domain, db)
    if db_entry and db_entry["category"] == "confirmed_phishing":
        return _verdict(
            "dangerous", 100,
            db_entry["threat_types"] or ["CONFIRMED_PHISHING"],
            {
                "source": "internal_db", "first_detected": db_entry["created_at"],
                "safe_browsing": {"skipped": True},
                "phishtank": {"skipped": True},
                "virustotal": {"skipped": True},
            },
        )

    # Step 3: 외부 API 3종 + 도메인 분석 병렬 조회
    # (Vercel 서버리스 함수의 10초 타임아웃을 피하기 위해 순차 실행하지 않고 함께 실행)
    sb_result, vt_result, pt_result, domain_analysis = await asyncio.gather(
        check_safe_browsing(url),
        check_virustotal(url),
        check_phishtank(url),
        analyze_domain(url),
        return_exceptions=True,
    )

    if isinstance(sb_result, Exception):
        sb_result = {"is_safe": True, "threats": [], "error": str(sb_result)}
    if isinstance(vt_result, Exception):
        vt_result = {"is_safe": True, "threats": [], "malicious_count": 0, "error": str(vt_result)}
    if isinstance(pt_result, Exception):
        pt_result = {"available": False, "is_phishing": False, "error": str(pt_result)}
    if isinstance(domain_analysis, Exception):
        domain_analysis = {
            "domain": domain, "is_suspicious": False,
            "impersonation_patterns": [], "suspicious_tld": False,
            "domain_age": {"creation_date": None, "age_days": None, "is_new_domain": False},
            "url_structure_flags": [],
        }

    # Step 4: API 직접 탐지 체계 — 신뢰도 높은 위협 인텔리전스 결과 종합
    api_threats: list[str] = []
    api_risk_score = 0  # API 체계 전용 점수 (≥ _API_DANGER_CUTOFF이면 즉시 위험)

    if not sb_result.get("is_safe", True):
        api_threats.extend(sb_result.get("threats", []))
        api_risk_score = max(api_risk_score, _GSB_HIT_SCORE)

    if not vt_result.get("is_safe", True):
        malicious = vt_result.get("malicious_count", 0)
        total = vt_result.get("total_engines", 1) or 1
        vt_score = int((malicious / total) * 100)  # 탐지 엔진 비율을 점수화
        api_risk_score = max(api_risk_score, vt_score)
        api_threats.extend(vt_result.get("threats", []))

    # PhishTank: verified + valid 둘 다 true여야 확정 피싱
    if pt_result.get("is_phishing"):
        api_threats.append("PHISHTANK_VERIFIED_PHISHING")
        api_risk_score = max(api_risk_score, _PT_HIT_SCORE)

    if api_risk_score >= _API_DANGER_CUTOFF:
        _save_to_db(url, domain, "confirmed_phishing", "api_detection", list(set(api_threats)), db)
        return _verdict(
            "dangerous", min(api_risk_score, 100),
            list(set(api_threats)),
            {
                "scoring_system": "api_direct_detection",
                "safe_browsing": sb_result,
                "virustotal": vt_result,
                "phishtank": pt_result,
            },
        )

    # Step 5: ML+도메인 합산 점수 체계 — 미탐지 URL에 대한 보조 신호 분석
    ml_result = ml_predict(url)  # ML은 주력이 아닌 신종 URL 보조 탐지 신호

    sus_threats: list[str] = []
    domain_risk = 0

    if domain_analysis["impersonation_patterns"]:
        sus_threats.append("IMPERSONATION")
        sus_threats.extend(domain_analysis["impersonation_patterns"])
        domain_risk += 45

    if domain_analysis["domain_age"]["is_new_domain"]:
        sus_threats.append("NEW_DOMAIN")
        domain_risk += 25
    elif domain_analysis["domain_age"]["age_days"] is not None:
        if domain_analysis["domain_age"]["age_days"] >= 365:
            domain_risk = max(0, domain_risk - 10)

    if domain_analysis["suspicious_tld"]:
        sus_threats.append("SUSPICIOUS_TLD")
        domain_risk += 15

    for flag in domain_analysis["url_structure_flags"]:
        sus_threats.append(flag)
        domain_risk += 10

    # ML 보조 신호: ml_score ≥ 70일 때만 domain_risk에 가산
    if ml_result and ml_result["ml_score"] >= 70:
        sus_threats.append("ML_PHISHING_DETECTED")
        domain_risk += int(ml_result["ml_score"] * 0.3)

    combined_risk = min(domain_risk, 95)

    details = {
        "scoring_system": "ml_domain_combined",
        "safe_browsing": sb_result,
        "virustotal": vt_result,
        "phishtank": pt_result,
        "domain_analysis": domain_analysis,
        "ml": ml_result,
    }

    # Step 6: combined_risk ≥ 70 → 위험 (ML+도메인 체계)
    if combined_risk >= _ML_DOMAIN_DANGER:
        _save_to_db(url, domain, "confirmed_phishing", "auto_detected", list(set(sus_threats)), db)
        return _verdict("dangerous", combined_risk, list(set(sus_threats)), details)

    # Step 7: combined_risk ≥ 25 → 의심 (ML+도메인 체계)
    if combined_risk >= _ML_DOMAIN_SUSPICIOUS:
        _save_to_db(url, domain, "suspicious", "auto_detected", list(set(sus_threats)), db)
        return _verdict("suspicious", combined_risk, list(set(sus_threats)), details)

    if db_entry and db_entry["category"] in ("suspicious", "user_reported"):
        return _verdict(
            "suspicious", 35,
            db_entry["threat_types"] or ["PREVIOUSLY_FLAGGED"],
            {"source": "internal_db", "db_category": db_entry["category"],
             "safe_browsing": sb_result, "virustotal": vt_result, "phishtank": pt_result},
        )

    # Step 8: 모두 통과 → 안전
    return _verdict("safe", max(api_risk_score, 0), [], details)


def _lookup_db(domain: str, db: Session) -> dict | None:
    site = db.query(MaliciousSite).filter(MaliciousSite.domain == domain).first()
    if site:
        return {
            "category": site.category,
            "source": site.source,
            "threat_types": site.threat_types or [],
            "created_at": site.created_at.isoformat(),
        }
    return None


def _save_to_db(url, domain, category, source, threat_types, db):
    existing = db.query(MaliciousSite).filter(MaliciousSite.domain == domain).first()
    if not existing:
        db.add(MaliciousSite(
            url=url, domain=domain, category=category, source=source,
            threat_types=threat_types,
            confirmed_at=datetime.utcnow() if category == "confirmed_phishing" else None,
        ))
        db.commit()
        return
    if existing.category != "confirmed_phishing" and category == "confirmed_phishing":
        existing.category = "confirmed_phishing"
        existing.source = source
        existing.threat_types = threat_types
        existing.confirmed_at = datetime.utcnow()
        db.commit()


def _verdict(verdict, risk_score, threat_types, details):
    return {"verdict": verdict, "risk_score": risk_score, "threat_types": threat_types, "details": details}
