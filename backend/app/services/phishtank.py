import base64
import httpx
from app.config import settings

PHISHTANK_ENDPOINT = "https://checkurl.phishtank.com/checkurl/"


async def check_phishtank(url: str) -> dict:
    """PhishTank API로 URL이 피싱 사이트인지 확인.

    Returns:
        available: API 호출 성공 여부
        in_database: PhishTank DB에 등록된 URL인지
        verified: 검증된 제보인지
        valid: 현재 유효한 피싱 URL인지 (핵심 판단 기준)
        is_phishing: in_database AND verified AND valid 모두 true일 때만 true
    """
    encoded_url = base64.b64encode(url.encode("utf-8")).decode("ascii")
    payload = {"url": encoded_url, "format": "json"}
    if settings.phishtank_app_key:
        payload["app_key"] = settings.phishtank_app_key

    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.post(
                PHISHTANK_ENDPOINT,
                data=payload,
                headers={"User-Agent": "phishtank/malicious-site-detector"},
            )

        if resp.status_code == 509:
            return {"available": False, "skipped": False, "error": "rate_limited", "is_phishing": False}

        if resp.status_code != 200:
            return {"available": False, "skipped": False, "error": f"http_{resp.status_code}", "is_phishing": False}

        data = resp.json()
        results = data.get("results", {})

        def to_bool(v):
            if isinstance(v, bool):
                return v
            return str(v).lower() in {"true", "yes", "1"}

        in_database = to_bool(results.get("in_database", False))
        verified = to_bool(results.get("verified", False))
        valid = to_bool(results.get("valid", False))

        return {
            "available": True,
            "in_database": in_database,
            "verified": verified,
            "valid": valid,
            "phish_id": results.get("phish_id"),
            "is_phishing": in_database and verified and valid,
        }

    except Exception as e:
        return {"available": False, "skipped": False, "error": str(e), "is_phishing": False}
