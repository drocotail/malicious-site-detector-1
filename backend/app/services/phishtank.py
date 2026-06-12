"""PhishTank + OpenPhish 피싱 URL 조회 서비스.

PhishTank는 2020년부터 신규 API 키 발급이 중단된 상태이므로,
API 호출 실패(403/401/509) 또는 예외 발생 시 OpenPhish 피드로 자동 폴백한다.
OpenPhish: https://openphish.com/feed.txt (무료, 비상업 조건)
"""

import asyncio
import base64
import time
import httpx

from app.config import settings

PHISHTANK_ENDPOINT = "https://checkurl.phishtank.com/checkurl/"
OPENPHISH_FEED = "https://openphish.com/feed.txt"

# OpenPhish 피드 인메모리 캐시 (TTL: 1시간)
_openphish_cache: set[str] = set()
_openphish_last_update: float = 0.0
_CACHE_TTL = 3600
_refresh_lock = asyncio.Lock()


async def _refresh_openphish() -> None:
    global _openphish_cache, _openphish_last_update
    async with _refresh_lock:
        if time.time() - _openphish_last_update < _CACHE_TTL:
            return
        try:
            async with httpx.AsyncClient(timeout=4.0) as client:
                resp = await client.get(OPENPHISH_FEED)
            if resp.status_code == 200:
                _openphish_cache = {
                    line.strip() for line in resp.text.splitlines() if line.strip()
                }
                _openphish_last_update = time.time()
        except Exception:
            pass


async def _check_openphish(url: str) -> dict:
    """OpenPhish 피드에서 URL 조회 (PhishTank 폴백)."""
    await _refresh_openphish()
    is_phishing = url in _openphish_cache
    return {
        "available": True,
        "source": "openphish",
        "in_database": is_phishing,
        "verified": is_phishing,
        "valid": is_phishing,
        "is_phishing": is_phishing,
    }


async def check_phishtank(url: str) -> dict:
    """PhishTank API로 URL 피싱 여부 확인. 사용 불가 시 OpenPhish 폴백.

    Returns:
        available: API/피드 조회 성공 여부
        source: 'phishtank' 또는 'openphish'
        in_database: DB에 등록된 URL인지
        verified: 검증된 제보인지
        valid: 현재 유효한 피싱 URL인지
        is_phishing: in_database AND verified AND valid 모두 true일 때만 true
    """
    encoded_url = base64.b64encode(url.encode("utf-8")).decode("ascii")
    payload = {"url": encoded_url, "format": "json"}
    if settings.phishtank_app_key:
        payload["app_key"] = settings.phishtank_app_key

    try:
        async with httpx.AsyncClient(timeout=4.0) as client:
            resp = await client.post(
                PHISHTANK_ENDPOINT,
                data=payload,
                headers={"User-Agent": "phishtank/malicious-site-detector"},
            )

        # 키 미발급/사용 불가(403/401) 또는 Rate limit(509) → OpenPhish 폴백
        if resp.status_code in (401, 403, 509):
            return await _check_openphish(url)
        if resp.status_code != 200:
            return await _check_openphish(url)

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
            "source": "phishtank",
            "in_database": in_database,
            "verified": verified,
            "valid": valid,
            "phish_id": results.get("phish_id"),
            "is_phishing": in_database and verified and valid,
        }

    except Exception:
        return await _check_openphish(url)
