"""Google Safe Browsing API 연동 서비스.

⚠ 라이선스 주의:
  - Safe Browsing API (v4/v5)는 비상업적 용도 전용이다.
  - 상업적 서비스화 시 유료 Web Risk API(cloud.google.com/web-risk)로 전환해야 한다.
  - v4는 deprecated 상태이며 공식 후속은 v5. 코드는 v5 우선, 실패 시 v4 폴백 구조.
"""

import httpx
from app.config import settings

SB_V5_URL = "https://safebrowsing.googleapis.com/v5alpha1/urls:search"
SB_V4_URL = "https://safebrowsing.googleapis.com/v4/threatMatches:find"


async def check_safe_browsing(url: str) -> dict:
    """Google Safe Browsing API로 URL 검사. v5alpha1 우선, 실패 시 v4 폴백.
    API 키 없으면 스킵."""
    if not settings.google_safe_browsing_api_key:
        return {"is_safe": True, "threats": [], "skipped": True}

    result = await _check_v5(url)
    if result is not None:
        return result

    return await _check_v4(url)


async def _check_v5(url: str) -> dict | None:
    """v5alpha1: GET 방식, $alt=json으로 JSON 강제."""
    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            resp = await client.get(
                SB_V5_URL,
                params={
                    "key": settings.google_safe_browsing_api_key,
                    "urls": url,
                    "$alt": "json",
                },
            )

        # API 키 오류 등 클라이언트 에러 → v4로 폴백
        if resp.status_code == 400:
            return None

        data = resp.json()

        # v5 응답: matches 배열에 threatTypes 포함
        # 위협 없으면 {} 또는 {"matches": []}
        matches = data.get("matches", [])
        if matches:
            threats = []
            for m in matches:
                threats.extend(m.get("threatTypes", []))
            return {
                "is_safe": False,
                "threats": list(set(threats)),
                "source": "google_safe_browsing_v5",
                "matches": matches,
            }

        return {"is_safe": True, "threats": [], "source": "google_safe_browsing_v5"}

    except Exception:
        return None  # 예외 시 v4로 폴백


async def _check_v4(url: str) -> dict:
    """v4: POST 방식 폴백."""
    payload = {
        "client": {"clientId": "malicious-site-detector", "clientVersion": "1.0.0"},
        "threatInfo": {
            "threatTypes": [
                "MALWARE",
                "SOCIAL_ENGINEERING",
                "UNWANTED_SOFTWARE",
                "POTENTIALLY_HARMFUL_APPLICATION",
            ],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}],
        },
    }

    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            resp = await client.post(
                f"{SB_V4_URL}?key={settings.google_safe_browsing_api_key}",
                json=payload,
            )
            data = resp.json()

        if "matches" in data and data["matches"]:
            threats = [m["threatType"] for m in data["matches"]]
            return {"is_safe": False, "threats": threats, "source": "google_safe_browsing_v4"}

        return {"is_safe": True, "threats": [], "source": "google_safe_browsing_v4"}

    except Exception as e:
        return {"is_safe": True, "threats": [], "error": str(e), "source": "google_safe_browsing_v4"}
