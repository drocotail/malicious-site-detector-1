import base64
import httpx
from app.config import settings

VT_BASE = "https://www.virustotal.com/api/v3"


def _url_id(url: str) -> str:
    return base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")


async def check_virustotal(url: str) -> dict:
    """VirusTotal API로 URL 검사. API 키 없으면 스킵."""
    if not settings.virustotal_api_key:
        return {
            "is_safe": True,
            "threats": [],
            "malicious_count": 0,
            "total_engines": 0,
            "skipped": True,
            "source": "virustotal",
        }

    headers = {"x-apikey": settings.virustotal_api_key}

    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.get(f"{VT_BASE}/urls/{_url_id(url)}", headers=headers)

            if resp.status_code == 404:
                # 처음 보는 URL → 분석 요청
                submit = await client.post(f"{VT_BASE}/urls", headers=headers, data={"url": url})
                if submit.status_code != 200:
                    return _empty_result()
                analysis_id = submit.json()["data"]["id"]
                resp = await client.get(f"{VT_BASE}/analyses/{analysis_id}", headers=headers)

            data = resp.json()

        attrs = data.get("data", {}).get("attributes", {})
        stats = attrs.get("last_analysis_stats", {})
        malicious = stats.get("malicious", 0)
        suspicious_vt = stats.get("suspicious", 0)
        total = sum(stats.values()) or 1

        threats = []
        if malicious or suspicious_vt:
            categories = attrs.get("categories", {})
            threats = list(set(categories.values())) if categories else ["malware"]

        return {
            "is_safe": malicious == 0 and suspicious_vt == 0,
            "threats": threats,
            "malicious_count": malicious,
            "suspicious_count": suspicious_vt,
            "total_engines": total,
            "source": "virustotal",
        }

    except Exception as e:
        return {**_empty_result(), "error": str(e)}


def _empty_result() -> dict:
    return {
        "is_safe": True,
        "threats": [],
        "malicious_count": 0,
        "total_engines": 0,
        "source": "virustotal",
    }
