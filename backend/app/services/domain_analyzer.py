import asyncio
import ipaddress
import re
import time
from datetime import datetime, timezone
from urllib.parse import urlparse

import httpx

# 유명 브랜드 사칭 패턴 (도메인에서 탐지)
IMPERSONATION_PATTERNS = [
    (r"pay.?pal", "PayPal 사칭"),
    (r"amaz[o0]n", "Amazon 사칭"),
    (r"g[o0]{2}gle", "Google 사칭"),
    (r"app1e|appl[e3]", "Apple 사칭"),
    (r"micr[o0]s[o0]ft", "Microsoft 사칭"),
    (r"faceb[o0]{2}k|facbook", "Facebook 사칭"),
    (r"netfl[i1]x", "Netflix 사칭"),
    (r"[nN]aver(?!\.com)", "Naver 사칭"),
    (r"kaka[o0](?!\.com)", "Kakao 사칭"),
    (r"t[o0]ss(?!\.im)", "Toss 사칭"),
    (r"(shinhan|kookmin|hana|woori|kb|nh).{0,5}bank", "국내 은행 사칭"),
]

SUSPICIOUS_TLDS = {
    ".xyz", ".top", ".click", ".work", ".loan", ".win", ".bid",
    ".download", ".stream", ".gq", ".ml", ".cf", ".tk", ".ga",
    ".buzz", ".monster", ".cyou", ".fun",
}


# ── 도메인 나이 조회 (RDAP) ─────────────────────────────────────────────────
# whois(포트 43)는 응답 없는 서버에서 ~10초씩 블로킹되어 Render 재시작/502의 원인이 되었음.
# RDAP는 등록 정보를 HTTPS + JSON으로 제공하는 IETF 표준(RFC 9083)이라
# 비동기 httpx + 짧은 타임아웃으로 안전하게 조회할 수 있다.
# rdap.org는 TLD별 공식 RDAP 서버로 리다이렉트해 주는 부트스트랩 서비스.
_RDAP_URL = "https://rdap.org/domain/{}"
_RDAP_TIMEOUT = 3.0          # 초. 넘으면 '확인 불가'로 처리 (검사 전체를 지연시키지 않음)
_NEW_DOMAIN_DAYS = 30        # 생성 30일 미만 → 신규 도메인
_RDAP_CACHE_TTL = 6 * 3600   # 같은 도메인 반복 조회 방지 (6시간)
_RDAP_CACHE_MAX = 1000
_rdap_cache: dict[str, tuple[float, str | None]] = {}

# 2단계 공개 접미사 (등록 도메인 추출용). 예: shop.example.co.kr → example.co.kr
_MULTI_PART_SUFFIXES = {
    "co.kr", "or.kr", "go.kr", "ac.kr", "ne.kr", "re.kr", "pe.kr", "mil.kr",
    "hs.kr", "ms.kr", "es.kr", "sc.kr", "kg.kr",
    "co.uk", "org.uk", "ac.uk", "gov.uk", "com.au", "net.au", "org.au",
    "co.jp", "ne.jp", "or.jp", "com.cn", "net.cn", "com.tw", "com.hk",
    "com.br", "co.in", "co.nz",
}

_UNKNOWN_AGE = {"creation_date": None, "age_days": None, "is_new_domain": False}


def registered_domain(domain: str) -> str | None:
    """호스트명에서 RDAP 조회 대상인 등록 도메인을 추출. IP·단일 라벨이면 None."""
    domain = domain.strip(".").lower()
    if not domain:
        return None
    try:
        ipaddress.ip_address(domain)
        return None  # IP 주소는 도메인 등록 정보가 없음
    except ValueError:
        pass
    try:
        domain = domain.encode("idna").decode("ascii")  # 한글 도메인 → punycode
    except UnicodeError:
        return None
    parts = domain.split(".")
    if len(parts) < 2:
        return None
    if len(parts) >= 3 and ".".join(parts[-2:]) in _MULTI_PART_SUFFIXES:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


def _parse_registration_date(data: dict) -> str | None:
    """RDAP 응답의 events 중 registration 일자를 ISO 문자열로 반환."""
    for event in data.get("events", []) or []:
        if str(event.get("eventAction", "")).lower() == "registration" and event.get("eventDate"):
            return str(event["eventDate"])
    return None


def _to_datetime(value: str) -> datetime | None:
    try:
        dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


async def _fetch_rdap_registration(reg_domain: str) -> str | None:
    """RDAP로 도메인 등록일 조회. 실패·타임아웃 시 None (예외를 밖으로 던지지 않음)."""
    now = time.monotonic()
    cached = _rdap_cache.get(reg_domain)
    if cached and now - cached[0] < _RDAP_CACHE_TTL:
        return cached[1]

    async def _get():
        async with httpx.AsyncClient(
            timeout=_RDAP_TIMEOUT, follow_redirects=True, max_redirects=3,
            headers={"Accept": "application/rdap+json, application/json"},
        ) as client:
            return await client.get(_RDAP_URL.format(reg_domain))

    try:
        resp = await asyncio.wait_for(_get(), timeout=_RDAP_TIMEOUT + 0.5)
    except Exception:
        return None  # 타임아웃·네트워크 오류는 캐시하지 않음 (다음 검사 때 재시도)

    created = None
    if resp.status_code == 200:
        try:
            created = _parse_registration_date(resp.json())
        except ValueError:
            created = None
    elif resp.status_code != 404:
        return None  # 429/5xx 등 일시 오류는 캐시하지 않음

    if len(_rdap_cache) >= _RDAP_CACHE_MAX:
        _rdap_cache.pop(next(iter(_rdap_cache)))  # 가장 오래된 항목 제거
    _rdap_cache[reg_domain] = (now, created)
    return created


async def get_domain_age(domain: str) -> dict:
    """도메인 나이 정보 반환: creation_date(ISO), age_days, is_new_domain."""
    reg = registered_domain(domain)
    if not reg:
        return dict(_UNKNOWN_AGE)
    created = await _fetch_rdap_registration(reg)
    created_dt = _to_datetime(created) if created else None
    if not created_dt:
        return dict(_UNKNOWN_AGE)
    age_days = max((datetime.now(timezone.utc) - created_dt).days, 0)
    return {
        "creation_date": created_dt.date().isoformat(),
        "age_days": age_days,
        "is_new_domain": age_days < _NEW_DOMAIN_DAYS,
    }


def extract_domain(url: str) -> str:
    try:
        parsed = urlparse(url if url.startswith("http") else f"http://{url}")
        return parsed.netloc.lower().split(":")[0]
    except Exception:
        return url.lower()


def _check_impersonation(domain: str) -> list[str]:
    return [label for pattern, label in IMPERSONATION_PATTERNS if re.search(pattern, domain, re.I)]


def _check_suspicious_tld(domain: str) -> bool:
    return any(domain.endswith(tld) for tld in SUSPICIOUS_TLDS)


def _check_url_structure(url: str, domain: str) -> list[str]:
    flags = []
    if len(url) > 120:
        flags.append("EXCESSIVE_URL_LENGTH")
    if "@" in url:
        flags.append("AT_SIGN_IN_URL")
    if re.search(r"https?://\d{1,3}(\.\d{1,3}){3}", url):
        flags.append("IP_ADDRESS_URL")
    parts = domain.split(".")
    if len(parts) > 5:
        flags.append("EXCESSIVE_SUBDOMAINS")
    return flags


async def analyze_domain(url: str) -> dict:
    domain = extract_domain(url)
    impersonation = _check_impersonation(domain)
    suspicious_tld = _check_suspicious_tld(domain)
    # 도메인 나이: whois 대신 RDAP(HTTPS) 비동기 조회, 최대 약 3초. 실패 시 '확인 불가'.
    domain_age = await get_domain_age(domain)
    url_flags = _check_url_structure(url, domain)

    is_suspicious = bool(impersonation or suspicious_tld or url_flags or domain_age["is_new_domain"])

    return {
        "domain": domain,
        "is_suspicious": is_suspicious,
        "impersonation_patterns": impersonation,
        "suspicious_tld": suspicious_tld,
        "domain_age": domain_age,
        "url_structure_flags": url_flags,
    }
