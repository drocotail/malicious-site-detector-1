import re
import asyncio
import socket
from datetime import datetime
from urllib.parse import urlparse

import whois

# whois 라이브러리는 소켓에 자체 타임아웃을 설정하지 않아,
# 응답 없는 WHOIS 서버에 무한정 블로킹될 수 있다.
# (프로세스가 멈춰 Render에서 OOM/헬스체크로 재시작되는 원인이 됨)
socket.setdefaulttimeout(2.0)

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


def _check_domain_age(domain: str) -> dict:
    try:
        info = whois.whois(domain)
        created = info.creation_date
        if isinstance(created, list):
            created = created[0]
        if created:
            age_days = (datetime.now() - created).days
            return {
                "creation_date": created.isoformat(),
                "age_days": age_days,
                "is_new_domain": age_days < 30,
            }
    except Exception:
        pass
    return {"creation_date": None, "age_days": None, "is_new_domain": False}


async def _check_domain_age_async(domain: str) -> dict:
    loop = asyncio.get_event_loop()
    try:
        result = await asyncio.wait_for(
            loop.run_in_executor(None, _check_domain_age, domain),
            timeout=3.0
        )
        return result
    except asyncio.TimeoutError:
        return {"creation_date": None, "age_days": None, "is_new_domain": False}


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
    domain_age = await _check_domain_age_async(domain)
    url_flags = _check_url_structure(url, domain)

    is_suspicious = bool(impersonation or suspicious_tld or domain_age["is_new_domain"] or url_flags)

    return {
        "domain": domain,
        "is_suspicious": is_suspicious,
        "impersonation_patterns": impersonation,
        "suspicious_tld": suspicious_tld,
        "domain_age": domain_age,
        "url_structure_flags": url_flags,
    }
