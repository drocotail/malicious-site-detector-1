import re
from urllib.parse import urlparse

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
    # whois 조회는 응답 없는 서버에서 ~10초씩 블로킹되어 Render 인스턴스를
    # OOM/재시작시키는 원인이 되어 제거함. domain_age는 항상 미확인으로 처리.
    domain_age = {"creation_date": None, "age_days": None, "is_new_domain": False}
    url_flags = _check_url_structure(url, domain)

    is_suspicious = bool(impersonation or suspicious_tld or url_flags)

    return {
        "domain": domain,
        "is_suspicious": is_suspicious,
        "impersonation_patterns": impersonation,
        "suspicious_tld": suspicious_tld,
        "domain_age": domain_age,
        "url_structure_flags": url_flags,
    }
