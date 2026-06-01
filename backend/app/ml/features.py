"""
URL 피처 추출 모듈

25개 피처를 추출하여 ML 모델의 입력값으로 사용.
규칙 기반(domain_analyzer.py)과 달리, 순수 수치 피처만 추출.
"""

import math
import re
from urllib.parse import urlparse, parse_qs

SUSPICIOUS_TLDS = {
    ".xyz", ".top", ".click", ".work", ".loan", ".win", ".bid",
    ".download", ".stream", ".gq", ".ml", ".cf", ".tk", ".ga",
    ".buzz", ".monster", ".cyou", ".fun", ".pw", ".cc", ".su",
}

BRAND_KEYWORDS = [
    "paypal", "amazon", "google", "apple", "microsoft", "facebook",
    "naver", "kakao", "toss", "shinhan", "kookmin", "hana", "woori",
    "netflix", "instagram", "twitter", "youtube", "samsung", "lg",
]


def _shannon_entropy(s: str) -> float:
    """문자열의 Shannon 엔트로피 (높을수록 무작위적 = 의심스러움)"""
    if not s:
        return 0.0
    freq = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    length = len(s)
    return -sum((f / length) * math.log2(f / length) for f in freq.values())


def _vowel_ratio(s: str) -> float:
    """도메인 내 모음 비율 (너무 낮으면 DGA 의심)"""
    if not s:
        return 0.0
    vowels = sum(1 for c in s.lower() if c in "aeiou아에이오우")
    alpha = sum(1 for c in s if c.isalpha())
    return vowels / alpha if alpha > 0 else 0.0


def _max_consecutive_consonants(s: str) -> int:
    """최대 연속 자음 수 (DGA 도메인 탐지용)"""
    vowels = set("aeiou")
    max_run = cur = 0
    for c in s.lower():
        if c.isalpha() and c not in vowels:
            cur += 1
            max_run = max(max_run, cur)
        else:
            cur = 0
    return max_run


def extract(url: str) -> list[float]:
    """
    URL → 25개 수치 피처 리스트 반환.
    순서가 모델 학습 시와 동일해야 함.
    """
    url = url.strip()
    if not url.startswith(("http://", "https://")):
        url = "http://" + url

    try:
        parsed = urlparse(url)
    except Exception:
        return [0.0] * 25

    full_url = url
    domain = parsed.netloc.lower().split(":")[0]
    path = parsed.path or ""
    query = parsed.query or ""

    # 서브도메인 분리 (마지막 2개 = 등록 도메인)
    domain_parts = domain.split(".")
    registered_domain = ".".join(domain_parts[-2:]) if len(domain_parts) >= 2 else domain
    subdomains = domain_parts[:-2] if len(domain_parts) > 2 else []

    # TLD
    tld = "." + domain_parts[-1] if domain_parts else ""

    features = [
        # 1. URL 전체 길이
        float(len(full_url)),

        # 2. 도메인 길이
        float(len(domain)),

        # 3. 경로 길이
        float(len(path)),

        # 4. 쿼리 문자열 길이
        float(len(query)),

        # 5. 점(.) 개수
        float(full_url.count(".")),

        # 6. 하이픈(-) 개수
        float(full_url.count("-")),

        # 7. @ 기호 포함 여부
        1.0 if "@" in full_url else 0.0,

        # 8. IP 주소 직접 사용 여부
        1.0 if re.search(r"https?://\d{1,3}(\.\d{1,3}){3}", full_url) else 0.0,

        # 9. HTTPS 사용 여부 (안전 신호)
        1.0 if parsed.scheme == "https" else 0.0,

        # 10. 포트 명시 여부
        1.0 if parsed.port else 0.0,

        # 11. 서브도메인 depth
        float(len(subdomains)),

        # 12. 경로 depth (슬래시 수)
        float(path.count("/")),

        # 13. 쿼리 파라미터 개수
        float(len(parse_qs(query))),

        # 14. URL 내 숫자 비율
        sum(1.0 for c in full_url if c.isdigit()) / max(len(full_url), 1),

        # 15. URL 특수문자 개수 (?, =, &, %, #, ! 등)
        float(sum(1 for c in full_url if c in "?=&#!~")),

        # 16. 퍼센트 인코딩(%xx) 개수
        float(full_url.count("%")),

        # 17. URL 전체 Shannon 엔트로피
        _shannon_entropy(full_url),

        # 18. 등록 도메인 Shannon 엔트로피
        _shannon_entropy(registered_domain.replace(".", "")),

        # 19. 도메인 내 모음 비율
        _vowel_ratio(registered_domain),

        # 20. 최대 연속 자음 수 (DGA 탐지)
        float(_max_consecutive_consonants(registered_domain)),

        # 21. 의심 TLD 여부
        1.0 if tld in SUSPICIOUS_TLDS else 0.0,

        # 22. 브랜드 키워드 포함 여부 (사칭 탐지)
        1.0 if any(kw in domain for kw in BRAND_KEYWORDS) else 0.0,

        # 23. 브랜드 키워드가 등록 도메인이 아닌 서브도메인에만 있는지
        #     (예: paypal.evil.com → subdomain에 paypal, 등록도메인은 evil.com)
        1.0 if (
            any(kw in ".".join(subdomains) for kw in BRAND_KEYWORDS)
            and not any(kw in registered_domain for kw in BRAND_KEYWORDS)
        ) else 0.0,

        # 24. 이중 슬래시(//) 비정상 사용 (http:// 제외)
        float(max(full_url.replace("://", "___").count("//"), 0)),

        # 25. URL 내 'redirect', 'login', 'secure', 'account' 등 민감 키워드 수
        float(sum(1 for kw in ["redirect", "login", "secure", "account", "verify", "update", "confirm"]
                  if kw in full_url.lower())),
    ]

    return features


FEATURE_NAMES = [
    "url_length", "domain_length", "path_length", "query_length",
    "num_dots", "num_hyphens", "has_at_sign", "has_ip_address",
    "has_https", "has_port", "subdomain_depth", "path_depth",
    "num_query_params", "digit_ratio", "num_special_chars",
    "num_percent_encoding", "url_entropy", "domain_entropy",
    "vowel_ratio", "max_consecutive_consonants", "suspicious_tld",
    "has_brand_keyword", "brand_in_subdomain_only",
    "double_slash_count", "sensitive_keyword_count",
]
