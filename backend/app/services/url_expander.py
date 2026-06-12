import asyncio
import ipaddress
import httpx
from urllib.parse import urlparse, parse_qs

# 알려진 단축 URL 서비스 도메인 목록
_SHORTENER_DOMAINS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "buff.ly",
    "short.link", "is.gd", "rb.gy", "cutt.ly", "lnkd.in",
    "youtu.be", "amzn.to", "fb.me", "tiny.cc", "v.gd",
    "han.gl", "me2.do", "lrl.kr", "url.kr", "naver.me", "me2.kr",
}

# lrl.kr/check/url?r=https://... 같은 중간 리다이렉트 페이지에서
# 실제 목적지 URL을 쿼리 파라미터로 넘기는 패턴 처리
_REDIRECT_PARAMS = ("r", "redirect", "url", "u", "target", "goto", "next", "link", "dest", "to")


def _domain(url: str) -> str:
    return urlparse(url).netloc.lower().removeprefix("www.")


def _extract_redirect_from_qs(url: str) -> str | None:
    """쿼리 파라미터 안에 숨은 실제 목적지 URL을 꺼낸다."""
    qs = parse_qs(urlparse(url).query)
    for key in _REDIRECT_PARAMS:
        values = qs.get(key, [])
        if values and values[0].startswith("http"):
            return values[0]
    return None


async def _is_safe_host(url: str) -> bool:
    """SSRF 방지: 사설·루프백·링크-로컬 IP로의 요청을 차단한다.

    서버가 의심 URL을 직접 요청할 때 내부망 탐색(SSRF)에 악용될 수 있으므로,
    127.0.0.1 / 10.x / 172.16.x / 192.168.x / 169.254.x 등을 차단한다.

    DNS 조회는 비동기(getaddrinfo) + 타임아웃으로 수행한다.
    동기 socket.gethostbyname()은 존재하지 않는 도메인(NXDOMAIN)에서
    이벤트 루프 전체를 수십 초간 블로킹할 수 있기 때문이다.
    """
    try:
        host = urlparse(url).hostname
        if not host:
            return False
        loop = asyncio.get_event_loop()
        infos = await asyncio.wait_for(loop.getaddrinfo(host, None), timeout=2.0)
        resolved = infos[0][4][0]
        addr = ipaddress.ip_address(resolved)
        if addr.is_private or addr.is_loopback or addr.is_link_local or addr.is_reserved:
            return False
    except Exception:
        pass  # DNS 실패/타임아웃 시 httpx 레벨에서 추가 차단됨
    return True


def is_shortener(url: str) -> bool:
    """알려진 단축 URL 서비스 도메인인지 확인한다."""
    domain = _domain(url)
    return any(domain == d or domain.endswith("." + d) for d in _SHORTENER_DOMAINS)


async def expand_url(url: str, timeout: float = 3.0) -> tuple[str, bool]:
    """단축 URL 또는 리다이렉트 체인을 따라 최종 URL을 반환한다.

    Returns:
        (final_url, is_shortened):
            is_shortened=True  → 단축링크였고 최종 URL 추적 완료
            is_shortened=False → 단축링크가 아니거나 추적 불가
    """
    original_domain = _domain(url)

    # SSRF 방지: 내부망 URL이면 즉시 반환
    if not await _is_safe_host(url):
        return url, False

    async with httpx.AsyncClient(
        follow_redirects=True,
        timeout=timeout,
        headers={"User-Agent": "Mozilla/5.0 (compatible; SafeScanner/1.0)"},
        max_redirects=10,
    ) as client:

        # 1차: HEAD (본문 다운로드 없이 헤더·최종 URL만 취득)
        try:
            response = await client.head(url)
            # 리다이렉트 체인 중 내부망 IP로 유도되면 차단
            for r in response.history:
                if not await _is_safe_host(str(r.url)):
                    return url, False
            final_url = str(response.url)
            if response.history:
                if _domain(final_url) != original_domain:
                    return final_url, True
                hidden = _extract_redirect_from_qs(final_url)
                if hidden and _domain(hidden) != original_domain:
                    return hidden, True
        except Exception:
            pass

        # 2차: GET
        try:
            response = await client.get(url)
            for r in response.history:
                if not await _is_safe_host(str(r.url)):
                    return url, False
            final_url = str(response.url)
            if response.history:
                if _domain(final_url) != original_domain:
                    return final_url, True
                hidden = _extract_redirect_from_qs(final_url)
                if hidden and _domain(hidden) != original_domain:
                    return hidden, True
            return final_url, False
        except Exception:
            pass

    return url, False
