import httpx
from urllib.parse import urlparse, parse_qs


def _domain(url: str) -> str:
    return urlparse(url).netloc.lower().removeprefix("www.")


# lrl.kr/check/url?r=https://... 같은 중간 리다이렉트 페이지에서
# 실제 목적지 URL을 쿼리 파라미터로 넘기는 패턴 처리
_REDIRECT_PARAMS = ("r", "redirect", "url", "u", "target", "goto", "next", "link", "dest", "to")

def _extract_redirect_from_qs(url: str) -> str | None:
    """쿼리 파라미터 안에 숨은 실제 목적지 URL을 꺼낸다."""
    qs = parse_qs(urlparse(url).query)
    for key in _REDIRECT_PARAMS:
        values = qs.get(key, [])
        if values and values[0].startswith("http"):
            return values[0]
    return None


async def expand_url(url: str, timeout: float = 10.0) -> tuple[str, bool]:
    original_domain = _domain(url)

    async with httpx.AsyncClient(
        follow_redirects=True,
        timeout=timeout,
        headers={"User-Agent": "Mozilla/5.0 (compatible; SafeScanner/1.0)"},
        max_redirects=10,
        verify=False,
    ) as client:

        # 1차: HEAD
        try:
            response = await client.head(url)
            final_url = str(response.url)
            if response.history:
                # 최종 도메인이 다르면 바로 단축링크
                if _domain(final_url) != original_domain:
                    return final_url, True
                # 같은 도메인이지만 쿼리 파라미터에 목적지 URL이 있는 패턴 (ex: lrl.kr/check/url?r=...)
                hidden = _extract_redirect_from_qs(final_url)
                if hidden and _domain(hidden) != original_domain:
                    return hidden, True
        except Exception:
            pass

        # 2차: GET
        try:
            response = await client.get(url)
            final_url = str(response.url)
            if bool(response.history):
                if _domain(final_url) != original_domain:
                    return final_url, True
                hidden = _extract_redirect_from_qs(final_url)
                if hidden and _domain(hidden) != original_domain:
                    return hidden, True
            return final_url, False
        except Exception:
            pass

    return url, False
