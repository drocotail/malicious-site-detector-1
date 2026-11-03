import asyncio
import ipaddress
import logging
import re
from html import unescape
from urllib.parse import urljoin, urlparse, parse_qs

import httpx

logger = logging.getLogger(__name__)

# 알려진 단축 URL 서비스 도메인 목록
_SHORTENER_DOMAINS = {
    # 해외
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "buff.ly",
    "short.link", "is.gd", "rb.gy", "cutt.ly", "lnkd.in",
    "youtu.be", "amzn.to", "fb.me", "tiny.cc", "v.gd",
    "t.ly", "shorturl.at", "rebrand.ly", "s.id", "bl.ink", "tiny.one",
    # 국내
    "han.gl", "me2.do", "lrl.kr", "url.kr", "naver.me", "me2.kr",
    "buly.kr", "vo.la", "c11.kr", "zrr.kr",
}

# lrl.kr/check/url?r=https://... 같은 중간 리다이렉트 페이지에서
# 실제 목적지 URL을 쿼리 파라미터로 넘기는 패턴 처리
_REDIRECT_PARAMS = ("r", "redirect", "url", "u", "target", "goto", "next", "link", "dest", "to")

_TIMEOUT = 5.0          # 요청 1회 제한 시간(초). 해외(Render) → 국내 서버 지연 대비 3 → 5초
_MAX_HOPS = 10          # 리다이렉트 최대 추적 횟수
_MAX_BODY = 64 * 1024   # 페이지 내 이동 주소를 찾을 때 읽는 최대 본문 크기 (64KB)
_REDIRECT_CODES = {301, 302, 303, 307, 308}

# 일부 단축 서비스는 봇처럼 보이는 요청(예: 'SafeScanner/1.0')을 차단하거나 응답하지 않으므로
# 일반 브라우저와 같은 헤더로 요청한다. (페이지 내용은 실행하지 않고 주소·헤더만 읽음)
_BROWSER_HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36"
    ),
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "ko-KR,ko;q=0.9,en-US;q=0.8,en;q=0.7",
}

# 페이지 안에서 이동시키는 방식(HTTP 리다이렉트가 아닌 경우) 탐지 패턴
_META_REFRESH_RE = re.compile(
    r"""<meta[^>]+http-equiv\s*=\s*["']?refresh["']?[^>]*content\s*=\s*["'][^"']*?url\s*=\s*['"]?([^"'>\s]+)""",
    re.I,
)
_META_REFRESH_RE2 = re.compile(  # content 속성이 http-equiv보다 앞에 오는 경우
    r"""<meta[^>]+content\s*=\s*["'][^"']*?url\s*=\s*['"]?([^"'>\s]+)[^>]*http-equiv\s*=\s*["']?refresh""",
    re.I,
)
# 중간 안내(인터스티셜) 페이지: "이동하려는 URL: https://..." 처럼 목적지를 글로 보여주고
# '바로가기' 버튼을 눌러야 이동하는 방식 (예: url.kr의 '사이트 안전성 체크' 페이지)
_LABELED_DEST_RE = re.compile(
    r"(?:이동하려는\s*URL|이동할\s*(?:주소|URL)|목적지|원본\s*(?:주소|URL)|연결(?:될|할)\s*(?:주소|URL)"
    r"|destination|redirecting\s+to|you\s+are\s+being\s+redirected)"
    r"[\s\S]{0,400}?(https?://[^\s<>\"']+)",
    re.I,
)
_GO_BUTTON_RE = re.compile(
    r"""<a\b[^>]*href\s*=\s*["'](https?://[^"']+)["'][^>]*>(?:(?!</a>)[\s\S]){0,300}?"""
    r"""(?:바로\s*가기|바로\s*이동|이동하기|계속\s*하기|사이트로\s*이동|continue|proceed|go\s+to|visit)""",
    re.I,
)
# 안내 페이지에 함께 있는 광고·운영사 링크는 목적지 후보에서 제외
_NOISE_DOMAINS = (
    "kakao.com", "doubleclick.net", "googlesyndication.com", "google.com", "googletagmanager.com",
    "coupang.com", "link.coupang.com", "facebook.com", "twitter.com", "instagram.com", "webworks.co.kr",
)

_JS_REDIRECT_RE = re.compile(
    r"""(?:window\.|document\.|top\.|self\.)?location(?:\.href)?\s*=\s*["']([^"']+)["']"""
    r"""|location\.(?:replace|assign)\(\s*["']([^"']+)["']\s*\)""",
    re.I,
)


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


def _extract_in_page_redirect(html: str, base_url: str) -> str | None:
    """HTML 본문에서 meta refresh / JavaScript location 이동 주소를 찾는다 (실행하지 않고 문자열로만 읽음)."""
    for pattern in (_META_REFRESH_RE, _META_REFRESH_RE2):
        m = pattern.search(html)
        if m:
            target = urljoin(base_url, unescape(m.group(1)).strip())
            if target.startswith(("http://", "https://")):
                return target
    for m in _JS_REDIRECT_RE.finditer(html):
        raw = m.group(1) or m.group(2)
        target = urljoin(base_url, unescape(raw).strip())
        if target.startswith(("http://", "https://")) and _domain(target) != _domain(base_url):
            return target
    # 중간 안내 페이지: "이동하려는 URL" 같은 표시 문구 뒤의 주소 → '바로가기' 버튼 링크 순서로 확인
    for pattern in (_LABELED_DEST_RE, _GO_BUTTON_RE):
        for m in pattern.finditer(html):
            target = unescape(m.group(1)).strip().rstrip(".,);")
            if _is_candidate(target, base_url):
                return target
    return None


def _is_candidate(target: str, base_url: str) -> bool:
    """안내 페이지에서 찾은 주소가 실제 목적지 후보인지 (자기 도메인·광고·운영사 링크 제외)."""
    d = _domain(target)
    if not d or d == _domain(base_url):
        return False
    return not any(d == n or d.endswith("." + n) for n in _NOISE_DOMAINS)


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
        for info in infos:  # 여러 IP가 반환되면 모두 검사
            addr = ipaddress.ip_address(info[4][0])
            if addr.is_private or addr.is_loopback or addr.is_link_local or addr.is_reserved:
                return False
    except Exception:
        pass  # DNS 실패/타임아웃 시 실제 요청 단계에서 실패 처리됨
    return True


def is_shortener(url: str) -> bool:
    """알려진 단축 URL 서비스 도메인인지 확인한다."""
    domain = _domain(url)
    return any(domain == d or domain.endswith("." + d) for d in _SHORTENER_DOMAINS)


class _Blocked(Exception):
    """리다이렉트 경로에 내부망 주소가 포함됨."""


async def _follow(client: httpx.AsyncClient, url: str, method: str) -> tuple[str, int, str | None]:
    """리다이렉트를 한 단계씩 따라가며, 매 단계 요청 '전에' SSRF 검사를 한다.

    Returns: (최종 URL, 최종 상태 코드, HTML 본문 일부 또는 None)
    """
    current = url
    for _ in range(_MAX_HOPS + 1):
        if not await _is_safe_host(current):
            raise _Blocked(current)
        if method == "HEAD":
            resp = await client.head(current)
            body = None
        else:
            async with client.stream("GET", current) as resp:
                body = None
                if resp.status_code not in _REDIRECT_CODES and "html" in resp.headers.get("content-type", ""):
                    chunks, size = [], 0
                    async for chunk in resp.aiter_bytes():
                        chunks.append(chunk)
                        size += len(chunk)
                        if size >= _MAX_BODY:
                            break
                    body = b"".join(chunks)[:_MAX_BODY].decode(resp.encoding or "utf-8", errors="ignore")
        location = resp.headers.get("location")
        if resp.status_code in _REDIRECT_CODES and location:
            current = urljoin(current, location)
            continue
        return current, resp.status_code, body
    return current, 0, None  # 리다이렉트 과다


async def expand_url(url: str, timeout: float = _TIMEOUT) -> tuple[str, bool]:
    """단축 URL 또는 리다이렉트 체인을 따라 최종 URL을 반환한다.

    Returns:
        (final_url, is_shortened):
            is_shortened=True  → 단축링크였고 최종 URL 추적 완료
            is_shortened=False → 단축링크가 아니거나 추적 불가
    """
    original_domain = _domain(url)
    shortener = is_shortener(url)

    def judge(final: str | None) -> str | None:
        """최종 URL이 처음 도메인과 다르면 해석 성공으로 본다."""
        if not final:
            return None
        if _domain(final) != original_domain:
            return final
        hidden = _extract_redirect_from_qs(final)
        if hidden and _domain(hidden) != original_domain:
            return hidden
        return None

    def fail(reason: str) -> tuple[str, bool]:
        if shortener:
            logger.warning("[단축링크 해석 실패] %s — %s", original_domain, reason)
        return url, False

    # SSRF 방지: 내부망 URL이면 즉시 반환
    if not await _is_safe_host(url):
        return fail("내부망 주소")

    async with httpx.AsyncClient(follow_redirects=False, timeout=timeout, headers=_BROWSER_HEADERS) as client:
        # 1차: HEAD (본문 다운로드 없이 헤더·최종 URL만 취득)
        head_status = None
        try:
            final, head_status, _ = await _follow(client, url, "HEAD")
            result = judge(final)
            if result:
                return result, True
        except _Blocked as b:
            return fail(f"리다이렉트 경로에 내부망 주소 포함 ({_domain(str(b))})")
        except httpx.TimeoutException:
            return fail(f"응답 시간 초과 ({timeout:.0f}초)")  # 응답 없는 서버에 GET 재시도는 시간만 낭비
        except Exception as e:
            head_status = f"HEAD 오류: {type(e).__name__}"

        # 2차: GET (HEAD를 거부하는 서비스 대비 + 페이지 안의 이동 주소 확인용 본문 확보)
        try:
            final, status, body = await _follow(client, url, "GET")
        except _Blocked as b:
            return fail(f"리다이렉트 경로에 내부망 주소 포함 ({_domain(str(b))})")
        except httpx.TimeoutException:
            return fail(f"응답 시간 초과 ({timeout:.0f}초)")
        except Exception as e:
            return fail(f"GET 오류: {type(e).__name__} (HEAD: {head_status})")

        result = judge(final)
        if result:
            return result, True

        # 3차: 페이지 안의 이동(meta refresh / JavaScript) — 알려진 단축 서비스에만 적용
        # (일반 사이트의 JS 이동을 단축링크로 오인하지 않도록)
        if shortener and body:
            target = _extract_in_page_redirect(body, final)
            if target:
                if not await _is_safe_host(target):
                    return fail(f"페이지 내 이동 주소가 내부망 ({_domain(target)})")
                try:
                    target_final, _, _ = await _follow(client, target, "HEAD")
                except Exception:
                    target_final = target  # 목적지가 HEAD에 응답하지 않아도 주소 자체는 확보됨
                result = judge(target_final) or judge(target)
                if result:
                    return result, True

        if status == 0:
            return fail(f"리다이렉트가 {_MAX_HOPS}회를 넘음 (반복 이동)")
        if status in (401, 403, 429):
            return fail(f"접근 차단 (HTTP {status}) — 해외/봇 요청 차단 가능성")
        return fail(f"목적지를 찾지 못함 (HTTP {status})")
