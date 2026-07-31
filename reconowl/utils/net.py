"""HTTP client and URL helpers used by native checks.

A thin wrapper over ``requests`` with sane defaults (timeouts, no verify errors
aborting a scan, a shared session, optional rate limiting) plus small URL
utilities so every phase treats targets consistently.
"""

from __future__ import annotations

import collections
import random
import threading
import time
import urllib.parse
from dataclasses import dataclass, field

import requests
import urllib3

# Scanning frequently hits hosts with bad/self-signed certs; that is data, not a
# reason to abort. Silence the noise and never verify by default.
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


@dataclass
class HttpResponse:
    """A normalized view of an HTTP response (or a failed attempt)."""

    url: str
    ok: bool
    status: int | None = None
    headers: dict[str, str] = None  # type: ignore[assignment]
    text: str = ""
    error: str = ""
    elapsed: float = 0.0
    final_url: str = ""
    # What was actually sent — used to build per-finding proof.
    request_method: str = "GET"
    request_headers: dict[str, str] = field(default_factory=dict)
    request_body: str = ""

    def header(self, name: str) -> str:
        if not self.headers:
            return ""
        for key, value in self.headers.items():
            if key.lower() == name.lower():
                return value
        return ""


class HttpClient:
    """A shared, polite HTTP client for native checks."""

    def __init__(
        self,
        *,
        timeout: float = 12.0,
        user_agent: str = "reconowl/0.3",
        rate_limit: float = 0.0,
        max_bytes: int = 2_000_000,
        headers: dict[str, str] | None = None,
        adaptive: bool = True,
        jitter: float = 0.0,
    ) -> None:
        self.timeout = timeout
        self.max_bytes = max_bytes
        self._session = requests.Session()
        self._session.headers.update({"User-Agent": user_agent})
        # Auth headers (bearer/cookie/custom) ride on every request; per-request
        # headers passed to request() are merged on top of these.
        if headers:
            self._session.headers.update(headers)
        self._min_interval = 1.0 / rate_limit if rate_limit > 0 else 0.0
        self._last = 0.0
        self._lock = threading.Lock()
        # Adaptive backoff: watch a rolling window of outcomes and slow down when
        # the target starts blocking/rate-limiting.
        self.adaptive = adaptive
        self.jitter = jitter
        self._recent: collections.deque[str] = collections.deque(maxlen=25)
        self.was_throttled = False
        self.throttle_events = 0
        #: After sustained blocking, stop hammering and fast-skip requests.
        self.gave_up = False

    def _throttle(self) -> None:
        if self.jitter > 0:
            time.sleep(random.uniform(0, self.jitter))
        if self._min_interval <= 0:
            return
        with self._lock:
            wait = self._min_interval - (time.monotonic() - self._last)
            if wait > 0:
                time.sleep(wait)
            self._last = time.monotonic()

    def _record(self, kind: str) -> None:
        """Record a request outcome and back off if blocks/errors spike."""
        if not self.adaptive:
            return
        with self._lock:
            self._recent.append(kind)
            if len(self._recent) < self._recent.maxlen:
                return
            bad = sum(1 for k in self._recent if k != "ok")
            if bad / len(self._recent) >= 0.5:
                self._min_interval = min(max(self._min_interval * 2, 0.4), 2.0)
                self.was_throttled = True
                self.throttle_events += 1
                self._recent.clear()
                if self.throttle_events >= 2:
                    # The target is persistently blocking — stop hammering it.
                    self.gave_up = True

    @staticmethod
    def _classify(status: int | None, ok: bool) -> str:
        if not ok:
            return "error"
        if status in (403, 406, 429, 503, 509):
            return "block"
        return "ok"

    def request(
        self,
        method: str,
        url: str,
        *,
        allow_redirects: bool = True,
        headers: dict[str, str] | None = None,
        data: str | None = None,
    ) -> HttpResponse:
        if self.gave_up:
            return HttpResponse(url=url, ok=False, error="skipped: target blocking",
                                request_method=method)
        self._throttle()
        start = time.monotonic()
        try:
            resp = self._session.request(
                method,
                url,
                timeout=self.timeout,
                allow_redirects=allow_redirects,
                verify=False,
                headers=headers,
                data=data,
                stream=True,
            )
            body = resp.raw.read(self.max_bytes, decode_content=True) or b""
            text = body.decode(resp.encoding or "utf-8", errors="replace")
            self._record(self._classify(resp.status_code, True))
            return HttpResponse(
                url=url,
                ok=True,
                status=resp.status_code,
                headers=dict(resp.headers),
                text=text,
                elapsed=time.monotonic() - start,
                final_url=str(resp.url),
                request_method=method,
                request_headers=dict(headers or {}),
                request_body=data or "",
            )
        except requests.RequestException as exc:
            self._record("error")
            return HttpResponse(
                url=url, ok=False, error=str(exc), elapsed=time.monotonic() - start,
                request_method=method, request_headers=dict(headers or {}), request_body=data or "",
            )
        finally:
            try:
                resp.close()  # type: ignore[has-type]
            except Exception:  # noqa: BLE001
                pass

    def get(self, url: str, **kwargs) -> HttpResponse:
        return self.request("GET", url, **kwargs)

    def head(self, url: str, **kwargs) -> HttpResponse:
        return self.request("HEAD", url, **kwargs)


def build_client(config, timeout: float | None = None) -> HttpClient:
    """Construct an HttpClient carrying the run's auth headers/cookie."""
    return HttpClient(
        timeout=timeout if timeout is not None else config.timeout,
        user_agent=config.user_agent,
        rate_limit=config.rate_limit,
        headers=config.build_headers(),
        adaptive=getattr(config, "adaptive", True),
        jitter=getattr(config, "jitter", 0.0),
    )


_SENSITIVE_HEADERS = {"cookie", "authorization", "x-api-key", "proxy-authorization"}


def build_proof(resp: HttpResponse, max_body: int = 1500) -> dict[str, str]:
    """Render a request/response pair for a finding's evidence (auth redacted)."""
    req = [f"{resp.request_method} {resp.url}"]
    for k, v in (resp.request_headers or {}).items():
        req.append(f"{k}: {'[redacted]' if k.lower() in _SENSITIVE_HEADERS else v}")
    if resp.request_body:
        req.append("")
        req.append(resp.request_body[:800])

    res = [f"HTTP {resp.status if resp.status is not None else resp.error}"]
    for k, v in (resp.headers or {}).items():
        res.append(f"{k}: {'[redacted]' if k.lower() == 'set-cookie' else v}")
    body = (resp.text or "")[:max_body]
    if body:
        res.append("")
        res.append(body)

    return {"request": "\n".join(req), "response": "\n".join(res)}


# --- URL helpers ----------------------------------------------------------- #
def normalize_scheme_host(raw: str) -> tuple[str, str]:
    """Return ``(scheme, host)`` for a raw target; default scheme https."""
    raw = raw.strip()
    if "://" not in raw:
        raw = "https://" + raw
    parts = urllib.parse.urlsplit(raw)
    return (parts.scheme or "https"), parts.netloc.split("@")[-1]


def base_url(scheme: str, host: str) -> str:
    return f"{scheme}://{host}"


def join(base: str, path: str) -> str:
    return urllib.parse.urljoin(base if base.endswith("/") else base + "/", path.lstrip("/"))


def same_host(url: str, host: str) -> bool:
    return urllib.parse.urlsplit(url).netloc.split(":")[0].lower() == host.lower()


# Common multi-label public suffixes (second-level registries) where the
# registrable domain is the *last three* labels, e.g. ``insuyu.com.tr`` or
# ``bbc.co.uk``. Not the full PSL, but covers the ccTLDs seen in practice so
# scope filtering and email-auth lookups target the real registrable domain.
_MULTI_LABEL_SUFFIXES = {
    # Turkey
    "com.tr", "net.tr", "org.tr", "edu.tr", "gov.tr", "bel.tr", "pol.tr",
    "mil.tr", "k12.tr", "av.tr", "dr.tr", "gen.tr", "web.tr", "biz.tr",
    "info.tr", "name.tr", "tv.tr", "bbs.tr",
    # United Kingdom
    "co.uk", "org.uk", "gov.uk", "ac.uk", "me.uk", "net.uk", "ltd.uk",
    "plc.uk", "sch.uk", "nhs.uk",
    # Australia / NZ
    "com.au", "net.au", "org.au", "edu.au", "gov.au", "id.au",
    "co.nz", "org.nz", "net.nz", "govt.nz", "ac.nz",
    # Japan / Korea / China / Taiwan / HK / Singapore
    "co.jp", "ne.jp", "or.jp", "go.jp", "ac.jp",
    "co.kr", "or.kr", "go.kr", "com.cn", "net.cn", "org.cn", "gov.cn",
    "com.tw", "com.hk", "com.sg", "com.my", "com.ph", "com.vn",
    # Americas
    "com.br", "net.br", "org.br", "gov.br", "com.mx", "com.ar", "com.co",
    "com.pe", "com.ve", "co.cr",
    # Europe / Middle East / Africa / India
    "co.in", "net.in", "org.in", "gov.in", "ac.in", "co.za", "org.za",
    "co.il", "com.sa", "com.eg", "com.ua", "com.ru", "com.pl", "com.gr",
    "com.es", "com.pk", "com.ng", "com.kw", "com.qa", "com.lb",
}


def apex_domain(host: str) -> str:
    """Best-effort registrable domain (eTLD+1).

    Returns the last two labels, or the last three when the last two form a
    known multi-label public suffix (e.g. ``com.tr`` -> ``insuyu.com.tr``).
    """
    parts = host.lower().strip(".").split(".")
    if len(parts) < 2:
        return host.lower()
    if len(parts) >= 3 and ".".join(parts[-2:]) in _MULTI_LABEL_SUFFIXES:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


def in_scope(url: str, target_host: str) -> bool:
    """True if ``url``'s host is the target or a sibling under its apex domain.

    Keeps active payloads from ever reaching unrelated hosts pulled in from a
    sitemap, archive, or third-party link.
    """
    host = urllib.parse.urlsplit(url).netloc.split("@")[-1].split(":")[0].lower()
    if not host:
        return False
    target = target_host.lower()
    apex = apex_domain(target)
    return host == target or host == apex or host.endswith("." + apex)
