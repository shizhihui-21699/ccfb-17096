"""HTTP transport with timing capture and no automatic redirects."""
from __future__ import annotations

import gzip
import http.client
import ssl
import time
import urllib.error
import urllib.request
import zlib
from dataclasses import dataclass, field

from .payload import _replace_tokens, _template_values


@dataclass
class ResponseData:
    requested_url: str
    status: int | None = None
    ok: bool = False
    error: str | None = None
    error_type: str | None = None
    ttfb_ms: float | None = None
    total_ms: float | None = None
    body: bytes = b""
    header_items: list[tuple[str, str]] = field(default_factory=list)


class NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # type: ignore[no-untyped-def]
        # Returning None causes urllib to surface the 3xx as an HTTPError,
        # which contains the status and Location header we need.
        return None


def _maybe_decompress(raw: bytes, header_items: list[tuple[str, str]]) -> bytes:
    encoding = ""
    for name, value in header_items:
        if name.lower() == "content-encoding":
            encoding = (value or "").lower()
            break
    try:
        if "gzip" in encoding:
            return gzip.decompress(raw)
        if "deflate" in encoding:
            try:
                return zlib.decompress(raw)
            except zlib.error:
                return zlib.decompress(raw, -zlib.MAX_WBITS)
    except (OSError, EOFError, zlib.error):
        return raw
    return raw


class HttpSender:
    def __init__(
        self,
        timeout: float = 15.0,
        proxy: str | None = None,
        insecure: bool = False,
        max_body_bytes: int = 1_048_576,
    ) -> None:
        self.timeout = timeout
        self.max_body_bytes = max_body_bytes
        handlers: list[urllib.request.BaseHandler] = [NoRedirectHandler()]
        if proxy:
            handlers.append(urllib.request.ProxyHandler({"http": proxy, "https": proxy}))
        if insecure:
            context = ssl._create_unverified_context()  # noqa: S323 - explicit opt-in for lab/Burp
            handlers.append(urllib.request.HTTPSHandler(context=context))
        self.opener = urllib.request.build_opener(*handlers)

    def send(
        self,
        url: str,
        method: str,
        headers: dict[str, str],
        body: bytes | None,
    ) -> ResponseData:
        req = urllib.request.Request(url=url, data=body, method=method.upper(), headers=headers)
        start = time.perf_counter()
        try:
            resp = self.opener.open(req, timeout=self.timeout)
            ttfb = (time.perf_counter() - start) * 1000.0
            header_items = list(resp.headers.items())
            raw = resp.read(self.max_body_bytes)
            resp.close()
            raw = _maybe_decompress(raw, header_items)
            total = (time.perf_counter() - start) * 1000.0
            return ResponseData(
                requested_url=url,
                status=getattr(resp, "status", resp.getcode()),
                ok=True,
                ttfb_ms=ttfb,
                total_ms=total,
                body=raw or b"",
                header_items=header_items,
            )
        except urllib.error.HTTPError as exc:
            # The server returned an HTTP status; these are valuable evidence.
            ttfb = (time.perf_counter() - start) * 1000.0
            try:
                raw = exc.read(self.max_body_bytes)
            except Exception:  # pragma: no cover - defensive socket handling
                raw = b""
            finally:
                exc.close()
            total = (time.perf_counter() - start) * 1000.0
            header_items = list(exc.headers.items()) if exc.headers else []
            raw = _maybe_decompress(raw, header_items)
            return ResponseData(
                requested_url=url,
                status=exc.code,
                ok=True,
                ttfb_ms=ttfb,
                total_ms=total,
                body=raw or b"",
                header_items=header_items,
            )
        except (
            urllib.error.URLError,
            TimeoutError,
            OSError,
            EOFError,
            http.client.HTTPException,
        ) as exc:
            total = (time.perf_counter() - start) * 1000.0
            reason = getattr(exc, "reason", exc)
            return ResponseData(
                requested_url=url,
                ok=False,
                error=str(reason),
                error_type=type(reason).__name__ if not isinstance(reason, str) else type(exc).__name__,
                total_ms=total,
            )

    def render_url(self, url: str, account: str, password: str | None, index: int) -> str:
        values = _template_values(account, password, index)
        # URL placeholders are query/path values, so encode the account token.
        values = dict(values)
        from urllib.parse import quote

        values["account"] = quote(account, safe="")
        if password is not None:
            values["password"] = quote(password, safe="")
        return _replace_tokens(url, values)
