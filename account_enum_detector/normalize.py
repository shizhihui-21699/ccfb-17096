"""Response normalization used to separate dynamic noise from stable differences."""
from __future__ import annotations

import hashlib
import html as html_lib
import json
import re
from typing import Any, Iterable
from collections.abc import Mapping

UUID_RE = re.compile(
    r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b"
)
JWT_RE = re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b")
LONG_HEX_RE = re.compile(r"\b[a-fA-F0-9]{16,}\b")
LONG_BASE64_RE = re.compile(r"\b[A-Za-z0-9+/_-]{24,}={0,2}\b")
ISO_TIME_RE = re.compile(r"\b\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?\b")
DATE_RE = re.compile(r"\b(?:Mon|Tue|Wed|Thu|Fri|Sat|Sun),\s+\d{1,2}\s+[A-Za-z]{3}\s+\d{4}\s+\d{2}:\d{2}:\d{2}\s+GMT\b")
GENERIC_DATE_RE = re.compile(r"\b\d{4}/\d{1,2}/\d{1,2}(?:\s+\d{1,2}:\d{2}(?::\d{2})?)?\b")
NUMBER_TIME_RE = re.compile(r"\b1[0-9]{9}(?:\.[0-9]+)?\b|\b1[0-9]{12}(?:\.[0-9]+)?\b")

DYNAMIC_JSON_KEY_RE = re.compile(
    r"(?ix)^(?:.*?(?:csrf|xsrf|token|nonce|timestamp|request[_-]?id|trace[_-]?id|span[_-]?id|"
    r"session[_-]?id|signature|sig|jti|expires?_at|issued_at|date|time).*?)$"
)

DYNAMIC_HEADERS = {
    "date",
    "x-request-id",
    "x-correlation-id",
    "x-trace-id",
    "traceparent",
    "tracestate",
    "cf-ray",
    "x-amzn-trace-id",
    "x-cloud-trace-context",
    "x-akamai-request-id",
    "x-served-by",
    "x-cache",
    "x-cache-hits",
    "age",
    "report-to",
    "nel",
}

MAX_NORMALIZED_BODY = 20_000


def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8", "replace")).hexdigest()


def _account_pattern(accounts: Iterable[str]) -> re.Pattern[str] | None:
    values = sorted({re.escape(a) for a in accounts if a}, key=len, reverse=True)
    if not values:
        return None
    return re.compile("|".join(values))


def scrub_dynamic_strings(value: str, accounts: Iterable[str] | re.Pattern[str] | None = None) -> str:
    """Replace request-specific values so equivalent responses compare equal."""
    if not isinstance(value, str):
        value = str(value)

    pattern = accounts
    if pattern is not None and not isinstance(pattern, re.Pattern):
        pattern = _account_pattern(pattern)
    if pattern is not None:
        value = pattern.sub("<account>", value)

    value = JWT_RE.sub("<jwt>", value)
    value = UUID_RE.sub("<uuid>", value)
    value = ISO_TIME_RE.sub("<datetime>", value)
    value = DATE_RE.sub("<http-date>", value)
    value = GENERIC_DATE_RE.sub("<date>", value)
    value = NUMBER_TIME_RE.sub("<epoch>", value)
    value = LONG_HEX_RE.sub("<hex>", value)
    value = LONG_BASE64_RE.sub("<token>", value)
    return value


def _scrub_json_obj(obj: Any, account_pattern: re.Pattern[str] | None) -> Any:
    if isinstance(obj, Mapping):
        result = {}
        for key, val in obj.items():
            key_s = str(key)
            if DYNAMIC_JSON_KEY_RE.match(key_s):
                # Keep the dynamic key name stable; replace its value.
                result[key_s] = "<dynamic>"
            else:
                # Account-derived JSON object keys are request-specific too.
                stable_key = scrub_dynamic_strings(key_s, account_pattern)
                result[stable_key] = _scrub_json_obj(val, account_pattern)
        return result
    if isinstance(obj, list):
        return [_scrub_json_obj(v, account_pattern) for v in obj]
    if isinstance(obj, str):
        return scrub_dynamic_strings(obj, account_pattern)
    return obj


def normalize_body(body: str | bytes | None, accounts: Iterable[str] = ()) -> str:
    if body is None:
        return ""
    if isinstance(body, bytes):
        body = body.decode("utf-8", "replace")

    account_pattern = _account_pattern(accounts)
    text = body.replace("\r\n", "\n").replace("\r", "\n")

    # Common CSRF/hidden-token markup before generic token scrubbing.
    text = re.sub(
        r'(?is)(<input[^>]+name=["\'][^"\']*(?:csrf|xsrf|token|nonce)[^"\']*["\'][^>]+value=["\'])[^"\']*(["\'])',
        r"\1<token>\2",
        text,
    )
    text = re.sub(
        r'(?is)(<input[^>]+value=["\'])[^"\']*(["\'][^>]+name=["\'][^"\']*(?:csrf|xsrf|token|nonce))',
        r"\1<token>\2",
        text,
    )

    stripped = text.strip()
    if stripped and stripped[0] in "{[":
        try:
            obj = json.loads(stripped)
            obj = _scrub_json_obj(obj, account_pattern)
            normalized = json.dumps(obj, ensure_ascii=False, indent=2, sort_keys=True)
            return normalized[:MAX_NORMALIZED_BODY]
        except (json.JSONDecodeError, TypeError, ValueError):
            pass

    if re.search(r"(?is)<!doctype\s+html|<html\b|<body\b|<div\b|<form\b", text):
        text = re.sub(r"(?is)<(script|style|noscript|svg)[^>]*>.*?</\1>", " ", text)
        text = re.sub(r"(?is)<!--.*?-->", " ", text)
        text = re.sub(r"(?s)<[^>]+>", "\n", text)
        text = html_lib.unescape(text)

    text = scrub_dynamic_strings(text, account_pattern)
    # Normalize HTML-adjacent whitespace without joining message-bearing lines too aggressively.
    text = re.sub(r"[ \t\f\v]+", " ", text)
    text = re.sub(r"\n{3,}", "\n\n", text)
    return text.strip()[:MAX_NORMALIZED_BODY]


def _normalize_set_cookie(value: str) -> str:
    first_pair = value.split(";", 1)[0].strip()
    name = first_pair.split("=", 1)[0].strip()
    return f"{name}=<dynamic>" if name else "<dynamic-cookie>"


def normalize_headers(
    header_items: Iterable[tuple[str, str]], accounts: Iterable[str] = ()
) -> dict[str, str]:
    account_pattern = _account_pattern(accounts)
    grouped: dict[str, list[str]] = {}
    for raw_name, raw_value in header_items:
        name = raw_name.lower()
        value = raw_value or ""
        if name == "set-cookie":
            value = _normalize_set_cookie(value)
        elif name in DYNAMIC_HEADERS:
            value = "<dynamic>"
        else:
            value = scrub_dynamic_strings(value, account_pattern).strip()
        grouped.setdefault(name, []).append(value)

    normalized: dict[str, str] = {}
    for name, values in grouped.items():
        values = sorted(set(values))
        normalized[name] = values[0] if len(values) == 1 else "\n".join(values)
    return dict(sorted(normalized.items()))


def header_signature(normalized_headers: Mapping[str, str]) -> str:
    canonical = "\n".join(f"{k}: {v}" for k, v in normalized_headers.items())
    return sha256_text(canonical)
