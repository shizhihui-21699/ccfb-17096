#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
授权场景下的账号枚举差异检测器。

只使用 Python 标准库。设计目标：
- 顺序、低速、熔断，避免触发限流/验证码/账号锁定；
- 使用“一个已知存在样本 + 一个同形态不存在样本”的配对；
- 比较状态码、响应体、稳定响应头和响应时间；
- 输出 JSON/Markdown 证据报告。

警告：没有任何工具能保证“绝不触发锁定”。登录接口应优先使用专门申请的测试账号，
并先确认锁定阈值、IP 限流和告警策略。
"""
from __future__ import annotations

import argparse
import difflib
import hashlib
import itertools
import json
import math
import os
import random
import re
import secrets
import ssl
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from statistics import median
from typing import Any

TOOL_NAME = "AccountEnumDetector/1.1"

DEFAULT_STOP_PATTERNS = [
    "too many requests", "too many attempts", "rate limit", "rate-limited",
    "try again later", "temporarily unavailable",
    "captcha required", "invalid captcha", "enter captcha",
    "account has been locked", "account is locked", "account temporarily locked",
    "user is locked", "user has been locked",
    "账号已锁定", "账户已锁定", "账号已被锁定", "账户已被锁定",
    "多次密码错误", "密码错误次数过多", "尝试次数过多",
    "操作过于频繁", "请求过于频繁", "操作频繁", "请稍后再试",
    "请完成验证码", "请输入验证码", "验证码错误", "验证码失效",
]

DEFAULT_STOP_STATUSES = [423, 429, 503]

IGNORE_HEADER_KEYS = {
    "date", "age", "connection", "keep-alive", "transfer-encoding", "te",
    "trailer", "upgrade", "proxy-authenticate", "proxy-authorization",
}

VOLATILE_HEADER_PARTS = (
    "request-id", "requestid", "trace-id", "traceid", "correlation",
    "cf-ray", "server-timing", "x-runtime", "x-response-time",
    "amzn-trace-id", "via",
)

CACHE_HEADER_KEYS = {
    "age", "x-cache", "cf-cache-status", "x-cache-lookup",
    "x-proxy-cache", "x-drupal-cache",
}

VOLATILE_JSON_KEYS = {
    "timestamp", "time", "date", "datetime", "ts", "_ts", "requestid", "request_id",
    "traceid", "trace_id", "correlationid", "correlation_id", "nonce",
    "jti", "token", "accesstoken", "access_token", "refreshtoken",
    "refresh_token", "csrftoken", "csrf_token", "_csrf", "signature", "sig",
}

SENSITIVE_KEY_PARTS = (
    "password", "passwd", "pwd", "pass", "mima", "secret", "token",
    "credential", "authorization", "cookie", "set-cookie", "captcha",
    "otp", "mfa", "signature", "sig", "apikey", "api_key",
)

INTERESTING_FIELD_PARTS = (
    "message", "msg", "error", "reason", "code", "status", "tip", "hint",
    "errmsg", "err_msg", "description",
)


class CliError(Exception):
    """用法或安全门禁错误。"""


# ---------------------------------------------------------------------------
# 基础工具
# ---------------------------------------------------------------------------

def now_iso() -> str:
    return datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds")


def read_account_file(path: str | Path) -> list[str]:
    p = Path(path)
    values: list[str] = []
    for line in p.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            values.append(line)
    return values


def dedupe_keep_order(values: list[str]) -> list[str]:
    seen: set[str] = set()
    out = []
    for value in values:
        value = value.strip()
        if value and value not in seen:
            seen.add(value)
            out.append(value)
    return out


def mask_account(account: str) -> str:
    if "@" in account:
        local, domain = account.rsplit("@", 1)
        head = local[0] if local else "?"
        return f"{head}***@{domain}"
    if len(account) <= 2:
        return account[0] + "***" if account else "***"
    if len(account) <= 5:
        return account[0] + "***"
    return f"{account[:2]}***{account[-1:]}"


def display_account(account: str, show: bool) -> str:
    return account if show else mask_account(account)


def is_sensitive_key(key: str) -> bool:
    low = key.lower().replace("-", "_")
    return any(part in low for part in SENSITIVE_KEY_PARTS)


def redact_obj(obj: Any) -> Any:
    if isinstance(obj, dict):
        return {
            k: ("<redacted>" if is_sensitive_key(str(k)) else redact_obj(v))
            for k, v in obj.items()
        }
    if isinstance(obj, list):
        return [redact_obj(v) for v in obj]
    return obj


def parse_kv(text: str, separator: str = "=") -> tuple[str, str]:
    if separator in text:
        k, v = text.split(separator, 1)
    elif ":" in text:
        k, v = text.split(":", 1)
    else:
        raise CliError(f"参数必须是 key=value 或 Key: value 形式：{text}")
    return k.strip(), v.strip()


def account_variants(account: str) -> set[str]:
    variants = {account}
    try:
        variants.add(urllib.parse.quote(account, safe=""))
        variants.add(urllib.parse.quote_plus(account))
    except Exception:
        pass
    return {v for v in variants if v}


def replace_accounts(text: str, accounts: list[str], replacement: str = "<account>") -> str:
    if not text:
        return ""
    for account in sorted(accounts, key=len, reverse=True):
        for variant in account_variants(account):
            text = text.replace(variant, replacement)
    return text


_UUID_RE = re.compile(
    r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-"
    r"[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b"
)
_JWT_RE = re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b")
_HEX_RE = re.compile(r"\b[a-fA-F0-9]{16,}\b")
_LONG_TOKEN_RE = re.compile(r"\b[A-Za-z0-9+_=-]{28,}\b")
_VOLATILE_QUERY_RE = re.compile(
    r"([?&](?:token|signature|sig|auth|key|request_id|requestid|trace_id|traceid|nonce|t)=)"
    r"[^&\s\"'<>]+",
    re.IGNORECASE,
)


_ANSI_ESCAPE_RE = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]")
_CONTROL_CHARS_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")


def clean_evidence_text(text: str) -> str:
    """移除目标响应中的 ANSI/终端控制字符，避免查看报告时影响终端。"""
    if not text:
        return ""
    text = _ANSI_ESCAPE_RE.sub("", text)
    return _CONTROL_CHARS_RE.sub("", text)


def normalize_text(text: str, accounts: list[str]) -> str:
    """去除账号回显和常见一次性 ID，保留业务 code/message。"""
    if not text:
        return ""
    text = clean_evidence_text(text)
    text = text.replace("\r\n", "\n").replace("\r", "\n")
    text = replace_accounts(text, accounts)
    text = _JWT_RE.sub("<jwt>", text)
    text = _UUID_RE.sub("<uuid>", text)
    text = _HEX_RE.sub("<hex>", text)
    text = _LONG_TOKEN_RE.sub("<token>", text)
    text = _VOLATILE_QUERY_RE.sub(r"\1<volatile>", text)
    text = re.sub(r"[ \t]+", " ", text)
    text = re.sub(r"\n{3,}", "\n\n", text)
    return text.strip()


def canonical_text(text: str, accounts: list[str]) -> str:
    return re.sub(r"\s+", " ", normalize_text(text, accounts)).strip()


def looks_dynamic_scalar(value: str) -> bool:
    if _UUID_RE.fullmatch(value) or _JWT_RE.fullmatch(value):
        return True
    if _HEX_RE.fullmatch(value) and len(value) >= 16:
        return True
    if _LONG_TOKEN_RE.fullmatch(value):
        return True
    return False


def sanitize_json(obj: Any, accounts: list[str], key: str | None = None) -> Any:
    if isinstance(obj, dict):
        return {k: sanitize_json(v, accounts, str(k)) for k, v in obj.items()}
    if isinstance(obj, list):
        return [sanitize_json(v, accounts, key) for v in obj]
    if isinstance(obj, str):
        value = clean_evidence_text(replace_accounts(obj, accounts))
        if key and key.lower() in VOLATILE_JSON_KEYS:
            return "<volatile>"
        if looks_dynamic_scalar(value):
            return "<volatile-pattern>"
        return value
    if key and key.lower() in VOLATILE_JSON_KEYS and isinstance(obj, (int, float)):
        return "<volatile>"
    return obj


def stable_json_hash(body: str, accounts: list[str]) -> str | None:
    try:
        obj = json.loads(body)
    except Exception:
        return None
    clean = sanitize_json(obj, accounts)
    encoded = json.dumps(clean, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(encoded).hexdigest()


def flatten_json(obj: Any, prefix: str = "$") -> dict[str, str]:
    out: dict[str, str] = {}

    def walk(value: Any, path: str) -> None:
        if isinstance(value, dict):
            for k, v in value.items():
                child = f"{path}.{k}" if path != "$" else f"$.{k}"
                walk(v, child)
        elif isinstance(value, list):
            for i, v in enumerate(value[:50]):
                walk(v, f"{path}[{i}]")
        elif value is None or isinstance(value, (str, int, float, bool)):
            out[path] = "" if value is None else str(value)

    walk(obj, prefix)
    return out


# ---------------------------------------------------------------------------
# 不存在样本生成：尽量保持与已知账号相同的长度和字符形态
# ---------------------------------------------------------------------------

def _same_shape(text: str, rng: random.Random) -> str:
    alphabet_lower = "abcdefghijkmnpqrstuvwxyz"
    alphabet_upper = alphabet_lower.upper()
    digits = "23456789"
    out = []
    for ch in text:
        if ch.islower():
            out.append(rng.choice(alphabet_lower))
        elif ch.isupper():
            out.append(rng.choice(alphabet_upper))
        elif ch.isdigit():
            out.append(rng.choice(digits))
        elif ch in "._-+":
            out.append(ch)
        else:
            out.append(rng.choice(alphabet_lower))
    return "".join(out)


def generate_nonexisting_control(existing: str, rng: random.Random, existing_set: set[str]) -> str:
    # 不自动生成手机号/纯数字 ID：随机号码可能属于真实用户。
    if re.fullmatch(r"\+?[\d\s-]{5,}", existing) and any(ch.isdigit() for ch in existing):
        digits = re.sub(r"\D", "", existing)
        if len(digits) >= 6:
            raise CliError(
                "检测到手机号/数字型账号。为避免生成可能属于真实用户的号码，"
                "请用 --nonexisting/--nonexisting-file 提供已确认未注册的控制样本。"
            )

    for _ in range(20):
        if "@" in existing:
            local, domain = existing.rsplit("@", 1)
            if len(local) < 6:
                raise CliError(
                    f"邮箱本地段 {mask_account(existing)} 过短，自动同形态随机样本碰撞概率较高；"
                    "请用 --nonexisting/--nonexisting-file 提供长度和域名匹配、已确认未注册的样本。"
                )
            candidate_local = _same_shape(local, rng)
            candidate = f"{candidate_local}@{domain}"
        else:
            if len(existing) < 6:
                raise CliError(
                    f"账号 {mask_account(existing)} 过短，自动同形态随机样本碰撞概率较高；"
                    "请用 --nonexisting/--nonexisting-file 提供长度和字符形态匹配、已确认不存在的样本。"
                )
            candidate = _same_shape(existing, rng)
        if candidate != existing and candidate not in existing_set:
            return candidate
    return f"enum_audit_{secrets.token_hex(8)}"


# ---------------------------------------------------------------------------
# 请求构造与发送
# ---------------------------------------------------------------------------

def load_body_template(path: str | None) -> Any:
    if not path:
        return None
    p = Path(path)
    text = p.read_text(encoding="utf-8")
    if p.suffix.lower() == ".json":
        return json.loads(text)
    return text


def render_template(obj: Any, account: str) -> Any:
    if isinstance(obj, str):
        return obj.replace("{{account}}", account).replace("{{ACCOUNT}}", account)
    if isinstance(obj, dict):
        return {k: render_template(v, account) for k, v in obj.items()}
    if isinstance(obj, list):
        return [render_template(v, account) for v in obj]
    return obj


def build_request(args: argparse.Namespace, account: str) -> tuple[str, bytes | None, dict[str, str]]:
    url = args.url
    headers = dict(args.header_map)
    method = args.method.upper()
    data: bytes | None = None

    params = dict(args.param_list)

    if args.format == "query":
        query = dict(urllib.parse.parse_qsl(urllib.parse.urlsplit(url).query, keep_blank_values=True))
        query.update(params)
        if args.field:
            query[args.field] = account
        parts = urllib.parse.urlsplit(url)
        url = urllib.parse.urlunsplit((
            parts.scheme, parts.netloc, parts.path,
            urllib.parse.urlencode(query), parts.fragment,
        ))
        if method in {"POST", "PUT", "PATCH"} and "Content-Type" not in headers:
            headers["Content-Type"] = "application/x-www-form-urlencoded"
        return url, None, headers

    if args.body_template is not None:
        rendered = render_template(args.body_template, account)
        if args.format == "raw" or isinstance(rendered, str):
            data = rendered.encode("utf-8")
            headers.setdefault("Content-Type", "text/plain; charset=utf-8")
        elif args.format == "form":
            if not isinstance(rendered, dict) or any(isinstance(v, (dict, list)) for v in rendered.values()):
                raise CliError("form 模板必须是值均为标量的扁平 JSON 对象；嵌套结构请改用 json 格式")
            form_data = {
                k: ("true" if v is True else "false" if v is False else "" if v is None else v)
                for k, v in rendered.items()
            }
            data = urllib.parse.urlencode(form_data).encode("utf-8")
            headers.setdefault("Content-Type", "application/x-www-form-urlencoded")
        else:
            data = json.dumps(rendered, ensure_ascii=False).encode("utf-8")
            headers.setdefault("Content-Type", "application/json; charset=utf-8")
        return url, data, headers

    body: dict[str, Any] = dict(params)
    if args.field:
        body[args.field] = account

    if args.format == "json":
        data = json.dumps(body, ensure_ascii=False).encode("utf-8")
        headers.setdefault("Content-Type", "application/json; charset=utf-8")
    elif args.format == "form":
        data = urllib.parse.urlencode(body).encode("utf-8")
        headers.setdefault("Content-Type", "application/x-www-form-urlencoded")
    elif args.format == "raw":
        raw = args.raw_body or ""
        data = raw.replace("{{account}}", account).encode("utf-8")
        headers.setdefault("Content-Type", "text/plain; charset=utf-8")
    return url, data, headers


class NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    """保留 3xx 和 Location，不自动跟随重定向。"""

    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: D401
        return None


def build_opener(args: argparse.Namespace) -> urllib.request.OpenerDirector:
    handlers: list[urllib.request.BaseHandler] = [NoRedirectHandler()]
    if args.insecure:
        ctx = ssl._create_unverified_context()
        handlers.append(urllib.request.HTTPSHandler(context=ctx))
    if args.proxy:
        handlers.append(urllib.request.ProxyHandler({"http": args.proxy, "https": args.proxy}))
    return urllib.request.build_opener(*handlers)


def read_limited(resp: Any, limit: int) -> tuple[bytes, int, bool]:
    chunks: list[bytes] = []
    kept = 0
    seen = 0
    truncated = False
    while True:
        chunk = resp.read(65536)
        if not chunk:
            break
        seen += len(chunk)
        if kept < limit:
            take = chunk[: max(0, limit - kept)]
            chunks.append(take)
            kept += len(take)
        if kept >= limit:
            truncated = True
            break
    return b"".join(chunks), seen, truncated


def cache_header_hint(header_items: list[tuple[str, str]]) -> dict[str, str]:
    hint = {}
    for k, v in header_items:
        if k.lower() in CACHE_HEADER_KEYS:
            hint[k.lower()] = v[:120]
    return hint


def normalize_header_signature(header_items: list[tuple[str, str]], accounts: list[str]) -> dict[str, str]:
    raw: dict[str, list[tuple[str, str]]] = {}
    for k, v in header_items:
        raw.setdefault(k.lower(), []).append((k, v))

    signature: dict[str, str] = {}
    for key, pairs in raw.items():
        if key in IGNORE_HEADER_KEYS:
            continue
        if any(part in key for part in VOLATILE_HEADER_PARTS):
            continue
        if key == "set-cookie":
            names = sorted({v.split("=", 1)[0].strip() for _, v in pairs if "=" in v})
            signature[key] = "cookie-names:" + ",".join(names)
            continue

        values = []
        for _, value in pairs:
            value = replace_accounts(value, accounts)
            if key == "location":
                parts = urllib.parse.urlsplit(value)
                query = urllib.parse.parse_qsl(parts.query, keep_blank_values=True)
                query = [
                    (k, "<volatile>" if k.lower() in VOLATILE_JSON_KEYS else replace_accounts(v, accounts))
                    for k, v in query
                ]
                value = urllib.parse.urlunsplit((
                    parts.scheme, parts.netloc, parts.path,
                    urllib.parse.urlencode(query), parts.fragment,
                ))
            else:
                value = normalize_text(value, accounts)
            values.append(value[:300])
        signature[key] = " || ".join(sorted(set(values)))
    return signature


def scan_stop_signals(
    status: int | None,
    header_items: list[tuple[str, str]],
    body_text: str,
    patterns: list[str],
    statuses: list[int],
) -> list[str]:
    found: list[str] = []
    if status in statuses:
        found.append(f"HTTP {status}")
    haystack_headers = "\n".join(f"{k}: {v}" for k, v in header_items)
    haystack = (haystack_headers + "\n" + body_text[:20000]).lower()
    for pattern in patterns:
        if pattern.lower() in haystack:
            found.append(pattern)
    return sorted(set(found))


def send_one(
    opener: urllib.request.OpenerDirector,
    args: argparse.Namespace,
    account: str,
    role: str,
    pair_id: int,
    order: int,
    all_accounts: list[str],
) -> dict[str, Any]:
    url, data, headers = build_request(args, account)
    headers.setdefault("User-Agent", TOOL_NAME)
    headers.setdefault("Accept", "application/json, text/plain;q=0.9, */*;q=0.8")
    req = urllib.request.Request(url, data=data, headers=headers, method=args.method.upper())

    sample: dict[str, Any] = {
        "pair_id": pair_id,
        "role": role,
        "account": account,
        "order": order,
        "url": url,
        "status": None,
        "elapsed_ms": None,
        "error": None,
        "body_text": "",
        "body_sha256": None,
        "body_bytes": 0,
        "truncated": False,
        "header_signature": {},
        "cache_headers": {},
        "stop_signals": [],
    }

    started = time.perf_counter()
    resp = None
    try:
        try:
            resp = opener.open(req, timeout=args.timeout)
            status = getattr(resp, "status", None) or resp.getcode()
            header_items = list(resp.headers.items()) if resp.headers else []
            body, seen, truncated = read_limited(resp, args.max_response_bytes)
        except urllib.error.HTTPError as exc:
            status = exc.code
            header_items = list(exc.headers.items()) if exc.headers else []
            try:
                body, seen, truncated = read_limited(exc, args.max_response_bytes)
            except Exception:
                body, seen, truncated = b"", 0, False
        sample["elapsed_ms"] = (time.perf_counter() - started) * 1000.0
        sample["status"] = status
        sample["body_bytes"] = len(body)
        sample["bytes_seen"] = seen
        sample["truncated"] = truncated
        sample["body_sha256"] = hashlib.sha256(body).hexdigest()
        body_text = body.decode("utf-8", errors="replace")
        sample["body_text"] = body_text
        sample["header_signature"] = normalize_header_signature(header_items, all_accounts)
        sample["cache_headers"] = cache_header_hint(header_items)
        sample["stop_signals"] = scan_stop_signals(
            status, header_items, body_text, args.stop_patterns_effective, args.stop_statuses_effective
        )
    except Exception as exc:  # 网络错误不自动重试：超时请求可能已被服务端处理
        sample["elapsed_ms"] = (time.perf_counter() - started) * 1000.0
        sample["error"] = f"{type(exc).__name__}: {exc}"
    finally:
        if resp is not None:
            try:
                resp.close()
            except Exception:
                pass
    return sample


# ---------------------------------------------------------------------------
# 统计：稳健描述统计、配对 bootstrap、符号翻转置换检验、Cliff's delta
# ---------------------------------------------------------------------------

def quantile(sorted_values: list[float], q: float) -> float | None:
    if not sorted_values:
        return None
    if len(sorted_values) == 1:
        return float(sorted_values[0])
    pos = (len(sorted_values) - 1) * q
    lo = math.floor(pos)
    hi = math.ceil(pos)
    if lo == hi:
        return float(sorted_values[lo])
    return float(sorted_values[lo] * (hi - pos) + sorted_values[hi] * (pos - lo))


def stats_block(values: list[float]) -> dict[str, Any] | None:
    if not values:
        return None
    s = sorted(values)
    n = len(s)
    mean = sum(s) / n
    variance = sum((x - mean) ** 2 for x in s) / (n - 1) if n > 1 else 0.0
    sd = math.sqrt(max(0.0, variance))
    med = median(s)
    mad = median([abs(x - med) for x in s]) if s else 0.0
    return {
        "n": n,
        "mean_ms": round(mean, 3),
        "median_ms": round(med, 3),
        "p25_ms": round(quantile(s, 0.25), 3),
        "p75_ms": round(quantile(s, 0.75), 3),
        "min_ms": round(s[0], 3),
        "max_ms": round(s[-1], 3),
        "sd_ms": round(sd, 3),
        "mad_ms": round(mad, 3),
        "cv": round(sd / mean, 3) if mean else None,
    }


def cliffs_delta(a: list[float], b: list[float]) -> float | None:
    if not a or not b:
        return None
    greater = less = 0
    for x in a:
        for y in b:
            if x > y:
                greater += 1
            elif x < y:
                less += 1
    return (greater - less) / (len(a) * len(b))


def bootstrap_median_ci(diffs: list[float], samples: int, seed: int) -> list[float] | None:
    if len(diffs) < 2:
        return None
    rng = random.Random(seed)
    vals = []
    n = len(diffs)
    for _ in range(samples):
        vals.append(median([rng.choice(diffs) for _ in range(n)]))
    vals.sort()
    low = quantile(vals, 0.025)
    high = quantile(vals, 0.975)
    if low is None or high is None:
        return None
    return [round(low, 3), round(high, 3)]


def sign_flip_test(diffs: list[float], permutation_samples: int, seed: int) -> float | None:
    """配对符号翻转检验；检验统计量用均值，位置估计和 CI 仍用稳健中位数。"""
    if not diffs:
        return None
    observed = abs(sum(diffs) / len(diffs))
    n = len(diffs)
    ge = 0
    total = 0

    if n <= 12:
        for signs in itertools.product((-1.0, 1.0), repeat=n):
            value = abs(sum(d * s for d, s in zip(diffs, signs)) / n)
            total += 1
            if value + 1e-9 >= observed:
                ge += 1
        return ge / total

    rng = random.Random(seed)
    for _ in range(permutation_samples):
        signs = [rng.choice((-1.0, 1.0)) for _ in range(n)]
        value = abs(sum(d * s for d, s in zip(diffs, signs)) / n)
        total += 1
        if value + 1e-9 >= observed:
            ge += 1
    return (ge + 1) / (total + 1)


def slope_ms_per_order(samples: list[dict[str, Any]]) -> float | None:
    points = [(s["order"], s["elapsed_ms"]) for s in samples if s.get("elapsed_ms") is not None]
    if len(points) < 3:
        return None
    mx = sum(x for x, _ in points) / len(points)
    my = sum(y for _, y in points) / len(points)
    denom = sum((x - mx) ** 2 for x, _ in points)
    if denom == 0:
        return None
    numer = sum((x - mx) * (y - my) for x, y in points)
    return round(numer / denom, 4)


def timing_analysis(samples: list[dict[str, Any]], args: argparse.Namespace, seed: int) -> dict[str, Any]:
    ok = [s for s in samples if s.get("elapsed_ms") is not None and s.get("error") is None]
    existing = [s["elapsed_ms"] for s in ok if s["role"] == "existing"]
    nonexisting = [s["elapsed_ms"] for s in ok if s["role"] == "nonexisting"]

    by_pair: dict[int, dict[str, float]] = {}
    first_role_by_pair: dict[int, tuple[int, str]] = {}
    for s in ok:
        by_pair.setdefault(s["pair_id"], {})[s["role"]] = s["elapsed_ms"]
        current = first_role_by_pair.get(s["pair_id"])
        if current is None or s["order"] < current[0]:
            first_role_by_pair[s["pair_id"]] = (s["order"], s["role"])
    paired = [(v["existing"], v["nonexisting"]) for pid, v in by_pair.items()
              if "existing" in v and "nonexisting" in v]
    paired_pair_ids = [pid for pid, v in by_pair.items()
                       if "existing" in v and "nonexisting" in v]
    diffs = [e - n for e, n in paired]
    existing_first = sum(
        1 for pid in paired_pair_ids if first_role_by_pair.get(pid, (0, ""))[1] == "existing"
    )

    result: dict[str, Any] = {
        "existing": stats_block(existing),
        "nonexisting": stats_block(nonexisting),
        "paired_difference_existing_minus_nonexisting": stats_block(diffs),
        "pairs": len(diffs),
        "existing_first_pairs": existing_first,
        "nonexisting_first_pairs": len(diffs) - existing_first,
        "cliffs_delta": None,
        "auc": None,
        "bootstrap_ci_median_difference_ms": None,
        "sign_flip_p_value": None,
        "same_direction_fraction": None,
        "leave_one_out_sign_stable": None,
        "order_slope_ms_per_request": slope_ms_per_order(ok),
        "cache_header_samples": sum(1 for s in ok if s.get("cache_headers")),
        "level": "insufficient",
        "detected": False,
        "direction": None,
        "reasons": [],
    }
    delta = cliffs_delta(existing, nonexisting)
    result["cliffs_delta"] = round(delta, 3) if delta is not None else None
    result["auc"] = round((delta + 1.0) / 2.0, 3) if delta is not None else None

    if len(diffs) < 2:
        result["reasons"].append("完整配对数不足，无法进行可信时序统计。")
        return result

    med_diff = median(diffs)
    result["direction"] = "existing_slower" if med_diff > 0 else "existing_faster" if med_diff < 0 else "equal"
    result["bootstrap_ci_median_difference_ms"] = bootstrap_median_ci(
        diffs, args.bootstrap_samples, seed + 17
    )
    result["sign_flip_p_value"] = round(
        sign_flip_test(diffs, args.permutation_samples, seed + 31), 5
    )

    sign = 1 if med_diff > 0 else -1 if med_diff < 0 else 0
    same = sum(1 for d in diffs if (d > 0 and sign > 0) or (d < 0 and sign < 0))
    result["same_direction_fraction"] = round(same / len(diffs), 3) if sign else None

    loo_signs = []
    for i in range(len(diffs)):
        rest = diffs[:i] + diffs[i + 1:]
        if rest:
            m = median(rest)
            if abs(m) > 1e-9:
                loo_signs.append(1 if m > 0 else -1)
    result["leave_one_out_sign_stable"] = bool(loo_signs) and all(x == sign for x in loo_signs)

    ci = result["bootstrap_ci_median_difference_ms"]
    p_value = result["sign_flip_p_value"]
    practical = args.min_timing_effect_ms
    ci_excludes_zero = bool(ci and (ci[0] > 0 or ci[1] < 0))
    ci_beats_practical = bool(ci and (ci[0] > practical or ci[1] < -practical))
    abs_delta = abs(delta or 0.0)
    consistency = result["same_direction_fraction"] or 0.0
    order_balance_floor = max(1, len(diffs) // 2 - 1)
    order_balanced = min(existing_first, len(diffs) - existing_first) >= order_balance_floor

    reasons = result["reasons"]
    reasons.append(
        f"配对中位数差={med_diff:.1f}ms，95% bootstrap CI={ci}，"
        f"符号翻转 p={p_value}，Cliff's δ={result['cliffs_delta']}，"
        f"先后顺序 E-first/N-first={existing_first}/{len(diffs) - existing_first}。"
    )

    if (
        len(diffs) >= 8 and p_value is not None and p_value < args.timing_alpha
        and ci_excludes_zero and ci_beats_practical and abs_delta >= 0.60
        and consistency >= 0.75 and result["leave_one_out_sign_stable"]
        and order_balanced
    ):
        result["level"] = "high"
        result["detected"] = True
        reasons.append("时序差异通过显著性、效应量、置信区间、顺序平衡和留一稳定性门槛。")
    elif (
        len(diffs) >= 5 and p_value is not None and p_value < 0.05
        and ci_excludes_zero and ci_beats_practical and abs_delta >= 0.474
        and consistency >= 0.70
    ):
        result["level"] = "medium"
        result["detected"] = True
        reasons.append("存在中等置信时序差异，但样本数、顺序平衡或稳定性尚未达到高置信门槛。")
    elif abs_delta >= 0.30 or (abs(med_diff) >= practical and consistency >= 0.67):
        result["level"] = "low"
        reasons.append("有弱时序信号；网络抖动/缓存/样本量可能导致假阳性，不能单独作为确证。")
    else:
        result["level"] = "none"
        reasons.append("未发现满足稳健性门槛的时序差异。")

    if not order_balanced:
        reasons.append("配对内请求先后顺序不平衡，首轮连接/TLS/缓存效应可能与账号类别混杂；建议更换 --seed 复测。")

    if result["order_slope_ms_per_request"] is not None and len(ok) >= 4:
        drift = result["order_slope_ms_per_request"] * max(s["order"] for s in ok)
        if abs(drift) >= max(20.0, abs(med_diff)):
            reasons.append(f"响应时间随请求顺序漂移约 {drift:.1f}ms，可能是网络/服务端冷启动或缓存效应。")
    if result["cache_header_samples"]:
        reasons.append("部分响应包含缓存头；时序结论需考虑缓存命中影响。")
    return result


# ---------------------------------------------------------------------------
# 状态码 / 响应体 / 响应头分析
# ---------------------------------------------------------------------------

def dominant(values: list[Any]) -> tuple[Any, int, float]:
    if not values:
        return None, 0, 0.0
    value, count = Counter(values).most_common(1)[0]
    return value, count, count / len(values)


def distribution(values: list[Any], limit: int = 8) -> dict[str, int]:
    return {str(k): int(v) for k, v in Counter(values).most_common(limit)}


def status_analysis(samples: list[dict[str, Any]], stability: float) -> dict[str, Any]:
    ok = [s for s in samples if s.get("status") is not None]
    e = [s["status"] for s in ok if s["role"] == "existing"]
    n = [s["status"] for s in ok if s["role"] == "nonexisting"]
    e_dom, e_count, e_purity = dominant(e)
    n_dom, n_count, n_purity = dominant(n)
    detected = bool(e and n and e_dom != n_dom and e_purity >= stability and n_purity >= stability)
    level = "insufficient"
    if detected:
        if len(e) >= 3 and len(n) >= 3 and e_purity >= 0.999 and n_purity >= 0.999:
            level = "high"
        elif len(e) >= 2 and len(n) >= 2:
            level = "medium"
        else:
            level = "low"
    elif len(e) >= 2 and len(n) >= 2:
        level = "none"
    return {
        "detected": detected,
        "level": level,
        "existing_distribution": distribution(e),
        "nonexisting_distribution": distribution(n),
        "existing_dominant": e_dom,
        "nonexisting_dominant": n_dom,
        "existing_purity": round(e_purity, 3),
        "nonexisting_purity": round(n_purity, 3),
        "evidence": f"存在样本主要为 HTTP {e_dom}，不存在样本主要为 HTTP {n_dom}。" if detected else "状态码未形成稳定的类别差异。",
    }


def medoid_canonical(group: list[dict[str, Any]]) -> tuple[dict[str, Any] | None, str]:
    if not group:
        return None, ""
    if len(group) == 1:
        return group[0], group[0]["_canonical"]
    texts = [s["_canonical"][:20000] for s in group]
    best_i = 0
    best_score = -1.0
    for i, text in enumerate(texts):
        others = [t for j, t in enumerate(texts) if j != i]
        score = sum(difflib.SequenceMatcher(None, text, other).ratio() for other in others) / len(others)
        if score > best_score:
            best_score = score
            best_i = i
    return group[best_i], group[best_i]["_norm_lines"]


def body_analysis(samples: list[dict[str, Any]], accounts: list[str], stability: float) -> dict[str, Any]:
    ok = [s for s in samples if s.get("body_text")]
    enriched = []
    for s in ok:
        item = dict(s)
        item["_norm_lines"] = normalize_text(s["body_text"], accounts)
        item["_canonical"] = canonical_text(s["body_text"], accounts)
        item["_stable_hash"] = stable_json_hash(s["body_text"], accounts) or hashlib.sha256(
            item["_canonical"].encode("utf-8")
        ).hexdigest()
        try:
            item["_json"] = json.loads(s["body_text"])
        except Exception:
            item["_json"] = None
        enriched.append(item)

    e = [s for s in enriched if s["role"] == "existing"]
    n = [s for s in enriched if s["role"] == "nonexisting"]
    e_hash, _, e_purity = dominant([s["_stable_hash"] for s in e])
    n_hash, _, n_purity = dominant([s["_stable_hash"] for s in n])
    hash_diff = bool(e and n and e_hash != n_hash and e_purity >= stability and n_purity >= stability)

    field_candidates: list[dict[str, Any]] = []
    all_paths: set[str] = set()
    flat_maps: dict[int, dict[str, str]] = {}
    for s in enriched:
        if s["_json"] is not None:
            flat = flatten_json(sanitize_json(s["_json"], accounts))
        else:
            flat = {}
        flat_maps[id(s)] = flat
        all_paths.update(flat.keys())

    for path in sorted(all_paths):
        leaf = path.rsplit(".", 1)[-1].lower().replace("_", "")
        if leaf in VOLATILE_JSON_KEYS or any(part in leaf for part in ("token", "csrf", "trace", "requestid")):
            continue
        ev = [flat_maps[id(s)].get(path, "<missing>") for s in e]
        nv = [flat_maps[id(s)].get(path, "<missing>") for s in n]
        ed, _, ep = dominant(ev)
        nd, _, npur = dominant(nv)
        if ed != nd and ep >= stability and npur >= stability:
            field_candidates.append({
                "path": path,
                "interesting": any(part in leaf for part in INTERESTING_FIELD_PARTS),
                "existing_purity": round(ep, 3),
                "nonexisting_purity": round(npur, 3),
                "existing_values": distribution(ev, 5),
                "nonexisting_values": distribution(nv, 5),
                "existing_dominant": ed[:300] if isinstance(ed, str) else ed,
                "nonexisting_dominant": nd[:300] if isinstance(nd, str) else nd,
            })
    field_candidates.sort(key=lambda x: (not x["interesting"], x["path"]))

    e_medoid, e_text = medoid_canonical(e)
    n_medoid, n_text = medoid_canonical(n)
    similarity = None
    diff_excerpt = ""
    if e_text and n_text:
        similarity = round(difflib.SequenceMatcher(
            None, e_medoid["_canonical"][:30000], n_medoid["_canonical"][:30000]
        ).ratio(), 4)
        diff = list(difflib.unified_diff(
            n_text.splitlines(), e_text.splitlines(),
            fromfile="nonexisting", tofile="existing", n=2,
        ))
        diff_excerpt = "\n".join(line[:240] for line in diff[:60])

    length_e = [s["body_bytes"] for s in e if not s.get("truncated")]
    length_n = [s["body_bytes"] for s in n if not s.get("truncated")]
    detected = hash_diff or bool(field_candidates)
    level = "insufficient"
    if detected:
        pure_interesting_field = any(
            c["interesting"]
            and c["existing_purity"] >= 0.999
            and c["nonexisting_purity"] >= 0.999
            for c in field_candidates
        )
        if (
            len(e) >= 3 and len(n) >= 3
            and (
                (e_purity >= 0.999 and n_purity >= 0.999 and hash_diff)
                or pure_interesting_field
            )
        ):
            level = "high"
        elif len(e) >= 2 and len(n) >= 2:
            level = "medium"
        else:
            level = "low"
    elif len(e) >= 2 and len(n) >= 2:
        level = "none"

    return {
        "detected": detected,
        "level": level,
        "stable_cluster_difference": hash_diff,
        "existing_hash_purity": round(e_purity, 3),
        "nonexisting_hash_purity": round(n_purity, 3),
        "medoid_similarity": similarity,
        "field_candidates": field_candidates[:20],
        "length_existing": stats_block([float(x) for x in length_e]),
        "length_nonexisting": stats_block([float(x) for x in length_n]),
        "existing_excerpt": e_text[:1200],
        "nonexisting_excerpt": n_text[:1200],
        "diff_excerpt": diff_excerpt[:4000],
        "evidence": (
            f"发现 {len(field_candidates)} 个稳定不同字段；响应代表相似度={similarity}。"
            if detected else "响应体未形成稳定的类别差异。"
        ),
        "_enriched": enriched,
    }


def header_analysis(samples: list[dict[str, Any]], stability: float) -> dict[str, Any]:
    ok = [s for s in samples if s.get("header_signature")]
    keys = sorted({k for s in ok for k in s["header_signature"]})
    candidates = []
    for key in keys:
        e = [s["header_signature"].get(key, "<missing>") for s in ok if s["role"] == "existing"]
        n = [s["header_signature"].get(key, "<missing>") for s in ok if s["role"] == "nonexisting"]
        ed, _, ep = dominant(e)
        nd, _, npur = dominant(n)
        if e and n and ed != nd and ep >= stability and npur >= stability:
            candidates.append({
                "header": key,
                "existing_dominant": str(ed)[:300],
                "nonexisting_dominant": str(nd)[:300],
                "existing_values": distribution(e, 5),
                "nonexisting_values": distribution(n, 5),
            })

    content_length_only = bool(candidates) and all(c["header"] == "content-length" for c in candidates)
    detected = bool(candidates)
    level = "insufficient"
    if detected:
        ne = sum(1 for s in ok if s["role"] == "existing")
        nn = sum(1 for s in ok if s["role"] == "nonexisting")
        if ne >= 3 and nn >= 3 and not content_length_only:
            level = "high"
        elif ne >= 2 and nn >= 2:
            level = "medium" if not content_length_only else "low"
        else:
            level = "low"
    elif sum(1 for s in ok if s["role"] == "existing") >= 2 and sum(1 for s in ok if s["role"] == "nonexisting") >= 2:
        level = "none"
    return {
        "detected": detected,
        "level": level,
        "content_length_only": content_length_only,
        "candidates": candidates,
        "evidence": f"发现 {len(candidates)} 个稳定不同响应头。" if candidates else "响应头未形成稳定的类别差异（已忽略 Date/Trace 等噪声头）。",
    }


# ---------------------------------------------------------------------------
# 结论与报告
# ---------------------------------------------------------------------------

LEVEL_CN = {
    "high": "高",
    "medium": "中",
    "low": "低",
    "none": "无",
    "insufficient": "样本不足",
}


def overall_verdict(
    status: dict[str, Any],
    body: dict[str, Any],
    headers: dict[str, Any],
    timing: dict[str, Any],
    aborted: bool,
    abort_reason: str | None,
    completed_count: int,
    existing_completed: int,
    nonexisting_completed: int,
) -> tuple[str, str, int]:
    deterministic_high = status["level"] == "high" or body["level"] == "high" or headers["level"] == "high"
    deterministic_medium = status["level"] == "medium" or body["level"] == "medium" or headers["level"] == "medium"
    deterministic_any = status["detected"] or body["detected"] or headers["detected"]

    if aborted:
        if deterministic_any or timing.get("detected"):
            return (
                "ABORTED_WITH_EVIDENCE",
                "检测已因限流/验证码/锁定/连续网络错误等安全信号中止；中止前已观察到类别差异，"
                "但不能排除锁定或风控响应造成的假阳性。请改用隔离测试环境或专用测试账号复测。",
                2,
            )
        return (
            "ABORTED_INCONCLUSIVE",
            "检测已按安全策略中止，未获得足够证据；请先处理验证码、限流、锁定或网络问题后在授权测试环境复测。",
            2,
        )

    if completed_count < 2 or existing_completed < 1 or nonexisting_completed < 1:
        return "INCONCLUSIVE", "成功响应过少或缺少某一类别，无法判断。", 4
    if existing_completed < 2 or nonexisting_completed < 2:
        return "INCONCLUSIVE", "每类至少需要 2 个成功响应才能给出稳定差异结论；当前只能作为人工复核线索。", 4

    if deterministic_high:
        return "ENUMERABLE", "可枚举（高置信）：状态码、响应体或稳定响应头存在一致的类别差异。", 3
    if deterministic_medium or timing.get("level") == "high":
        return "LIKELY_ENUMERABLE", "可能可枚举：存在较稳定差异或强时序侧信道，建议人工复核证据后复测。", 3
    if body["level"] == "low" or status["level"] == "low" or headers["level"] == "low" or timing.get("level") in {"medium", "low"}:
        return "SUSPECTED", "存在疑似差异，但样本量或稳定性不足，不能据此直接出具“可枚举”确证结论。", 4
    return "NOT_DETECTED", "在本次样本、网络路径和统计门槛下，未发现可稳定复现的账号枚举差异。", 0


def safe_url(url: str, accounts: list[str], show_accounts: bool) -> str:
    parts = urllib.parse.urlsplit(url)
    query = urllib.parse.parse_qsl(parts.query, keep_blank_values=True)
    safe_query = []
    for k, v in query:
        if is_sensitive_key(k):
            v = "<redacted>"
        elif not show_accounts:
            v = replace_accounts(v, accounts, "<account>")
        safe_query.append((k, v))
    path = parts.path
    if not show_accounts:
        path = replace_accounts(path, accounts, "<account>")
    return urllib.parse.urlunsplit((
        parts.scheme, parts.netloc, path, urllib.parse.urlencode(safe_query), parts.fragment
    ))


def slim_samples(
    samples: list[dict[str, Any]],
    enriched: list[dict[str, Any]] | None,
    accounts: list[str],
    show_accounts: bool,
) -> list[dict[str, Any]]:
    excerpt_by_order: dict[int, str] = {}
    if enriched:
        for item in enriched:
            excerpt_by_order[item["order"]] = item["_norm_lines"][:1000]

    out = []
    for s in samples:
        item = {
            "order": s["order"],
            "pair_id": s["pair_id"],
            "role": s["role"],
            "account": display_account(s["account"], show_accounts),
            "url": safe_url(s["url"], accounts, show_accounts),
            "status": s["status"],
            "elapsed_ms": round(s["elapsed_ms"], 3) if s.get("elapsed_ms") is not None else None,
            "error": s["error"],
            "body_sha256": s["body_sha256"],
            "body_bytes": s["body_bytes"],
            "truncated": s["truncated"],
            "header_signature": s["header_signature"],
            "cache_headers": s["cache_headers"],
            "stop_signals": s["stop_signals"],
            "body_excerpt_normalized": excerpt_by_order.get(s["order"], ""),
        }
        out.append(item)
    return out


def build_markdown(report: dict[str, Any]) -> str:
    v = report["verdict"]
    safety = report["safety"]
    st = report["channels"]["status"]
    body = report["channels"]["body"]
    hd = report["channels"]["headers"]
    tm = report["channels"]["timing"]

    lines = [
        "# 账号枚举检测报告",
        "",
        f"- 检测时间：{report['started_at']} → {report['finished_at']}",
        f"- 目标：`{report['request']['url']}`",
        f"- 方法/格式：{report['request']['method']} / {report['request']['format']} / 类型 {report['request']['endpoint_kind']}",
        f"- 结论代码：`{v['code']}`",
        f"- **总结论：{v['summary']}**",
        "",
        "## 1. 安全与采样",
        "",
        f"- 配对数：{safety['pairs']}；计划请求数：{safety['planned_requests']}；实际样本数：{safety['sample_count']}",
        f"- 成功 HTTP 响应：{safety['completed_count']}（存在 {safety.get('existing_completed')} / 不存在 {safety.get('nonexisting_completed')}）；网络错误：{safety['error_count']}",
        f"- 顺序请求间隔：{safety['delay_seconds']}s + 0~{safety['jitter_seconds']}s 随机抖动；并发=1；不自动重试超时请求",
        f"- 每个已知账号最大请求次数：{safety['max_requests_per_existing']}",
        f"- 安全中止：{'是 — ' + str(safety['abort_reason']) if safety['aborted'] else '否'}",
        f"- 停止信号：{', '.join(safety['all_stop_signals']) if safety['all_stop_signals'] else '无'}",
        f"- 随机种子：`{safety['seed']}`（可用于复现请求顺序/控制样本形态）",
        "",
        "## 2. 通道结论",
        "",
        "| 通道 | 是否检出 | 置信度 | 证据 |",
        "|---|---:|---|---|",
        f"| 状态码 | {'是' if st['detected'] else '否'} | {LEVEL_CN.get(st['level'], st['level'])} | {st['evidence']} |",
        f"| 响应体/业务字段 | {'是' if body['detected'] else '否'} | {LEVEL_CN.get(body['level'], body['level'])} | {body['evidence']} |",
        f"| 响应头 | {'是' if hd['detected'] else '否'} | {LEVEL_CN.get(hd['level'], hd['level'])} | {hd['evidence']} |",
        f"| 响应时间 | {'是' if tm['detected'] else '否/弱信号'} | {LEVEL_CN.get(tm['level'], tm['level'])} | 配对数 {tm.get('pairs')}，Cliff's δ={tm.get('cliffs_delta')}，p={tm.get('sign_flip_p_value')} |",
        "",
        "## 3. 状态码证据",
        "",
        "```json",
        json.dumps({
            "existing": st["existing_distribution"],
            "nonexisting": st["nonexisting_distribution"],
        }, ensure_ascii=False, indent=2),
        "```",
        "",
        "## 4. 响应体证据",
        "",
        f"- 稳定聚类差异：{body['stable_cluster_difference']}",
        f"- 类内指纹纯度：existing={body['existing_hash_purity']}, nonexisting={body['nonexisting_hash_purity']}",
        f"- 代表响应相似度：{body['medoid_similarity']}",
        "",
    ]

    if body.get("field_candidates"):
        lines += ["### 稳定不同字段", "", "| JSON 路径 | 已知存在样本 | 不存在样本 |", "|---|---|---|"]
        for c in body["field_candidates"][:12]:
            ev = str(c["existing_dominant"]).replace("|", "\\|").replace("\n", " ")[:180]
            nv = str(c["nonexisting_dominant"]).replace("|", "\\|").replace("\n", " ")[:180]
            lines.append(f"| `{c['path']}` | `{ev}` | `{nv}` |")
        lines.append("")

    if body.get("diff_excerpt"):
        lines += ["### 代表响应 Diff（- 不存在，+ 存在）", "", "```diff", body["diff_excerpt"], "```", ""]

    lines += [
        "## 5. 响应头证据",
        "",
    ]
    if hd.get("candidates"):
        lines += ["| Header | 已知存在样本 | 不存在样本 |", "|---|---|---|"]
        for c in hd["candidates"][:15]:
            ev = str(c["existing_dominant"]).replace("|", "\\|")[:180]
            nv = str(c["nonexisting_dominant"]).replace("|", "\\|")[:180]
            lines.append(f"| `{c['header']}` | `{ev}` | `{nv}` |")
        lines.append("")
    else:
        lines += ["未发现稳定不同的响应头。", ""]

    t_e = tm.get("existing")
    t_n = tm.get("nonexisting")
    t_d = tm.get("paired_difference_existing_minus_nonexisting")
    lines += [
        "## 6. 响应时间统计",
        "",
        "| 组别 | n | 中位数 ms | MAD ms | 均值 ms | SD ms | P25/P75 |",
        "|---|---:|---:|---:|---:|---:|---:|",
    ]
    for name, block in [("存在", t_e), ("不存在", t_n), ("配对差 E-N", t_d)]:
        if block:
            lines.append(
                f"| {name} | {block['n']} | {block['median_ms']} | {block['mad_ms']} | "
                f"{block['mean_ms']} | {block['sd_ms']} | {block['p25_ms']}/{block['p75_ms']} |"
            )
    lines += [
        "",
        f"- 95% bootstrap 中位数差 CI：`{tm.get('bootstrap_ci_median_difference_ms')}` ms",
        f"- 配对符号翻转 p 值：`{tm.get('sign_flip_p_value')}`",
        f"- Cliff's δ：`{tm.get('cliffs_delta')}`；AUC：`{tm.get('auc')}`（>0.5 表示存在样本更慢）",
        f"- 同向比例：`{tm.get('same_direction_fraction')}`；留一符号稳定：`{tm.get('leave_one_out_sign_stable')}`",
        f"- 配对内先后顺序（存在先/不存在先）：`{tm.get('existing_first_pairs')}/{tm.get('nonexisting_first_pairs')}`",
        f"- 顺序漂移斜率：`{tm.get('order_slope_ms_per_request')}` ms/请求",
        "",
        "统计说明：时序容易受 TLS 握手、网络抖动、连接复用、服务端/CDN 缓存和冷启动影响。"
        "本工具使用同形态控制样本、随机配对顺序、稳健中位数/MAD、配对 bootstrap 和符号翻转检验；"
        "但时序结论仍应通过更换时间窗口、网络路径和授权测试环境复测确认。",
        "",
        "## 7. 修复建议",
        "",
        "1. 登录失败统一返回相同文案、状态码、响应结构和跳转，例如“账号或密码错误”。",
        "2. 找回密码统一返回“如果该标识已注册，重置指引已发送”，避免直接提示账号是否存在。",
        "3. 注册/可用性检查是枚举高发点；应要求高强度人机校验、限流和监控，并尽量不提供匿名实时可用性查询。",
        "4. 对不存在用户执行等价的哈希计算/哑操作，缩小存在与不存在账号的处理时延差异。",
        "5. 限流应按 IP、设备、会话和目标标识组合控制；避免简单累计失败次数后锁定真实用户，可采用临时延迟、告警和专用客服流程。",
        "6. 不要把验证码当作唯一修复；验证码可被打码平台/会话复用绕过，且验证码出现本身也可能形成区分信号。",
        "",
    ]
    return "\n".join(lines)


def write_outputs(report: dict[str, Any], json_path: str, markdown_path: str) -> None:
    jp = Path(json_path)
    mp = Path(markdown_path)
    if jp.parent and str(jp.parent) not in {"", "."}:
        jp.parent.mkdir(parents=True, exist_ok=True)
    if mp.parent and str(mp.parent) not in {"", "."}:
        mp.parent.mkdir(parents=True, exist_ok=True)
    jp.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    mp.write_text(build_markdown(report), encoding="utf-8")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="授权场景下的账号枚举差异检测工具（标准库实现，低速配对采样）",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    target = p.add_argument_group("目标与请求")
    target.add_argument("--url", required=True, help="完整接口 URL")
    target.add_argument("--method", default="POST", choices=["GET", "POST", "PUT", "PATCH"])
    target.add_argument("--format", default="json", choices=["json", "form", "query", "raw"], help="请求编码；GET 通常用 query")
    target.add_argument("--endpoint-kind", default="generic", choices=["login", "password-reset", "register", "generic"])
    target.add_argument("--field", default="username", help="账号字段名；使用嵌套 JSON 时请改用 --body-template-file")
    target.add_argument("--param", action="append", default=[], metavar="KEY=VALUE", help="附加字段，可重复，如 password=...")
    target.add_argument("--header", action="append", default=[], metavar="'Key: Value'", help="请求头，可重复")
    target.add_argument("--body-template-file", help="JSON/文本请求体模板，使用 {{account}} 占位")
    target.add_argument("--raw-body", help="--format raw 时的原始请求体，可包含 {{account}}")
    target.add_argument("--timeout", type=float, default=10.0)
    target.add_argument("--proxy", help="HTTP/HTTPS 代理，如 http://127.0.0.1:8080；也尊重 HTTPS_PROXY 环境变量")
    target.add_argument("--insecure", action="store_true", help="跳过 TLS 证书校验（仅用于授权测试代理/实验环境）")

    samples = p.add_argument_group("样本")
    samples.add_argument("--existing", action="append", default=[], help="已知存在的专用测试账号，可重复")
    samples.add_argument("--existing-file", help="已知账号文件，每行一个，# 开头为注释")
    samples.add_argument("--nonexisting", action="append", default=[], help="已确认不存在的控制账号，可重复；提供后优先使用")
    samples.add_argument("--nonexisting-file", help="不存在账号文件")
    samples.add_argument("--pairs", type=int, default=0, help="配对数；0 表示等于去重后的已知账号数，每个账号默认只请求一次")
    samples.add_argument("--max-requests-per-existing", type=int, default=1, help="每个已知账号最大请求次数；硬上限 5")
    samples.add_argument("--seed", type=int, help="随机种子；不填则生成并写入报告")

    safety = p.add_argument_group("安全门禁")
    safety.add_argument("--i-am-authorized", action="store_true", help="确认已获得书面授权，且测试在授权范围/时间窗内")
    safety.add_argument("--test-accounts-are-dedicated", action="store_true", help="确认已知账号为专用测试账号或已获账号持有人许可，不会影响真实用户")
    safety.add_argument("--register-template-cannot-create-account", action="store_true", help="注册接口：确认模板会在校验阶段返回，不会创建持久账号")
    safety.add_argument("--dry-run", action="store_true", help="只打印请求计划和脱敏请求，不发送任何网络请求")
    safety.add_argument("--max-requests", type=int, default=40, help="总请求数硬上限")
    safety.add_argument("--delay", type=float, default=2.0, help="请求间基础延迟秒数")
    safety.add_argument("--jitter", type=float, default=1.5, help="请求间随机附加延迟上限秒数")
    safety.add_argument("--start-delay", type=float, default=3.0, help="正式发送前等待秒数，给操作者最后中止机会")
    safety.add_argument("--max-response-bytes", type=int, default=2_000_000)
    safety.add_argument("--stop-status", type=int, action="append", default=[], help="追加停止状态码；默认 423/429/503")
    safety.add_argument("--stop-pattern", action="append", default=[], help="追加停止文本（大小写不敏感字面匹配）")
    safety.add_argument("--no-default-stop-patterns", action="store_true", help="危险：禁用默认限流/验证码/锁定文本规则")

    detect = p.add_argument_group("统计阈值")
    detect.add_argument("--stability", type=float, default=0.8, help="类内响应指纹主导比例阈值")
    detect.add_argument("--min-timing-effect-ms", type=float, default=10.0, help="时序置信区间必须超过的最小实际差值")
    detect.add_argument("--timing-alpha", type=float, default=0.01, help="高置信时序 p 值门槛")
    detect.add_argument("--bootstrap-samples", type=int, default=5000)
    detect.add_argument("--permutation-samples", type=int, default=20000)

    out = p.add_argument_group("输出")
    out.add_argument("--json-output", default="account_enum_report.json")
    out.add_argument("--markdown-output", default="account_enum_report.md")
    out.add_argument("--show-accounts", action="store_true", help="报告中保留完整账号；默认脱敏")
    out.add_argument("--quiet", action="store_true")
    return p


def validate_and_prepare(args: argparse.Namespace) -> tuple[list[str], list[str], list[str], int, random.Random]:
    if not (0 < args.stability <= 1):
        raise CliError("--stability 必须在 (0,1]")
    if args.delay < 0 or args.jitter < 0 or args.start_delay < 0:
        raise CliError("延迟参数不能为负数")
    if args.max_requests_per_existing < 1 or args.max_requests_per_existing > 5:
        raise CliError("为降低锁定风险，--max-requests-per-existing 必须在 1..5；建议准备更多专用测试账号而不是重复请求同一账号。")

    existing = list(args.existing)
    if args.existing_file:
        existing.extend(read_account_file(args.existing_file))
    existing = dedupe_keep_order(existing)
    if not existing:
        raise CliError("至少需要一个 --existing 或 --existing-file 已知存在样本。")

    explicit_controls = list(args.nonexisting)
    if args.nonexisting_file:
        explicit_controls.extend(read_account_file(args.nonexisting_file))
    explicit_controls = dedupe_keep_order(explicit_controls)

    try:
        args.param_list = [parse_kv(x, "=") for x in args.param]
    except Exception as exc:
        raise CliError(str(exc)) from exc

    args.header_map = {}
    for h in args.header:
        k, v = parse_kv(h, ":")
        args.header_map[k] = v

    if args.body_template_file:
        args.body_template = load_body_template(args.body_template_file)
    else:
        args.body_template = None

    if args.method == "GET" and args.format != "query":
        raise CliError("GET 请求请使用 --format query/--field 构造查询参数；请求体枚举请使用 POST/PUT/PATCH。")
    if args.format == "raw" and args.body_template is None and not args.raw_body:
        raise CliError("--format raw 需要 --raw-body 或 --body-template-file")
    if args.format == "query" and args.body_template is not None:
        raise CliError("--format query 通过 --field/--param 构造查询参数；--body-template-file 仅用于请求体格式")
    if args.format in {"json", "form"} and not args.field and args.body_template is None:
        raise CliError("必须提供 --field，或使用包含 {{account}} 的 --body-template-file")

    pairs = args.pairs or len(existing)
    if pairs < 1:
        raise CliError("--pairs 必须 >= 1")
    planned = pairs * 2
    if planned > args.max_requests:
        raise CliError(f"计划请求数 {planned} 超过 --max-requests {args.max_requests}；请减少 pairs 或显式提高上限。")

    max_use = math.ceil(pairs / len(existing))
    if max_use > args.max_requests_per_existing:
        raise CliError(
            f"{pairs} 个配对、{len(existing)} 个已知账号时，单账号最多请求 {max_use} 次，"
            f"超过当前上限 {args.max_requests_per_existing}。请增加专用测试账号、减少 --pairs，"
            "或在确认锁定策略后显式提高 --max-requests-per-existing（硬上限 5）。"
        )

    if explicit_controls and len(explicit_controls) < pairs:
        raise CliError(
            f"显式不存在样本只有 {len(explicit_controls)} 个，少于配对数 {pairs}。"
            "为避免重复控制样本导致缓存偏差，请补充样本或使用自动同形态生成。"
        )

    if args.seed is None:
        args.seed = secrets.randbits(63)
    rng = random.Random(args.seed)

    args.stop_statuses_effective = sorted(set(DEFAULT_STOP_STATUSES + list(args.stop_status or [])))
    args.stop_patterns_effective = list(args.stop_pattern or [])
    if not args.no_default_stop_patterns:
        args.stop_patterns_effective = DEFAULT_STOP_PATTERNS + args.stop_patterns_effective

    if not args.dry_run:
        if not args.i_am_authorized:
            raise CliError("拒绝运行：请确认授权并添加 --i-am-authorized。可先用 --dry-run 检查请求。")
        if not args.test_accounts_are_dedicated:
            raise CliError("拒绝运行：请添加 --test-accounts-are-dedicated，确认已知账号为专用测试账号或已获许可。")
        if args.endpoint_kind == "register" and not args.register_template_cannot_create_account:
            raise CliError(
                "注册接口有创建持久账号风险。请使用会在校验阶段停止的模板，并添加 "
                "--register-template-cannot-create-account 确认不会创建账号。"
            )

    return existing, explicit_controls, pairs, planned, rng


def build_schedule(
    existing: list[str],
    explicit_controls: list[str],
    pairs: int,
    rng: random.Random,
) -> tuple[list[dict[str, Any]], list[str]]:
    existing_set = set(existing)
    all_accounts = list(existing)
    account_pool = existing[:]
    rng.shuffle(account_pool)
    jobs: list[dict[str, Any]] = []
    for pair_id in range(pairs):
        account = account_pool[pair_id % len(account_pool)]
        if explicit_controls:
            control = explicit_controls[pair_id % len(explicit_controls)]
        else:
            control = generate_nonexisting_control(account, rng, existing_set)
        all_accounts.append(control)

        members = [
            {"role": "existing", "account": account},
            {"role": "nonexisting", "account": control},
        ]
        rng.shuffle(members)
        for member in members:
            jobs.append({"pair_id": pair_id, **member})
    return jobs, dedupe_keep_order(all_accounts)


def print_dry_run(args: argparse.Namespace, jobs: list[dict[str, Any]]) -> None:
    print("=== DRY RUN：不会发送请求 ===")
    print(f"URL: {args.url}")
    print(f"Method/Format: {args.method} / {args.format}")
    print(f"Seed: {args.seed}")
    print(f"计划请求数: {len(jobs)}（顺序已随机化）")
    print("\n请求顺序（账号默认脱敏）：")
    for i, job in enumerate(jobs, 1):
        print(f"  {i:02d}. pair={job['pair_id']:02d} {job['role']:<13} {mask_account(job['account'])}")

    url, data, headers = build_request(argparse.Namespace(**{**vars(args)}), "{{account}}")
    print("\n请求预览：")
    print(f"  {args.method.upper()} {url}")
    safe_headers = {k: ("<redacted>" if is_sensitive_key(k) else v) for k, v in headers.items()}
    for k, v in safe_headers.items():
        print(f"  {k}: {v}")
    if data:
        preview = data.decode("utf-8", errors="replace")
        try:
            preview = json.dumps(redact_obj(json.loads(preview)), ensure_ascii=False, indent=2)
        except Exception:
            if args.format == "form":
                form = dict(urllib.parse.parse_qsl(preview))
                preview = urllib.parse.urlencode(redact_obj(form))
        print("\nBody:")
        print(preview[:4000])


def run(args: argparse.Namespace) -> int:
    existing, explicit_controls, pairs, planned, rng = validate_and_prepare(args)
    jobs, all_accounts = build_schedule(existing, explicit_controls, pairs, rng)

    if args.dry_run:
        print_dry_run(args, jobs)
        return 0

    if not args.quiet:
        print(f"[安全] 授权确认已提供；将顺序发送 {len(jobs)} 个请求，基础间隔 {args.delay}s + 0~{args.jitter}s 抖动。")
        print(f"[安全] 遇到状态码 {args.stop_statuses_effective} 或验证码/限流/锁定文本将立即停止。")
        print(f"[安全] {args.start_delay}s 后开始；按 Ctrl+C 可中止。")
    if args.start_delay > 0:
        time.sleep(args.start_delay)

    opener = build_opener(args)
    samples: list[dict[str, Any]] = []
    abort_reason: str | None = None
    consecutive_errors = 0
    started_at = now_iso()
    started_perf = time.perf_counter()

    try:
        for index, job in enumerate(jobs):
            if index > 0:
                time.sleep(args.delay + rng.random() * max(0.0, args.jitter))

            sample = send_one(
                opener, args, job["account"], job["role"], job["pair_id"],
                index, all_accounts,
            )
            samples.append(sample)

            if sample["error"]:
                consecutive_errors += 1
                if not args.quiet:
                    print(f"[{index + 1:02d}/{len(jobs)}] {job['role']:<13} ERROR {sample['error'][:160]}")
                if consecutive_errors >= 3:
                    abort_reason = "连续 3 个网络错误，已停止以避免在异常网络路径上产生不可信结论。"
                    break
            else:
                consecutive_errors = 0
                if not args.quiet:
                    print(
                        f"[{index + 1:02d}/{len(jobs)}] {job['role']:<13} "
                        f"HTTP {sample['status']} {sample['elapsed_ms']:.1f}ms "
                        f"{mask_account(job['account'])}"
                    )

            if sample["stop_signals"]:
                abort_reason = "命中安全停止信号：" + "; ".join(sample["stop_signals"][:8])
                if not args.quiet:
                    print(f"[中止] {abort_reason}")
                break
    except KeyboardInterrupt:
        abort_reason = "操作者通过 Ctrl+C 中止；已生成部分报告。"
        if not args.quiet:
            print(f"\n[中止] {abort_reason}")

    finished_at = now_iso()
    elapsed_total = time.perf_counter() - started_perf

    status_result = status_analysis(samples, args.stability)
    body_result = body_analysis(samples, all_accounts, args.stability)
    enriched = body_result.pop("_enriched", [])
    header_result = header_analysis(samples, args.stability)
    timing_result = timing_analysis(samples, args, args.seed or 1)

    completed = [s for s in samples if s.get("status") is not None]
    existing_completed = sum(1 for s in completed if s["role"] == "existing")
    nonexisting_completed = sum(1 for s in completed if s["role"] == "nonexisting")
    errors = [s for s in samples if s.get("error")]
    all_stop = sorted({signal for s in samples for signal in s.get("stop_signals", [])})
    verdict_code, summary, exit_code = overall_verdict(
        status_result, body_result, header_result, timing_result,
        abort_reason is not None, abort_reason, len(completed),
        existing_completed, nonexisting_completed,
    )

    report = {
        "tool": TOOL_NAME,
        "started_at": started_at,
        "finished_at": finished_at,
        "wall_time_seconds": round(elapsed_total, 2),
        "verdict": {"code": verdict_code, "summary": summary, "exit_code": exit_code},
        "request": {
            "url": safe_url(args.url, all_accounts, args.show_accounts),
            "method": args.method.upper(),
            "format": args.format,
            "endpoint_kind": args.endpoint_kind,
            "field": args.field,
            "headers": {k: ("<redacted>" if is_sensitive_key(k) else v) for k, v in args.header_map.items()},
            "params": redact_obj(dict(args.param_list)),
            "body_template_file": args.body_template_file,
            "proxy_configured": bool(args.proxy),
            "tls_verify_disabled": bool(args.insecure),
        },
        "safety": {
            "authorized_flag": args.i_am_authorized,
            "dedicated_test_accounts_flag": args.test_accounts_are_dedicated,
            "register_no_creation_confirmed": args.register_template_cannot_create_account,
            "pairs": pairs,
            "planned_requests": planned,
            "sample_count": len(samples),
            "completed_count": len(completed),
            "existing_completed": existing_completed,
            "nonexisting_completed": nonexisting_completed,
            "error_count": len(errors),
            "delay_seconds": args.delay,
            "jitter_seconds": args.jitter,
            "max_requests_per_existing": args.max_requests_per_existing,
            "seed": args.seed,
            "aborted": abort_reason is not None,
            "abort_reason": abort_reason,
            "stop_statuses": args.stop_statuses_effective,
            "default_stop_patterns_enabled": not args.no_default_stop_patterns,
            "all_stop_signals": all_stop,
        },
        "channels": {
            "status": status_result,
            "body": body_result,
            "headers": header_result,
            "timing": timing_result,
        },
        "samples": slim_samples(samples, enriched, all_accounts, args.show_accounts),
        "limitations": [
            "本工具只检测给定样本和网络路径下的统计差异，不证明后端一定存在可利用的账号枚举。",
            "时序差异可能由缓存、连接复用、TLS、网络抖动、账号数据量或风控逻辑导致。",
            "默认每个已知账号仅请求一次；这降低锁定风险，但会限制时序统计功效。",
            "遇到验证码、限流或锁定信号会停止，不会尝试绕过。",
        ],
    }

    write_outputs(report, args.json_output, args.markdown_output)

    if not args.quiet:
        print("\n" + "=" * 72)
        print(summary)
        print(f"JSON 证据: {Path(args.json_output).resolve()}")
        print(f"Markdown 报告: {Path(args.markdown_output).resolve()}")
        print("=" * 72)
    return exit_code


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return run(args)
    except CliError as exc:
        print(f"错误：{exc}", file=sys.stderr)
        return 1
    except FileNotFoundError as exc:
        print(f"文件不存在：{exc}", file=sys.stderr)
        return 1
    except json.JSONDecodeError as exc:
        print(f"JSON 模板解析失败：{exc}", file=sys.stderr)
        return 1
    except OSError as exc:
        print(f"文件/报告写入失败：{exc}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("\n已中止。若请求已经发出，请按授权预案确认是否需要通知目标系统负责人。", file=sys.stderr)
        return 130


if __name__ == "__main__":
    raise SystemExit(main())

