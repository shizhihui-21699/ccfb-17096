"""Safety, masking, and blocking-signal helpers."""
from __future__ import annotations

import hashlib
import re
from typing import Iterable

DEFENSE_PATTERNS: dict[str, tuple[str, ...]] = {
    "rate_limit": (
        "too many requests",
        "rate limit",
        "rate-limit",
        "ratelimit",
        "slow down",
        "try again later",
        "please wait",
        "请求过于频繁",
        "操作太频繁",
        "操作频繁",
        "稍后再试",
        "请稍后",
        "频率限制",
    ),
    "account_lockout": (
        "account locked",
        "account has been locked",
        "temporarily locked",
        "too many failed attempts",
        "账号已锁定",
        "账户已锁定",
        "账号被锁定",
        "账户被锁定",
        "锁定",
    ),
    "captcha_or_challenge": (
        "captcha",
        "recaptcha",
        "hcaptcha",
        "turnstile",
        "verify you are human",
        "human verification",
        "complete the security check",
        "complete security verification",
        "人机验证",
        "滑块验证",
        "滑动验证",
        "安全验证",
        "图形验证码",
        "请完成验证",
        "完成验证后",
    ),
}

DEFENSE_STATUS = {429}
DEFENSE_HEADERS = ("retry-after",)


def mask_account(account: str) -> str:
    """Mask an account while preserving enough structure for a report."""
    if not account:
        return ""
    if "@" in account:
        local, _, domain = account.partition("@")
        if len(local) <= 2:
            masked_local = local[0] + "*" if local else "*"
        else:
            masked_local = local[0] + "***" + local[-1]
        return f"{masked_local}@{domain}"
    if len(account) <= 2:
        return account[0] + "*"
    return account[0] + "***" + account[-1]


def account_fingerprint(account: str) -> str:
    return hashlib.sha256(account.encode("utf-8", "replace")).hexdigest()[:12]


def detect_defense(
    status: int | None,
    body: str,
    headers: Iterable[tuple[str, str]] | dict[str, str] | None,
) -> list[str]:
    """Return defense/lockout/captcha reasons observed in one response."""
    reasons: list[str] = []
    if status in DEFENSE_STATUS:
        reasons.append(f"http_{status}")

    header_items: Iterable[tuple[str, str]]
    if headers is None:
        header_items = ()
    elif isinstance(headers, dict):
        header_items = headers.items()
    else:
        header_items = headers

    for name, value in header_items:
        lname = name.lower()
        if lname in DEFENSE_HEADERS and value:
            reasons.append(f"header:{lname}")
        if lname.startswith("x-ratelimit-") and value.strip() in {"0", "0.0"}:
            reasons.append(f"header:{lname}=0")

    haystack = f" {body or ''} ".lower()
    for reason, patterns in DEFENSE_PATTERNS.items():
        if any(p.lower() in haystack for p in patterns):
            reasons.append(reason)

    # Deduplicate while preserving order.
    return list(dict.fromkeys(reasons))


def looks_like_email(value: str) -> bool:
    return re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", value or "") is not None
