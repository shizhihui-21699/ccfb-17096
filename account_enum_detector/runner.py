"""Safe, sequential, interleaved probe execution."""
from __future__ import annotations

import hashlib
import random
import time
from dataclasses import dataclass, field
from datetime import datetime

from .errors import SafetyGateError
from .models import ProbeRecord
from .normalize import normalize_body, normalize_headers, header_signature, scrub_dynamic_strings
from .payload import BodyConfig, build_body, render_account_pattern
from .requestor import HttpSender
from .safety import detect_defense, mask_account


@dataclass
class ScanConfig:
    url: str
    known_accounts: list[str]
    nonexistent_pattern: str
    cached_nonexistent_account: str | None = None
    body_config: BodyConfig = field(default_factory=lambda: BodyConfig())
    method: str = "POST"
    headers: dict[str, str] = field(default_factory=dict)
    samples_per_class: int = 5
    warmup_requests: int = 1
    delay_seconds: float = 1.0
    jitter_seconds: float = 0.75
    timeout_seconds: float = 15.0
    proxy: str | None = None
    insecure: bool = False
    request_cap: int = 40
    max_known_probes_per_account: int = 1
    allow_known_reuse: bool = False
    stop_on_defense: bool = True
    cache_control: bool = True
    max_consecutive_errors: int = 3
    seed: int | None = None
    user_agent: str = "AccountEnumDetector/0.1 (+authorized-security-testing)"


@dataclass
class PlannedRequest:
    seq: int
    round_index: int
    klass: str
    account: str
    order_in_round: int


@dataclass
class RunResult:
    records: list[ProbeRecord]
    plan: list[PlannedRequest]
    seed: int
    planned_request_count: int
    sent_request_count: int
    stop_reason: str | None = None


def build_plan(config: ScanConfig, seed: int | None = None) -> tuple[list[PlannedRequest], int]:
    if config.samples_per_class < 1:
        raise SafetyGateError("--samples-per-class must be at least 1")
    if config.warmup_requests < 0:
        raise SafetyGateError("--warmup-requests must not be negative")
    if config.request_cap < 1:
        raise SafetyGateError("--request-cap must be at least 1")
    if config.request_cap > 100:
        raise SafetyGateError("The tool will not send more than 100 requests in one run")
    if not config.known_accounts:
        raise SafetyGateError("At least one known/test-owned existing account is required")

    known = list(dict.fromkeys(a.strip() for a in config.known_accounts if a.strip()))
    if not known:
        raise SafetyGateError("Known-account list contains no non-empty accounts")

    if len(known) < config.samples_per_class and not config.allow_known_reuse:
        raise SafetyGateError(
            f"Need {config.samples_per_class} distinct known accounts for one safe probe each; "
            f"only {len(known)} supplied. Provide more test-owned accounts or pass "
            "--allow-known-reuse with an explicit per-account cap."
        )

    max_per_account = max(1, config.max_known_probes_per_account)
    if config.allow_known_reuse and max_per_account > 3:
        raise SafetyGateError(
            "Hard safety cap is 3 probes per known account. Use more test-owned accounts for timing samples."
        )
    if not config.allow_known_reuse:
        max_per_account = 1
    if config.samples_per_class > len(known) * max_per_account:
        raise SafetyGateError(
            f"{config.samples_per_class} existing-account samples exceed "
            f"{len(known)} known account(s) × {max_per_account} probe(s)/account. "
            "Use more test accounts or lower --samples-per-class."
        )

    effective_seed = seed if seed is not None else random.Random().randrange(1, 2**63 - 1)
    rng = random.Random(effective_seed)

    cached_nonexisting = config.cached_nonexistent_account or render_account_pattern(
        config.nonexistent_pattern, 500_001
    )
    while cached_nonexisting in known:
        cached_nonexisting = render_account_pattern(config.nonexistent_pattern, 510_001)

    plan: list[PlannedRequest] = []
    known_usage = {account: 0 for account in known}
    seq = 0

    for round_index in range(config.samples_per_class):
        if round_index < len(known):
            existing_account = known[round_index]
        else:
            reusable = [a for a, used in known_usage.items() if used < max_per_account]
            if not reusable:
                raise SafetyGateError("Known-account reuse cap exceeded while planning")
            existing_account = rng.choice(reusable)
        known_usage[existing_account] += 1

        fresh_nonexisting = render_account_pattern(config.nonexistent_pattern, round_index)
        # Avoid an accidental collision with supplied accounts.
        while fresh_nonexisting in known or fresh_nonexisting == cached_nonexisting:
            fresh_nonexisting = render_account_pattern(config.nonexistent_pattern, round_index + 10_000 + seq)

        group = [
            ("existing", existing_account),
            ("nonexisting", fresh_nonexisting),
        ]
        if config.cache_control:
            group.append(("nonexisting_cached", cached_nonexisting))
        rng.shuffle(group)
        for order, (klass, account) in enumerate(group):
            seq += 1
            plan.append(PlannedRequest(seq, round_index + 1, klass, account, order))

    total_planned = config.warmup_requests + len(plan)
    if len(plan) > 100 or total_planned > 100:
        raise SafetyGateError("The tool will not send more than 100 requests in one run")
    if total_planned > config.request_cap:
        raise SafetyGateError(
            f"Plan sends {total_planned} requests including {config.warmup_requests} warm-up; "
            f"request cap is {config.request_cap}. Lower samples/warm-up or raise --request-cap "
            "up to the absolute maximum of 100."
        )

    return plan, effective_seed


def _now() -> str:
    return datetime.now().astimezone().isoformat(timespec="seconds")


def execute(config: ScanConfig) -> RunResult:
    plan, seed = build_plan(config, config.seed)
    rng = random.Random(seed + 7919)
    sender = HttpSender(
        timeout=config.timeout_seconds,
        proxy=config.proxy,
        insecure=config.insecure,
    )

    all_accounts = [p.account for p in plan] + list(config.known_accounts)
    records: list[ProbeRecord] = []
    sent = 0
    consecutive_errors = 0
    stop_reason: str | None = None

    base_headers = dict(config.headers)

    def has_header(name: str) -> bool:
        return any(existing.lower() == name.lower() for existing in base_headers)

    if not has_header("User-Agent"):
        base_headers["User-Agent"] = config.user_agent
    if not has_header("Accept"):
        base_headers["Accept"] = "application/json, text/plain, text/html;q=0.9, */*;q=0.8"
    if config.method.upper() not in {"GET", "HEAD"} and not has_header("Content-Type"):
        base_headers["Content-Type"] = config.body_config.content_type

    # Warm-up uses only a non-existent account. It warms DNS/TLS/WAF paths without
    # adding a failed login attempt to a real account.
    warmup_account = render_account_pattern(config.nonexistent_pattern, 900_001)
    warmup_plan = [("warmup", 0, warmup_account)]

    def run_one(seq: int, round_index: int, klass: str, account: str) -> ProbeRecord:
        nonlocal sent, consecutive_errors, stop_reason
        if sent > 0 and config.delay_seconds >= 0:
            sleep_for = config.delay_seconds + rng.random() * max(0.0, config.jitter_seconds)
            if sleep_for > 0:
                time.sleep(sleep_for)

        sent += 1
        url = sender.render_url(config.url, account, config.body_config.password, seq)
        body = build_body(account, seq, config.body_config) if config.method.upper() not in {"GET", "HEAD"} else None
        response = sender.send(url, config.method, dict(base_headers), body)

        body_text = response.body.decode("utf-8", "replace")
        norm_body = normalize_body(body_text, all_accounts + [account])
        norm_headers = normalize_headers(response.header_items, all_accounts + [account])
        defense = detect_defense(response.status, body_text, response.header_items)

        record = ProbeRecord(
            seq=seq,
            round_index=round_index,
            klass=klass,
            account=account,
            account_masked=mask_account(account),
            requested_at=_now(),
            status=response.status,
            ok=response.ok,
            error=response.error or response.error_type,
            ttfb_ms=round(response.ttfb_ms, 3) if response.ttfb_ms is not None else None,
            total_ms=round(response.total_ms, 3) if response.total_ms is not None else None,
            body_length=len(response.body),
            body_sha256=hashlib.sha256(response.body).hexdigest() if response.body else None,
            body_excerpt=scrub_dynamic_strings(body_text[:1200], all_accounts + [account]),
            normalized_body=norm_body[:4000],
            normalized_sha256=hashlib.sha256(norm_body.encode()).hexdigest() if norm_body else None,
            header_signature=header_signature(norm_headers),
            headers_normalized=norm_headers,
            defense_reasons=defense,
        )
        records.append(record)

        server_error = response.status is not None and response.status >= 500
        if not response.ok or server_error:
            consecutive_errors += 1
        else:
            consecutive_errors = 0

        if defense and config.stop_on_defense:
            stop_reason = "defense_signal:" + ",".join(defense)
        elif consecutive_errors >= config.max_consecutive_errors:
            stop_reason = f"too_many_network_errors:{consecutive_errors}"
        return record

    for i in range(config.warmup_requests):
        klass, round_index, account = warmup_plan[0]
        run_one(10_000 + i, 0, klass, account)
        if stop_reason:
            return RunResult(records, plan, seed, config.warmup_requests + len(plan), sent, stop_reason)

    for item in plan:
        run_one(item.seq, item.round_index, item.klass, item.account)
        if stop_reason:
            break

    if stop_reason is None and sent < config.warmup_requests + len(plan):
        stop_reason = "stopped_early"
    return RunResult(records, plan, seed, config.warmup_requests + len(plan), sent, stop_reason)
