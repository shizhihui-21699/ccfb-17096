"""Turn probe records into a conservative, evidence-backed verdict."""
from __future__ import annotations

from collections import Counter
from difflib import SequenceMatcher, unified_diff
from typing import Any

from .models import AnalysisResult, Finding, ProbeRecord
from .normalize import DYNAMIC_HEADERS as NORMALIZED_DYNAMIC_HEADERS
from .runner import RunResult
from .stats import (
    bootstrap_median_diff_ci,
    cliffs_delta,
    describe,
    mann_whitney_permutation_p,
    median,
)

CACHE_HEADERS = {
    "age",
    "cache-control",
    "cf-cache-status",
    "x-cache",
    "x-cache-status",
    "x-cache-hits",
    "x-drupal-cache",
    "x-proxy-cache",
    "x-varnish-cache",
    "via",
}

HEADER_ORACLE_IGNORE = NORMALIZED_DYNAMIC_HEADERS | CACHE_HEADERS


def _ok_http(records: list[ProbeRecord]) -> list[ProbeRecord]:
    return [r for r in records if r.ok and r.status is not None]


def _similarity(a: str, b: str) -> float:
    if not a and not b:
        return 1.0
    return SequenceMatcher(None, a, b).ratio()


def _median_pairwise_similarity(texts: list[str]) -> float | None:
    if len(texts) < 2:
        return None
    sims: list[float] = []
    for i, a in enumerate(texts):
        for b in texts[i + 1 :]:
            sims.append(_similarity(a, b))
    return median(sims)


def _diff_text(a: str, b: str, limit: int = 5000) -> str:
    a_lines = a.splitlines() or [a]
    b_lines = b.splitlines() or [b]
    diff = "\n".join(
        unified_diff(a_lines, b_lines, fromfile="existing-normalized", tofile="nonexisting-normalized", n=2)
    )
    return diff[:limit]


def analyze_status(ex: list[ProbeRecord], non: list[ProbeRecord]) -> Finding | None:
    ex_counts = Counter(r.status for r in ex)
    non_counts = Counter(r.status for r in non)
    ex_set = set(ex_counts)
    non_set = set(non_counts)
    if not ex_set or not non_set or not ex_set.isdisjoint(non_set):
        return None

    uniform = len(ex_set) == 1 and len(non_set) == 1
    return Finding(
        kind="status_code_oracle",
        verdict_weight="strong" if uniform else "moderate",
        title="状态码存在稳定的账号类别差异",
        evidence={
            "uniform": uniform,
            "existing_status_counts": {str(k): v for k, v in ex_counts.items()},
            "nonexisting_status_counts": {str(k): v for k, v in non_counts.items()},
            "example_existing_seq": next((r.seq for r in ex), None),
            "example_nonexisting_seq": next((r.seq for r in non), None),
        },
    )


def analyze_body(ex: list[ProbeRecord], non: list[ProbeRecord]) -> Finding | None:
    if not ex or not non:
        return None

    ex_sig = Counter(r.normalized_sha256 or "<empty>" for r in ex)
    non_sig = Counter(r.normalized_sha256 or "<empty>" for r in non)
    ex_set, non_set = set(ex_sig), set(non_sig)
    disjoint = ex_set.isdisjoint(non_set)

    ex_rep = max(ex, key=lambda r: ex_sig[r.normalized_sha256 or "<empty>"])
    non_rep = max(non, key=lambda r: non_sig[r.normalized_sha256 or "<empty>"])
    similarity = _similarity(ex_rep.normalized_body, non_rep.normalized_body)
    diff = _diff_text(ex_rep.normalized_body, non_rep.normalized_body)

    within_ex = _median_pairwise_similarity([r.normalized_body for r in ex])
    within_non = _median_pairwise_similarity([r.normalized_body for r in non])

    base_evidence = {
        "signature_sets_disjoint": disjoint,
        "existing_signature_count": len(ex_set),
        "nonexisting_signature_count": len(non_set),
        "existing_signature_counts": dict(ex_sig),
        "nonexisting_signature_counts": dict(non_sig),
        "representative_similarity": round(similarity, 4),
        "median_within_existing_similarity": round(within_ex, 4) if within_ex is not None else None,
        "median_within_nonexisting_similarity": round(within_non, 4) if within_non is not None else None,
        "existing_example_seq": ex_rep.seq,
        "nonexisting_example_seq": non_rep.seq,
        "existing_body_excerpt": ex_rep.body_excerpt[:500],
        "nonexisting_body_excerpt": non_rep.body_excerpt[:500],
        "normalized_diff": diff,
    }

    if not disjoint:
        return None

    uniform = len(ex_set) == 1 and len(non_set) == 1
    repeated_templates = max(ex_sig.values()) >= 2 and max(non_sig.values()) >= 2
    stable_similarity = (
        (within_ex is None or within_ex >= 0.85)
        and (within_non is None or within_non >= 0.85)
    )

    if uniform:
        return Finding(
            kind="body_message_oracle",
            verdict_weight="strong",
            title="响应正文/提示语在所有样本中按账号是否存在稳定区分",
            evidence={**base_evidence, "separation": "uniform_signatures"},
        )
    if repeated_templates and stable_similarity:
        return Finding(
            kind="body_message_oracle",
            verdict_weight="strong",
            title="响应正文存在可重复且按账号类别分离的模板",
            evidence={**base_evidence, "separation": "repeated_class_specific_templates"},
        )
    if stable_similarity and similarity < 0.995:
        return Finding(
            kind="body_message_difference_unstable",
            verdict_weight="moderate",
            title="观察到正文差异，但归一化签名尚未在每组中完全稳定",
            evidence={**base_evidence, "separation": "similarity_gap_but_unstable_signatures"},
        )

    return Finding(
        kind="body_signature_noise",
        verdict_weight="info",
        title="正文签名互不相同，可能是动态内容/归一化不足，不能单独作为枚举证据",
        evidence={**base_evidence, "separation": "all_signatures_unique_or_unstable"},
    )


def analyze_headers(ex: list[ProbeRecord], non: list[ProbeRecord]) -> list[Finding]:
    if not ex or not non:
        return []
    keys = set()
    for r in ex + non:
        keys.update(r.headers_normalized.keys())

    differences: dict[str, dict[str, Any]] = {}

    for key in sorted(keys):
        ex_values = Counter(r.headers_normalized.get(key, "<absent>") for r in ex)
        non_values = Counter(r.headers_normalized.get(key, "<absent>") for r in non)
        ex_vals, non_vals = set(ex_values), set(non_values)
        if ex_vals and non_vals and ex_vals.isdisjoint(non_vals):
            entry = {
                "existing_values": dict(ex_values),
                "nonexisting_values": dict(non_values),
            }
            differences[key] = entry

    findings: list[Finding] = []
    if not differences:
        return findings

    independent = {
        k: v
        for k, v in differences.items()
        if k != "content-length" and k not in HEADER_ORACLE_IGNORE
    }
    if independent:
        strong_key = any(k in {"location", "www-authenticate"} for k in independent)
        findings.append(
            Finding(
                kind="header_oracle",
                verdict_weight="strong" if strong_key else "moderate",
                title="响应头存在稳定的账号类别差异",
                evidence={"headers": independent, "all_differences": differences},
            )
        )
    elif "content-length" in differences:
        findings.append(
            Finding(
                kind="content_length_difference",
                verdict_weight="info",
                title="Content-Length 随正文差异变化（属于正文证据的一部分，不是独立头部预言机）",
                evidence={"content_length": differences.get("content-length")},
            )
        )

    cache_diffs = {k: v for k, v in differences.items() if k in CACHE_HEADERS}
    if cache_diffs:
        findings.append(
            Finding(
                kind="cache_header_confounder",
                verdict_weight="info",
                title="缓存相关响应头存在差异；这可能是缓存状态而不是账号查询时间/内容差异",
                evidence={"cache_headers": cache_diffs},
            )
        )
    return findings


def assess_timing_pair(
    a: list[float],
    b: list[float],
    *,
    min_diff_ms: float,
    min_ratio: float,
    min_cliffs_delta: float,
    seed_offset: int = 0,
) -> dict[str, Any]:
    result: dict[str, Any] = {
        "existing": describe(a),
        "comparison": describe(b),
        "sample_size_ok": len(a) >= 4 and len(b) >= 4,
    }
    if len(a) < 2 or len(b) < 2:
        result["classification"] = "insufficient_data"
        return result

    ci = bootstrap_median_diff_ci(a, b, seed=20261126 + seed_offset)
    p_value = mann_whitney_permutation_p(a, b, seed=20261127 + seed_offset)
    delta = cliffs_delta(a, b)
    diff = ci["difference_ms"]
    med_a, med_b = median(a), median(b)
    ratio = None
    if med_a is not None and med_b is not None and min(med_a, med_b) > 0:
        ratio = max(med_a / med_b, med_b / med_a)

    ci_excludes_zero = (
        ci.get("low_ms") is not None
        and ci.get("high_ms") is not None
        and (ci["low_ms"] > 0 or ci["high_ms"] < 0)
    )
    practical = (
        diff is not None
        and abs(diff) >= min_diff_ms
        and ratio is not None
        and ratio >= min_ratio
    )
    large_effect = delta is not None and abs(delta) >= min_cliffs_delta
    statistically_supported = ci_excludes_zero and (p_value is not None and p_value <= 0.05)

    if result["sample_size_ok"] and practical and large_effect and statistically_supported:
        classification = "strong_timing_oracle"
    elif practical and delta is not None and abs(delta) >= max(0.40, min_cliffs_delta - 0.15):
        classification = "suspicious_timing_difference"
    else:
        classification = "no_reliable_timing_evidence"

    result.update(
        {
            "classification": classification,
            "existing_minus_nonexisting_median_ms": diff,
            "bootstrap_95ci_ms": [ci.get("low_ms"), ci.get("high_ms")],
            "rank_permutation_p_value": round(p_value, 5) if p_value is not None else None,
            "cliffs_delta": round(delta, 3) if delta is not None else None,
            "median_ratio": round(ratio, 3) if ratio is not None else None,
            "ci_excludes_zero": ci_excludes_zero,
            "practical_threshold_met": practical,
            "large_effect_met": large_effect,
        }
    )
    return result


def analyze_timing(
    ex: list[ProbeRecord],
    non_fresh: list[ProbeRecord],
    non_cached: list[ProbeRecord],
    *,
    min_diff_ms: float,
    min_ratio: float,
    min_cliffs_delta: float,
) -> tuple[Finding | None, dict[str, Any]]:
    ex_ttfb = [r.ttfb_ms for r in ex if r.ttfb_ms is not None]
    fresh_ttfb = [r.ttfb_ms for r in non_fresh if r.ttfb_ms is not None]
    # First hit to the repeated key is a cache miss; exclude it from hot-cache stats.
    cached_hot = [r for r in non_cached if r.round_index > 1]
    cached_ttfb = [r.ttfb_ms for r in cached_hot if r.ttfb_ms is not None]

    primary = assess_timing_pair(
        ex_ttfb,
        fresh_ttfb,
        min_diff_ms=min_diff_ms,
        min_ratio=min_ratio,
        min_cliffs_delta=min_cliffs_delta,
        seed_offset=0,
    )
    existing_vs_hot = None
    cache_effect = None
    if cached_ttfb:
        existing_vs_hot = assess_timing_pair(
            ex_ttfb,
            cached_ttfb,
            min_diff_ms=min_diff_ms,
            min_ratio=min_ratio,
            min_cliffs_delta=min_cliffs_delta,
            seed_offset=10,
        )
        cache_effect = assess_timing_pair(
            fresh_ttfb,
            cached_ttfb,
            min_diff_ms=min_diff_ms,
            min_ratio=min_ratio,
            min_cliffs_delta=min_cliffs_delta,
            seed_offset=20,
        )

    timing_report = {
        "metric": "time_to_response_headers_ttfb",
        "thresholds": {
            "min_median_difference_ms": min_diff_ms,
            "min_median_ratio": min_ratio,
            "min_absolute_cliffs_delta": min_cliffs_delta,
        },
        "existing_vs_unique_nonexisting": primary,
        "existing_vs_repeated_nonexisting_hot": existing_vs_hot,
        "unique_cold_vs_repeated_hot_cache_effect": cache_effect,
        "total_ms_existing": describe([r.total_ms for r in ex if r.total_ms is not None]),
        "total_ms_nonexisting_unique": describe([r.total_ms for r in non_fresh if r.total_ms is not None]),
    }

    classification = primary.get("classification")
    if classification not in {"strong_timing_oracle", "suspicious_timing_difference"}:
        finding = Finding(
            kind="timing_analysis",
            verdict_weight="info",
            title="时间统计未达到可靠枚举判定阈值",
            evidence=timing_report,
        )
        return finding, timing_report

    cache_confounded = False
    if (
        cache_effect
        and cache_effect.get("practical_threshold_met")
        and existing_vs_hot
        and existing_vs_hot.get("classification") == "no_reliable_timing_evidence"
    ):
        cache_confounded = True
        timing_report["cache_confounder_warning"] = (
            "唯一不存在账号看起来更慢/更快，但冷热缓存对照也有同等差异，"
            "且 existing 与热缓存不存在账号之间不稳定；时间差可能来自缓存路径。"
        )

    weight = "moderate"
    title = "响应时间存在可疑统计差异"
    if classification == "strong_timing_oracle" and not cache_confounded:
        title = "响应时间存在稳定且显著的统计差异，可能形成时间侧信道枚举"
    if cache_confounded:
        title = "观察到时间差，但缓存/冷热路径可以解释，不能可靠判定为账号枚举"
        weight = "info"

    finding = Finding(
        kind="timing_oracle",
        verdict_weight=weight,
        title=title,
        evidence=timing_report,
    )
    return finding, timing_report


def analyze(
    run: RunResult,
    *,
    min_timing_diff_ms: float = 30.0,
    min_timing_ratio: float = 1.15,
    min_cliffs_delta: float = 0.55,
) -> AnalysisResult:
    probe_records = [r for r in run.records if r.klass != "warmup"]
    ex_all = [r for r in probe_records if r.klass == "existing"]
    non_all = [r for r in probe_records if r.klass == "nonexisting"]
    cached_all = [r for r in probe_records if r.klass == "nonexisting_cached"]

    ex = _ok_http(ex_all)
    non = _ok_http(non_all)
    cached = _ok_http(cached_all)

    defense_records = [r for r in run.records if r.defense_reasons]
    defense_reasons = Counter(reason for r in defense_records for reason in r.defense_reasons)
    account_lockout = any("account_lockout" in r.defense_reasons for r in defense_records)
    defense_blocked = bool(defense_records) or bool(run.stop_reason and run.stop_reason.startswith("defense_signal"))
    network_errors = [r for r in probe_records if not r.ok]

    findings: list[Finding] = []
    status_finding = analyze_status(ex, non)
    if status_finding:
        findings.append(status_finding)

    body_finding = analyze_body(ex, non)
    if body_finding:
        findings.append(body_finding)

    findings.extend(analyze_headers(ex, non))

    timing_finding, timing_report = analyze_timing(
        ex,
        non,
        cached,
        min_diff_ms=min_timing_diff_ms,
        min_ratio=min_timing_ratio,
        min_cliffs_delta=min_cliffs_delta,
    )
    if timing_finding:
        findings.append(timing_finding)

    strong = [f for f in findings if f.verdict_weight == "strong"]
    moderate = [f for f in findings if f.verdict_weight == "moderate"]
    strong_oracle = [
        f for f in strong if f.kind in {"status_code_oracle", "body_message_oracle", "header_oracle"}
    ]
    moderate_oracle = [
        f for f in moderate if f.kind in {"status_code_oracle", "body_message_oracle", "header_oracle"}
    ]
    enough_for_deterministic = len(ex) >= 2 and len(non) >= 2
    timing_reliable = bool(
        timing_finding
        and timing_finding.verdict_weight in {"moderate", "strong"}
        and not timing_report.get("cache_confounder_warning")
    )

    if account_lockout:
        verdict = "blocked_account_lockout_signal"
        confidence = "high"
        summary = (
            "响应中出现账号锁定/过多失败尝试信号，工具已立即停止。请联系账号负责人确认状态，"
            "不要继续对该账号发送失败登录请求。"
        )
    elif strong_oracle and enough_for_deterministic:
        verdict = "enumerable"
        confidence = "high" if len(ex) >= 3 and len(non) >= 3 else "medium"
        summary = "状态码、正文提示或关键响应头中存在可稳定复现的账号类别差异，可判定存在账号枚举风险。"
        if defense_blocked:
            summary += " 检测过程中出现限流/验证码等防护信号，工具已停止；建议在授权白名单或测试环境中完成更大样本复测。"
    elif moderate_oracle and enough_for_deterministic:
        verdict = "likely_enumerable"
        confidence = "medium"
        summary = "观察到较稳定但非完全一致的响应差异，大概率存在账号枚举，建议用更多授权测试账号或人工复核证据。"
        if defense_blocked:
            summary += " 后续请求已被限流/验证码等防护信号中断。"
    elif defense_blocked:
        verdict = "blocked_by_rate_limit_or_challenge"
        confidence = "high"
        summary = (
            "检测到限流、验证码、人机验证或 Retry-After 信号并已停止。当前样本不足以给出可靠枚举结论；"
            "应在授权窗口、测试账号或隔离环境中降速/加白后复测，工具不会尝试绕过这些控制。"
        )
    elif len(ex) < 2 or len(non) < 2:
        verdict = "inconclusive_insufficient_samples"
        confidence = "low"
        summary = "成功获得的 existing/nonexisting 响应过少，无法稳定比较；请检查网络、TLS、请求模板或接口参数。"
    elif timing_reliable:
        verdict = "likely_enumerable_timing_side_channel"
        confidence = "medium" if len(ex) >= 5 and len(non) >= 5 else "low"
        summary = "响应时间差异通过了阈值、效应量和 bootstrap/rank permutation 统计筛选，但时间侧信道仍需在低抖动/等缓存条件下复测。"
    elif body_finding and body_finding.verdict_weight == "moderate":
        verdict = "likely_enumerable"
        confidence = "low"
        summary = "正文存在可疑差异，但动态内容或样本量导致签名不够稳定，需要人工复核 diff 并增加测试账号。"
    else:
        verdict = "no_reliable_evidence_detected"
        confidence = "medium" if len(ex) >= 5 and len(non) >= 5 else "low"
        summary = (
            "在本次样本量和阈值下，未发现稳定的状态码/正文/响应头差异，也未发现可靠的统计时间差。"
            "这不等同于接口绝对安全；验证码、限流、缓存或样本不足都可能掩盖差异。"
        )

    defense_report = {
        "blocked": defense_blocked,
        "account_lockout_signal": account_lockout,
        "stop_reason": run.stop_reason,
        "reason_counts": dict(defense_reasons),
        "defense_record_seqs": [r.seq for r in defense_records],
        "network_error_count": len(network_errors),
        "network_errors": [
            {"seq": r.seq, "klass": r.klass, "error": r.error}
            for r in network_errors[:10]
        ],
    }

    return AnalysisResult(
        verdict=verdict,
        confidence=confidence,
        summary=summary,
        sample_counts={
            "existing": len(ex_all),
            "nonexisting_unique": len(non_all),
            "nonexisting_cached": len(cached_all),
            "warmup": len([r for r in run.records if r.klass == "warmup"]),
            "planned_total": run.planned_request_count,
            "sent": run.sent_request_count,
        },
        successful_counts={
            "existing_http_responses": len(ex),
            "nonexisting_unique_http_responses": len(non),
            "nonexisting_cached_http_responses": len(cached),
        },
        defense=defense_report,
        timing=timing_report,
        findings=findings,
    )
