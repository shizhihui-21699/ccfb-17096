"""Terminal, JSON, and Markdown reporting."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .analyzer import AnalysisResult
from .runner import RunResult


VERDICT_LABELS = {
    "enumerable": "可枚举（强证据）",
    "likely_enumerable": "可能可枚举",
    "likely_enumerable_timing_side_channel": "可能存在时间侧信道枚举",
    "no_reliable_evidence_detected": "未发现可靠枚举证据",
    "inconclusive_insufficient_samples": "证据不足，无法结论",
    "blocked_by_rate_limit_or_challenge": "被限流/验证码阻断",
    "blocked_account_lockout_signal": "出现账号锁定信号，已停止",
}


def build_json_report(
    run: RunResult,
    analysis: AnalysisResult,
    *,
    target_url: str,
    mode: str,
    include_accounts: bool = False,
) -> dict[str, Any]:
    return {
        "tool": "account-enum-detector",
        "authorized_testing_notice": "Use only under explicit authorization and on test-owned/safe accounts.",
        "target_url": target_url,
        "mode": mode,
        "seed": run.seed,
        "verdict": analysis.verdict,
        "verdict_label": VERDICT_LABELS.get(analysis.verdict, analysis.verdict),
        "confidence": analysis.confidence,
        "summary": analysis.summary,
        "counts": analysis.sample_counts,
        "successful_counts": analysis.successful_counts,
        "defense": analysis.defense,
        "timing": analysis.timing,
        "findings": [f.to_dict() for f in analysis.findings],
        "records": [r.to_dict(include_accounts=include_accounts) for r in run.records],
    }


def write_json_report(path: str | Path, report: dict[str, Any]) -> None:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")


def _timing_line(name: str, report: dict[str, Any] | None) -> str | None:
    if not report:
        return None
    ex = report.get("existing") or {}
    other = report.get("comparison") or {}
    if not ex or not other:
        return None
    return (
        f"- {name}: existing median={ex.get('median_ms')}ms "
        f"(n={ex.get('n')}, MAD={ex.get('mad_ms')}); "
        f"control median={other.get('median_ms')}ms (n={other.get('n')}); "
        f"Δmedian={report.get('existing_minus_nonexisting_median_ms')}ms; "
        f"95% CI={report.get('bootstrap_95ci_ms')}; rank-p={report.get('rank_permutation_p_value')}; "
        f"Cliff δ={report.get('cliffs_delta')}; => {report.get('classification')}"
    )


def render_terminal(run: RunResult, analysis: AnalysisResult) -> str:
    label = VERDICT_LABELS.get(analysis.verdict, analysis.verdict)
    lines: list[str] = []
    lines.append("=" * 78)
    lines.append(f"结论: {label}  [confidence={analysis.confidence}]")
    lines.append(analysis.summary)
    lines.append("-" * 78)
    lines.append(
        "样本: "
        + ", ".join(f"{k}={v}" for k, v in analysis.sample_counts.items())
    )
    lines.append(
        "成功HTTP响应: "
        + ", ".join(f"{k}={v}" for k, v in analysis.successful_counts.items())
    )
    if run.stop_reason:
        lines.append(f"停止原因: {run.stop_reason}")

    defense = analysis.defense
    if defense.get("reason_counts"):
        lines.append(f"防护信号: {defense['reason_counts']}")

    lines.append("-" * 78)
    lines.append("发现:")
    if not analysis.findings:
        lines.append("  (无显著差异)")
    for finding in analysis.findings:
        lines.append(f"  [{finding.verdict_weight.upper()}] {finding.title}")
        ev = finding.evidence
        if finding.kind == "status_code_oracle":
            lines.append(f"    existing={ev.get('existing_status_counts')}")
            lines.append(f"    nonexisting={ev.get('nonexisting_status_counts')}")
        elif finding.kind in {"body_message_oracle", "body_message_difference_unstable", "body_signature_noise"}:
            lines.append(
                "    sigs ex/non="
                f"{ev.get('existing_signature_count')}/{ev.get('nonexisting_signature_count')}, "
                f"representative_similarity={ev.get('representative_similarity')}"
            )
            excerpt_a = (ev.get("existing_body_excerpt") or "").replace("\n", " ")[:180]
            excerpt_b = (ev.get("nonexisting_body_excerpt") or "").replace("\n", " ")[:180]
            lines.append(f"    existing[{ev.get('existing_example_seq')}]: {excerpt_a}")
            lines.append(f"    nonexisting[{ev.get('nonexisting_example_seq')}]: {excerpt_b}")
            if ev.get("normalized_diff"):
                lines.append("    normalized diff (first lines):")
                for diff_line in ev["normalized_diff"].splitlines()[:18]:
                    lines.append("      " + diff_line[:220])
        elif finding.kind == "header_oracle":
            for header, values in (ev.get("headers") or {}).items():
                lines.append(f"    {header}: existing={values.get('existing_values')} non={values.get('nonexisting_values')}")
        elif finding.kind == "content_length_difference":
            lines.append(f"    {ev.get('content_length')}")
        elif finding.kind == "cache_header_confounder":
            lines.append(f"    cache headers={list((ev.get('cache_headers') or {}).keys())}")
        elif finding.kind in {"timing_oracle", "timing_analysis"}:
            primary = ev.get("existing_vs_unique_nonexisting") or {}
            line = _timing_line("existing vs unique nonexisting(TTFB)", primary)
            if line:
                lines.append("  " + line)
            hot = _timing_line("existing vs repeated/hot nonexisting", ev.get("existing_vs_repeated_nonexisting_hot"))
            if hot:
                lines.append("  " + hot)
            cache = _timing_line("unique/cold vs repeated/hot cache effect", ev.get("unique_cold_vs_repeated_hot_cache_effect"))
            if cache:
                lines.append("  " + cache)
            if ev.get("cache_confounder_warning"):
                lines.append(f"    WARNING: {ev['cache_confounder_warning']}")

    lines.append("-" * 78)
    lines.append("逐请求证据（账号默认脱敏）:")
    for r in run.records:
        timing = f"ttfb={r.ttfb_ms}ms total={r.total_ms}ms" if r.ttfb_ms is not None else f"error={r.error}"
        defense_txt = f" defense={','.join(r.defense_reasons)}" if r.defense_reasons else ""
        lines.append(
            f"  #{r.seq:<5} r{r.round_index:<2} {r.klass:<18} {r.account_masked:<28} "
            f"status={r.status} len={r.body_length:<6} {timing}{defense_txt}"
        )
    lines.append("=" * 78)
    return "\n".join(lines)


def render_markdown(report: dict[str, Any]) -> str:
    lines: list[str] = []
    lines.append("# 账号枚举检测报告")
    lines.append("")
    lines.append(f"- 目标: `{report['target_url']}`")
    lines.append(f"- 模式: `{report['mode']}`")
    lines.append(f"- 结论: **{report['verdict_label']}**")
    lines.append(f"- 置信度: `{report['confidence']}`")
    lines.append(f"- 随机顺序种子: `{report['seed']}`")
    lines.append("")
    lines.append("## 结论说明")
    lines.append("")
    lines.append(report["summary"])
    lines.append("")
    lines.append("## 样本与防护")
    lines.append("")
    lines.append("```json")
    lines.append(json.dumps({
        "counts": report["counts"],
        "successful_counts": report["successful_counts"],
        "defense": report["defense"],
    }, ensure_ascii=False, indent=2))
    lines.append("```")
    lines.append("")
    lines.append("## 发现与证据")
    lines.append("")
    if not report["findings"]:
        lines.append("未发现显著差异。")
    for finding in report["findings"]:
        lines.append(f"### [{finding['verdict_weight']}] {finding['title']}")
        lines.append("")
        lines.append("```json")
        lines.append(json.dumps(finding["evidence"], ensure_ascii=False, indent=2)[:20000])
        lines.append("```")
        lines.append("")
    lines.append("## 逐请求记录")
    lines.append("")
    lines.append("| seq | round | class | account | status | length | TTFB ms | total ms | defense | error |")
    lines.append("|---:|---:|---|---|---|---:|---:|---:|---|---|")
    for r in report["records"]:
        lines.append(
            f"| {r['seq']} | {r['round_index']} | {r['klass']} | `{r['account_masked']}` | "
            f"{r['status'] if r['status'] is not None else ''} | {r['body_length']} | "
            f"{r['ttfb_ms'] if r['ttfb_ms'] is not None else ''} | "
            f"{r['total_ms'] if r['total_ms'] is not None else ''} | "
            f"{', '.join(r['defense_reasons'])} | {r['error'] or ''} |"
        )
    lines.append("")
    lines.append("> 本工具只做低请求量、顺序、带防护停止的验证；时间结论需结合授权测试环境和缓存状态复核。")
    return "\n".join(lines)
