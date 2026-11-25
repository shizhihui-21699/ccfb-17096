"""Command-line interface."""
from __future__ import annotations

import argparse
import os
import random
import sys
from pathlib import Path
from typing import Sequence
from urllib.parse import urlparse

from .analyzer import analyze
from .errors import AccountEnumToolError
from .payload import BodyConfig, build_body, default_nonexistent_pattern, render_account_pattern
from .report import build_json_report, render_markdown, render_terminal, write_json_report
from .runner import ScanConfig, build_plan, execute
from .safety import mask_account


EXIT_NO_EVIDENCE = 0
EXIT_ENUMERABLE = 10
EXIT_LIKELY = 11
EXIT_INCONCLUSIVE = 2
EXIT_ERROR = 1


def _parse_headers(values: Sequence[str] | None) -> dict[str, str]:
    headers: dict[str, str] = {}
    for item in values or []:
        if ":" not in item:
            raise AccountEnumToolError(f"Invalid --header {item!r}; expected 'Name: value'")
        key, value = item.split(":", 1)
        key, value = key.strip(), value.strip()
        if not key:
            raise AccountEnumToolError(f"Invalid empty header name in {item!r}")
        headers[key] = value
    return headers


def _parse_fields(values: Sequence[str] | None) -> dict[str, str]:
    fields: dict[str, str] = {}
    for item in values or []:
        if "=" not in item:
            raise AccountEnumToolError(f"Invalid --field {item!r}; expected key=value")
        key, value = item.split("=", 1)
        fields[key.strip()] = value
    return fields


def _read_known_accounts(args: argparse.Namespace) -> list[str]:
    accounts: list[str] = []
    accounts.extend(a.strip() for a in (args.known or []))
    if args.known_file:
        for path in args.known_file:
            text = Path(path).read_text(encoding="utf-8")
            for line in text.splitlines():
                line = line.strip()
                if line and not line.startswith("#"):
                    accounts.append(line)
    # Preserve order and de-duplicate.
    return list(dict.fromkeys(accounts))


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="account-enum-detector",
        description="Authorized account-enumeration detector for login, password-reset, and registration APIs.",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    scan = sub.add_parser("scan", help="run a safe interleaved enumeration check")
    scan.add_argument("--url", required=True, help="Full endpoint URL. {{account}} may be placed in query/path too.")
    scan.add_argument("--method", default="POST", choices=["GET", "POST", "PUT", "PATCH"], help="HTTP method")
    scan.add_argument("--mode", default="generic", choices=["login", "password-reset", "register", "generic"])

    scan.add_argument("--known", action="append", help="Known/test-owned existing account; repeatable")
    scan.add_argument("--known-file", action="append", help="File with one known account per line; repeatable")
    scan.add_argument(
        "--nonexistent-pattern",
        help="Pattern for unique non-existing accounts, e.g. nx-{{uuid}} or nx-{{uuid}}@example.com",
    )
    scan.add_argument(
        "--cached-nonexistent-account",
        help="Fixed non-existing account repeated as a hot-cache control; generated automatically if omitted",
    )
    scan.add_argument("--samples-per-class", type=int, default=5)
    scan.add_argument("--warmup-requests", type=int, default=1)
    scan.add_argument("--no-cache-control", action="store_true", help="Disable repeated non-existing cache control cohort")

    scan.add_argument("--body", help="Raw/JSON request body template containing {{account}}")
    scan.add_argument("--body-file", help="Read request body template from file")
    scan.add_argument("--content-type", default="application/json")
    scan.add_argument("--account-field", default="username", help="Field name when no --body template is supplied")
    scan.add_argument("--password-field", default="password")
    scan.add_argument("--field", action="append", help="Extra body field key=value; repeatable")
    scan.add_argument("--password", help="One fixed invalid test password. Prefer --password-env to avoid shell history.")
    scan.add_argument("--password-env", default="AEA_TEST_PASSWORD", help="Environment variable containing test password")

    scan.add_argument("--header", action="append", help="HTTP header 'Name: value'; repeatable")
    scan.add_argument("--proxy", help="HTTP/HTTPS proxy, e.g. http://127.0.0.1:8080 for Burp")
    scan.add_argument("--insecure", action="store_true", help="Skip TLS verification (useful with an intercepting proxy)")
    scan.add_argument("--timeout", type=float, default=15.0)

    scan.add_argument("--delay", type=float, default=1.0, help="Minimum delay between requests, seconds")
    scan.add_argument("--jitter", type=float, default=0.75, help="Random extra delay, seconds")
    scan.add_argument("--request-cap", type=int, default=40, help="Maximum total requests; absolute tool max is 100")
    scan.add_argument(
        "--max-known-probes-per-account",
        type=int,
        default=None,
        help="Default is 1, or 3 when --allow-known-reuse is used; 3 is the hard cap",
    )
    scan.add_argument(
        "--allow-known-reuse",
        action="store_true",
        help="Allow cycling known accounts. Risky for login/reset; use test-owned accounts only.",
    )
    scan.add_argument("--seed", type=int, help="Fixed ordering/bootstrap seed for reproducible test runs")

    scan.add_argument("--min-timing-diff-ms", type=float, default=30.0)
    scan.add_argument("--min-timing-ratio", type=float, default=1.15)
    scan.add_argument("--min-cliffs-delta", type=float, default=0.55)

    scan.add_argument("--json-out", help="Write full JSON report here")
    scan.add_argument("--markdown-out", help="Write Markdown report here")
    scan.add_argument("--out-dir", help="Directory for report.json and report.md")
    scan.add_argument("--include-accounts", action="store_true", help="Include unmasked accounts in JSON output")
    scan.add_argument("--quiet", action="store_true", help="Do not print terminal report")
    scan.add_argument("--dry-run", action="store_true", help="Build and print the safe request plan without sending")
    scan.add_argument(
        "--i-am-authorized",
        action="store_true",
        help="Confirm explicit authorization and permission to send low-volume probes to this target",
    )
    scan.add_argument(
        "--confirm-known-accounts-safe",
        action="store_true",
        help="Required for login/password-reset or known-account reuse: known accounts are test-owned or safe to probe",
    )
    return parser


def _make_scan_config(args: argparse.Namespace) -> ScanConfig:
    parsed_url = urlparse(args.url)
    if parsed_url.scheme not in {"http", "https"} or not parsed_url.netloc:
        raise AccountEnumToolError("--url must be a valid http(s) URL")

    known = _read_known_accounts(args)
    if not known:
        raise AccountEnumToolError("Provide at least one --known account or --known-file")

    pattern = args.nonexistent_pattern or default_nonexistent_pattern(known)
    sample_pattern_a = render_account_pattern(pattern, 0)
    sample_pattern_b = render_account_pattern(pattern, 1)
    if sample_pattern_a == sample_pattern_b:
        raise AccountEnumToolError(
            "--nonexistent-pattern must contain a varying token such as {{uuid}} or {uuid}; "
            f"pattern {pattern!r} produced repeated samples"
        )

    template = None
    if args.body_file:
        template = Path(args.body_file).read_text(encoding="utf-8")
    elif args.body is not None:
        template = args.body

    account_in_url = "{{account}}" in args.url
    if args.method.upper() in {"GET", "HEAD"} and not account_in_url:
        raise AccountEnumToolError("GET/HEAD checks need {{account}} in the URL query or path")
    if template is not None and "{{account}}" not in template and not account_in_url:
        raise AccountEnumToolError(
            "--body/--body-file must contain {{account}}, or place {{account}} in the URL"
        )

    password = args.password if args.password is not None else os.environ.get(args.password_env)
    body_config = BodyConfig(
        content_type=args.content_type,
        template=template,
        password=password,
        account_field=args.account_field,
        password_field=args.password_field,
        extra_fields=_parse_fields(args.field),
        mode=args.mode,
    )
    if body_config.uses_password() and not password:
        raise AccountEnumToolError(
            f"This request needs a password. Set --password or export {args.password_env}; "
            "use one deliberately invalid credential on a test-owned account."
        )

    headers = _parse_headers(args.header)
    if args.max_known_probes_per_account is None:
        max_known_probes = 3 if args.allow_known_reuse else 1
    else:
        max_known_probes = args.max_known_probes_per_account
    return ScanConfig(
        url=args.url,
        known_accounts=known,
        nonexistent_pattern=pattern,
        cached_nonexistent_account=args.cached_nonexistent_account,
        body_config=body_config,
        method=args.method.upper(),
        headers=headers,
        samples_per_class=args.samples_per_class,
        warmup_requests=args.warmup_requests,
        delay_seconds=max(0.0, args.delay),
        jitter_seconds=max(0.0, args.jitter),
        timeout_seconds=args.timeout,
        proxy=args.proxy,
        insecure=args.insecure,
        request_cap=args.request_cap,
        max_known_probes_per_account=max_known_probes,
        allow_known_reuse=args.allow_known_reuse,
        stop_on_defense=True,
        cache_control=not args.no_cache_control,
        seed=args.seed,
    )


def _print_dry_run(config: ScanConfig) -> int:
    plan, seed = build_plan(config, config.seed)
    total = config.warmup_requests + len(plan)
    print("DRY RUN — no requests will be sent")
    print(f"URL: {config.method} {config.url}")
    print(f"Seed: {seed}")
    print(f"Total requests including warm-up: {total} (cap={config.request_cap})")
    print(f"Delay: {config.delay_seconds}s + 0..{config.jitter_seconds}s jitter, sequential only")
    if config.method.upper() != "GET":
        sample_body = build_body(config.known_accounts[0], 1, config.body_config).decode("utf-8", "replace")
        if config.body_config.password:
            sample_body = sample_body.replace(config.body_config.password, "<redacted-password>")
        print(f"Sample body: {sample_body}")
    print("Plan order:")
    for i in range(config.warmup_requests):
        account = config.nonexistent_pattern.replace("{{uuid}}", "<warmup-uuid>").replace("{uuid}", "<warmup-uuid>")
        print(f"  warmup  {mask_account(account)}")
    for item in plan:
        print(f"  #{item.seq:<3} round={item.round_index} class={item.klass:<18} account={item.account}")
    return EXIT_NO_EVIDENCE


def cmd_scan(args: argparse.Namespace) -> int:
    config = _make_scan_config(args)
    if config.seed is None:
        config.seed = random.Random().randrange(1, 2**63 - 1)

    if args.dry_run:
        return _print_dry_run(config)

    authorized = args.i_am_authorized or os.environ.get("AEA_I_AM_AUTHORIZED") == "1"
    if not authorized:
        raise AccountEnumToolError(
            "Refusing to send probes without --i-am-authorized or AEA_I_AM_AUTHORIZED=1. "
            "Use only under explicit written authorization and prefer test-owned accounts."
        )

    accounts_confirmed_safe = (
        args.confirm_known_accounts_safe
        or os.environ.get("AEA_CONFIRM_KNOWN_ACCOUNTS_SAFE") == "1"
    )
    risky_account_operation = (
        config.body_config.mode in {"login", "password-reset"} or config.allow_known_reuse
    )
    if risky_account_operation and not accounts_confirmed_safe:
        raise AccountEnumToolError(
            "Login/password-reset/repeated-known-account checks require "
            "--confirm-known-accounts-safe or AEA_CONFIRM_KNOWN_ACCOUNTS_SAFE=1. "
            "Confirm these are test-owned or client-approved accounts and that one fixed invalid "
            "request per account will not lock out real users."
        )

    run = execute(config)
    analysis = analyze(
        run,
        min_timing_diff_ms=args.min_timing_diff_ms,
        min_timing_ratio=args.min_timing_ratio,
        min_cliffs_delta=args.min_cliffs_delta,
    )
    report = build_json_report(
        run,
        analysis,
        target_url=config.url,
        mode=args.mode,
        include_accounts=args.include_accounts,
    )

    if args.out_dir:
        out_dir = Path(args.out_dir)
        out_dir.mkdir(parents=True, exist_ok=True)
        write_json_report(out_dir / "report.json", report)
        (out_dir / "report.md").write_text(render_markdown(report), encoding="utf-8")
    if args.json_out:
        write_json_report(args.json_out, report)
    if args.markdown_out:
        markdown_path = Path(args.markdown_out)
        markdown_path.parent.mkdir(parents=True, exist_ok=True)
        markdown_path.write_text(render_markdown(report), encoding="utf-8")

    if not args.quiet:
        print(render_terminal(run, analysis))
        if args.json_out or args.markdown_out or args.out_dir:
            print("Reports written:")
            if args.out_dir:
                print(f"  {Path(args.out_dir) / 'report.json'}")
                print(f"  {Path(args.out_dir) / 'report.md'}")
            if args.json_out:
                print(f"  {args.json_out}")
            if args.markdown_out:
                print(f"  {args.markdown_out}")

    if analysis.verdict == "enumerable":
        return EXIT_ENUMERABLE
    if analysis.verdict.startswith("likely_enumerable"):
        return EXIT_LIKELY
    if analysis.verdict.startswith("blocked") or analysis.verdict == "inconclusive_insufficient_samples":
        return EXIT_INCONCLUSIVE
    return EXIT_NO_EVIDENCE


def main(argv: Sequence[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    try:
        if args.command == "scan":
            return cmd_scan(args)
        parser.error(f"Unknown command: {args.command}")
        return EXIT_ERROR
    except AccountEnumToolError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_ERROR
    except OSError as exc:
        print(f"file/network setup error: {exc}", file=sys.stderr)
        return EXIT_ERROR
    except KeyboardInterrupt:
        print("\ninterrupted; no further requests sent", file=sys.stderr)
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
