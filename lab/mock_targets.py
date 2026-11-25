#!/usr/bin/env python3
"""Local vulnerable/non-vulnerable mock endpoints for safe verification.

Run:
    python3 lab/mock_targets.py --port 18080

All data is in-memory and the server binds to 127.0.0.1 by default.
"""
from __future__ import annotations

import argparse
import json
import time
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs

KNOWN_ACCOUNTS = {f"user{i}@example.test" for i in range(1, 9)}
REQUEST_COUNTS: dict[str, int] = {}


def _parse_request(handler: BaseHTTPRequestHandler) -> dict[str, str]:
    length = int(handler.headers.get("Content-Length", "0") or "0")
    raw = handler.rfile.read(length) if length else b""
    content_type = handler.headers.get("Content-Type", "")
    if "application/json" in content_type:
        try:
            data = json.loads(raw.decode("utf-8"))
            return {str(k): str(v) for k, v in data.items()}
        except json.JSONDecodeError:
            return {}
    if "x-www-form-urlencoded" in content_type:
        parsed = parse_qs(raw.decode("utf-8"))
        return {k: v[0] for k, v in parsed.items() if v}
    return {}


def _send(handler: BaseHTTPRequestHandler, status: int, payload: dict, extra_headers=None) -> None:
    payload = dict(payload)
    payload.setdefault("request_id", uuid.uuid4().hex)
    payload.setdefault("timestamp", int(time.time()))
    body = json.dumps(payload, ensure_ascii=False, indent=2).encode("utf-8")
    handler.send_response(status)
    handler.send_header("Content-Type", "application/json; charset=utf-8")
    handler.send_header("Content-Length", str(len(body)))
    handler.send_header("X-Request-Id", uuid.uuid4().hex)
    if extra_headers:
        for key, value in extra_headers.items():
            handler.send_header(key, value)
    handler.end_headers()
    handler.wfile.write(body)


class Handler(BaseHTTPRequestHandler):
    server_version = "EnumLab/1.0"

    def log_message(self, fmt: str, *args) -> None:  # quieter test server
        return

    def do_POST(self) -> None:  # noqa: N802
        data = _parse_request(self)
        account = data.get("username") or data.get("email") or data.get("account") or ""
        path = self.path.split("?", 1)[0].rstrip("/")

        if path == "/login-message":
            if account in KNOWN_ACCOUNTS:
                _send(self, 401, {"code": 1002, "status": "error", "message": "密码错误，请检查后重试"})
            else:
                _send(self, 401, {"code": 1001, "status": "error", "message": "账号不存在"})
            return

        if path == "/login-status":
            if account in KNOWN_ACCOUNTS:
                _send(self, 401, {"code": "BAD_PASSWORD", "message": "invalid credentials"})
            else:
                _send(self, 404, {"code": "USER_NOT_FOUND", "message": "account does not exist"})
            return

        if path == "/register":
            if account in KNOWN_ACCOUNTS:
                _send(self, 409, {"code": "ALREADY_EXISTS", "message": "该账号已注册，请直接登录"})
            else:
                _send(self, 201, {"code": "CREATED", "message": "注册成功"})
            return

        if path == "/reset-generic":
            # Deliberately identical response for both states.
            _send(self, 200, {"code": "ACCEPTED", "message": "如果该账号存在，重置链接将发送到对应邮箱"})
            return

        if path == "/timing":
            # Existing accounts perform an expensive password hash; non-existing return early.
            if account in KNOWN_ACCOUNTS:
                time.sleep(0.09)
            else:
                time.sleep(0.006)
            _send(self, 401 if account in KNOWN_ACCOUNTS else 404, {"ok": False})
            return

        if path == "/cache-timing":
            # Unique accounts are cold; repeated control/existing hot path is fast.
            hot_control = account == "ae-cache-hot@example.test"
            unique = account not in KNOWN_ACCOUNTS and not hot_control
            if unique:
                time.sleep(0.08)
                cache_state = "MISS"
            else:
                time.sleep(0.006)
                cache_state = "HIT"
            _send(self, 200, {"ok": True}, {"X-Cache": cache_state})
            return

        if path == "/rate-limit":
            REQUEST_COUNTS["count"] = REQUEST_COUNTS.get("count", 0) + 1
            if REQUEST_COUNTS["count"] >= 7:
                _send(self, 429, {"message": "Too many requests, please try again later."}, {"Retry-After": "30"})
                return
            _send(self, 200, {"ok": True})
            return

        if path == "/lockout":
            if account in KNOWN_ACCOUNTS:
                _send(self, 423, {"message": "Account locked due to too many failed attempts"})
            else:
                _send(self, 404, {"message": "account not found"})
            return

        _send(self, 404, {"message": "unknown lab endpoint"})

    def do_GET(self) -> None:  # noqa: N802
        if self.path.startswith("/health"):
            _send(self, 200, {"ok": True})
        else:
            _send(self, 404, {"message": "not found"})


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=18080)
    args = parser.parse_args()
    server = ThreadingHTTPServer((args.host, args.port), Handler)
    print(f"mock enum lab on http://{args.host}:{args.port}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
