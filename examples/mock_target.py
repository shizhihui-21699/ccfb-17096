#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
仅监听 127.0.0.1 的本地练习靶场，用来验证 account_enum_detector.py。

端点：
  POST /api/message   状态码相同，但 code/message 不同（含动态 request_id）
  POST /api/timing    响应体完全相同，已知账号额外 sleep
  POST /api/safe      响应体相同，时序无稳定差异
  POST /api/register  注册场景：已存在 409，不存在返回模拟成功（不持久化）
  POST /api/blocked   始终返回 429 + 验证码/频繁提示，用于验证熔断

已知测试账号：probe01@example.com ... probe10@example.com
"""
from __future__ import annotations

import argparse
import json
import random
import secrets
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

EXISTING_LOCAL_PARTS = {f"probe{i:02d}" for i in range(1, 11)}


def account_from_request(handler: BaseHTTPRequestHandler) -> str:
    length = int(handler.headers.get("Content-Length", "0") or "0")
    raw = handler.rfile.read(length) if length else b""
    ctype = handler.headers.get("Content-Type", "")
    if "application/json" in ctype:
        try:
            data = json.loads(raw.decode("utf-8"))
            return str(data.get("username") or data.get("account") or data.get("email") or "")
        except Exception:
            return ""
    if "application/x-www-form-urlencoded" in ctype:
        from urllib.parse import parse_qs
        form = parse_qs(raw.decode("utf-8"))
        return (form.get("username") or form.get("account") or [""])[0]
    return ""


def is_existing(account: str) -> bool:
    local = account.split("@", 1)[0].lower()
    return local in EXISTING_LOCAL_PARTS


class Handler(BaseHTTPRequestHandler):
    server_version = "EnumMock/1.0"

    def log_message(self, fmt: str, *args) -> None:
        print(f"[mock] {self.address_string()} - {fmt % args}")

    def send_json(self, status: int, payload: dict, delay: float = 0.0) -> None:
        if delay:
            time.sleep(delay)
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("X-Request-Id", secrets.token_hex(8))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:  # noqa: N802
        if self.path == "/health":
            self.send_json(200, {"ok": True})
        else:
            self.send_json(404, {"message": "not found"})

    def do_POST(self) -> None:  # noqa: N802
        account = account_from_request(self)
        existing = is_existing(account)

        if self.path == "/api/message":
            if existing:
                self.send_json(401, {
                    "code": 1002,
                    "message": "密码错误，该账号已存在，请核对密码",
                    "request_id": secrets.token_hex(12),
                    "ts": int(time.time()),
                }, delay=random.uniform(0.01, 0.03))
            else:
                self.send_json(401, {
                    "code": 1001,
                    "message": "账号不存在",
                    "request_id": secrets.token_hex(12),
                    "ts": int(time.time()),
                }, delay=random.uniform(0.01, 0.03))
            return

        if self.path == "/api/timing":
            # 完全相同的响应；已知账号执行额外“哈希/查询”耗时。
            delay = random.uniform(0.11, 0.15) if existing else random.uniform(0.015, 0.04)
            self.send_json(401, {
                "code": 4001,
                "message": "登录失败，用户名或密码错误",
                "trace_id": secrets.token_hex(16),
            }, delay=delay)
            return

        if self.path == "/api/safe":
            self.send_json(401, {
                "code": 4001,
                "message": "登录失败，用户名或密码错误",
                "trace_id": secrets.token_hex(16),
            }, delay=random.uniform(0.02, 0.08))
            return

        if self.path == "/api/register":
            if existing:
                self.send_json(409, {"code": 2001, "message": "用户名已被注册"})
            else:
                # 练习靶场不保存任何注册状态。
                self.send_json(200, {"code": 0, "message": "校验通过（模拟环境，未创建账号）"})
            return

        if self.path == "/api/blocked":
            self.send_json(429, {"code": 4290, "message": "操作频繁，请完成验证码后再试"})
            return

        self.send_json(404, {"message": "not found"})


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8765)
    args = parser.parse_args()
    server = ThreadingHTTPServer((args.host, args.port), Handler)
    print(f"Mock target listening on http://{args.host}:{args.port}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopped")
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
