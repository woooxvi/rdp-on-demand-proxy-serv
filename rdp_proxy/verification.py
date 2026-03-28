from __future__ import annotations

import html
import logging
import threading
import time
from dataclasses import dataclass
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Callable
from urllib.parse import parse_qs, urlparse
from uuid import uuid4

from rdp_proxy.logging_utils import log_with_data


@dataclass
class VerificationToken:
    token: str
    created_at: float
    expires_at: float
    used: bool
    approved: bool
    event: threading.Event
    meta: dict


@dataclass
class ActionToken:
    token: str
    created_at: float
    expires_at: float
    used: bool
    target: str
    action: str


class VerificationService:
    def __init__(
        self,
        bind: str,
        port: int,
        external_base_url: str,
        ttl_seconds: int,
        on_verified: Callable[[str, dict], None] | None = None,
        on_action: Callable[[str, str], None] | None = None,
    ):
        self._bind = bind
        self._port = port
        self._external_base_url = external_base_url.rstrip("/")
        self._ttl_seconds = ttl_seconds
        self._tokens: dict[str, VerificationToken] = {}
        self._action_tokens: dict[str, ActionToken] = {}
        self._lock = threading.Lock()
        self._logger = logging.getLogger("rdp_proxy.verification")
        self._on_verified = on_verified
        self._on_action = on_action
        self._server: ThreadingHTTPServer | None = None
        self._thread: threading.Thread | None = None

    def start(self) -> None:
        handler_cls = self._make_handler()
        self._server = ThreadingHTTPServer((self._bind, self._port), handler_cls)
        self._thread = threading.Thread(target=self._server.serve_forever, name="verification-http", daemon=True)
        self._thread.start()
        log_with_data(
            self._logger,
            logging.INFO,
            "Verification HTTP server started",
            bind=self._bind,
            port=self._port,
        )

    def stop(self) -> None:
        if self._server:
            self._server.shutdown()
            self._server.server_close()

    def create_token(self, meta: dict) -> tuple[str, threading.Event, str]:
        now = time.time()
        token = uuid4().hex
        evt = threading.Event()

        vt = VerificationToken(
            token=token,
            created_at=now,
            expires_at=now + self._ttl_seconds,
            used=False,
            approved=False,
            event=evt,
            meta=meta,
        )
        with self._lock:
            self._cleanup_locked(now)
            self._tokens[token] = vt

        url = f"{self._external_base_url}/verify?token={token}"
        return token, evt, url

    def create_action_links(self, target: str) -> tuple[str, str]:
        now = time.time()
        keep_token = uuid4().hex
        shutdown_token = uuid4().hex

        keep = ActionToken(
            token=keep_token,
            created_at=now,
            expires_at=now + self._ttl_seconds,
            used=False,
            target=target,
            action="keep_running",
        )
        shutdown = ActionToken(
            token=shutdown_token,
            created_at=now,
            expires_at=now + self._ttl_seconds,
            used=False,
            target=target,
            action="shutdown_on_idle",
        )

        with self._lock:
            self._cleanup_locked(now)
            self._action_tokens[keep_token] = keep
            self._action_tokens[shutdown_token] = shutdown

        keep_url = f"{self._external_base_url}/action?token={keep_token}"
        shutdown_url = f"{self._external_base_url}/action?token={shutdown_token}"
        return keep_url, shutdown_url

    def is_approved(self, token: str) -> bool:
        with self._lock:
            vt = self._tokens.get(token)
            return bool(vt and vt.approved)

    def _cleanup_locked(self, now: float) -> None:
        expired = [k for k, v in self._tokens.items() if v.expires_at < now or (v.used and now - v.created_at > 3600)]
        for k in expired:
            self._tokens.pop(k, None)

        action_expired = [
            k for k, v in self._action_tokens.items() if v.expires_at < now or (v.used and now - v.created_at > 3600)
        ]
        for k in action_expired:
            self._action_tokens.pop(k, None)

    def _make_handler(self) -> type[BaseHTTPRequestHandler]:
        service = self

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self) -> None:
                parsed = urlparse(self.path)
                if parsed.path == "/action":
                    self._handle_action(parsed)
                    return
                if parsed.path != "/verify":
                    self._send_html(HTTPStatus.NOT_FOUND, "Not Found")
                    return

                token = parse_qs(parsed.query).get("token", [""])[0]
                if not token:
                    self._send_html(HTTPStatus.BAD_REQUEST, "Missing token")
                    return

                with service._lock:
                    now = time.time()
                    service._cleanup_locked(now)
                    vt = service._tokens.get(token)
                    if not vt:
                        self._send_html(HTTPStatus.GONE, "链接已失效")
                        return
                    if vt.used:
                        self._send_html(HTTPStatus.CONFLICT, "链接已被使用")
                        return
                    if vt.expires_at < now:
                        self._send_html(HTTPStatus.GONE, "链接已过期")
                        return

                    vt.used = True
                    vt.approved = True
                    vt.event.set()

                log_with_data(
                    service._logger,
                    logging.INFO,
                    "Verification approved",
                    token=token,
                    **vt.meta,
                )
                if service._on_verified:
                    service._on_verified(token, vt.meta)
                self._send_html(HTTPStatus.OK, "验证成功，RDP 连接已放行")

            def _handle_action(self, parsed) -> None:
                token = parse_qs(parsed.query).get("token", [""])[0]
                if not token:
                    self._send_html(HTTPStatus.BAD_REQUEST, "Missing token")
                    return

                with service._lock:
                    now = time.time()
                    service._cleanup_locked(now)
                    at = service._action_tokens.get(token)
                    if not at:
                        self._send_html(HTTPStatus.GONE, "链接已失效")
                        return
                    if at.used:
                        self._send_html(HTTPStatus.CONFLICT, "链接已被使用")
                        return
                    if at.expires_at < now:
                        self._send_html(HTTPStatus.GONE, "链接已过期")
                        return

                    at.used = True

                if service._on_action:
                    service._on_action(at.target, at.action)

                log_with_data(
                    service._logger,
                    logging.INFO,
                    "Post-disconnect action selected",
                    target=at.target,
                    action=at.action,
                    token=token,
                )
                if at.action == "shutdown_on_idle":
                    self._send_html(HTTPStatus.OK, "已选择：立即关机（空闲超时后执行）")
                    return
                self._send_html(HTTPStatus.OK, "已选择：保持开机")

            def log_message(self, format: str, *args) -> None:
                return

            def _send_html(self, status: HTTPStatus, message: str) -> None:
                body = (
                    "<html><head><meta charset='utf-8'></head><body>"
                    f"<h3>{html.escape(message)}</h3>"
                    "</body></html>"
                ).encode("utf-8")
                self.send_response(int(status))
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

        return Handler
