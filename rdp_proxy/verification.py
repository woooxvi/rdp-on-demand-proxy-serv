from __future__ import annotations

import json
import html
import logging
import threading
import time
from dataclasses import dataclass
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Callable
from urllib.parse import parse_qs, urlencode, urlparse
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


@dataclass
class ControlAuthToken:
    token: str
    created_at: float
    expires_at: float
    used: bool


class VerificationService:
    def __init__(
        self,
        bind: str,
        port: int,
        external_base_url: str,
        ttl_seconds: int,
        on_verified: Callable[[str, dict], None] | None = None,
        on_action: Callable[[str, str], None] | None = None,
        on_whitelist_message: Callable[[str], tuple[bool, str]] | None = None,
        add_whitelist_ip: Callable[[str, str], tuple[bool, str]] | None = None,
        delete_whitelist_entry: Callable[[str], tuple[bool, str]] | None = None,
        list_whitelist_entries: Callable[[], list[dict[str, object]]] | None = None,
        list_recent_rejections: Callable[[], list[dict[str, object]]] | None = None,
    ):
        self._bind = bind
        self._port = port
        self._external_base_url = external_base_url.rstrip("/")
        self._ttl_seconds = ttl_seconds
        self._tokens: dict[str, VerificationToken] = {}
        self._action_tokens: dict[str, ActionToken] = {}
        self._control_auth_tokens: dict[str, ControlAuthToken] = {}
        self._lock = threading.Lock()
        self._logger = logging.getLogger("rdp_proxy.verification")
        self._on_verified = on_verified
        self._on_action = on_action
        self._on_whitelist_message = on_whitelist_message
        self._add_whitelist_ip = add_whitelist_ip
        self._delete_whitelist_entry = delete_whitelist_entry
        self._list_whitelist_entries = list_whitelist_entries
        self._list_recent_rejections = list_recent_rejections
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

    def create_control_auth_token(self) -> tuple[str, str]:
        """Generate a one-time control panel auth token (valid for 1 hour max)."""
        now = time.time()
        token = uuid4().hex
        auth_ttl = min(3600, self._ttl_seconds)  # Max 1 hour

        cat = ControlAuthToken(
            token=token,
            created_at=now,
            expires_at=now + auth_ttl,
            used=False,
        )
        with self._lock:
            self._cleanup_locked(now)
            self._control_auth_tokens[token] = cat

        auth_url = f"{self._external_base_url}/whitelist?auth={token}"
        return token, auth_url

    def is_control_auth_valid(self, token: str) -> bool:
        """Check if control auth token is valid (not used, not expired)."""
        if not token:
            return False
        with self._lock:
            now = time.time()
            self._cleanup_locked(now)
            cat = self._control_auth_tokens.get(token)
            if not cat or cat.used or cat.expires_at < now:
                return False
            cat.used = True
            return True

    @property
    def whitelist_url(self) -> str:
        return f"{self._external_base_url}/whitelist"

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

    def list_pending_verification_links(self, limit: int = 5) -> list[dict[str, str]]:
        now = time.time()
        with self._lock:
            self._cleanup_locked(now)
            pending = [
                vt
                for vt in self._tokens.values()
                if (not vt.used) and vt.expires_at >= now
            ]
        pending.sort(key=lambda item: item.created_at, reverse=True)
        limited = pending[: max(1, int(limit))]
        results: list[dict[str, str]] = []
        for vt in limited:
            target = str(vt.meta.get("target", "")) if isinstance(vt.meta, dict) else ""
            client_ip = str(vt.meta.get("client_ip", "")) if isinstance(vt.meta, dict) else ""
            results.append(
                {
                    "token": vt.token,
                    "target": target,
                    "client_ip": client_ip,
                    "verify_url": f"{self._external_base_url}/verify?token={vt.token}",
                }
            )
        return results

    def cancel_token(self, token: str) -> bool:
        if not token:
            return False

        with self._lock:
            vt = self._tokens.pop(token, None)

        if not vt:
            return False

        vt.used = True
        vt.approved = False
        vt.event.set()
        log_with_data(
            self._logger,
            logging.INFO,
            "Verification token cancelled",
            token=token,
            **vt.meta,
        )
        return True

    def _cleanup_locked(self, now: float) -> None:
        expired = [k for k, v in self._tokens.items() if v.expires_at < now or (v.used and now - v.created_at > 3600)]
        for k in expired:
            self._tokens.pop(k, None)

        action_expired = [
            k for k, v in self._action_tokens.items() if v.expires_at < now or (v.used and now - v.created_at > 3600)
        ]
        for k in action_expired:
            self._action_tokens.pop(k, None)

        auth_expired = [k for k, v in self._control_auth_tokens.items() if v.expires_at < now or (v.used and now - v.created_at > 3600)]
        for k in auth_expired:
            self._control_auth_tokens.pop(k, None)

    def _make_handler(self) -> type[BaseHTTPRequestHandler]:
        service = self

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self) -> None:
                parsed = urlparse(self.path)
                if parsed.path == "/action":
                    self._handle_action(parsed)
                    return
                if parsed.path == "/whitelist":
                    self._render_whitelist_page(parsed)
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

            def do_POST(self) -> None:
                parsed = urlparse(self.path)
                if parsed.path != "/whitelist":
                    self._send_html(HTTPStatus.NOT_FOUND, "Not Found")
                    return
                content_type = self.headers.get("Content-Type", "")
                if "application/x-www-form-urlencoded" in content_type:
                    self._handle_whitelist_form()
                    return
                self._handle_whitelist_api(parsed, allow_body=True)

            def _handle_whitelist_api(self, parsed, allow_body: bool = False) -> None:
                if not service._on_whitelist_message:
                    self._send_html(HTTPStatus.NOT_IMPLEMENTED, "Whitelist ingestion is disabled")
                    return

                message = ""
                if allow_body:
                    length_text = self.headers.get("Content-Length", "0")
                    try:
                        content_length = max(0, int(length_text))
                    except ValueError:
                        content_length = 0
                    raw_body = self.rfile.read(content_length).decode("utf-8", errors="replace") if content_length else ""
                    content_type = self.headers.get("Content-Type", "")
                    if "application/json" in content_type:
                        try:
                            payload = json.loads(raw_body or "{}")
                        except ValueError:
                            payload = {}
                        if isinstance(payload, dict):
                            for key in ("text", "content", "message", "ip"):
                                value = payload.get(key)
                                if isinstance(value, str) and value.strip():
                                    message = value.strip()
                                    break
                            if not message:
                                nested = payload.get("content")
                                if isinstance(nested, dict):
                                    for key in ("text", "message", "ip"):
                                        value = nested.get(key)
                                        if isinstance(value, str) and value.strip():
                                            message = value.strip()
                                            break
                        if not message:
                            message = raw_body.strip()
                    else:
                        message = raw_body.strip()
                else:
                    query = parse_qs(parsed.query)
                    for key in ("text", "ip", "message"):
                        values = query.get(key, [])
                        if values and values[0].strip():
                            message = values[0].strip()
                            break

                if not message:
                    self._send_html(HTTPStatus.BAD_REQUEST, "Missing whitelist message")
                    return

                ok, detail = service._on_whitelist_message(message)
                if ok:
                    self._send_html(HTTPStatus.OK, f"Whitelist updated: {html.escape(detail)}")
                    return
                self._send_html(HTTPStatus.BAD_REQUEST, html.escape(detail))

            def _handle_whitelist_form(self) -> None:
                length_text = self.headers.get("Content-Length", "0")
                try:
                    content_length = max(0, int(length_text))
                except ValueError:
                    content_length = 0
                raw_body = self.rfile.read(content_length).decode("utf-8", errors="replace") if content_length else ""
                form = parse_qs(raw_body, keep_blank_values=True)
                action = form.get("action", [""])[0].strip()

                ok = False
                detail = "unknown action"
                if action == "add_ip" and service._add_whitelist_ip is not None:
                    candidate = form.get("ip", [""])[0].strip()
                    ok, detail = service._add_whitelist_ip(candidate, "http-manual")
                elif action == "allow_current" and service._add_whitelist_ip is not None:
                    ok, detail = service._add_whitelist_ip(self._resolve_request_ip(), "http-visitor")
                elif action == "allow_rejected" and service._add_whitelist_ip is not None:
                    candidate = form.get("rejected_ip", [""])[0].strip()
                    ok, detail = service._add_whitelist_ip(candidate, "http-rejected")
                elif action == "delete_entry" and service._delete_whitelist_entry is not None:
                    identifier = form.get("entry_id", [""])[0].strip()
                    ok, detail = service._delete_whitelist_entry(identifier)

                self._redirect_whitelist(detail, ok)

            def _render_whitelist_page(self, parsed) -> None:
                query = parse_qs(parsed.query)
                auth_token = query.get("auth", [""])[0]
                is_authenticated = service.is_control_auth_valid(auth_token) if auth_token else False

                if not is_authenticated and not auth_token:
                    self._send_html(
                        HTTPStatus.UNAUTHORIZED,
                        "<html><head><meta charset='utf-8'></head><body style='font-family:sans-serif;padding:20px'>"
                        "<h1>RDP 代理 - 管理页面</h1>"
                        "<p>访问管理页面需要通过 IM 指令 <code>/control</code> 获取授权链接。</p>"
                        "<p>请在 Telegram 中输入 <code>/control</code> 获取包含访问令牌的链接。</p>"
                        "</body></html>"
                    )
                    return

                if not is_authenticated:
                    self._send_html(
                        HTTPStatus.UNAUTHORIZED,
                        "<html><head><meta charset='utf-8'></head><body style='font-family:sans-serif;padding:20px'>"
                        "<h1>链接已失效</h1>"
                        "<p>管理链接已过期或已被使用。请在 IM 中重新输入 <code>/control</code> 获取新链接。</p>"
                        "</body></html>"
                    )
                    return

                visitor_ip = self._resolve_request_ip()
                flash_message = query.get("message", [""])[0]
                flash_level = query.get("level", [""])[0]
                whitelist_entries = service._list_whitelist_entries() if service._list_whitelist_entries else []
                rejected_entries = service._list_recent_rejections() if service._list_recent_rejections else []

                flash_html = ""
                if flash_message:
                    css_class = "flash flash-ok" if flash_level == "ok" else "flash flash-error"
                    flash_html = f"<div class='{css_class}'>{html.escape(flash_message)}</div>"

                whitelist_rows: list[str] = []
                for entry in whitelist_entries:
                    ip_text = str(entry.get("ip", "")).strip() or "<legacy>"
                    source = str(entry.get("source", "")).strip() or "-"
                    added_at = str(entry.get("added_at_text", "-")).strip() or "-"
                    entry_id = str(entry.get("cipher", "")).strip()
                    legacy = bool(entry.get("legacy", False))
                    delete_label = "删除"
                    legacy_text = " <span class='legacy'>(legacy)</span>" if legacy else ""
                    whitelist_rows.append(
                        "<tr>"
                        f"<td>{html.escape(ip_text)}{legacy_text}</td>"
                        f"<td>{html.escape(source)}</td>"
                        f"<td>{html.escape(added_at)}</td>"
                        "<td>"
                        "<form method='post' class='inline-form'>"
                        "<input type='hidden' name='action' value='delete_entry'>"
                        f"<input type='hidden' name='entry_id' value='{html.escape(entry_id)}'>"
                        f"<button type='submit'>{delete_label}</button>"
                        "</form>"
                        "</td>"
                        "</tr>"
                    )

                if not whitelist_rows:
                    whitelist_rows.append("<tr><td colspan='4' class='empty'>白名单为空</td></tr>")

                rejected_rows: list[str] = []
                for item in rejected_entries:
                    ip_text = str(item.get("ip", "")).strip()
                    geo = str(item.get("geo", "")).strip() or "-"
                    target = str(item.get("target", "")).strip() or "-"
                    count = str(item.get("count", 0))
                    last_seen = str(item.get("last_seen_at_text", "-")).strip() or "-"
                    rejected_rows.append(
                        "<tr>"
                        f"<td>{html.escape(ip_text)}</td>"
                        f"<td>{html.escape(geo)}</td>"
                        f"<td>{html.escape(target)}</td>"
                        f"<td>{html.escape(last_seen)}</td>"
                        f"<td>{html.escape(count)}</td>"
                        "<td>"
                        "<form method='post' class='inline-form'>"
                        "<input type='hidden' name='action' value='allow_rejected'>"
                        f"<input type='hidden' name='rejected_ip' value='{html.escape(ip_text)}'>"
                        "<button type='submit'>一键放行</button>"
                        "</form>"
                        "</td>"
                        "</tr>"
                    )

                if not rejected_rows:
                    rejected_rows.append("<tr><td colspan='6' class='empty'>暂无最近拒绝记录</td></tr>")

                body = f"""
<html>
<head>
    <meta charset='utf-8'>
    <title>Whitelist Manager</title>
    <style>
        body {{ font-family: 'Segoe UI', sans-serif; margin: 24px; color: #1f2937; background: #f4f6f8; }}
        h1, h2 {{ margin-bottom: 12px; }}
        .grid {{ display: grid; grid-template-columns: 1fr; gap: 20px; }}
        .card {{ background: #fff; border-radius: 12px; padding: 20px; box-shadow: 0 10px 30px rgba(15, 23, 42, 0.08); }}
        .flash {{ padding: 12px 14px; border-radius: 8px; margin-bottom: 16px; }}
        .flash-ok {{ background: #dcfce7; color: #166534; }}
        .flash-error {{ background: #fee2e2; color: #991b1b; }}
        .toolbar {{ display: flex; flex-wrap: wrap; gap: 12px; align-items: center; margin-bottom: 12px; }}
        .visitor {{ font-weight: 600; }}
        table {{ width: 100%; border-collapse: collapse; }}
        th, td {{ text-align: left; padding: 10px 8px; border-bottom: 1px solid #e5e7eb; vertical-align: top; }}
        th {{ color: #475569; font-size: 13px; }}
        input[type='text'] {{ min-width: 280px; padding: 10px 12px; border: 1px solid #cbd5e1; border-radius: 8px; }}
        button {{ padding: 9px 14px; border: 0; border-radius: 8px; background: #0f172a; color: white; cursor: pointer; }}
        button:hover {{ background: #1e293b; }}
        .inline-form {{ display: inline; }}
        .empty {{ color: #64748b; }}
        .legacy {{ color: #b45309; font-size: 12px; }}
    </style>
</head>
<body>
    <div class='grid'>
        <div class='card'>
            <h1>白名单管理</h1>
            {flash_html}
            <div class='toolbar'>
                <span class='visitor'>当前访问端 IP: {html.escape(visitor_ip)}</span>
                <form method='post' class='inline-form'>
                    <input type='hidden' name='action' value='allow_current'>
                    <button type='submit'>一键放行当前访问端</button>
                </form>
            </div>
            <form method='post' class='toolbar'>
                <input type='hidden' name='action' value='add_ip'>
                <input type='text' name='ip' placeholder='输入 IPv4 或 IPv6 地址'>
                <button type='submit'>新增白名单</button>
            </form>
        </div>

        <div class='card'>
            <h2>现有白名单</h2>
            <table>
                <thead>
                    <tr><th>IP</th><th>来源</th><th>加入时间</th><th>操作</th></tr>
                </thead>
                <tbody>
                    {''.join(whitelist_rows)}
                </tbody>
            </table>
        </div>

        <div class='card'>
            <h2>最近被拒绝的来源</h2>
            <table>
                <thead>
                    <tr><th>IP</th><th>GEO</th><th>目标</th><th>最近请求时间</th><th>次数</th><th>操作</th></tr>
                </thead>
                <tbody>
                    {''.join(rejected_rows)}
                </tbody>
            </table>
        </div>
    </div>
</body>
</html>
"""
                body_bytes = body.encode("utf-8")
                self.send_response(int(HTTPStatus.OK))
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.send_header("Content-Length", str(len(body_bytes)))
                self.end_headers()
                self.wfile.write(body_bytes)

            def _resolve_request_ip(self) -> str:
                forwarded = self.headers.get("X-Forwarded-For", "")
                if forwarded:
                    first = forwarded.split(",", 1)[0].strip()
                    if first:
                        return first
                return str(self.client_address[0])

            def _redirect_whitelist(self, message: str, ok: bool) -> None:
                query = urlencode({"message": message, "level": "ok" if ok else "error"})
                self.send_response(int(HTTPStatus.SEE_OTHER))
                self.send_header("Location", f"/whitelist?{query}")
                self.end_headers()

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
