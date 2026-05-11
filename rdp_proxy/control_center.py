from __future__ import annotations

import html
import logging
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Callable
from urllib.parse import parse_qs, urlparse
from uuid import uuid4

from rdp_proxy.logging_utils import log_with_data


@dataclass
class ControlRequestEvent:
    request_id: str
    connection_id: str
    target: str
    client_ip: str
    client_port: int
    geo_text: str
    requested_at: float
    status: str = "pending"
    approved_at: float | None = None
    closed_at: float | None = None
    close_reason: str = ""
    wait_event: threading.Event = field(default_factory=threading.Event, repr=False)


@dataclass
class ControlRequestAggregate:
    target: str
    client_ip: str
    geo_text: str
    request_count: int = 0
    approved_count: int = 0
    first_requested_at: float = 0.0
    last_requested_at: float = 0.0
    previous_requested_at: float | None = None
    status: str = "idle"
    active_request_id: str = ""
    active_connection_id: str = ""
    active_requested_at: float = 0.0
    active_approved_at: float | None = None
    last_state_change_at: float = 0.0
    last_close_reason: str = ""


@dataclass
class ActionToken:
    token: str
    created_at: float
    expires_at: float
    used: bool
    target: str
    action: str


class ControlCenterService:
    def __init__(
        self,
        bind: str,
        port: int,
        external_base_url: str,
        ttl_seconds: int,
        on_approved: Callable[[str, dict], None] | None = None,
        on_action: Callable[[str, str], None] | None = None,
        history_retention_seconds: int = 24 * 3600,
    ):
        self._bind = bind
        self._port = port
        self._external_base_url = external_base_url.rstrip("/")
        self._ttl_seconds = max(1, int(ttl_seconds))
        self._history_retention_seconds = max(self._ttl_seconds, int(history_retention_seconds))
        self._control_token = uuid4().hex
        self._requests_by_id: dict[str, ControlRequestEvent] = {}
        self._requests_by_key: dict[tuple[str, str], ControlRequestAggregate] = {}
        self._request_history: list[ControlRequestEvent] = []
        self._action_tokens: dict[str, ActionToken] = {}
        self._whitelist_set: set[tuple[str, str]] = set()  # (target, client_ip)
        self._blacklist_set: set[tuple[str, str]] = set()  # (target, client_ip)
        self._total_requested_count = 0
        self._total_approved_count = 0
        self._lock = threading.Lock()
        self._logger = logging.getLogger("rdp_proxy.control_center")
        self._on_approved = on_approved
        self._on_action = on_action
        self._server: ThreadingHTTPServer | None = None
        self._thread: threading.Thread | None = None

    @property
    def control_url(self) -> str:
        return f"{self._external_base_url}/control?token={self._control_token}"

    def recent_url(self, window_seconds: int) -> str:
        window_seconds = max(1, int(window_seconds))
        return f"{self._external_base_url}/control?token={self._control_token}&view=recent&window={window_seconds}"

    def is_blacklisted(self, target: str, client_ip: str) -> bool:
        """检查是否在黑名单中"""
        with self._lock:
            return (target, client_ip) in self._blacklist_set

    def is_whitelisted(self, target: str, client_ip: str) -> bool:
        """检查是否在白名单中（已放行过）"""
        with self._lock:
            return (target, client_ip) in self._whitelist_set

    def get_request_status(self, request_id: str) -> str | None:
        """获取请求的当前状态，用于检查黑名单/白名单状态"""
        with self._lock:
            event = self._requests_by_id.get(request_id)
            if event is None:
                return None
            return event.status

    def is_request_rejected(self, request_id: str) -> bool:
        """检查请求是否已被拒绝（黑名单）"""
        with self._lock:
            event = self._requests_by_id.get(request_id)
            if event is None:
                return False
            return event.status == "rejected"

    def blacklist_targets(self, targets: list[tuple[str, str]]) -> None:
        """批量加入黑名单，targets 为 [(target, client_ip), ...]"""
        with self._lock:
            for target, client_ip in targets:
                if target and client_ip:
                    self._blacklist_set.add((target, client_ip))
                    # 从白名单中移除
                    self._whitelist_set.discard((target, client_ip))
                    log_with_data(
                        self._logger,
                        logging.INFO,
                        "Target added to blacklist",
                        target=target,
                        client_ip=client_ip,
                    )

    def get_whitelist_snapshot(self) -> list[dict[str, str]]:
        """获取当前白名单快照"""
        with self._lock:
            return [{"target": target, "client_ip": client_ip} for target, client_ip in sorted(self._whitelist_set)]

    def get_blacklist_snapshot(self) -> list[dict[str, str]]:
        """获取当前黑名单快照"""
        with self._lock:
            return [{"target": target, "client_ip": client_ip} for target, client_ip in sorted(self._blacklist_set)]

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

    def start(self) -> None:
        handler_cls = self._make_handler()
        self._server = ThreadingHTTPServer((self._bind, self._port), handler_cls)
        self._thread = threading.Thread(target=self._server.serve_forever, name="control-center-http", daemon=True)
        self._thread.start()
        log_with_data(
            self._logger,
            logging.INFO,
            "Control center HTTP server started",
            bind=self._bind,
            port=self._port,
        )

    def stop(self) -> None:
        if self._server:
            self._server.shutdown()
            self._server.server_close()

    def register_request(self, target: str, connection_id: str, client_ip: str, client_port: int, geo_text: str) -> threading.Event:
        now = time.time()
        event = ControlRequestEvent(
            request_id=connection_id,
            connection_id=connection_id,
            target=target,
            client_ip=client_ip,
            client_port=client_port,
            geo_text=geo_text,
            requested_at=now,
        )

        with self._lock:
            self._cleanup_locked(now)
            key = (target, client_ip)

            # 检查是否在黑名单中，如果在直接拒绝
            if key in self._blacklist_set:
                event.status = "rejected"
                event.closed_at = now
                event.close_reason = "blacklisted"
                event.wait_event.set()
                self._requests_by_id[connection_id] = event
                self._request_history.append(event)
                log_with_data(
                    self._logger,
                    logging.INFO,
                    "Request rejected - target in blacklist",
                    target=target,
                    client_ip=client_ip,
                )
                return event.wait_event

            # 检查是否在白名单中，如果在直接放行
            if key in self._whitelist_set:
                event.status = "approved"
                event.approved_at = now
                event.wait_event.set()
                aggregate = self._requests_by_key.get(key)
                if aggregate is None:
                    aggregate = ControlRequestAggregate(target=target, client_ip=client_ip, geo_text=geo_text)
                    self._requests_by_key[key] = aggregate
                aggregate.status = "approved"
                aggregate.approved_count += 1
                aggregate.active_approved_at = now
                self._requests_by_id[connection_id] = event
                self._request_history.append(event)
                self._total_approved_count += 1
                if self._on_approved:
                    self._on_approved(connection_id, self._event_meta(event))
                log_with_data(
                    self._logger,
                    logging.INFO,
                    "Request auto-approved - target in whitelist",
                    target=target,
                    client_ip=client_ip,
                )
                return event.wait_event

            aggregate = self._requests_by_key.get(key)
            if aggregate is None:
                aggregate = ControlRequestAggregate(target=target, client_ip=client_ip, geo_text=geo_text)
                self._requests_by_key[key] = aggregate
            elif aggregate.active_request_id:
                previous_event = self._requests_by_id.get(aggregate.active_request_id)
                if previous_event and previous_event.status in {"pending", "approved"}:
                    previous_event.status = "superseded"
                    previous_event.closed_at = now
                    previous_event.close_reason = "same_ip_takeover"

            aggregate.previous_requested_at = aggregate.last_requested_at or None
            aggregate.last_requested_at = now
            if aggregate.first_requested_at <= 0:
                aggregate.first_requested_at = now
            aggregate.request_count += 1
            aggregate.geo_text = geo_text or aggregate.geo_text
            aggregate.status = "pending"
            aggregate.active_request_id = connection_id
            aggregate.active_connection_id = connection_id
            aggregate.active_requested_at = now
            aggregate.active_approved_at = None
            aggregate.last_state_change_at = now
            aggregate.last_close_reason = ""

            self._requests_by_id[connection_id] = event
            self._request_history.append(event)
            self._total_requested_count += 1

        return event.wait_event

    def approve_request(self, request_id: str) -> bool:
        if not request_id:
            return False

        now = time.time()
        with self._lock:
            self._cleanup_locked(now)
            event = self._requests_by_id.get(request_id)
            if event is None or event.status != "pending":
                return False
            event.status = "approved"
            event.approved_at = now
            aggregate = self._requests_by_key.get((event.target, event.client_ip))
            if aggregate is not None:
                aggregate.status = "approved"
                aggregate.approved_count += 1
                aggregate.active_approved_at = now
                aggregate.last_state_change_at = now
                aggregate.last_close_reason = ""
            self._total_approved_count += 1
            # 添加到白名单
            self._whitelist_set.add((event.target, event.client_ip))

        event.wait_event.set()
        log_with_data(
            self._logger,
            logging.INFO,
            "Request approved",
            request_id=request_id,
            target=event.target,
            client_ip=event.client_ip,
        )
        if self._on_approved:
            self._on_approved(request_id, self._event_meta(event))
        return True

    def close_request(self, request_id: str, reason: str) -> bool:
        if not request_id:
            return False

        now = time.time()
        with self._lock:
            self._cleanup_locked(now)
            event = self._requests_by_id.get(request_id)
            if event is None:
                return False
            if event.status in {"closed", "superseded"}:
                return False
            event.status = "closed"
            event.closed_at = now
            event.close_reason = reason
            aggregate = self._requests_by_key.get((event.target, event.client_ip))
            if aggregate is not None and aggregate.active_request_id == request_id:
                aggregate.status = "closed"
                aggregate.active_request_id = ""
                aggregate.active_connection_id = ""
                aggregate.active_requested_at = 0.0
                aggregate.active_approved_at = None
                aggregate.last_state_change_at = now
                aggregate.last_close_reason = reason

        return True

    def get_dashboard_snapshot(self, view: str = "active", window_seconds: int = 3600) -> dict[str, object]:
        now = time.time()
        window_seconds = max(1, int(window_seconds))
        with self._lock:
            self._cleanup_locked(now)
            aggregates = list(self._requests_by_key.values())
            aggregates.sort(key=lambda item: (item.last_requested_at, item.request_count), reverse=True)
            recent_since = now - window_seconds
            recent_events = [event for event in self._request_history if event.requested_at >= recent_since]
            recent_events.sort(key=lambda item: item.requested_at, reverse=True)

            pending_records = [item for item in aggregates if item.status == "pending" and item.active_request_id]
            approved_records = [item for item in aggregates if item.status == "approved" and item.active_request_id]
            
            # 区分pending中哪些是历史已放行过的
            previously_approved_records = [
                item for item in pending_records
                if (item.target, item.client_ip) in self._whitelist_set
            ]
            other_pending_records = [
                item for item in pending_records
                if (item.target, item.client_ip) not in self._whitelist_set
            ]
            
            if view == "recent":
                records = recent_events
            else:
                records = pending_records + approved_records

            current_requested = sum(item.request_count for item in aggregates)
            current_approved = sum(item.approved_count for item in aggregates)
            recent_requested = len(recent_events)
            recent_approved = sum(1 for event in recent_events if event.approved_at is not None and event.approved_at >= recent_since)

        return {
            "generated_at": now,
            "view": view,
            "window_seconds": window_seconds,
            "control_url": self.control_url,
            "recent_url": self.recent_url(window_seconds),
            "totals": {
                "requested": current_requested,
                "approved": current_approved,
            },
            "recent_totals": {
                "requested": recent_requested,
                "approved": recent_approved,
            },
            "records": [self._aggregate_to_dict(item) for item in records] if view != "recent" else [self._event_to_dict(item) for item in records],
            "pending_records": [self._aggregate_to_dict(item) for item in pending_records],
            "approved_records": [self._aggregate_to_dict(item) for item in approved_records],
            "previously_approved_records": [self._aggregate_to_dict(item) for item in previously_approved_records],
            "other_pending_records": [self._aggregate_to_dict(item) for item in other_pending_records],
            "recent_records": [self._event_to_dict(item) for item in recent_events],
        }

    def _cleanup_locked(self, now: float) -> None:
        cutoff = now - self._history_retention_seconds
        self._request_history = [item for item in self._request_history if item.requested_at >= cutoff]
        expired_ids = [request_id for request_id, event in self._requests_by_id.items() if event.requested_at < cutoff and event.status in {"closed", "superseded"}]
        for request_id in expired_ids:
            self._requests_by_id.pop(request_id, None)

        action_expired = [token for token, action in self._action_tokens.items() if action.expires_at < now or (action.used and now - action.created_at > self._history_retention_seconds)]
        for token in action_expired:
            self._action_tokens.pop(token, None)

        stale_keys = []
        for key, aggregate in self._requests_by_key.items():
            if aggregate.active_request_id:
                continue
            if aggregate.last_requested_at and aggregate.last_requested_at >= cutoff:
                continue
            stale_keys.append(key)
        for key in stale_keys:
            self._requests_by_key.pop(key, None)

    def _event_meta(self, event: ControlRequestEvent) -> dict:
        return {
            "target": event.target,
            "client_ip": event.client_ip,
            "client_port": event.client_port,
            "geo_text": event.geo_text,
            "request_id": event.request_id,
        }

    def _aggregate_to_dict(self, aggregate: ControlRequestAggregate) -> dict[str, object]:
        return {
            "target": aggregate.target,
            "client_ip": aggregate.client_ip,
            "geo_text": aggregate.geo_text,
            "request_count": aggregate.request_count,
            "approved_count": aggregate.approved_count,
            "first_requested_at": aggregate.first_requested_at,
            "last_requested_at": aggregate.last_requested_at,
            "previous_requested_at": aggregate.previous_requested_at,
            "status": aggregate.status,
            "active_request_id": aggregate.active_request_id,
            "active_requested_at": aggregate.active_requested_at,
            "active_approved_at": aggregate.active_approved_at,
            "last_state_change_at": aggregate.last_state_change_at,
            "last_close_reason": aggregate.last_close_reason,
        }

    def _event_to_dict(self, event: ControlRequestEvent) -> dict[str, object]:
        return {
            "request_id": event.request_id,
            "target": event.target,
            "client_ip": event.client_ip,
            "client_port": event.client_port,
            "geo_text": event.geo_text,
            "requested_at": event.requested_at,
            "status": event.status,
            "approved_at": event.approved_at,
            "closed_at": event.closed_at,
            "close_reason": event.close_reason,
        }

    def _make_handler(self) -> type[BaseHTTPRequestHandler]:
        service = self

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self) -> None:
                parsed = urlparse(self.path)
                if parsed.path == "/control":
                    self._handle_control(parsed)
                    return
                if parsed.path == "/action":
                    self._handle_action(parsed)
                    return
                self._send_html(HTTPStatus.NOT_FOUND, "Not Found")

            def do_POST(self) -> None:
                parsed = urlparse(self.path)
                if parsed.path == "/approve":
                    self._handle_approve()
                    return
                if parsed.path == "/blacklist":
                    self._handle_blacklist()
                    return
                self._send_html(HTTPStatus.NOT_FOUND, "Not Found")

            def _handle_control(self, parsed) -> None:
                token = parse_qs(parsed.query).get("token", [""])[0]
                if token != service._control_token:
                    self._send_html(HTTPStatus.FORBIDDEN, "无效的控制地址")
                    return

                view = parse_qs(parsed.query).get("view", ["active"])[0]
                window_raw = parse_qs(parsed.query).get("window", ["3600"])[0]
                try:
                    window_seconds = max(1, int(window_raw))
                except ValueError:
                    window_seconds = 3600

                snapshot = service.get_dashboard_snapshot(view=view, window_seconds=window_seconds)
                self._send_html(HTTPStatus.OK, self._render_dashboard(snapshot))

            def _handle_approve(self) -> None:
                length = int(self.headers.get("Content-Length", "0") or "0")
                body = self.rfile.read(length).decode("utf-8") if length > 0 else ""
                form = parse_qs(body)
                token = form.get("token", [""])[0]
                request_id = form.get("request_id", [""])[0]
                if token != service._control_token:
                    self._send_html(HTTPStatus.FORBIDDEN, "无效的控制地址")
                    return
                if not request_id:
                    self._send_html(HTTPStatus.BAD_REQUEST, "缺少请求记录")
                    return
                if not service.approve_request(request_id):
                    self._send_html(HTTPStatus.CONFLICT, self._close_page_html("记录已失效或已处理"))
                    return
                self._send_html(HTTPStatus.OK, self._close_page_html("请求已放行"))

            def _handle_blacklist(self) -> None:
                length = int(self.headers.get("Content-Length", "0") or "0")
                body = self.rfile.read(length).decode("utf-8") if length > 0 else ""
                form = parse_qs(body)
                token = form.get("token", [""])[0]
                if token != service._control_token:
                    self._send_html(HTTPStatus.FORBIDDEN, "无效的控制地址")
                    return
                targets_raw = form.get("targets", [""])[0]
                if not targets_raw:
                    self._send_html(HTTPStatus.BAD_REQUEST, "缺少黑名单目标")
                    return
                try:
                    import json
                    targets = json.loads(targets_raw)
                    if not isinstance(targets, list):
                        targets = []
                    service.blacklist_targets([(t.get("target", ""), t.get("client_ip", "")) for t in targets if isinstance(t, dict)])
                    self._send_html(HTTPStatus.OK, self._close_page_html(f"已添加 {len(targets)} 个目标到黑名单"))
                except Exception as e:
                    self._send_html(HTTPStatus.BAD_REQUEST, self._close_page_html(f"黑名单操作失败: {str(e)}"))


            def _handle_action(self, parsed) -> None:
                token = parse_qs(parsed.query).get("token", [""])[0]
                if not token:
                    self._send_html(HTTPStatus.BAD_REQUEST, "Missing token")
                    return

                with service._lock:
                    now = time.time()
                    service._cleanup_locked(now)
                    action_token = getattr(service, "_action_tokens", {}).get(token) if hasattr(service, "_action_tokens") else None
                    if not action_token:
                        self._send_html(HTTPStatus.GONE, "链接已失效")
                        return
                    if action_token.used:
                        self._send_html(HTTPStatus.CONFLICT, "链接已被使用")
                        return
                    if action_token.expires_at < now:
                        self._send_html(HTTPStatus.GONE, "链接已过期")
                        return

                    action_token.used = True

                if service._on_action:
                    service._on_action(action_token.target, action_token.action)

                log_with_data(
                    service._logger,
                    logging.INFO,
                    "Post-disconnect action selected",
                    target=action_token.target,
                    action=action_token.action,
                    token=token,
                )
                if action_token.action == "shutdown_on_idle":
                    self._send_html(HTTPStatus.OK, "已选择：立即关机（空闲超时后执行）")
                    return
                self._send_html(HTTPStatus.OK, "已选择：保持开机")

            def log_message(self, format: str, *args) -> None:
                return

            def _render_dashboard(self, snapshot: dict[str, object]) -> str:
                view = str(snapshot.get("view", "active"))
                generated_at = self._format_time(float(snapshot.get("generated_at", time.time())))
                totals = snapshot.get("totals", {})
                recent_totals = snapshot.get("recent_totals", {})
                control_url = html.escape(str(snapshot.get("control_url", service.control_url)))
                recent_url = html.escape(str(snapshot.get("recent_url", service.recent_url(int(snapshot.get("window_seconds", 3600))))))
                pending_records = list(snapshot.get("pending_records", []))
                approved_records = list(snapshot.get("approved_records", []))
                recent_records = list(snapshot.get("recent_records", []))
                body_parts = [
                    "<html><head><meta charset='utf-8'>",
                    "<meta name='viewport' content='width=device-width, initial-scale=1'>",
                    "<style>",
                    ":root{--bg:#0b1220;--panel:#111a2b;--panel2:#16233a;--text:#ecf3ff;--muted:#8ea4c7;--accent:#74c0fc;--good:#7ee787;--warn:#ffb86b;--line:#22314d;--bad:#ff7b72;}",
                    "*{box-sizing:border-box;}body{margin:0;font-family:Arial,Helvetica,sans-serif;background:radial-gradient(circle at top,#15213a 0,#0b1220 55%,#08101b 100%);color:var(--text);}a{color:var(--accent);text-decoration:none;}a:hover{text-decoration:underline;}",
                    ".wrap{max-width:1200px;margin:0 auto;padding:24px;} .hero{display:flex;justify-content:space-between;gap:16px;align-items:flex-end;flex-wrap:wrap;margin-bottom:18px;} h1{margin:0;font-size:28px;} .sub{color:var(--muted);margin-top:8px;line-height:1.6;} .pill{display:inline-flex;align-items:center;gap:8px;padding:10px 14px;border:1px solid var(--line);border-radius:999px;background:rgba(255,255,255,.03);color:var(--muted);} .grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:12px;margin:18px 0 24px;} .card{background:linear-gradient(180deg,rgba(255,255,255,.06),rgba(255,255,255,.03));border:1px solid var(--line);border-radius:18px;padding:16px;box-shadow:0 20px 60px rgba(0,0,0,.18);} .metric{font-size:28px;font-weight:700;margin-top:8px;} .section{margin-top:22px;} .section h2{margin:0 0 12px;font-size:20px;} table{width:100%;border-collapse:collapse;overflow:hidden;border-radius:16px;background:rgba(10,16,28,.72);border:1px solid var(--line);} th,td{padding:12px 10px;border-bottom:1px solid rgba(34,49,77,.7);text-align:left;vertical-align:top;} th{font-size:13px;color:var(--muted);background:rgba(255,255,255,.02);} td{font-size:14px;} tr:last-child td{border-bottom:none;} .status{display:inline-flex;align-items:center;padding:4px 10px;border-radius:999px;font-size:12px;font-weight:700;} .pending{background:rgba(255,184,107,.18);color:var(--warn);} .approved{background:rgba(126,231,135,.16);color:var(--good);} .closed{background:rgba(255,123,114,.16);color:var(--bad);} .empty{padding:18px;color:var(--muted);text-align:center;border:1px dashed var(--line);border-radius:16px;background:rgba(255,255,255,.02);} .action-btn{border:none;border-radius:999px;background:linear-gradient(135deg,#74c0fc,#4dabf7);color:#07101f;font-weight:700;padding:10px 16px;cursor:pointer;} .action-btn:hover{filter:brightness(1.05);} .toolbar{display:flex;gap:10px;flex-wrap:wrap;align-items:center;} .footer{margin-top:28px;color:var(--muted);font-size:12px;}",
                    "</style></head><body><div class='wrap'>",
                    "<div class='hero'>",
                    f"<div><h1>RDP 控制中心</h1><div class='sub'>服务启动后生成的控制地址可用于查看当前已放行与挂起请求。访问控制页后，页面会按当前会话状态实时展示记录。</div></div>",
                    f"<div class='pill'>控制地址已启用 · {generated_at}</div>",
                    "</div>",
                    "<div class='grid'>",
                    f"<div class='card'><div class='sub'>本次服务启动总发起次数</div><div class='metric'>{int(totals.get('requested', 0))}</div></div>",
                    f"<div class='card'><div class='sub'>本次服务启动总放行次数</div><div class='metric'>{int(totals.get('approved', 0))}</div></div>",
                    f"<div class='card'><div class='sub'>最近 {int(snapshot.get('window_seconds', 3600)) // 60} 分钟发起次数</div><div class='metric'>{int(recent_totals.get('requested', 0))}</div></div>",
                    f"<div class='card'><div class='sub'>最近 {int(snapshot.get('window_seconds', 3600)) // 60} 分钟放行次数</div><div class='metric'>{int(recent_totals.get('approved', 0))}</div></div>",
                    "</div>",
                    "<div class='section'>",
                    f"<h2>{'当前挂起待授权' if view != 'recent' else '最近请求记录'}</h2>",
                ]

                if view == "recent":
                    body_parts.append(self._render_recent_table(recent_records))
                else:
                    body_parts.append("<div class='toolbar'><span class='pill'>当前控制链接：<a href='" + control_url + "'>打开</a></span><span class='pill'>最近记录：<a href='" + recent_url + "'>查看最近 1h</a></span></div>")
                    previously_approved = list(snapshot.get("previously_approved_records", []))
                    other_pending = list(snapshot.get("other_pending_records", []))
                    body_parts.append(self._render_record_table(previously_approved, other_pending, approved_records))
                    body_parts.append("<div class='section'><h2>最近 1h 请求记录</h2>")
                    body_parts.append(self._render_recent_table(recent_records))
                    body_parts.append("</div>")

                body_parts.append(f"<div class='footer'>记录按请求 IP 聚合显示；点击放行后会自动触发原始等待连接继续流程，并尝试关闭当前页面。</div>")
                body_parts.append("</div></body></html>")
                return "".join(body_parts)

            def _render_record_table(self, previously_approved_records: list[dict], other_pending_records: list[dict], approved_records: list[dict]) -> str:
                rows: list[str] = []
                
                if previously_approved_records:
                    rows.append("<h3 style='margin:12px 0 8px;'>历史曾经放行</h3>")
                    rows.append(self._table_from_aggregates(previously_approved_records, allow_action=True, allow_blacklist=False))
                else:
                    rows.append("<h3 style='margin:12px 0 8px;'>历史曾经放行</h3>")
                    rows.append("<div class='empty'>暂无历史放行记录</div>")
                
                if other_pending_records:
                    rows.append("<h3 style='margin:20px 0 8px;'>其他待授权 <span style='font-size:12px;color:var(--muted);'>(可批量加入黑名单)</span></h3>")
                    rows.append(self._table_from_aggregates(other_pending_records, allow_action=True, allow_blacklist=True))
                else:
                    rows.append("<h3 style='margin:20px 0 8px;'>其他待授权</h3>")
                    rows.append("<div class='empty'>暂无其他待授权请求</div>")
                
                if approved_records:
                    rows.append("<h3 style='margin:20px 0 8px;'>当前已放行</h3>")
                    rows.append(self._table_from_aggregates(approved_records, allow_action=False, allow_blacklist=False))
                else:
                    rows.append("<h3 style='margin:20px 0 8px;'>当前已放行</h3>")
                    rows.append("<div class='empty' style='margin-top:16px;'>暂无当前已放行请求</div>")
                
                return "".join(rows)

            def _render_recent_table(self, recent_records: list[dict]) -> str:
                if not recent_records:
                    return "<div class='empty'>最近 1h 没有请求记录</div>"
                header = "<table><thead><tr><th>目标</th><th>IP 地址</th><th>GEO 地址</th><th>发起时间</th><th>状态</th><th>放行时间</th></tr></thead><tbody>"
                rows = []
                for record in recent_records:
                    rows.append(
                        "<tr>"
                        f"<td>{html.escape(str(record.get('target', '')))}</td>"
                        f"<td>{html.escape(str(record.get('client_ip', '')))}</td>"
                        f"<td>{html.escape(self._display_geo(str(record.get('geo_text', ''))))}</td>"
                        f"<td>{self._format_time(float(record.get('requested_at', 0.0)))}</td>"
                        f"<td><span class='status {self._status_class(str(record.get('status', '')))}'>{html.escape(self._status_text(str(record.get('status', ''))))}</span></td>"
                        f"<td>{self._format_optional_time(record.get('approved_at'))}</td>"
                        "</tr>"
                    )
                return header + "".join(rows) + "</tbody></table>"

            def _table_from_aggregates(self, records: list[dict], allow_action: bool, allow_blacklist: bool = False) -> str:
                if not records:
                    return "<div class='empty'>暂无记录</div>"
                
                if allow_blacklist:
                    header = "<div style='margin-bottom:12px;'><form id='blacklist-form' method='post' action='/blacklist' style='display:inline;'><input type='hidden' name='token' value='" + html.escape(service._control_token) + "'><input type='hidden' id='targets-input' name='targets' value='[]'><button class='action-btn' type='button' onclick='submitBlacklist()' style='background:linear-gradient(135deg,#ff7b72,#ff5555);'>批量加入黑名单</button></form></div><table><thead><tr><th><input type='checkbox' id='select-all-blacklist' onclick='toggleAll()'></th><th>目标</th><th>IP 地址</th><th>GEO 地址</th><th>最近一次发起</th><th>上一次发起</th><th>发起次数</th><th>放行次数</th><th>状态</th><th>操作</th></tr></thead><tbody>"
                else:
                    header = "<table><thead><tr><th>目标</th><th>IP 地址</th><th>GEO 地址</th><th>最近一次发起</th><th>上一次发起</th><th>发起次数</th><th>放行次数</th><th>状态</th><th>操作</th></tr></thead><tbody>"
                
                rows = []
                for idx, record in enumerate(records):
                    request_id = html.escape(str(record.get('active_request_id', '')))
                    target = html.escape(str(record.get('target', '')))
                    client_ip = html.escape(str(record.get('client_ip', '')))
                    
                    if allow_blacklist:
                        checkbox = f"<input type='checkbox' class='blacklist-check' value='{{\"{target}\",\"{client_ip}\"}}'>"
                        rows.append(
                            "<tr>"
                            f"<td>{checkbox}</td>"
                            f"<td>{target}</td>"
                            f"<td>{client_ip}</td>"
                            f"<td>{html.escape(self._display_geo(str(record.get('geo_text', ''))))}</td>"
                            f"<td>{self._format_optional_time(record.get('last_requested_at'))}</td>"
                            f"<td>{self._format_optional_time(record.get('previous_requested_at'))}</td>"
                            f"<td>{int(record.get('request_count', 0))}</td>"
                            f"<td>{int(record.get('approved_count', 0))}</td>"
                            f"<td><span class='status {self._status_class(str(record.get('status', '')))}'>{html.escape(self._status_text(str(record.get('status', ''))))}</span></td>"
                            f"<td>{self._render_action_button(request_id, allow_action)}</td>"
                            "</tr>"
                        )
                    else:
                        rows.append(
                            "<tr>"
                            f"<td>{target}</td>"
                            f"<td>{client_ip}</td>"
                            f"<td>{html.escape(self._display_geo(str(record.get('geo_text', ''))))}</td>"
                            f"<td>{self._format_optional_time(record.get('last_requested_at'))}</td>"
                            f"<td>{self._format_optional_time(record.get('previous_requested_at'))}</td>"
                            f"<td>{int(record.get('request_count', 0))}</td>"
                            f"<td>{int(record.get('approved_count', 0))}</td>"
                            f"<td><span class='status {self._status_class(str(record.get('status', '')))}'>{html.escape(self._status_text(str(record.get('status', ''))))}</span></td>"
                            f"<td>{self._render_action_button(request_id, allow_action)}</td>"
                            "</tr>"
                        )
                
                result = header + "".join(rows) + "</tbody></table>"
                
                if allow_blacklist:
                    result += """<script>
function toggleAll() {
    const selectAll = document.getElementById('select-all-blacklist');
    const checks = document.querySelectorAll('.blacklist-check');
    checks.forEach(c => c.checked = selectAll.checked);
}
function submitBlacklist() {
    const checks = document.querySelectorAll('.blacklist-check:checked');
    const targets = [];
    checks.forEach(c => {
        const parts = c.value.slice(1, -1).split(',').map(x => x.trim().slice(1, -1));
        if (parts.length === 2) {
            targets.push({target: parts[0], client_ip: parts[1]});
        }
    });
    if (!targets.length) {
        alert('请先选择要加入黑名单的项目');
        return;
    }
    if (!confirm('确认要将选中的 ' + targets.length + ' 个项目加入黑名单吗？')) {
        return;
    }
    document.getElementById('targets-input').value = JSON.stringify(targets);
    document.getElementById('blacklist-form').submit();
}
</script>"""
                
                return result

            def _render_action_button(self, request_id: str, allow_action: bool) -> str:
                if not allow_action or not request_id:
                    return "-"
                return (
                    "<form method='post' action='/approve' onsubmit=\"return confirm('确认放行该请求？')\">"
                    f"<input type='hidden' name='token' value='{html.escape(service._control_token)}'>"
                    f"<input type='hidden' name='request_id' value='{request_id}'>"
                    "<button class='action-btn' type='submit'>放行</button>"
                    "</form>"
                )

            def _close_page_html(self, message: str) -> str:
                escaped = html.escape(message)
                return (
                    "<html><head><meta charset='utf-8'>"
                    "<meta name='viewport' content='width=device-width, initial-scale=1'>"
                    "<style>body{margin:0;font-family:Arial,Helvetica,sans-serif;background:#0b1220;color:#ecf3ff;display:grid;place-items:center;min-height:100vh;} .box{padding:28px 32px;border:1px solid #22314d;border-radius:18px;background:#111a2b;box-shadow:0 20px 60px rgba(0,0,0,.2);text-align:center;} .sub{margin-top:10px;color:#8ea4c7;}</style>"
                    "</head><body><div class='box'><div style='font-size:22px;font-weight:700;'>"
                    f"{escaped}</div><div class='sub'>页面将自动关闭</div><script>setTimeout(function(){{window.close();}},100);</script></div></body></html>"
                )

            def _send_html(self, status: HTTPStatus, body: str) -> None:
                payload = body.encode("utf-8")
                self.send_response(int(status))
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)

            @staticmethod
            def _format_time(ts: float) -> str:
                if ts <= 0:
                    return "-"
                return datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M:%S")

            def _format_optional_time(self, value) -> str:
                if value in (None, "", 0, 0.0):
                    return "-"
                try:
                    return self._format_time(float(value))
                except (TypeError, ValueError):
                    return "-"

            @staticmethod
            def _display_geo(text: str) -> str:
                return text if text else "-"

            @staticmethod
            def _status_class(status: str) -> str:
                if status == "approved":
                    return "approved"
                if status == "pending":
                    return "pending"
                return "closed"

            @staticmethod
            def _status_text(status: str) -> str:
                if status == "approved":
                    return "已放行"
                if status == "pending":
                    return "待授权"
                if status == "superseded":
                    return "已被新请求替代"
                if status == "closed":
                    return "已关闭"
                return status or "未知"

        return Handler
