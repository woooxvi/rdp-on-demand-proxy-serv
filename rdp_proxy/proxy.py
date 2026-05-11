from __future__ import annotations

import logging
import select
import socket
import threading
import time
from contextlib import suppress
from datetime import datetime
from pathlib import Path
from uuid import uuid4

from rdp_proxy.cloud.base import CloudProvider
from rdp_proxy.cloud.factory import create_provider
from rdp_proxy.config import AppConfig, TargetConfig
from rdp_proxy.control_center import ControlCenterService
from rdp_proxy.logging_utils import log_with_data, sanitize_sensitive_log_fields
from rdp_proxy.notifications import Notifier


class TargetProxy:
    def __init__(
        self,
        bind_host: str,
        target: TargetConfig,
        notifier: Notifier,
        verification: ControlCenterService,
        security_enabled: bool,
        verification_wait_seconds: int,
        deny_if_timeout: bool,
        forwarding_slot_wait_seconds: int,
        max_pending_connections: int,
        max_pending_verification_connections: int,
        max_pending_verifications_per_ip: int,
        approved_ip_reuse_seconds: int,
        per_ip_connection_rate_window_seconds: int,
        per_ip_connection_rate_limit: int,
    ):
        self._bind_host = bind_host
        self._target = target
        self._notifier = notifier
        self._verification = verification
        self._security_enabled = security_enabled
        self._verification_wait_seconds = verification_wait_seconds
        self._verification_notify_delay_seconds = 2.0
        self._deny_if_timeout = deny_if_timeout
        self._max_pending_connections = max_pending_connections
        self._provider: CloudProvider | None = (
            create_provider(target.cloud) if target.cloud_control_enabled and target.cloud is not None else None
        )

        self._logger = logging.getLogger(f"rdp_proxy.target.{target.name}")
        self._stop_event = threading.Event()
        self._listener: socket.socket | None = None
        self._accept_thread: threading.Thread | None = None
        self._idle_thread: threading.Thread | None = None

        self._single_session_lock = threading.Lock()
        self._api_lock = threading.Lock()
        self._state_lock = threading.Lock()
        self._active_connections = 0
        self._last_disconnect_at = time.time()
        self._idle_action = "keep_running"
        self._max_action_retries = 3
        self._retry_backoff_seconds = [5, 10, 20]
        self._disconnect_notify_grace_seconds = 30
        self._disconnect_notify_generation = 0
        # Scanner/noise suppression heuristics.
        self._rdp_probe_timeout_seconds = 2.0
        self._disconnect_notify_min_duration_seconds = 12.0
        self._disconnect_notify_min_upstream_bytes = 32768
        self._connection_log_lock = threading.Lock()
        self._connection_log_path = Path("logs") / f"connections-{self._target.name}.log"
        self._connection_log_path.parent.mkdir(parents=True, exist_ok=True)
        self._pending_verifications: dict[str, dict[str, object]] = {}
        self._max_pending_verification_connections = max(1, int(max_pending_verification_connections))
        self._max_pending_verifications_per_ip = max(1, int(max_pending_verifications_per_ip))
        self._forwarding_slot_wait_seconds = max(0, int(forwarding_slot_wait_seconds))
        self._approved_ip_reuse_seconds = max(0, int(approved_ip_reuse_seconds))
        self._per_ip_connection_rate_window_seconds = max(0, int(per_ip_connection_rate_window_seconds))
        self._per_ip_connection_rate_limit = max(0, int(per_ip_connection_rate_limit))
        self._recent_approved_ips: dict[str, float] = {}
        self._ip_rate_windows: dict[str, tuple[float, int]] = {}

    def set_verification_notify_delay(self, delay_seconds: float) -> None:
        self._verification_notify_delay_seconds = max(0.0, float(delay_seconds))

    def _state_satisfies_operation(self, operation: str, state: str) -> bool:
        if operation == "start":
            return state in {"RUNNING", "STARTING"}
        if operation == "stop":
            return state in {"STOPPED", "STOPPING"}
        return False

    def _state_blocks_operation(self, operation: str, state: str) -> bool:
        if operation == "start":
            return state == "STOPPING"
        if operation == "stop":
            return state == "STARTING"
        return False

    def start(self) -> None:
        self._accept_thread = threading.Thread(target=self._accept_loop, name=f"accept-{self._target.name}", daemon=True)
        self._accept_thread.start()

        self._idle_thread = threading.Thread(target=self._idle_shutdown_loop, name=f"idle-{self._target.name}", daemon=True)
        self._idle_thread.start()

        log_with_data(
            self._logger,
            logging.INFO,
            "Target proxy started",
            target=self._target.name,
            listen_port=self._target.listen_port,
            target_ip=self._target.target_ip,
            target_port=self._target.target_rdp_port,
        )

    def stop(self) -> None:
        self._stop_event.set()
        if self._listener:
            with suppress(OSError):
                self._listener.close()

    def _accept_loop(self) -> None:
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind((self._bind_host, self._target.listen_port))
        listener.listen(self._max_pending_connections)
        listener.settimeout(1.0)
        self._listener = listener

        while not self._stop_event.is_set():
            try:
                conn, addr = listener.accept()
            except socket.timeout:
                continue
            except OSError:
                break

            client_ip, client_port = addr[0], addr[1]
            t = threading.Thread(
                target=self._handle_connection,
                args=(conn, client_ip, client_port),
                name=f"conn-{self._target.name}-{client_ip}",
                daemon=True,
            )
            t.start()

    def _register_pending_verification(
        self,
        connection_id: str,
        client: socket.socket,
        client_ip: str,
        client_port: int,
    ) -> tuple[bool, str, dict[str, object] | None]:
        replaced: dict[str, object] | None = None
        replaced_sock: socket.socket | None = None
        with self._state_lock:
            pending_total = len(self._pending_verifications)
            same_ip_entries = [
                (conn_id, payload)
                for conn_id, payload in self._pending_verifications.items()
                if payload.get("client_ip") == client_ip
            ]
            pending_for_ip = len(same_ip_entries)
            if pending_total >= self._max_pending_verification_connections:
                return False, "pending_pool_full", None
            if pending_for_ip >= self._max_pending_verifications_per_ip and same_ip_entries:
                old_conn_id, old_payload = same_ip_entries[0]
                replaced = {
                    "connection_id": old_conn_id,
                    "client_ip": str(old_payload.get("client_ip", "")),
                    "client_port": int(old_payload.get("client_port", 0)),
                }
                self._verification.close_request(old_conn_id, "same_ip_takeover")
                old_sock = old_payload.get("socket")
                if isinstance(old_sock, socket.socket):
                    replaced_sock = old_sock
                self._pending_verifications.pop(old_conn_id, None)
            self._pending_verifications[connection_id] = {
                "socket": client,
                "client_ip": client_ip,
                "client_port": client_port,
            }

        if replaced_sock is not None:
            with suppress(OSError):
                replaced_sock.shutdown(socket.SHUT_RDWR)
            with suppress(OSError):
                replaced_sock.close()
            return True, "registered_with_same_ip_takeover", replaced

        return True, "registered", None

    def _unregister_pending_verification(self, connection_id: str) -> None:
        with self._state_lock:
            self._pending_verifications.pop(connection_id, None)

    def _is_recently_approved_ip(self, client_ip: str) -> bool:
        if self._approved_ip_reuse_seconds <= 0:
            return False
        now = time.time()
        with self._state_lock:
            approved_at = self._recent_approved_ips.get(client_ip)
            if approved_at is None:
                return False
            if now - approved_at <= self._approved_ip_reuse_seconds:
                return True
            self._recent_approved_ips.pop(client_ip, None)
        return False

    def _mark_ip_approved(self, client_ip: str) -> None:
        if self._approved_ip_reuse_seconds <= 0:
            return
        now = time.time()
        with self._state_lock:
            self._recent_approved_ips[client_ip] = now
            # Opportunistically clean stale entries to avoid unbounded growth.
            expiry_before = now - self._approved_ip_reuse_seconds
            stale_ips = [ip for ip, ts in self._recent_approved_ips.items() if ts < expiry_before]
            for ip in stale_ips:
                self._recent_approved_ips.pop(ip, None)

    def _consume_ip_connection_slot(self, client_ip: str) -> tuple[bool, float]:
        if self._per_ip_connection_rate_window_seconds <= 0 or self._per_ip_connection_rate_limit <= 0:
            return True, 0.0

        now = time.time()
        with self._state_lock:
            window_start, count = self._ip_rate_windows.get(client_ip, (now, 0))
            elapsed = now - window_start
            if elapsed >= self._per_ip_connection_rate_window_seconds:
                window_start = now
                count = 0

            if count < self._per_ip_connection_rate_limit:
                self._ip_rate_windows[client_ip] = (window_start, count + 1)
                return True, 0.0

            wait_seconds = max(0.0, self._per_ip_connection_rate_window_seconds - elapsed)
            return False, wait_seconds

    def _wait_for_ip_connection_slot(
        self,
        client: socket.socket,
        client_ip: str,
        connection_id: str,
        client_port: int,
    ) -> tuple[bool, str]:
        while True:
            allowed, wait_seconds = self._consume_ip_connection_slot(client_ip)
            if allowed:
                return True, "acquired"

            self._append_connection_audit(
                "rate_limit_wait",
                connection_id=connection_id,
                client_port=client_port,
                target=self._target.name,
                window_seconds=self._per_ip_connection_rate_window_seconds,
                limit=self._per_ip_connection_rate_limit,
                wait_seconds=round(wait_seconds, 2),
            )

            deadline = time.time() + wait_seconds
            while time.time() < deadline:
                timeout = min(0.2, max(0.0, deadline - time.time()))
                try:
                    readable, _, _ = select.select([client], [], [], timeout)
                except (OSError, ValueError):
                    return False, "client_disconnected_while_rate_limited"
                if not readable:
                    continue
                try:
                    peek = client.recv(1, socket.MSG_PEEK)
                except OSError:
                    return False, "client_disconnected_while_rate_limited"
                if not peek:
                    return False, "client_disconnected_while_rate_limited"

    def _handle_connection(self, client: socket.socket, client_ip: str, client_port: int) -> None:
        start_ts = time.time()
        connection_id = uuid4().hex[:12]
        stage = "accepted"
        approved = False
        forwarding_started = False
        pending_registered = False
        forwarding_slot_acquired = False
        c2u_bytes = 0
        u2c_bytes = 0
        with self._state_lock:
            self._active_connections += 1
            # A new connection means previous pending disconnect alerts should be skipped.
            self._disconnect_notify_generation += 1

        log_with_data(
            self._logger,
            logging.INFO,
            "Client connected",
            connection_id=connection_id,
            client_ip=client_ip,
            client_port=client_port,
            target=self._target.name,
        )
        self._append_connection_audit(
            "connected",
            connection_id=connection_id,
            client_ip=client_ip,
            client_port=client_port,
            target=self._target.name,
        )

        upstream: socket.socket | None = None
        try:
            stage = "ip_rate_limit"
            rate_ok, rate_reason = self._wait_for_ip_connection_slot(
                client=client,
                client_ip=client_ip,
                connection_id=connection_id,
                client_port=client_port,
            )
            if not rate_ok:
                self._append_connection_audit(
                    "connection_aborted",
                    connection_id=connection_id,
                    client_port=client_port,
                    target=self._target.name,
                    stage=stage,
                    reason=rate_reason,
                )
                return

            stage = "probe_rdp_hello"
            if not self._looks_like_rdp_client_hello(client):
                log_with_data(
                    self._logger,
                    logging.INFO,
                    "Connection dropped by scanner filter",
                    connection_id=connection_id,
                    client_ip=client_ip,
                    client_port=client_port,
                    target=self._target.name,
                    reason="not_rdp_handshake_or_no_initial_payload",
                )
                self._append_connection_audit(
                    "connection_aborted",
                    connection_id=connection_id,
                    client_port=client_port,
                    target=self._target.name,
                    stage=stage,
                    reason="not_rdp_handshake_or_no_initial_payload",
                )
                return

            if self._security_enabled:
                stage = "notify_delay_window"
                if not self._wait_for_verification_notify_window(client):
                    self._append_connection_audit(
                        "verification_notify_suppressed",
                        connection_id=connection_id,
                        client_port=client_port,
                        target=self._target.name,
                        reason="client_disconnected_before_notify_window",
                        delay_seconds=round(self._verification_notify_delay_seconds, 2),
                    )
                    self._append_connection_audit(
                        "connection_aborted",
                        connection_id=connection_id,
                        client_port=client_port,
                        target=self._target.name,
                        stage=stage,
                        reason="client_disconnected_before_notify_window",
                    )
                    return

                stage = "create_verification"
                can_wait, queue_reason, replaced = self._register_pending_verification(
                    connection_id=connection_id,
                    client=client,
                    client_ip=client_ip,
                    client_port=client_port,
                )
                if not can_wait:
                    self._append_connection_audit(
                        "connection_rejected",
                        connection_id=connection_id,
                        client_port=client_port,
                        target=self._target.name,
                        reason=queue_reason,
                    )
                    return
                if replaced:
                    self._append_connection_audit(
                        "pending_replaced_same_ip",
                        connection_id=connection_id,
                        client_port=client_port,
                        target=self._target.name,
                        replaced_connection_id=str(replaced.get("connection_id", "")),
                        replaced_client_port=int(replaced.get("client_port", 0)),
                    )
                pending_registered = True
                geo_text = self._notifier.resolve_geo_text(client_ip)
                evt = self._verification.register_request(
                    target=self._target.name,
                    connection_id=connection_id,
                    client_ip=client_ip,
                    client_port=client_port,
                    geo_text=geo_text,
                )
                self._append_connection_audit(
                    "verification_recorded",
                    connection_id=connection_id,
                    client_port=client_port,
                    target=self._target.name,
                    geo_text=geo_text,
                )

                # 检查是否被黑名单拒绝
                if self._verification.is_request_rejected(connection_id):
                    log_with_data(
                        self._logger,
                        logging.INFO,
                        "Connection rejected - target in blacklist",
                        connection_id=connection_id,
                        client_ip=client_ip,
                        target=self._target.name,
                    )
                    self._append_connection_audit(
                        "connection_rejected_blacklist",
                        connection_id=connection_id,
                        client_port=client_port,
                        target=self._target.name,
                    )
                    self._unregister_pending_verification(connection_id)
                    self._verification.close_request(connection_id, "blacklisted")
                    return

                # 检查是否被自动白名单放行
                req_status = self._verification.get_request_status(connection_id)
                if req_status == "approved":
                    approved = True
                    log_with_data(
                        self._logger,
                        logging.INFO,
                        "Connection auto-approved - target in whitelist",
                        connection_id=connection_id,
                        client_ip=client_ip,
                        target=self._target.name,
                    )
                    self._append_connection_audit(
                        "verification_auto_approved_whitelist",
                        connection_id=connection_id,
                        client_port=client_port,
                        target=self._target.name,
                    )
                    self._unregister_pending_verification(connection_id)
                    pending_registered = False
                elif self._is_recently_approved_ip(client_ip):
                    approved = True
                    self._verification.approve_request(connection_id)
                    self._append_connection_audit(
                        "verification_bypassed_recent_approval",
                        connection_id=connection_id,
                        client_port=client_port,
                        target=self._target.name,
                        reuse_seconds=self._approved_ip_reuse_seconds,
                    )
                    self._unregister_pending_verification(connection_id)
                    pending_registered = False
                else:
                    stage = "wait_verification"
                    wait_start_ts = time.time()
                    self._append_connection_audit(
                        "verification_wait_started",
                        connection_id=connection_id,
                        client_port=client_port,
                        target=self._target.name,
                        wait_seconds=self._verification_wait_seconds,
                    )
                    approved, wait_reason = self._wait_for_verification_or_disconnect(
                        client=client,
                        event=evt,
                        timeout_seconds=self._verification_wait_seconds,
                    )
                    self._append_connection_audit(
                        "verification_wait_finished",
                        connection_id=connection_id,
                        client_port=client_port,
                        target=self._target.name,
                        approved=approved,
                        reason=wait_reason,
                        waited_seconds=round(time.time() - wait_start_ts, 2),
                    )
                    if not approved and wait_reason == "client_disconnected":
                        self._verification.close_request(connection_id, wait_reason)
                        self._append_connection_audit(
                            "verification_cancelled",
                            connection_id=connection_id,
                            client_port=client_port,
                            target=self._target.name,
                            reason=wait_reason,
                        )
                        self._append_connection_audit(
                            "connection_aborted",
                            connection_id=connection_id,
                            client_port=client_port,
                            target=self._target.name,
                            stage=stage,
                            reason=wait_reason,
                        )
                        return
                    if not approved:
                        log_with_data(
                            self._logger,
                            logging.WARNING,
                            "Verification timeout",
                            connection_id=connection_id,
                            client_ip=client_ip,
                            target=self._target.name,
                        )
                        self._verification.close_request(connection_id, wait_reason)
                        self._append_connection_audit(
                            "verification_timeout",
                            connection_id=connection_id,
                            client_port=client_port,
                            target=self._target.name,
                            wait_seconds=self._verification_wait_seconds,
                            reason=wait_reason,
                        )
                        if self._deny_if_timeout:
                            self._append_connection_audit(
                                "connection_aborted",
                                connection_id=connection_id,
                                client_port=client_port,
                                target=self._target.name,
                                stage=stage,
                                reason="verification_timeout_deny",
                            )
                            return

                    self._unregister_pending_verification(connection_id)
                    pending_registered = False

                if approved:
                    self._mark_ip_approved(client_ip)

            stage = "wait_forwarding_slot"
            lock_ok, lock_reason = self._acquire_forwarding_slot_or_disconnect(
                client=client,
                timeout_seconds=self._forwarding_slot_wait_seconds,
                is_approved=approved,
            )
            if not lock_ok:
                log_with_data(
                    self._logger,
                    logging.WARNING,
                    "Forwarding slot not acquired",
                    connection_id=connection_id,
                    client_ip=client_ip,
                    target=self._target.name,
                    reason=lock_reason,
                    wait_seconds=self._forwarding_slot_wait_seconds,
                )
                self._append_connection_audit(
                    "connection_aborted",
                    connection_id=connection_id,
                    client_port=client_port,
                    target=self._target.name,
                    stage=stage,
                    reason=lock_reason,
                )
                return
            forwarding_slot_acquired = True

            stage = "ensure_instance_running"
            if not self._ensure_instance_running(client_ip):
                self._append_connection_audit(
                    "instance_not_ready",
                    connection_id=connection_id,
                    client_port=client_port,
                    target=self._target.name,
                )
                self._append_connection_audit(
                    "connection_aborted",
                    connection_id=connection_id,
                    client_port=client_port,
                    target=self._target.name,
                    stage=stage,
                    reason="instance_not_ready",
                )
                return

            stage = "connect_upstream"
            upstream = socket.create_connection((self._target.target_ip, self._target.target_rdp_port), timeout=10)
            client.settimeout(None)
            upstream.settimeout(None)
            with suppress(OSError):
                client.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            with suppress(OSError):
                upstream.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)

            log_with_data(
                self._logger,
                logging.INFO,
                "Forwarding started",
                connection_id=connection_id,
                client_ip=client_ip,
                target=self._target.name,
                latency_seconds=round(time.time() - start_ts, 2),
            )
            self._notifier.on_connection_established(self._target.name)
            self._append_connection_audit(
                "forwarding_started",
                connection_id=connection_id,
                client_port=client_port,
                target=self._target.name,
                latency_seconds=round(time.time() - start_ts, 2),
            )

            forwarding_started = True
            stage = "forwarding"
            c2u_bytes, u2c_bytes = self._pipe_bidirectional(client, upstream)
            log_with_data(
                self._logger,
                logging.INFO,
                "Forwarding stream ended",
                connection_id=connection_id,
                client_ip=client_ip,
                target=self._target.name,
                client_to_upstream_bytes=c2u_bytes,
                upstream_to_client_bytes=u2c_bytes,
            )
            self._append_connection_audit(
                "forwarding_ended",
                connection_id=connection_id,
                client_port=client_port,
                target=self._target.name,
                client_to_upstream_bytes=c2u_bytes,
                upstream_to_client_bytes=u2c_bytes,
            )

        except ConnectionResetError as exc:
            # WinError 10054 usually means peer (often upstream RDP host) reset the TCP session.
            log_with_data(
                self._logger,
                logging.WARNING,
                "Connection reset by peer",
                connection_id=connection_id,
                stage=stage,
                client_ip=client_ip,
                target=self._target.name,
                errno=getattr(exc, "errno", None),
                winerror=getattr(exc, "winerror", None),
                error=str(exc),
            )
            self._append_connection_audit(
                "connection_reset",
                connection_id=connection_id,
                stage=stage,
                client_port=client_port,
                target=self._target.name,
                errno=getattr(exc, "errno", None),
                winerror=getattr(exc, "winerror", None),
                error=str(exc),
            )
        except Exception as exc:
            log_with_data(
                self._logger,
                logging.ERROR,
                "Connection handling failed",
                connection_id=connection_id,
                stage=stage,
                client_ip=client_ip,
                target=self._target.name,
                error=str(exc),
            )
            self._append_connection_audit(
                "connection_failed",
                connection_id=connection_id,
                stage=stage,
                client_port=client_port,
                target=self._target.name,
                error=str(exc),
            )
        finally:
            if pending_registered:
                self._unregister_pending_verification(connection_id)
            self._verification.close_request(connection_id, "connection_closed")
            with suppress(OSError):
                client.close()
            if upstream:
                with suppress(OSError):
                    upstream.close()

            with self._state_lock:
                self._active_connections = max(0, self._active_connections - 1)
                self._last_disconnect_at = time.time()
                self._disconnect_notify_generation += 1
                disconnect_generation = self._disconnect_notify_generation
                previous_action = self._idle_action

            if forwarding_slot_acquired:
                self._single_session_lock.release()

            duration_seconds = time.time() - start_ts
            should_notify, reason = self._should_send_disconnect_notification(
                approved=approved,
                forwarding_started=forwarding_started,
                duration_seconds=duration_seconds,
                upstream_to_client_bytes=u2c_bytes,
            )

            log_with_data(
                self._logger,
                logging.INFO,
                "Forwarding ended",
                connection_id=connection_id,
                stage=stage,
                client_ip=client_ip,
                target=self._target.name,
                duration_seconds=round(time.time() - start_ts, 2),
            )
            self._append_connection_audit(
                "connection_closed",
                connection_id=connection_id,
                stage=stage,
                client_port=client_port,
                target=self._target.name,
                duration_seconds=round(duration_seconds, 2),
                approved=approved,
                forwarding_started=forwarding_started,
                client_to_upstream_bytes=c2u_bytes,
                upstream_to_client_bytes=u2c_bytes,
            )

            if should_notify:
                threading.Thread(
                    target=self._send_disconnect_options_with_grace,
                    args=(client_ip, previous_action, disconnect_generation),
                    name=f"disconnect-notify-{self._target.name}",
                    daemon=True,
                ).start()
            else:
                log_with_data(
                    self._logger,
                    logging.INFO,
                    "Disconnect notification suppressed by eligibility filter",
                    target=self._target.name,
                    client_ip=client_ip,
                    duration_seconds=round(duration_seconds, 2),
                    client_to_upstream_bytes=c2u_bytes,
                    upstream_to_client_bytes=u2c_bytes,
                    reason=reason,
                )

    def _wait_for_verification_notify_window(self, client: socket.socket) -> bool:
        delay_seconds = max(0.0, self._verification_notify_delay_seconds)
        if delay_seconds <= 0:
            return True

        deadline = time.time() + delay_seconds
        while time.time() < deadline:
            timeout = min(0.2, max(0.0, deadline - time.time()))
            try:
                readable, _, _ = select.select([client], [], [], timeout)
            except (OSError, ValueError):
                return False
            if not readable:
                continue
            try:
                peek = client.recv(1, socket.MSG_PEEK)
            except OSError:
                return False
            if not peek:
                return False

        return True

    def _wait_for_verification_or_disconnect(
        self,
        client: socket.socket,
        event: threading.Event,
        timeout_seconds: int,
    ) -> tuple[bool, str]:
        deadline = time.time() + max(0, timeout_seconds)

        while time.time() < deadline:
            if event.wait(timeout=0.2):
                return True, "approved"

            try:
                readable, _, _ = select.select([client], [], [], 0)
            except (OSError, ValueError):
                return False, "client_disconnected"
            if not readable:
                continue
            try:
                peek = client.recv(1, socket.MSG_PEEK)
            except OSError:
                return False, "client_disconnected"
            if not peek:
                return False, "client_disconnected"

        return False, "timeout"

    def _acquire_forwarding_slot_or_disconnect(
        self,
        client: socket.socket,
        timeout_seconds: int,
        is_approved: bool = False,
    ) -> tuple[bool, str]:
        # 已放行的连接获得更长的超时或优先权
        effective_timeout = timeout_seconds
        if is_approved:
            effective_timeout = max(timeout_seconds, timeout_seconds * 2)
        
        deadline = time.time() + max(0, effective_timeout)
        waiting_logged = False
        # 已放行连接使用更短的select超时以获得更多的锁获取机会
        select_timeout = 0.05 if is_approved else 0.2

        while time.time() < deadline:
            if self._single_session_lock.acquire(blocking=False):
                return True, "acquired"

            if not waiting_logged:
                log_with_data(
                    self._logger,
                    logging.INFO,
                    "Forwarding slot busy, waiting",
                    target=self._target.name,
                    wait_seconds=timeout_seconds,
                    priority="high" if is_approved else "normal",
                )
                waiting_logged = True

            try:
                readable, _, _ = select.select([client], [], [], select_timeout)
            except (OSError, ValueError):
                log_with_data(
                    self._logger,
                    logging.INFO,
                    "Client disconnected while waiting forwarding slot",
                    target=self._target.name,
                )
                return False, "client_disconnected_while_waiting_forwarding_slot"
            if not readable:
                continue
            try:
                peek = client.recv(1, socket.MSG_PEEK)
            except OSError:
                log_with_data(
                    self._logger,
                    logging.INFO,
                    "Client disconnected while waiting forwarding slot",
                    target=self._target.name,
                )
                return False, "client_disconnected_while_waiting_forwarding_slot"
            if not peek:
                log_with_data(
                    self._logger,
                    logging.INFO,
                    "Client disconnected while waiting forwarding slot",
                    target=self._target.name,
                )
                return False, "client_disconnected_while_waiting_forwarding_slot"

        log_with_data(
            self._logger,
            logging.WARNING,
            "Forwarding slot wait timeout",
            target=self._target.name,
            wait_seconds=timeout_seconds,
        )
        return False, "forwarding_slot_busy_timeout"

    def _append_connection_audit(self, event: str, **fields: object) -> None:
        now = datetime.now().isoformat(sep=" ", timespec="seconds")
        payload = dict(fields)
        payload.pop("client_ip", None)
        payload = sanitize_sensitive_log_fields(payload)
        pairs = [f"{k}={payload[k]}" for k in sorted(payload.keys())]
        line = f"{now} event={event}"
        if pairs:
            line = f"{line} {' '.join(pairs)}"

        try:
            with self._connection_log_lock:
                with self._connection_log_path.open("a", encoding="utf-8") as fp:
                    fp.write(line + "\n")
        except OSError as exc:
            log_with_data(
                self._logger,
                logging.WARNING,
                "Connection audit log write failed",
                target=self._target.name,
                error=str(exc),
            )

    def _looks_like_rdp_client_hello(self, client: socket.socket) -> bool:
        deadline = time.time() + self._rdp_probe_timeout_seconds
        with suppress(OSError):
            client.settimeout(0.2)

        try:
            while time.time() < deadline:
                try:
                    data = client.recv(12, socket.MSG_PEEK)
                except socket.timeout:
                    continue
                except OSError:
                    return False

                if not data:
                    return False

                # Typical RDP first packet uses TPKT + X.224 Connection Request.
                if len(data) >= 6 and data[0] == 0x03 and data[1] == 0x00 and data[5] == 0xE0:
                    return True
                return False
        finally:
            with suppress(OSError):
                client.settimeout(None)

        return False

    def _should_send_disconnect_notification(
        self,
        approved: bool,
        forwarding_started: bool,
        duration_seconds: float,
        upstream_to_client_bytes: int,
    ) -> tuple[bool, str]:
        if not approved and self._security_enabled:
            return False, "verification_not_approved"
        if not forwarding_started:
            return False, "forwarding_not_started"

        # If RDP auth fails quickly, session usually ends in short time with low upstream bytes.
        likely_real_session = (
            duration_seconds >= self._disconnect_notify_min_duration_seconds
            or upstream_to_client_bytes >= self._disconnect_notify_min_upstream_bytes
        )
        if not likely_real_session:
            return False, "too_short_or_low_traffic"
        return True, "eligible"

    def _send_disconnect_options_with_grace(self, client_ip: str, previous_action: str, generation: int) -> None:
        time.sleep(self._disconnect_notify_grace_seconds)

        with self._state_lock:
            active = self._active_connections
            latest_generation = self._disconnect_notify_generation

        if active > 0 or latest_generation != generation:
            log_with_data(
                self._logger,
                logging.INFO,
                "Disconnect notification suppressed by reconnect window",
                target=self._target.name,
                client_ip=client_ip,
                grace_seconds=self._disconnect_notify_grace_seconds,
            )
            return

        keep_url, shutdown_url = self._verification.create_action_links(self._target.name)
        self._notifier.send_disconnect_options(
            client_ip=client_ip,
            target=self._target,
            keep_running_url=keep_url,
            shutdown_on_idle_url=shutdown_url,
            previous_action=previous_action,
        )
        log_with_data(
            self._logger,
            logging.INFO,
            "Disconnect options sent",
            client_ip=client_ip,
            target=self._target.name,
            previous_action=previous_action,
            keep_running_url=keep_url,
            shutdown_on_idle_url=shutdown_url,
        )

    def apply_idle_action(self, action: str) -> None:
        if action not in {"keep_running", "shutdown_on_idle"}:
            return

        with self._state_lock:
            self._idle_action = action

        log_with_data(
            self._logger,
            logging.INFO,
            "Idle action updated",
            target=self._target.name,
            action=action,
        )

    def _pipe_bidirectional(self, client: socket.socket, upstream: socket.socket) -> tuple[int, int]:
        sockets = [client, upstream]
        mapping = {client: upstream, upstream: client}
        c2u_bytes = 0
        u2c_bytes = 0
        last_stat_ts = time.time()

        while not self._stop_event.is_set():
            readable, _, _ = select.select(sockets, [], [], 1.0)
            if not readable:
                now = time.time()
                if now - last_stat_ts >= 10:
                    log_with_data(
                        self._logger,
                        logging.INFO,
                        "Forwarding stats",
                        target=self._target.name,
                        client_to_upstream_bytes=c2u_bytes,
                        upstream_to_client_bytes=u2c_bytes,
                    )
                    last_stat_ts = now
                continue

            for src in readable:
                dst = mapping[src]
                try:
                    data = src.recv(8192)
                except ConnectionResetError as exc:
                    side = "client" if src is client else "upstream"
                    log_with_data(
                        self._logger,
                        logging.WARNING,
                        "Socket reset during forwarding",
                        target=self._target.name,
                        reset_side=side,
                        errno=getattr(exc, "errno", None),
                        winerror=getattr(exc, "winerror", None),
                        error=str(exc),
                        client_to_upstream_bytes=c2u_bytes,
                        upstream_to_client_bytes=u2c_bytes,
                    )
                    return c2u_bytes, u2c_bytes

                if not data:
                    return c2u_bytes, u2c_bytes
                try:
                    dst.sendall(data)
                except ConnectionResetError as exc:
                    side = "upstream" if src is client else "client"
                    log_with_data(
                        self._logger,
                        logging.WARNING,
                        "Socket reset during send",
                        target=self._target.name,
                        reset_side=side,
                        errno=getattr(exc, "errno", None),
                        winerror=getattr(exc, "winerror", None),
                        error=str(exc),
                        client_to_upstream_bytes=c2u_bytes,
                        upstream_to_client_bytes=u2c_bytes,
                    )
                    return c2u_bytes, u2c_bytes

                if src is client:
                    c2u_bytes += len(data)
                else:
                    u2c_bytes += len(data)

        return c2u_bytes, u2c_bytes

    def _ensure_instance_running(self, client_ip: str) -> bool:
        if not self._target.cloud_control_enabled:
            log_with_data(
                self._logger,
                logging.INFO,
                "Cloud control disabled, skip instance state checks",
                client_ip=client_ip,
                target=self._target.name,
            )
            return True

        deadline = time.time() + self._target.startup_timeout_seconds
        started = False

        with self._api_lock:
            while time.time() < deadline:
                if self._provider is None:
                    return True
                state = self._provider.get_instance_state()
                log_with_data(
                    self._logger,
                    logging.INFO,
                    "Instance state checked",
                    client_ip=client_ip,
                    target=self._target.name,
                    state=state,
                )

                if state == "RUNNING":
                    return True

                if state == "STOPPED" and not started:
                    if not self._execute_cloud_action_with_retry("start", client_ip):
                        return False
                    started = True
                    log_with_data(
                        self._logger,
                        logging.INFO,
                        "Instance start requested",
                        client_ip=client_ip,
                        target=self._target.name,
                        instance_id=self._target.cloud.instance_id,
                    )

                time.sleep(self._target.startup_poll_seconds)

        log_with_data(
            self._logger,
            logging.ERROR,
            "Instance startup timeout",
            client_ip=client_ip,
            target=self._target.name,
            timeout_seconds=self._target.startup_timeout_seconds,
        )
        return False

    def _is_non_retryable_auth_error(self, exc: Exception) -> bool:
        msg = f"{type(exc).__name__}: {exc}".lower()
        keywords = [
            "invalidsecretid",
            "signaturefailure",
            "authfailure",
            "unauthorizedoperation",
            "unauthorized",
            "invalidaccesskeyid",
            "signaturedoesnotmatch",
            "security token included in the request is invalid",
            "access key",
            "ak",
        ]
        return any(k in msg for k in keywords)

    def _is_non_retryable_business_error(self, exc: Exception) -> bool:
        msg = f"{type(exc).__name__}: {exc}".lower()
        keywords = [
            "invalidinstanceid",
            "invalidparameter",
            "resource not found",
            "instance not found",
        ]
        return any(k in msg for k in keywords)

    def _execute_cloud_action_with_retry(self, operation: str, client_ip: str) -> bool:
        if self._provider is None:
            return True

        attempts = 0
        last_exc: Exception | None = None
        state_wait_reason = ""

        for retry_index in range(self._max_action_retries + 1):
            attempts = retry_index + 1
            try:
                state = self._provider.get_instance_state()
            except Exception as exc:
                state = "UNKNOWN"
                last_exc = exc
                state_wait_reason = f"state-check-failed: {exc}"

            if self._state_satisfies_operation(operation, state):
                self._notifier.send_cloud_operation_result(
                    target=self._target,
                    operation=operation,
                    success=True,
                    attempts=attempts,
                    client_ip=client_ip,
                )
                log_with_data(
                    self._logger,
                    logging.INFO,
                    "Cloud action treated as success by current state",
                    target=self._target.name,
                    operation=operation,
                    client_ip=client_ip,
                    state=state,
                    attempts=attempts,
                )
                return True

            if self._state_blocks_operation(operation, state):
                state_wait_reason = f"state-blocked:{state}"
                is_last_try = retry_index >= self._max_action_retries
                if is_last_try:
                    break
                backoff = self._retry_backoff_seconds[min(retry_index, len(self._retry_backoff_seconds) - 1)]
                log_with_data(
                    self._logger,
                    logging.WARNING,
                    "Cloud action blocked by transient state, waiting",
                    target=self._target.name,
                    operation=operation,
                    client_ip=client_ip,
                    state=state,
                    attempt=attempts,
                    next_retry_in_seconds=backoff,
                )
                time.sleep(backoff)
                continue

            try:
                if operation == "start":
                    self._provider.start_instance()
                elif operation == "stop":
                    stop_mode = self._target.cloud.stop_mode if self._target.cloud else "STOP_CHARGING"
                    self._provider.stop_instance(stop_mode)
                else:
                    raise ValueError(f"Unknown operation: {operation}")

                self._notifier.send_cloud_operation_result(
                    target=self._target,
                    operation=operation,
                    success=True,
                    attempts=attempts,
                    client_ip=client_ip,
                )
                return True
            except Exception as exc:
                last_exc = exc
                non_retryable = self._is_non_retryable_auth_error(exc)
                non_retryable = non_retryable or self._is_non_retryable_business_error(exc)

                # Some provider errors happen while state has already reached desired result.
                try:
                    latest_state = self._provider.get_instance_state()
                except Exception:
                    latest_state = "UNKNOWN"
                if self._state_satisfies_operation(operation, latest_state):
                    self._notifier.send_cloud_operation_result(
                        target=self._target,
                        operation=operation,
                        success=True,
                        attempts=attempts,
                        client_ip=client_ip,
                    )
                    log_with_data(
                        self._logger,
                        logging.INFO,
                        "Cloud action treated as success after exception by latest state",
                        target=self._target.name,
                        operation=operation,
                        client_ip=client_ip,
                        state=latest_state,
                        attempts=attempts,
                        error=str(exc),
                    )
                    return True

                is_last_try = retry_index >= self._max_action_retries
                if non_retryable or is_last_try:
                    break

                backoff = self._retry_backoff_seconds[min(retry_index, len(self._retry_backoff_seconds) - 1)]
                log_with_data(
                    self._logger,
                    logging.WARNING,
                    "Cloud action failed, retrying",
                    target=self._target.name,
                    operation=operation,
                    client_ip=client_ip,
                    attempt=attempts,
                    next_retry_in_seconds=backoff,
                    error=str(exc),
                )
                time.sleep(backoff)

        error_text = str(last_exc) if last_exc else "unknown error"
        if state_wait_reason:
            error_text = f"{error_text}; {state_wait_reason}" if error_text else state_wait_reason
        self._notifier.send_cloud_operation_result(
            target=self._target,
            operation=operation,
            success=False,
            attempts=attempts,
            error=error_text,
            client_ip=client_ip,
        )
        log_with_data(
            self._logger,
            logging.ERROR,
            "Cloud action failed after retries",
            target=self._target.name,
            operation=operation,
            client_ip=client_ip,
            attempts=attempts,
            error=error_text,
        )
        return False

    def _idle_shutdown_loop(self) -> None:
        idle_seconds = self._target.idle_shutdown_minutes * 60

        while not self._stop_event.is_set():
            time.sleep(10)
            if not self._target.cloud_control_enabled:
                continue

            with self._state_lock:
                active = self._active_connections
                last_disconnect_at = self._last_disconnect_at
                idle_action = self._idle_action

            if idle_action != "shutdown_on_idle":
                continue

            if active > 0:
                continue
            if time.time() - last_disconnect_at < idle_seconds:
                continue

            with self._api_lock:
                if self._provider is None:
                    continue
                state = self._provider.get_instance_state()
                if state != "RUNNING":
                    continue
                try:
                    if not self._execute_cloud_action_with_retry("stop", "system-idle-timer"):
                        continue
                    with self._state_lock:
                        self._last_disconnect_at = time.time()
                    log_with_data(
                        self._logger,
                        logging.INFO,
                        "Instance stop requested by idle timer",
                        target=self._target.name,
                        instance_id=self._target.cloud.instance_id if self._target.cloud else "N/A",
                        stop_mode=self._target.cloud.stop_mode if self._target.cloud else "STOP_CHARGING",
                    )
                except Exception as exc:
                    log_with_data(
                        self._logger,
                        logging.ERROR,
                        "Failed to stop instance",
                        target=self._target.name,
                        error=str(exc),
                    )


class RDPProxyApp:
    def __init__(self, cfg: AppConfig):
        self._cfg = cfg
        self._logger = logging.getLogger("rdp_proxy.app")
        self._verification = ControlCenterService(
            bind=cfg.server.control_http_bind,
            port=cfg.server.control_http_port,
            external_base_url=cfg.server.external_control_base_url,
            ttl_seconds=cfg.security.token_ttl_seconds,
            on_approved=self._handle_verification_approved,
            on_action=self._handle_post_disconnect_action,
        )
        self._notifier = Notifier(cfg.notifications)
        self._summary_interval_seconds = max(1, int(cfg.notifications.control_summary_interval_seconds))
        self._summary_stop_event = threading.Event()
        self._summary_thread: threading.Thread | None = None
        self._targets: list[TargetProxy] = [
            TargetProxy(
                bind_host=cfg.server.bind,
                target=t,
                notifier=self._notifier,
                verification=self._verification,
                security_enabled=cfg.security.enabled,
                verification_wait_seconds=cfg.security.wait_for_verification_seconds,
                deny_if_timeout=cfg.security.deny_if_timeout,
                forwarding_slot_wait_seconds=cfg.security.forwarding_slot_wait_seconds,
                max_pending_connections=cfg.server.max_pending_connections,
                max_pending_verification_connections=cfg.security.max_pending_verification_connections,
                max_pending_verifications_per_ip=cfg.security.max_pending_verifications_per_ip,
                approved_ip_reuse_seconds=cfg.security.approved_ip_reuse_seconds,
                per_ip_connection_rate_window_seconds=cfg.security.per_ip_connection_rate_window_seconds,
                per_ip_connection_rate_limit=cfg.security.per_ip_connection_rate_limit,
            )
            for t in cfg.targets
        ]
        for target_proxy in self._targets:
            target_proxy.set_verification_notify_delay(cfg.security.verification_notify_delay_seconds)
        self._target_by_name = {t._target.name: t for t in self._targets}

    def _handle_post_disconnect_action(self, target_name: str, action: str) -> None:
        target = self._target_by_name.get(target_name)
        if not target:
            log_with_data(
                self._logger,
                logging.WARNING,
                "Action target not found",
                target=target_name,
                action=action,
            )
            return
        target.apply_idle_action(action)
        log_with_data(
            self._logger,
            logging.INFO,
            "Post-disconnect action applied",
            target=target_name,
            action=action,
        )

    def _handle_verification_approved(self, token: str, meta: dict) -> None:
        log_with_data(
            self._logger,
            logging.INFO,
            "Request approval callback processed",
            token=token,
            target=meta.get("target", "unknown"),
            client_ip=meta.get("client_ip", "unknown"),
        )

    def _summary_loop(self) -> None:
        while not self._summary_stop_event.wait(self._summary_interval_seconds):
            snapshot = self._verification.get_dashboard_snapshot(view="recent", window_seconds=self._summary_interval_seconds)
            recent_totals = snapshot.get("recent_totals", {})
            self._notifier.send_control_summary(
                window_seconds=self._summary_interval_seconds,
                requested_count=int(recent_totals.get("requested", 0)),
                approved_count=int(recent_totals.get("approved", 0)),
                summary_url=self._verification.recent_url(self._summary_interval_seconds),
            )

    def start(self) -> None:
        self._verification.start()
        for target in self._targets:
            target.start()
        self._notifier.send_control_startup(self._verification.control_url)
        self._summary_thread = threading.Thread(target=self._summary_loop, name="control-summary", daemon=True)
        self._summary_thread.start()
        log_with_data(self._logger, logging.INFO, "RDP proxy app started", target_count=len(self._targets))

    def stop(self) -> None:
        self._summary_stop_event.set()
        for target in self._targets:
            target.stop()
        self._verification.stop()
        log_with_data(self._logger, logging.INFO, "RDP proxy app stopped")
