from __future__ import annotations

import json
import logging
import ssl
import base64
import hashlib
import hmac
import ipaddress
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime

try:
    import pytz
except ImportError:
    pytz = None

from rdp_proxy.config import NotificationsConfig, TargetConfig
from rdp_proxy.logging_utils import log_with_data


class Notifier:
    def __init__(self, config: NotificationsConfig):
        self._cfg = config
        self._logger = logging.getLogger("rdp_proxy.notifications")
        self._telegram_verification_messages: dict[str, list[int]] = {}
        self._geoip_cache: dict[str, tuple[float, str]] = {}
        self._lock = threading.Lock()
        self._timezone_obj = self._init_timezone()

    def _init_timezone(self):
        """Initialize timezone object based on config."""
        tz_config = self._cfg.timezone.strip()
        if tz_config == "utc":
            return None  # Special marker for UTC
        if tz_config == "server":
            return "server"  # Special marker for server local time
        # Try to load as IANA timezone
        if pytz:
            try:
                return pytz.timezone(tz_config)
            except pytz.exceptions.UnknownTimeZoneError:
                self._logger.warning(f"Unknown timezone: {tz_config}, falling back to server time")
                return "server"
        else:
            self._logger.warning("pytz not installed, cannot use IANA timezones, falling back to server time")
            return "server"

    def _format_time(self) -> str:
        """Format current time according to configured timezone."""
        if self._timezone_obj is None:
            # UTC
            return datetime.utcnow().isoformat(sep=' ', timespec='seconds') + " UTC"
        elif self._timezone_obj == "server":
            # Server local time
            return datetime.now().isoformat(sep=' ', timespec='seconds')
        else:
            # IANA timezone
            return datetime.now(self._timezone_obj).isoformat(sep=' ', timespec='seconds')

    def send_verification(self, client_ip: str, target: TargetConfig, verify_url: str, token: str = "") -> None:
        title = "RDP 登录请求提醒"
        instance_id = target.cloud.instance_id if target.cloud else "N/A"
        origin = self._format_origin(client_ip)
        time_str = self._format_time()
        text = (
            f"来自 {origin} 的 RDP 访问请求，点击链接允许连接\n"
            f"实例: {instance_id}\n"
            f"目标IP: {target.target_ip}\n"
            f"时间: {time_str}\n"
            f"验证链接: {verify_url}"
        )

        telegram_text = (
            f"<b>{self._escape_html(title)}</b>\n\n"
            f"来自 {self._escape_html(origin)} 的 RDP 访问请求，点击链接允许连接\n"
            f"实例: {self._escape_html(instance_id)}\n"
            f"目标IP: {self._escape_html(target.target_ip)}\n"
            f"时间: {self._escape_html(time_str)}\n"
            f"验证链接: {self._escape_html(verify_url)}"
        )

        results, telegram_message_id = self._broadcast(
            title,
            text,
            telegram_text=telegram_text,
            telegram_parse_mode="HTML",
        )
        if token and telegram_message_id is not None:
            with self._lock:
                self._telegram_verification_messages.setdefault(token, []).append(telegram_message_id)
        sent = any(results.values())

        if not sent:
            log_with_data(
                self._logger,
                logging.WARNING,
                "No notification was sent",
                client_ip=client_ip,
                target=target.name,
            )

    def send_disconnect_options(
        self,
        client_ip: str,
        target: TargetConfig,
        keep_running_url: str,
        shutdown_on_idle_url: str,
        previous_action: str,
    ) -> None:
        title = "RDP 连接断开提醒"
        instance_id = target.cloud.instance_id if target.cloud else "N/A"
        previous_text = "立即关机" if previous_action == "shutdown_on_idle" else "保持开机"
        origin = self._format_origin(client_ip)
        now_text = self._format_time()
        text = (
            f"来自 {origin} 的 RDP 会话已断开\n"
            f"实例: {instance_id}\n"
            f"目标IP: {target.target_ip}\n"
            f"时间: {now_text}\n"
            f"上一次选择: {previous_text}\n"
            f"保持开机: {keep_running_url}\n"
            f"立即关机(空闲超时后执行): {shutdown_on_idle_url}"
        )

        telegram_text = (
            f"<b>{self._escape_html(title)}</b>\n\n"
            f"来自 {self._escape_html(origin)} 的 RDP 会话已断开\n"
            f"实例: {self._escape_html(instance_id)}\n"
            f"目标IP: {self._escape_html(target.target_ip)}\n"
            f"时间: {self._escape_html(now_text)}\n"
            f"上一次选择: {self._escape_html(previous_text)}\n"
            f"<b>保持开机</b>: {self._escape_html(keep_running_url)}\n"
            f"<b>立即关机</b>(空闲超时后执行): {self._escape_html(shutdown_on_idle_url)}"
        )

        results, _ = self._broadcast(title, text, telegram_text=telegram_text, telegram_parse_mode="HTML")
        sent = any(results.values())

        if not sent:
            log_with_data(
                self._logger,
                logging.WARNING,
                "No disconnect notification was sent",
                client_ip=client_ip,
                target=target.name,
            )

    def send_test_message(self, text: str) -> dict[str, bool]:
        title = "RDP Proxy 通知测试"
        results, _ = self._broadcast(title, text)
        return results

    def on_verification_approved(self, token: str) -> None:
        if not token:
            return
        if not self._cfg.telegram.enabled:
            return

        with self._lock:
            message_ids = list(self._telegram_verification_messages.pop(token, []))

        for message_id in message_ids:
            ok = self._delete_telegram_message(message_id)
            log_with_data(
                self._logger,
                logging.INFO,
                "Telegram verification message delete attempted",
                token=token,
                message_id=message_id,
                deleted=ok,
            )

    def send_cloud_operation_result(
        self,
        target: TargetConfig,
        operation: str,
        success: bool,
        attempts: int,
        error: str | None = None,
        client_ip: str = "system",
    ) -> dict[str, bool]:
        operation_text = "开机" if operation == "start" else "关机"
        result_text = "成功" if success else "失败"
        title = f"云主机{operation_text}结果通知"
        instance_id = target.cloud.instance_id if target.cloud else "N/A"

        text = (
            f"请求来源: {client_ip}\n"
            f"实例: {instance_id}\n"
            f"目标IP: {target.target_ip}\n"
            f"操作: {operation_text}\n"
            f"结果: {result_text}\n"
            f"尝试次数: {attempts}\n"
            f"时间: {self._format_time()}"
        )
        if error:
            text += f"\n错误: {error}"

        results, _ = self._broadcast(title, text)
        return results

    def _broadcast(
        self,
        title: str,
        text: str,
        telegram_text: str | None = None,
        telegram_parse_mode: str | None = None,
    ) -> tuple[dict[str, bool], int | None]:
        results: dict[str, bool] = {}
        telegram_message_id: int | None = None
        if self._cfg.telegram.enabled:
            telegram_ok, telegram_message_id = self._send_telegram(
                telegram_text if telegram_text is not None else f"{title}\n\n{text}",
                parse_mode=telegram_parse_mode,
            )
            results["telegram"] = telegram_ok
        if self._cfg.dingtalk.enabled:
            results["dingtalk"] = self._send_dingtalk(title, text)
        if self._cfg.wecom.enabled:
            results["wecom"] = self._send_wecom(title, text)

        log_with_data(
            self._logger,
            logging.INFO,
            "Notification broadcast result",
            **results,
        )
        return results, telegram_message_id

    def _post_json(self, url: str, payload: dict, insecure_skip_verify: bool = False) -> bool:
        ok, _ = self._post_json_with_response(url, payload, insecure_skip_verify=insecure_skip_verify)
        return ok

    def _post_json_with_response(
        self,
        url: str,
        payload: dict,
        insecure_skip_verify: bool = False,
    ) -> tuple[bool, dict | None]:
        data = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(
            url,
            data=data,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            context = ssl._create_unverified_context() if insecure_skip_verify else None
            with urllib.request.urlopen(req, timeout=8, context=context) as resp:
                raw = resp.read()
            if not raw:
                return True, None
            try:
                return True, json.loads(raw.decode("utf-8"))
            except (ValueError, UnicodeDecodeError):
                return True, None
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            log_with_data(self._logger, logging.ERROR, "Notification request failed", error=str(exc), url=url)
            return False, None

    def _send_telegram(self, text: str, parse_mode: str | None = None) -> tuple[bool, int | None]:
        token = self._cfg.telegram.bot_token
        chat_id = self._cfg.telegram.chat_id
        if not token or not chat_id:
            return False, None

        url = f"https://api.telegram.org/bot{token}/sendMessage"
        payload = {
            "chat_id": chat_id,
            "text": text,
            "disable_web_page_preview": False,
        }
        if parse_mode:
            payload["parse_mode"] = parse_mode
        ok, response = self._post_json_with_response(url, payload, insecure_skip_verify=self._cfg.telegram.insecure_skip_verify)
        if not ok:
            return False, None

        message_id: int | None = None
        if isinstance(response, dict):
            result = response.get("result")
            if isinstance(result, dict) and isinstance(result.get("message_id"), int):
                message_id = result["message_id"]
        return True, message_id

    def _delete_telegram_message(self, message_id: int) -> bool:
        token = self._cfg.telegram.bot_token
        chat_id = self._cfg.telegram.chat_id
        if not token or not chat_id:
            return False

        url = f"https://api.telegram.org/bot{token}/deleteMessage"
        payload = {
            "chat_id": chat_id,
            "message_id": message_id,
        }
        ok, _ = self._post_json_with_response(url, payload, insecure_skip_verify=self._cfg.telegram.insecure_skip_verify)
        return ok

    def _send_dingtalk(self, title: str, text: str) -> bool:
        webhook = self._cfg.dingtalk.webhook
        if not webhook:
            return False

        secret = self._cfg.dingtalk.secret
        if secret:
            timestamp = str(int(time.time() * 1000))
            string_to_sign = f"{timestamp}\n{secret}"
            sign = base64.b64encode(hmac.new(secret.encode("utf-8"), string_to_sign.encode("utf-8"), hashlib.sha256).digest())
            sign_encoded = urllib.parse.quote_plus(sign.decode("utf-8"))
            sep = "&" if "?" in webhook else "?"
            webhook = f"{webhook}{sep}timestamp={timestamp}&sign={sign_encoded}"

        payload = {
            "msgtype": "markdown",
            "markdown": {
                "title": title,
                "text": f"### {title}\n\n{text}",
            },
        }
        return self._post_json(webhook, payload)

    def _send_wecom(self, title: str, text: str) -> bool:
        webhook = self._cfg.wecom.webhook
        if not webhook:
            return False
        payload = {
            "msgtype": "markdown",
            "markdown": {
                "content": f"## {title}\n\n{text}",
            },
        }
        return self._post_json(webhook, payload)

    def _format_origin(self, client_ip: str) -> str:
        masked = self._mask_ip(client_ip) if self._cfg.privacy.mask_client_ip else client_ip
        city = self._resolve_city(client_ip)
        if city:
            return f"IP尾号 {masked} ({city})"
        return f"IP尾号 {masked}"

    def _mask_ip(self, client_ip: str) -> str:
        try:
            ip_obj = ipaddress.ip_address(client_ip)
        except ValueError:
            if len(client_ip) <= 3:
                return client_ip
            return client_ip[-3:]

        if isinstance(ip_obj, ipaddress.IPv4Address):
            return client_ip.split(".")[-1]

        exploded = ip_obj.exploded.split(":")
        return exploded[-1][-4:]

    def _resolve_city(self, client_ip: str) -> str:
        if not self._cfg.geoip.enabled:
            return ""

        now = time.time()
        with self._lock:
            cached = self._geoip_cache.get(client_ip)
            if cached and cached[0] >= now:
                return cached[1]

        city_text = self._lookup_city_online(client_ip)
        expire_at = now + max(1, self._cfg.geoip.cache_ttl_seconds)
        with self._lock:
            self._geoip_cache[client_ip] = (expire_at, city_text)
        return city_text

    def _lookup_city_online(self, client_ip: str) -> str:
        endpoints = self._build_geoip_endpoints(client_ip)
        if not endpoints:
            return ""

        timeout_seconds = max(0.2, self._cfg.geoip.timeout_seconds)
        for endpoint in endpoints:
            req = urllib.request.Request(endpoint, method="GET")
            try:
                with urllib.request.urlopen(req, timeout=timeout_seconds) as resp:
                    raw = resp.read()
            except (urllib.error.URLError, TimeoutError, OSError, ValueError) as exc:
                log_with_data(
                    self._logger,
                    logging.WARNING,
                    "GeoIP lookup failed on endpoint",
                    client_ip=client_ip,
                    endpoint=endpoint,
                    error=str(exc),
                )
                continue

            if not raw:
                continue

            try:
                payload = json.loads(raw.decode("utf-8"))
            except (ValueError, UnicodeDecodeError):
                continue
            if not isinstance(payload, dict):
                continue

            # Common providers expose different field names.
            city = str(payload.get("city", payload.get("city_name", ""))).strip()
            region = str(payload.get("region", payload.get("regionName", payload.get("region_name", "")))).strip()
            country = str(payload.get("country_name", payload.get("country", payload.get("countryCode", "")))).strip()
            parts = [p for p in [city, region, country] if p]
            if parts:
                return "/".join(parts)

        return ""

    def _build_geoip_endpoints(self, client_ip: str) -> list[str]:
        encoded_ip = urllib.parse.quote(client_ip, safe="")
        results: list[str] = []
        for template in self._cfg.geoip.endpoint_templates:
            tpl = str(template).strip()
            if not tpl:
                continue
            if "{ip}" in tpl:
                results.append(tpl.replace("{ip}", encoded_ip))
                continue
            if tpl.endswith("/"):
                results.append(f"{tpl}{encoded_ip}")
            else:
                results.append(f"{tpl}/{encoded_ip}")
        return results

    def _escape_html(self, text: str) -> str:
        return (
            text.replace("&", "&amp;")
            .replace("<", "&lt;")
            .replace(">", "&gt;")
        )
