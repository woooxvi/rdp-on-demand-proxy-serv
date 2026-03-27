from __future__ import annotations

import json
import logging
import ssl
import base64
import hashlib
import hmac
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime

from rdp_proxy.config import NotificationsConfig, TargetConfig
from rdp_proxy.logging_utils import log_with_data


class Notifier:
    def __init__(self, config: NotificationsConfig):
        self._cfg = config
        self._logger = logging.getLogger("rdp_proxy.notifications")

    def send_verification(self, client_ip: str, target: TargetConfig, verify_url: str) -> None:
        title = "RDP 登录请求提醒"
        instance_id = target.cloud.instance_id if target.cloud else "N/A"
        text = (
            f"来自 {client_ip} 的 RDP 访问请求，点击链接允许连接\n"
            f"实例: {instance_id}\n"
            f"目标IP: {target.target_ip}\n"
            f"时间: {datetime.now().isoformat(sep=' ', timespec='seconds')}\n"
            f"验证链接: {verify_url}"
        )

        results = self._broadcast(title, text)
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
        text = (
            f"来自 {client_ip} 的 RDP 会话已断开\n"
            f"实例: {instance_id}\n"
            f"目标IP: {target.target_ip}\n"
            f"时间: {datetime.now().isoformat(sep=' ', timespec='seconds')}\n"
            f"上一次选择: {previous_text}\n"
            f"保持开机: {keep_running_url}\n"
            f"立即关机(空闲超时后执行): {shutdown_on_idle_url}"
        )

        results = self._broadcast(title, text)
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
        return self._broadcast(title, text)

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
            f"时间: {datetime.now().isoformat(sep=' ', timespec='seconds')}"
        )
        if error:
            text += f"\n错误: {error}"

        return self._broadcast(title, text)

    def _broadcast(self, title: str, text: str) -> dict[str, bool]:
        results: dict[str, bool] = {}
        if self._cfg.telegram.enabled:
            results["telegram"] = self._send_telegram(f"{title}\n\n{text}")
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
        return results

    def _post_json(self, url: str, payload: dict, insecure_skip_verify: bool = False) -> bool:
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
                _ = resp.read()
            return True
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            log_with_data(self._logger, logging.ERROR, "Notification request failed", error=str(exc), url=url)
            return False

    def _send_telegram(self, text: str) -> bool:
        token = self._cfg.telegram.bot_token
        chat_id = self._cfg.telegram.chat_id
        if not token or not chat_id:
            return False

        url = f"https://api.telegram.org/bot{token}/sendMessage"
        payload = {
            "chat_id": chat_id,
            "text": text,
            "disable_web_page_preview": False,
        }
        return self._post_json(url, payload, insecure_skip_verify=self._cfg.telegram.insecure_skip_verify)

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
