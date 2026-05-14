from __future__ import annotations

import base64
import hashlib
import ipaddress
import json
import logging
import os
import threading
from dataclasses import dataclass
from pathlib import Path

from rdp_proxy.config import WhitelistConfig
from rdp_proxy.logging_utils import log_with_data


@dataclass(frozen=True)
class WhitelistResult:
    allowed: bool
    message: str
    normalized_ip: str = ""


class WhitelistStore:
    def __init__(self, config: WhitelistConfig):
        self._enabled = config.enabled
        self._logger = logging.getLogger("rdp_proxy.whitelist")
        self._lock = threading.Lock()
        self._path = Path(config.path)
        self._mode = self._normalize_mode(config.storage)
        self._secret_name = config.k8_secret_name
        self._secret_namespace = config.k8_secret_namespace
        self._secret_key = config.k8_secret_key
        self._cipher_ips: set[str] = set()
        self._last_loaded_mtime_ns: int | None = None
        self._load_from_disk()

    def _normalize_mode(self, value: str) -> str:
        mode = value.strip().lower()
        if mode in {"k8", "kubernetes", "secret"}:
            return "k8"
        return "filesystem"

    def _cipher_ip(self, client_ip: str) -> str:
        normalized_ip = ipaddress.ip_address(client_ip.strip()).compressed
        digest = hashlib.sha256(f"rdp-proxy:whitelist:v1|{normalized_ip}".encode("utf-8")).digest()
        return base64.urlsafe_b64encode(digest).decode("ascii").rstrip("=")

    def _normalize_loaded_ip(self, value: object) -> str:
        text = str(value).strip()
        if not text:
            return ""
        try:
            return self._cipher_ip(text)
        except ValueError:
            return text

    def _decode_payload(self, payload: object) -> set[str]:
        values: list[object]
        if isinstance(payload, dict):
            raw_values = payload.get("cipher_ips")
            if raw_values is None:
                raw_values = payload.get("ips")
            if raw_values is None:
                raw_values = payload.get("items")
            if raw_values is None:
                raw_values = []
            if isinstance(raw_values, list):
                values = list(raw_values)
            else:
                values = [raw_values]
        elif isinstance(payload, list):
            values = list(payload)
        else:
            values = []

        result: set[str] = set()
        for item in values:
            cipher = self._normalize_loaded_ip(item)
            if cipher:
                result.add(cipher)
        return result

    def _serialize_payload(self) -> str:
        payload = {
            "version": 1,
            "encoding": "sha256",
            "cipher_ips": sorted(self._cipher_ips),
        }
        return json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True)

    def _load_from_disk(self) -> None:
        with self._lock:
            if not self._path.exists():
                self._cipher_ips = set()
                self._last_loaded_mtime_ns = None
                return

            try:
                text = self._path.read_text(encoding="utf-8")
                payload = json.loads(text) if text.strip() else {}
                self._cipher_ips = self._decode_payload(payload)
                self._last_loaded_mtime_ns = self._path.stat().st_mtime_ns
            except Exception as exc:
                log_with_data(
                    self._logger,
                    logging.WARNING,
                    "Whitelist file load failed",
                    path=str(self._path),
                    error=str(exc),
                )

    def _refresh_if_needed_locked(self) -> None:
        try:
            mtime_ns = self._path.stat().st_mtime_ns
        except OSError:
            return
        if self._last_loaded_mtime_ns == mtime_ns:
            return
        try:
            text = self._path.read_text(encoding="utf-8")
            payload = json.loads(text) if text.strip() else {}
            self._cipher_ips = self._decode_payload(payload)
            self._last_loaded_mtime_ns = mtime_ns
        except Exception as exc:
            log_with_data(
                self._logger,
                logging.WARNING,
                "Whitelist file refresh failed",
                path=str(self._path),
                error=str(exc),
            )

    def contains(self, client_ip: str) -> bool:
        if not self._enabled:
            return True

        cipher_ip = self._cipher_ip(client_ip)
        with self._lock:
            self._refresh_if_needed_locked()
            return cipher_ip in self._cipher_ips

    def ingest_text(self, text: str) -> WhitelistResult:
        candidate = text.strip()
        if not candidate:
            return WhitelistResult(False, "empty message")

        try:
            normalized_ip = ipaddress.ip_address(candidate).compressed
        except ValueError:
            return WhitelistResult(False, "message is not a valid IPv4 or IPv6 address")

        cipher_ip = self._cipher_ip(normalized_ip)
        with self._lock:
            self._refresh_if_needed_locked()
            if cipher_ip in self._cipher_ips:
                return WhitelistResult(True, "already present", normalized_ip)

            self._cipher_ips.add(cipher_ip)
            try:
                self._persist_locked()
            except Exception as exc:
                self._cipher_ips.discard(cipher_ip)
                raise exc

        log_with_data(
            self._logger,
            logging.INFO,
            "Whitelist entry added",
            normalized_ip=normalized_ip,
            storage=self._mode,
            path=str(self._path),
        )
        return WhitelistResult(True, "saved", normalized_ip)

    def _persist_locked(self) -> None:
        payload = self._serialize_payload()
        if self._mode == "k8":
            self._write_k8_secret(payload)
        else:
            self._write_filesystem(payload)

        try:
            self._last_loaded_mtime_ns = self._path.stat().st_mtime_ns
        except OSError:
            self._last_loaded_mtime_ns = None

    def _write_filesystem(self, payload: str) -> None:
        self._path.parent.mkdir(parents=True, exist_ok=True)
        tmp_path = self._path.with_suffix(f"{self._path.suffix}.tmp")
        tmp_path.write_text(payload, encoding="utf-8")
        tmp_path.replace(self._path)

    def _resolve_k8_namespace(self) -> str:
        if self._secret_namespace:
            return self._secret_namespace

        namespace_file = Path("/var/run/secrets/kubernetes.io/serviceaccount/namespace")
        if namespace_file.exists():
            try:
                value = namespace_file.read_text(encoding="utf-8").strip()
                if value:
                    return value
            except OSError:
                pass
        return os.environ.get("KUBERNETES_NAMESPACE", "default")

    def _write_k8_secret(self, payload: str) -> None:
        try:
            from kubernetes import client, config as kube_config
        except ImportError as exc:
            raise RuntimeError("K8 whitelist storage requires kubernetes package") from exc

        namespace = self._resolve_k8_namespace()
        if not self._secret_name:
            raise RuntimeError("K8 whitelist storage requires k8_secret_name")
        if not self._secret_key:
            raise RuntimeError("K8 whitelist storage requires k8_secret_key")

        try:
            kube_config.load_incluster_config()
        except Exception:
            kube_config.load_kube_config()

        api = client.CoreV1Api()
        encoded_payload = base64.b64encode(payload.encode("utf-8")).decode("ascii")
        api.patch_namespaced_secret(self._secret_name, namespace, {"data": {self._secret_key: encoded_payload}})
