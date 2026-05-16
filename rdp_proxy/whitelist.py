from __future__ import annotations

import base64
import hashlib
import ipaddress
import json
import logging
import os
import threading
import time
from dataclasses import dataclass
from datetime import datetime
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
        self._secret = (config.secret or "rdp-proxy-whitelist-fallback").encode("utf-8")
        self._secret_name = config.k8_secret_name
        self._secret_namespace = config.k8_secret_namespace
        self._secret_key = config.k8_secret_key
        self._entries_by_cipher: dict[str, dict[str, object]] = {}
        self._rejected_by_ip: dict[str, dict[str, object]] = {}
        self._last_loaded_mtime_ns: int | None = None
        self._load_from_disk()

    def _normalize_mode(self, value: str) -> str:
        mode = value.strip().lower()
        if mode in {"k8", "kubernetes", "secret"}:
            return "k8"
        return "filesystem"

    def _normalize_ip(self, client_ip: str) -> str:
        return ipaddress.ip_address(client_ip.strip()).compressed

    def _cipher_ip(self, client_ip: str) -> str:
        normalized_ip = self._normalize_ip(client_ip)
        digest = hashlib.sha256(f"rdp-proxy:whitelist:v2|{normalized_ip}".encode("utf-8")).digest()
        return base64.urlsafe_b64encode(digest).decode("ascii").rstrip("=")

    def _keystream(self, nonce: bytes, length: int) -> bytes:
        output = bytearray()
        counter = 0
        while len(output) < length:
            block = hashlib.sha256(self._secret + b"|" + nonce + b"|" + counter.to_bytes(4, "big")).digest()
            output.extend(block)
            counter += 1
        return bytes(output[:length])

    def _encrypt_ip(self, client_ip: str) -> str:
        normalized_ip = self._normalize_ip(client_ip)
        nonce = os.urandom(16)
        plain = normalized_ip.encode("utf-8")
        mask = self._keystream(nonce, len(plain))
        cipher = bytes(a ^ b for a, b in zip(plain, mask))
        token = base64.urlsafe_b64encode(nonce + cipher).decode("ascii")
        return token.rstrip("=")

    def _decode_base64(self, value: str) -> bytes:
        padding = "=" * (-len(value) % 4)
        return base64.urlsafe_b64decode(value + padding)

    def _decrypt_ip(self, value: str) -> str:
        raw = self._decode_base64(value)
        if len(raw) < 17:
            raise ValueError("encrypted whitelist entry is too short")
        nonce = raw[:16]
        cipher = raw[16:]
        mask = self._keystream(nonce, len(cipher))
        plain = bytes(a ^ b for a, b in zip(cipher, mask)).decode("utf-8")
        return self._normalize_ip(plain)

    def _decode_rejections(self, payload: object) -> dict[str, dict[str, object]]:
        if not isinstance(payload, list):
            return {}
        results: dict[str, dict[str, object]] = {}
        for item in payload:
            if not isinstance(item, dict):
                continue
            ip_text = str(item.get("ip", "")).strip()
            if not ip_text:
                continue
            try:
                normalized_ip = self._normalize_ip(ip_text)
            except ValueError:
                continue
            results[normalized_ip] = {
                "ip": normalized_ip,
                "geo": str(item.get("geo", "")).strip(),
                "target": str(item.get("target", "")).strip(),
                "count": int(item.get("count", 1) or 1),
                "last_seen_at": float(item.get("last_seen_at", 0.0) or 0.0),
            }
        return results

    def _decode_payload(self, payload: object) -> tuple[dict[str, dict[str, object]], dict[str, dict[str, object]]]:
        entries: dict[str, dict[str, object]] = {}
        rejections: dict[str, dict[str, object]] = {}

        if isinstance(payload, dict):
            rejections = self._decode_rejections(payload.get("rejected", []))
            raw_entries = payload.get("entries")
            if isinstance(raw_entries, list):
                for item in raw_entries:
                    if not isinstance(item, dict):
                        continue
                    cipher = str(item.get("cipher", "")).strip()
                    if not cipher:
                        continue
                    encrypted_ip = str(item.get("value", "")).strip()
                    ip_text = ""
                    if encrypted_ip:
                        try:
                            ip_text = self._decrypt_ip(encrypted_ip)
                        except ValueError:
                            ip_text = ""
                    entries[cipher] = {
                        "cipher": cipher,
                        "ip": ip_text,
                        "value": encrypted_ip,
                        "added_at": float(item.get("added_at", 0.0) or 0.0),
                        "source": str(item.get("source", "")).strip(),
                        "legacy": not bool(ip_text),
                    }
                return entries, rejections

            raw_values = payload.get("cipher_ips")
            if raw_values is None:
                raw_values = payload.get("ips")
            if raw_values is None:
                raw_values = payload.get("items")
            if raw_values is None:
                raw_values = []
            if isinstance(raw_values, list):
                for item in raw_values:
                    text = str(item).strip()
                    if not text:
                        continue
                    try:
                        cipher = self._cipher_ip(text)
                        ip_text = self._normalize_ip(text)
                        value = self._encrypt_ip(ip_text)
                        legacy = False
                    except ValueError:
                        cipher = text
                        ip_text = ""
                        value = ""
                        legacy = True
                    entries[cipher] = {
                        "cipher": cipher,
                        "ip": ip_text,
                        "value": value,
                        "added_at": 0.0,
                        "source": "legacy",
                        "legacy": legacy,
                    }
                return entries, rejections

        if isinstance(payload, list):
            for item in payload:
                text = str(item).strip()
                if not text:
                    continue
                try:
                    ip_text = self._normalize_ip(text)
                    cipher = self._cipher_ip(ip_text)
                    value = self._encrypt_ip(ip_text)
                    legacy = False
                except ValueError:
                    cipher = text
                    ip_text = ""
                    value = ""
                    legacy = True
                entries[cipher] = {
                    "cipher": cipher,
                    "ip": ip_text,
                    "value": value,
                    "added_at": 0.0,
                    "source": "legacy",
                    "legacy": legacy,
                }

        return entries, rejections

    def _serialize_payload(self) -> str:
        payload = {
            "version": 2,
            "encoding": "sha256+xor-stream",
            "entries": [
                {
                    "cipher": entry["cipher"],
                    "value": entry["value"],
                    "added_at": entry["added_at"],
                    "source": entry["source"],
                }
                for entry in sorted(
                    self._entries_by_cipher.values(),
                    key=lambda item: (float(item.get("added_at", 0.0) or 0.0), str(item.get("cipher", ""))),
                )
            ],
            "rejected": [
                {
                    "ip": item["ip"],
                    "geo": item["geo"],
                    "target": item["target"],
                    "count": item["count"],
                    "last_seen_at": item["last_seen_at"],
                }
                for item in sorted(
                    self._rejected_by_ip.values(),
                    key=lambda value: float(value.get("last_seen_at", 0.0) or 0.0),
                    reverse=True,
                )
            ],
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
                self._entries_by_cipher, self._rejected_by_ip = self._decode_payload(payload)
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
            self._entries_by_cipher, self._rejected_by_ip = self._decode_payload(payload)
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
            return cipher_ip in self._entries_by_cipher

    def add_ip(self, client_ip: str, source: str = "manual") -> WhitelistResult:
        normalized_ip = self._normalize_ip(client_ip)
        cipher_ip = self._cipher_ip(normalized_ip)
        now = time.time()

        with self._lock:
            self._refresh_if_needed_locked()
            existing = self._entries_by_cipher.get(cipher_ip)
            if existing is not None:
                if existing.get("legacy"):
                    existing["ip"] = normalized_ip
                    existing["value"] = self._encrypt_ip(normalized_ip)
                    existing["legacy"] = False
                    existing["source"] = source or str(existing.get("source", "legacy"))
                    if not float(existing.get("added_at", 0.0) or 0.0):
                        existing["added_at"] = now
                    self._persist_locked()
                self._rejected_by_ip.pop(normalized_ip, None)
                return WhitelistResult(True, "already present", normalized_ip)

            self._entries_by_cipher[cipher_ip] = {
                "cipher": cipher_ip,
                "ip": normalized_ip,
                "value": self._encrypt_ip(normalized_ip),
                "added_at": now,
                "source": source,
                "legacy": False,
            }
            self._rejected_by_ip.pop(normalized_ip, None)
            self._persist_locked()

        log_with_data(
            self._logger,
            logging.INFO,
            "Whitelist entry added",
            normalized_ip=normalized_ip,
            storage=self._mode,
            path=str(self._path),
            source=source,
        )
        return WhitelistResult(True, "saved", normalized_ip)

    def ingest_text(self, text: str) -> WhitelistResult:
        candidate = text.strip()
        if not candidate:
            return WhitelistResult(False, "empty message")

        try:
            normalized_ip = self._normalize_ip(candidate)
        except ValueError:
            return WhitelistResult(False, "message is not a valid IPv4 or IPv6 address")
        return self.add_ip(normalized_ip, source="im")

    def delete_ip(self, client_ip: str) -> WhitelistResult:
        try:
            normalized_ip = self._normalize_ip(client_ip)
        except ValueError:
            return WhitelistResult(False, "message is not a valid IPv4 or IPv6 address")

        cipher_ip = self._cipher_ip(normalized_ip)
        with self._lock:
            self._refresh_if_needed_locked()
            removed = self._entries_by_cipher.pop(cipher_ip, None)
            if removed is None:
                return WhitelistResult(False, "not found", normalized_ip)
            self._persist_locked()

        log_with_data(
            self._logger,
            logging.INFO,
            "Whitelist entry removed",
            normalized_ip=normalized_ip,
            storage=self._mode,
            path=str(self._path),
        )
        return WhitelistResult(True, "deleted", normalized_ip)

    def delete_entry(self, identifier: str) -> WhitelistResult:
        text = str(identifier).strip()
        if not text:
            return WhitelistResult(False, "missing identifier")

        try:
            normalized_ip = self._normalize_ip(text)
        except ValueError:
            normalized_ip = ""

        if normalized_ip:
            return self.delete_ip(normalized_ip)

        with self._lock:
            self._refresh_if_needed_locked()
            removed = self._entries_by_cipher.pop(text, None)
            if removed is None:
                return WhitelistResult(False, "not found")
            self._persist_locked()

        log_with_data(
            self._logger,
            logging.INFO,
            "Whitelist entry removed",
            identifier=text,
            storage=self._mode,
            path=str(self._path),
        )
        return WhitelistResult(True, "deleted")

    def list_entries(self) -> list[dict[str, object]]:
        with self._lock:
            self._refresh_if_needed_locked()
            entries = []
            for item in self._entries_by_cipher.values():
                entries.append(
                    {
                        "cipher": str(item.get("cipher", "")),
                        "ip": str(item.get("ip", "")).strip(),
                        "source": str(item.get("source", "")).strip(),
                        "added_at": float(item.get("added_at", 0.0) or 0.0),
                        "added_at_text": self._format_ts(float(item.get("added_at", 0.0) or 0.0)),
                        "legacy": bool(item.get("legacy", False)),
                    }
                )
        entries.sort(key=lambda item: (float(item["added_at"]), str(item["ip"])), reverse=True)
        return entries

    def record_rejected_ip(self, client_ip: str, geo_text: str = "", target_name: str = "") -> None:
        try:
            normalized_ip = self._normalize_ip(client_ip)
        except ValueError:
            return

        now = time.time()
        with self._lock:
            self._refresh_if_needed_locked()
            item = self._rejected_by_ip.get(normalized_ip)
            if item is None:
                item = {
                    "ip": normalized_ip,
                    "geo": geo_text,
                    "target": target_name,
                    "count": 0,
                    "last_seen_at": now,
                }
                self._rejected_by_ip[normalized_ip] = item
            item["geo"] = geo_text
            item["target"] = target_name
            item["count"] = int(item.get("count", 0) or 0) + 1
            item["last_seen_at"] = now
            self._persist_locked()

    def list_recent_rejections(self, limit: int = 100) -> list[dict[str, object]]:
        with self._lock:
            self._refresh_if_needed_locked()
            items = [
                {
                    "ip": str(item.get("ip", "")).strip(),
                    "geo": str(item.get("geo", "")).strip(),
                    "target": str(item.get("target", "")).strip(),
                    "count": int(item.get("count", 0) or 0),
                    "last_seen_at": float(item.get("last_seen_at", 0.0) or 0.0),
                    "last_seen_at_text": self._format_ts(float(item.get("last_seen_at", 0.0) or 0.0)),
                }
                for item in self._rejected_by_ip.values()
            ]
        items.sort(key=lambda item: float(item["last_seen_at"]), reverse=True)
        return items[: max(1, int(limit))]

    def _format_ts(self, value: float) -> str:
        if value <= 0:
            return "-"
        return datetime.fromtimestamp(value).isoformat(sep=" ", timespec="seconds")

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
            from kubernetes import client, config as kube_config  # type: ignore[import-not-found]
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
