from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class ServerConfig:
    bind: str
    verify_http_bind: str
    verify_http_port: int
    external_verify_base_url: str
    max_pending_connections: int = 50
    access_log_details: bool = True


@dataclass(frozen=True)
class SecurityConfig:
    enabled: bool
    token_ttl_seconds: int
    wait_for_verification_seconds: int
    deny_if_timeout: bool


@dataclass(frozen=True)
class TelegramConfig:
    enabled: bool
    bot_token: str
    chat_id: str
    insecure_skip_verify: bool = False


@dataclass(frozen=True)
class DingTalkConfig:
    enabled: bool
    webhook: str
    secret: str = ""


@dataclass(frozen=True)
class WeComConfig:
    enabled: bool
    webhook: str


@dataclass(frozen=True)
class NotificationPrivacyConfig:
    mask_client_ip: bool = True


@dataclass(frozen=True)
class GeoIPConfig:
    enabled: bool = False
    endpoint_templates: tuple[str, ...] = (
        "https://ipwho.is/{ip}",
        "https://ipapi.co/{ip}/json/",
        "http://ip-api.com/json/{ip}?fields=status,country,regionName,city",
    )
    timeout_seconds: float = 2.0
    cache_ttl_seconds: int = 3600


@dataclass(frozen=True)
class NotificationsConfig:
    telegram: TelegramConfig
    dingtalk: DingTalkConfig
    wecom: WeComConfig
    privacy: NotificationPrivacyConfig
    geoip: GeoIPConfig


@dataclass(frozen=True)
class CloudConfig:
    provider: str
    secret_id: str
    secret_key: str
    region: str
    instance_id: str
    stop_mode: str = "STOP_CHARGING"


@dataclass(frozen=True)
class TargetConfig:
    name: str
    listen_port: int
    target_rdp_port: int
    target_ip: str
    cloud_control_enabled: bool
    startup_timeout_seconds: int
    startup_poll_seconds: int
    idle_shutdown_minutes: int
    cloud: CloudConfig | None


@dataclass(frozen=True)
class AppConfig:
    server: ServerConfig
    security: SecurityConfig
    notifications: NotificationsConfig
    targets: list[TargetConfig]


def _load_raw(path: Path) -> dict[str, Any]:
    text = path.read_text(encoding="utf-8")
    if path.suffix.lower() in {".yaml", ".yml"}:
        try:
            import yaml  # type: ignore
        except ImportError as exc:
            raise RuntimeError("YAML config requires PyYAML installed") from exc
        obj = yaml.safe_load(text)
        if not isinstance(obj, dict):
            raise ValueError("YAML root must be an object")
        return obj

    obj = json.loads(text)
    if not isinstance(obj, dict):
        raise ValueError("JSON root must be an object")
    return obj


def load_config(config_path: str) -> AppConfig:
    raw = _load_raw(Path(config_path))

    server = raw["server"]
    security = raw["security"]
    notifications = raw["notifications"]
    geoip_raw = notifications.get("geoip", {})

    endpoint_templates_raw = geoip_raw.get("endpoint_templates")
    endpoint_templates: tuple[str, ...]
    if isinstance(endpoint_templates_raw, list):
        endpoint_templates = tuple(str(x).strip() for x in endpoint_templates_raw if str(x).strip())
    elif isinstance(endpoint_templates_raw, str) and endpoint_templates_raw.strip():
        endpoint_templates = (endpoint_templates_raw.strip(),)
    else:
        legacy_single = str(geoip_raw.get("endpoint_template", "")).strip()
        if legacy_single:
            endpoint_templates = (legacy_single,)
        else:
            endpoint_templates = (
                "https://ipwho.is/{ip}",
                "https://ipapi.co/{ip}/json/",
                "http://ip-api.com/json/{ip}?fields=status,country,regionName,city",
            )

    targets: list[TargetConfig] = []
    for item in raw["targets"]:
        cloud_raw = item.get("cloud")
        cloud_configured = isinstance(cloud_raw, dict) and len(cloud_raw) > 0
        explicit_control = item.get("cloud_control_enabled")
        if explicit_control is None:
            cloud_control_enabled = cloud_configured
        else:
            # If cloud is empty, cloud control is always disabled.
            cloud_control_enabled = bool(explicit_control) and cloud_configured

        cloud_cfg: CloudConfig | None = None
        if cloud_configured:
            assert isinstance(cloud_raw, dict)
            cloud_cfg = CloudConfig(
                provider=cloud_raw["provider"],
                secret_id=cloud_raw["secret_id"],
                secret_key=cloud_raw["secret_key"],
                region=cloud_raw["region"],
                instance_id=cloud_raw["instance_id"],
                stop_mode=cloud_raw.get("stop_mode", "STOP_CHARGING"),
            )

        targets.append(
            TargetConfig(
                name=item["name"],
                listen_port=int(item["listen_port"]),
                target_rdp_port=int(item.get("target_rdp_port", 3389)),
                target_ip=item["target_ip"],
                cloud_control_enabled=cloud_control_enabled,
                startup_timeout_seconds=int(item.get("startup_timeout_seconds", 60)),
                startup_poll_seconds=int(item.get("startup_poll_seconds", 5)),
                idle_shutdown_minutes=int(item.get("idle_shutdown_minutes", 10)),
                cloud=cloud_cfg,
            )
        )

    return AppConfig(
        server=ServerConfig(
            bind=server.get("bind", "0.0.0.0"),
            verify_http_bind=server.get("verify_http_bind", "0.0.0.0"),
            verify_http_port=int(server.get("verify_http_port", 8080)),
            external_verify_base_url=server["external_verify_base_url"],
            max_pending_connections=int(server.get("max_pending_connections", 50)),
            access_log_details=bool(server.get("access_log_details", True)),
        ),
        security=SecurityConfig(
            enabled=bool(security.get("enabled", True)),
            token_ttl_seconds=int(security.get("token_ttl_seconds", 300)),
            wait_for_verification_seconds=int(security.get("wait_for_verification_seconds", 300)),
            deny_if_timeout=bool(security.get("deny_if_timeout", True)),
        ),
        notifications=NotificationsConfig(
            telegram=TelegramConfig(
                enabled=bool(notifications["telegram"].get("enabled", False)),
                bot_token=notifications["telegram"].get("bot_token", ""),
                chat_id=str(notifications["telegram"].get("chat_id", "")),
                insecure_skip_verify=bool(notifications["telegram"].get("insecure_skip_verify", False)),
            ),
            dingtalk=DingTalkConfig(
                enabled=bool(notifications["dingtalk"].get("enabled", False)),
                webhook=notifications["dingtalk"].get("webhook", ""),
                secret=notifications["dingtalk"].get("secret", ""),
            ),
            wecom=WeComConfig(
                enabled=bool(notifications["wecom"].get("enabled", False)),
                webhook=notifications["wecom"].get("webhook", ""),
            ),
            privacy=NotificationPrivacyConfig(
                mask_client_ip=bool(notifications.get("privacy", {}).get("mask_client_ip", True)),
            ),
            geoip=GeoIPConfig(
                enabled=bool(geoip_raw.get("enabled", False)),
                endpoint_templates=endpoint_templates,
                timeout_seconds=float(geoip_raw.get("timeout_seconds", 2.0)),
                cache_ttl_seconds=int(geoip_raw.get("cache_ttl_seconds", 3600)),
            ),
        ),
        targets=targets,
    )
