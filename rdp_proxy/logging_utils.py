from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from typing import Any


_ACCESS_LOG_DETAILS_ENABLED = True
_IP_SENSITIVE_FIELDS = {"client_ip", "visitor_ip", "source_ip", "remote_ip"}


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, Any] = {
            "ts": datetime.now(timezone.utc).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }

        if hasattr(record, "extra_data") and isinstance(record.extra_data, dict):
            payload.update(record.extra_data)

        if record.exc_info:
            payload["exception"] = self.formatException(record.exc_info)

        return json.dumps(payload, ensure_ascii=False)


def setup_logging(level: str = "INFO") -> None:
    handler = logging.StreamHandler()
    handler.setFormatter(JsonFormatter())

    root = logging.getLogger()
    root.setLevel(level.upper())
    root.handlers.clear()
    root.addHandler(handler)


def set_access_log_details(enabled: bool) -> None:
    global _ACCESS_LOG_DETAILS_ENABLED
    _ACCESS_LOG_DETAILS_ENABLED = enabled


def is_access_log_details_enabled() -> bool:
    return _ACCESS_LOG_DETAILS_ENABLED


def sanitize_sensitive_log_fields(data: dict[str, Any]) -> dict[str, Any]:
    if _ACCESS_LOG_DETAILS_ENABLED:
        return data
    return {k: v for k, v in data.items() if k not in _IP_SENSITIVE_FIELDS}


def log_with_data(logger: logging.Logger, level: int, message: str, **data: Any) -> None:
    data = sanitize_sensitive_log_fields(data)
    logger.log(level, message, extra={"extra_data": data})
