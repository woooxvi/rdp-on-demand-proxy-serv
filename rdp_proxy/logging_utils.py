from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from typing import Any


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


def log_with_data(logger: logging.Logger, level: int, message: str, **data: Any) -> None:
    logger.log(level, message, extra={"extra_data": data})
