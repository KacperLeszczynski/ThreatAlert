import json
import logging
from datetime import UTC, datetime
from typing import Any

_STANDARD_LOG_FIELDS = set(logging.makeLogRecord({}).__dict__)


class JsonLogFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        document: dict[str, Any] = {
            "timestamp": datetime.now(UTC).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        document.update(
            {
                key: value
                for key, value in record.__dict__.items()
                if key not in _STANDARD_LOG_FIELDS and key != "message"
            }
        )
        return json.dumps(document, default=str, ensure_ascii=True)


def configure_application_logging(level: str) -> None:
    logger = logging.getLogger("threat_alerting")
    logger.setLevel(level)
    if not logger.handlers:
        handler = logging.StreamHandler()
        handler.setFormatter(JsonLogFormatter())
        logger.addHandler(handler)
    logger.propagate = False
