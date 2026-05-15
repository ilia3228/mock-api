"""Logging setup for the mock API.

The app is usually run by ``run.py`` with uvicorn reload enabled. Imports can
happen more than once across workers, so configuration is intentionally
idempotent and scoped to the ``mock_api`` logger tree.
"""

from __future__ import annotations

import json
import logging
import os
import sys
from logging.handlers import RotatingFileHandler
from pathlib import Path
from typing import Any

BASE_DIR = Path(__file__).resolve().parent
LOG_DIR = Path(os.environ.get("MOCK_API_LOG_DIR") or (BASE_DIR / "logs"))
LOG_FILE = LOG_DIR / "mock-api.log"


def _level_from_env() -> int:
    raw = os.environ.get("MOCK_API_LOG_LEVEL", "INFO").upper()
    return getattr(logging, raw, logging.INFO)


def configure_logging() -> logging.Logger:
    logger = logging.getLogger("mock_api")
    level = _level_from_env()
    logger.setLevel(level)
    logger.propagate = False

    if getattr(logger, "_mock_api_configured", False):
        for handler in logger.handlers:
            handler.setLevel(level)
        return logger

    LOG_DIR.mkdir(parents=True, exist_ok=True)

    formatter = logging.Formatter(
        fmt=(
            "%(asctime)s.%(msecs)03d %(levelname)-8s "
            "%(name)s pid=%(process)d %(message)s"
        ),
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    console = logging.StreamHandler(sys.stdout)
    console.setFormatter(formatter)
    console.setLevel(level)

    file_handler = RotatingFileHandler(
        LOG_FILE,
        maxBytes=5 * 1024 * 1024,
        backupCount=5,
        encoding="utf-8",
    )
    file_handler.setFormatter(formatter)
    file_handler.setLevel(level)

    logger.addHandler(console)
    logger.addHandler(file_handler)
    logger._mock_api_configured = True  # type: ignore[attr-defined]
    logger.info("logging_configured %s", kv(log_file=str(LOG_FILE), level=logging.getLevelName(logger.level)))
    return logger


def get_logger(name: str | None = None) -> logging.Logger:
    configure_logging()
    return logging.getLogger(f"mock_api.{name}" if name else "mock_api")


def kv(**fields: Any) -> str:
    parts: list[str] = []
    for key, value in fields.items():
        if value is None:
            continue
        parts.append(f"{key}={_format_value(value)}")
    return " ".join(parts)


def _format_value(value: Any) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (int, float)):
        return str(value)
    text = str(value)
    if not text:
        return '""'
    if any(ch.isspace() for ch in text) or any(ch in text for ch in '"='):
        return json.dumps(text, ensure_ascii=False)
    return text
