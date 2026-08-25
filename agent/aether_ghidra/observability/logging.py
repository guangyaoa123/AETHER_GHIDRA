from __future__ import annotations

import logging
import os
import sys
from pathlib import Path
from typing import Any


LOGGER_NAME = "aether_ghidra"
_HANDLER_MARKER = "_aether_ghidra_handler"


def _enabled(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    return str(value).strip().lower() in {"1", "true", "yes", "on", "debug"}


def configure_logging(config: dict[str, Any] | None = None) -> logging.Logger:
    """Configure service logging once and return the AETHER logger hierarchy."""
    config = config or {}
    debug = _enabled(os.getenv("AETHER_GHIDRA_DEBUG", config.get("DEBUG", False)))
    logger = logging.getLogger(LOGGER_NAME)
    logger.setLevel(logging.DEBUG if debug else logging.INFO)
    logger.propagate = False

    formatter = logging.Formatter(
        "%(asctime)s %(levelname)s %(name)s: %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%S",
    )
    if not any(getattr(handler, _HANDLER_MARKER, False) for handler in logger.handlers):
        stream = logging.StreamHandler(sys.stdout)
        setattr(stream, _HANDLER_MARKER, True)
        stream.setFormatter(formatter)
        logger.addHandler(stream)

    log_file = os.getenv("AETHER_GHIDRA_LOG_FILE") or config.get("LOG_FILE")
    log_path = Path(log_file).expanduser() if log_file else None
    if log_file and not any(
        getattr(handler, _HANDLER_MARKER, False) and getattr(handler, "baseFilename", None) == str(log_path.resolve())
        for handler in logger.handlers
    ):
        try:
            log_path.parent.mkdir(parents=True, exist_ok=True)
            file_handler = logging.FileHandler(log_path, encoding="utf-8")
            setattr(file_handler, _HANDLER_MARKER, True)
            file_handler.setFormatter(formatter)
            logger.addHandler(file_handler)
        except OSError:
            logger.warning("Could not open configured log file; continuing with console logging")
    return logger
