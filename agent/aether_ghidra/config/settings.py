from __future__ import annotations

import json
import os
from copy import deepcopy
from pathlib import Path
from typing import Any


CONFIG_PATH = Path(os.getenv("AETHER_GHIDRA_CONFIG", Path.home() / ".config" / "aether-ghidra" / "config.json"))

DEFAULT_CONFIG: dict[str, Any] = {
    "OPENAI_API_KEY": "",
    "OPENAI_MODEL": "qwen/qwen3-coder",
    "OPENAI_MEMORY_MODEL": "",
    "OPENAI_BASE_URL": "https://openrouter.ai/api/v1",
    "OPENAI_EXTRA_BODY": {},
    "LOG_FILE": "",
    "CONVERSATION_LOG_FILE": "",
    "CHATBOT_MAX_TOKENS": 65_536,
    "CHATBOT_MAX_ITERATIONS": -1,
    "CHATBOT_REQUEST_RETRIES": 2,
    "CHATBOT_REQUEST_RETRY_DELAY_SEC": 1.0,
    "CHATBOT_MAX_TOOL_CALLS": 10,
    "CHATBOT_MAX_CUMULATIVE_TOOL_OUTPUT": 0,
    "INDEXING_MODEL": "",
    "INDEXING_BATCH_SIZE": 50,
    "INDEXING_MAX_FUNC_SIZE_BYTES": 24_576,
    "INDEXING_DECOMP_MAX_FUNC_SIZE_BYTES": 12_288,
    "INDEXING_MAX_TOKENS": 65_536,
    "INDEXING_FAILED_RETRY_MAX": 5,
    "INDEXING_PSEUDOCODE_CACHE_ENABLED": True,
    "DEBUG": False,
}


def load_config() -> dict[str, Any]:
    try:
        raw = json.loads(CONFIG_PATH.read_text(encoding="utf-8"))
    except (FileNotFoundError, OSError, json.JSONDecodeError):
        raw = {}

    config = deepcopy(DEFAULT_CONFIG)
    persisted_keys: set[str] = set()
    if isinstance(raw, dict):
        for key in config:
            if key in raw and isinstance(raw[key], type(config[key])):
                config[key] = raw[key]
                persisted_keys.add(key)

    # A GUI-saved value is authoritative. Environment variables only fill gaps
    # for settings that have not been persisted yet.
    for key in ("OPENAI_API_KEY", "OPENAI_MODEL", "OPENAI_BASE_URL", "LOG_FILE", "CONVERSATION_LOG_FILE"):
        if key not in persisted_keys and os.getenv(key):
            config[key] = os.environ[key]
    return config


def save_config(config: dict[str, Any]) -> None:
    CONFIG_PATH.parent.mkdir(parents=True, exist_ok=True)
    merged = deepcopy(DEFAULT_CONFIG)
    merged.update({key: value for key, value in config.items() if key in merged})
    CONFIG_PATH.write_text(json.dumps(merged, indent=2) + "\n", encoding="utf-8")


def ensure_config() -> dict[str, Any]:
    config = load_config()
    if not CONFIG_PATH.exists():
        save_config(config)
    return config
