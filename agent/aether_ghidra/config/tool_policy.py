from __future__ import annotations

import json
from pathlib import Path
from typing import Iterable


TOOL_CONFIG_PATH = Path.home() / ".config" / "aether-ghidra" / "chatbot-tool-config.json"
TOOL_CONFIG_VERSION = 2
DEFAULT_GROUPS: dict[str, bool] = {
    "program_read": True,
    "analysis_context": True,
    "program_write": False,
    "planning": True,
    "memory": True,
    "conversation": True,
    "annotation_read": True,
    "annotation_write": False,
}


def load_tool_config(
    tool_names: Iterable[str],
    group_by_tool: dict[str, str] | None = None,
) -> dict[str, bool]:
    """Return effective tool enablement, migrating the legacy flat format."""
    names = set(tool_names)
    group_by_tool = group_by_tool or {}
    loaded = _read()
    groups = dict(DEFAULT_GROUPS)
    overrides: dict[str, bool] = {}
    migrated = not isinstance(loaded, dict) or loaded.get("version") != TOOL_CONFIG_VERSION

    if isinstance(loaded, dict) and loaded.get("version") == TOOL_CONFIG_VERSION:
        configured_groups = loaded.get("groups", {})
        if isinstance(configured_groups, dict):
            for group, enabled in configured_groups.items():
                if group in groups and isinstance(enabled, bool):
                    groups[group] = enabled
        configured_tools = loaded.get("tools", {})
        if isinstance(configured_tools, dict):
            overrides = {
                name: enabled for name, enabled in configured_tools.items()
                if isinstance(name, str) and isinstance(enabled, bool)
            }
    elif isinstance(loaded, dict):
        # Preserve the old per-tool choices while moving them into overrides.
        overrides = {
            name: enabled for name, enabled in loaded.items()
            if isinstance(name, str) and isinstance(enabled, bool)
        }

    effective = {
        name: overrides.get(name, groups.get(group_by_tool.get(name, ""), True))
        for name in sorted(names)
    }
    normalized = {"version": TOOL_CONFIG_VERSION, "groups": groups, "tools": overrides}
    if migrated or loaded != normalized:
        save_tool_config_document(normalized)
    return effective


def save_tool_config(config: dict[str, bool]) -> None:
    """Save a compatibility mapping as explicit per-tool overrides."""
    save_tool_config_document({"version": TOOL_CONFIG_VERSION, "groups": dict(DEFAULT_GROUPS), "tools": dict(config)})


def save_tool_config_document(document: dict[str, object]) -> None:
    TOOL_CONFIG_PATH.parent.mkdir(parents=True, exist_ok=True)
    TOOL_CONFIG_PATH.write_text(json.dumps(document, indent=2) + "\n", encoding="utf-8")


def capability_enabled(
    capability: str,
    capability_to_tool: dict[str, str],
    group_by_tool: dict[str, str],
) -> bool:
    tool_name = capability_to_tool.get(capability)
    if tool_name is None:
        return True
    return load_tool_config((tool_name,), group_by_tool).get(tool_name, True)


def _read() -> object:
    try:
        return json.loads(TOOL_CONFIG_PATH.read_text(encoding="utf-8"))
    except (FileNotFoundError, OSError, json.JSONDecodeError):
        return {}
