from __future__ import annotations

import re
from typing import Any

IMPORTANCE_LEVELS = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "MINIMAL")
IMPORTANCE_ORDER = {name: len(IMPORTANCE_LEVELS) - index for index, name in enumerate(IMPORTANCE_LEVELS)}
DEFAULT_FUNCTION_TAGS = {
    "network": "Network operations (sockets, HTTP, DNS, packet capture)",
    "crypto": "Cryptographic operations (encryption, hashing, key generation)",
    "file-io": "File system operations (read, write, create, delete)",
    "registry": "Registry operations (Windows registry read/write)",
    "process": "Process/thread management (create, inject, terminate)",
    "memory": "Memory management (allocation, mapping, protection)",
    "string-processing": "String manipulation and encoding/decoding",
    "data-structures": "Data structure operations (lists, trees, buffers)",
    "api-wrapper": "Thin wrapper around a single API call",
    "initialization": "Program/module initialization and setup",
    "cleanup": "Resource cleanup and deinitialization",
    "error-handling": "Error detection, logging, and recovery",
    "logging": "Logging, debug output, telemetry",
    "synchronization": "Locking, signaling, timing, thread sync",
    "control-flow": "Dispatch, routing, state machines, main loops",
    "execution": "Code execution (shellcode, DLL loading, eval)",
    "persistence": "Persistence mechanisms (services, run keys, tasks)",
    "discovery": "System/network reconnaissance and enumeration",
    "evasion": "Anti-analysis, anti-debug, VM detection, packing",
    "c2-communication": "Command-and-control protocol handling",
    "unknown": "Does not fit any other category (LAST RESORT ONLY)",
}


def normalize_tag(raw: Any) -> str:
    value = str(raw or "").strip().lower().replace("_", "-").replace(" ", "-")
    value = re.sub(r"[^a-z0-9:-]", "", value)
    return re.sub(r"-{2,}", "-", value).strip("-") or "unknown"


def _levenshtein(left: str, right: str) -> int:
    if len(left) < len(right):
        return _levenshtein(right, left)
    row = list(range(len(right) + 1))
    for i, char in enumerate(left, 1):
        current = [i]
        for j, other in enumerate(right, 1):
            current.append(min(current[j - 1] + 1, row[j] + 1, row[j - 1] + (char != other)))
        row = current
    return row[-1]


class DynamicTagManager:
    def __init__(self, existing: dict[str, dict[str, Any]] | None = None) -> None:
        self.tags = {key: dict(value) for key, value in (existing or {}).items()}

    def resolve(self, raw: Any, function_name: str = "") -> str:
        tag = normalize_tag(raw)
        if tag.upper() in IMPORTANCE_LEVELS:
            return tag.upper()
        if tag in DEFAULT_FUNCTION_TAGS:
            return tag
        parent = tag.split(":", 1)[0]
        if ":" in tag and parent in DEFAULT_FUNCTION_TAGS:
            self._register(tag, str(raw), function_name)
            return tag
        for known in DEFAULT_FUNCTION_TAGS:
            if _levenshtein(tag, known) <= 2 or (tag in known and len(known) - len(tag) <= 3):
                return known
        self._register(tag, str(raw), function_name)
        return tag

    def _register(self, tag: str, original: str, function_name: str) -> None:
        item = self.tags.setdefault(tag, {
            "originalForm": original,
            "description": "",
            "usageCount": 0,
            "exampleFunctions": [],
        })
        item["usageCount"] = int(item.get("usageCount", 0)) + 1
        examples = item.setdefault("exampleFunctions", [])
        if function_name and function_name not in examples and len(examples) < 10:
            examples.append(function_name)

    def to_dict(self) -> dict[str, dict[str, Any]]:
        return {key: dict(value) for key, value in self.tags.items()}


def importance_at_or_above(value: str, minimum: str) -> bool:
    return IMPORTANCE_ORDER.get(value.upper(), 0) >= IMPORTANCE_ORDER.get(minimum.upper(), 0)
