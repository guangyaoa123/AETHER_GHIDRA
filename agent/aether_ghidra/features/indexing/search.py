from __future__ import annotations

import json
import re

from .model import FunctionIndex


def render_function_refs(values: list[object]) -> str:
    return ", ".join(json.dumps(value, sort_keys=True, default=str) if isinstance(value, dict) else str(value) for value in values)


def search_index(index: FunctionIndex, query: str, *, limit: int = 20) -> str:
    if not index.is_usable():
        return "Error: No usable function index exists. Run or resume Index Binary first."
    terms = {term for term in re.findall(r"[a-z0-9_:-]+", query.lower()) if len(term) > 2}
    ranked: list[tuple[int, object]] = []
    for entry in index.entries_by_address.values():
        haystack = entry.searchable().lower()
        score = sum(5 if term in {tag.lower() for tag in entry.tags} else 3 if term in entry.name.lower() or term in entry.summary.lower() else 1 if term in haystack else 0 for term in terms)
        if score:
            ranked.append((score, entry))
    ranked.sort(key=lambda item: (-item[0], str(item[1].address)))
    if not ranked:
        ranked = [(0, entry) for entry in index.entries_by_importance("MEDIUM")[:limit]]
    lines = ["# Function Index Briefing", f"Query: {query}", f"Index: {index.size()} functions ({index.indexing_state})", ""]
    for score, entry in ranked[:limit]:
        function_ref = {
            "address": {
                "space": entry.address.split(":", 1)[0] if ":" in entry.address else "ram",
                "offset": entry.address.split(":", 1)[1] if ":" in entry.address else entry.address,
            },
            "name": entry.name,
        }
        lines.extend([
            f"- {json.dumps(function_ref)} (score={score})",
            f"  Tags: {', '.join(sorted(entry.tags))}",
            f"  Summary: {entry.summary}",
            f"  Called functions: {render_function_refs(entry.called_functions[:10])}" if entry.called_functions else "  Called functions: none recorded",
            f"  Callers: {render_function_refs(entry.caller_functions[:10])}" if entry.caller_functions else "  Callers: none recorded",
        ])
    return "\n".join(lines)
