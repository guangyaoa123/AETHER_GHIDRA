from __future__ import annotations

import re

from .model import FunctionIndex


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
        lines.extend([
            f"- [{entry.address}] {entry.name} (score={score})",
            f"  Tags: {', '.join(sorted(entry.tags))}",
            f"  Summary: {entry.summary}",
            f"  Called functions: {', '.join(entry.called_functions[:10])}" if entry.called_functions else "  Called functions: none recorded",
            f"  Callers: {', '.join(entry.caller_functions[:10])}" if entry.caller_functions else "  Callers: none recorded",
        ])
    return "\n".join(lines)
