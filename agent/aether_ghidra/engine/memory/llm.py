from __future__ import annotations

import json
import logging
import os
import re
from abc import ABC, abstractmethod
from typing import Any

from ...observability.conversation_logging import ConversationLogger


logger = logging.getLogger(__name__)


class LLMClient(ABC):
    @abstractmethod
    def complete(self, prompt: str, **kwargs: Any) -> str: ...

    @abstractmethod
    def evaluate_relevance(self, query: str, content: str) -> float: ...

    @abstractmethod
    def evaluate_relevance_batch(self, query: str, contents: list[str]) -> list[tuple[float, str]]: ...

    @abstractmethod
    def decide_branch_priority(self, query: str, node_name: str, node_description: str, sample_memories: list[str]) -> tuple[float, str]: ...

    @abstractmethod
    def decide_branch_priority_batch(self, query: str, branches: list[dict[str, Any]]) -> list[tuple[float, str]]: ...

    @abstractmethod
    def analyze_and_categorize(self, node_name: str, node_description: str, memories: list[str], max_categories: int = 5, min_items_per_category: int = 2) -> list[dict[str, Any]]: ...

    @abstractmethod
    def select_best_node(self, content: str, nodes: list[dict[str, Any]]) -> str: ...


class OpenAILLMClient(LLMClient):
    def __init__(self, api_key: str | None = None, model: str = "gpt-4o-mini", base_url: str | None = None, relevance_threshold: float = 0.3, max_tokens: int = 50, client: Any = None, disable_reasoning: bool = True) -> None:
        self.api_key = api_key or os.environ.get("OPENAI_API_KEY")
        self.base_url = base_url or os.environ.get("OPENAI_BASE_URL")
        self.model = model
        self.relevance_threshold = max(0.0, min(relevance_threshold, 1.0))
        self.max_tokens = max_tokens
        self.disable_reasoning = disable_reasoning
        self.conversation_logger = ConversationLogger()
        if client is not None:
            self.client = client
            return
        from openai import OpenAI
        kwargs: dict[str, Any] = {"api_key": self.api_key}
        if self.base_url:
            kwargs["base_url"] = self.base_url
        self.client = OpenAI(**kwargs)

    def complete(self, prompt: str, max_tokens_override: int | None = None, **kwargs: Any) -> str:
        logger.debug("memory LLM request model=%s prompt_chars=%s max_tokens=%s", self.model, len(prompt), max_tokens_override or self.max_tokens)
        request: dict[str, Any] = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": "You are a concise memory retrieval assistant. Return only the requested structured output."},
                {"role": "user", "content": prompt},
            ],
            "max_tokens": max_tokens_override or self.max_tokens,
            "temperature": 0.1,
            **kwargs,
        }
        if self.disable_reasoning:
            request.setdefault("extra_body", {"reasoning": {"enabled": False}})
        try:
            response = self.client.chat.completions.create(**request)
        except TypeError:
            request.pop("extra_body", None)
            response = self.client.chat.completions.create(**request)
        self.conversation_logger.record_completion("memory", request, response)
        choices = getattr(response, "choices", None) or []
        if not choices or getattr(choices[0], "message", None) is None:
            return ""
        message = choices[0].message
        content = str(getattr(message, "content", None) or getattr(message, "reasoning", None) or "").strip()
        logger.debug("memory LLM response chars=%s", len(content))
        return content

    def evaluate_relevance(self, query: str, content: str) -> float:
        response = self.complete(self._create_relevance_prompt(query, content))
        score = self._parse_score(response) if response else self._keyword_relevance_fallback(query, content)
        return score if score >= self.relevance_threshold else 0.0

    def evaluate_relevance_batch(self, query: str, contents: list[str]) -> list[tuple[float, str]]:
        if not contents:
            return []
        results = self._parse_batch_scored_results(self.complete(self._create_batch_relevance_prompt(query, contents), max_tokens_override=1000), len(contents))
        if not results or all(score == 0.0 for score, _ in results):
            results = [(self._keyword_relevance_fallback(query, content), "") for content in contents]
        return [(score if score >= self.relevance_threshold else 0.0, reason) for score, reason in results]

    def decide_branch_priority(self, query: str, node_name: str, node_description: str, sample_memories: list[str]) -> tuple[float, str]:
        response = self.complete(self._create_branch_priority_prompt(query, node_name, node_description, sample_memories))
        score, reason = self._parse_score_and_reason(response)
        return (score, reason) if response else self._branch_priority_keyword_fallback(query, node_name, node_description, sample_memories)

    def decide_branch_priority_batch(self, query: str, branches: list[dict[str, Any]]) -> list[tuple[float, str]]:
        if not branches:
            return []
        results = self._parse_batch_scored_results(self.complete(self._create_batch_branch_priority_prompt(query, branches), max_tokens_override=1500), len(branches))
        if not results or all(score == 0.0 for score, _ in results):
            return [self._branch_priority_keyword_fallback(query, str(branch.get("name", "")), str(branch.get("description", "")), list(branch.get("samples", []))) for branch in branches]
        return results

    def select_best_node(self, content: str, nodes: list[dict[str, Any]]) -> str:
        if not nodes:
            return "root"
        response = self.complete(self._create_node_selection_prompt(content, nodes), max_tokens_override=100)
        for node in nodes:
            if str(node.get("id", "")) and str(node["id"]) in response:
                return str(node["id"])
        return "root"

    def analyze_and_categorize(self, node_name: str, node_description: str, memories: list[str], max_categories: int = 5, min_items_per_category: int = 2) -> list[dict[str, Any]]:
        response = self.complete(self._create_categorization_prompt(node_name, node_description, memories, max_categories, min_items_per_category), max_tokens_override=3000)
        categories = self._parse_categorization_response(response, memories, min_items_per_category)
        return (categories or self._categorize_by_keywords(max_categories, min_items_per_category, memories))[:max_categories]

    def set_relevance_threshold(self, threshold: float) -> None:
        self.relevance_threshold = max(0.0, min(threshold, 1.0))

    @staticmethod
    def _create_relevance_prompt(query: str, content: str) -> str:
        return f"Rate relevance of the content to the query from 0.0 to 1.0. Return only a number.\n\nQuery: {query}\nContent: {content}\nScore:"

    @staticmethod
    def _create_batch_relevance_prompt(query: str, contents: list[str]) -> str:
        values = "\n".join(f"{index + 1}. {content}" for index, content in enumerate(contents))
        return f"Rate relevance of each content item to this query from 0.0 to 1.0.\nQuery: {query}\nContents:\n{values}\nReturn a JSON array with one {{\"score\": 0.9, \"reason\": \"brief reason\"}} per item."

    @staticmethod
    def _create_branch_priority_prompt(query: str, node_name: str, node_description: str, sample_memories: list[str]) -> str:
        return f"Rate whether this memory branch is worth exploring. Return JSON {{\"score\": 0.8, \"reason\": \"brief reason\"}}.\nQuery: {query}\nBranch: {node_name}\nDescription: {node_description}\nSamples: {'; '.join(sample_memories[:5])}"

    @staticmethod
    def _create_batch_branch_priority_prompt(query: str, branches: list[dict[str, Any]]) -> str:
        lines = [f"{index}. {branch.get('name', '')}: {branch.get('description', '')} (samples: {', '.join(map(str, branch.get('samples', [])[:3])) or 'none'})" for index, branch in enumerate(branches, 1)]
        return f"Rate how promising each memory branch is for this query from 0.0 to 1.0.\nQuery: {query}\nBranches:\n{'\n'.join(lines)}\nReturn a JSON array with one object per branch."

    @staticmethod
    def _create_node_selection_prompt(content: str, nodes: list[dict[str, Any]]) -> str:
        values = "\n".join(f"{index + 1}. ID: {node.get('id')}, Name: {node.get('name')}, Description: {node.get('description')}" for index, node in enumerate(nodes))
        return f"Select the best node for this memory content. Return only its ID or root.\nContent: {content}\nAvailable nodes:\n{values}"

    @staticmethod
    def _create_categorization_prompt(node_name: str, node_description: str, memories: list[str], max_categories: int, min_items_per_category: int) -> str:
        values = "\n".join(f"{index + 1}. {memory}" for index, memory in enumerate(memories))
        return f"Group these memories into at most {max_categories} categories with at least {min_items_per_category} items each. Return JSON {{\"categories\": [{{\"name\": \"...\", \"description\": \"...\", \"memory_numbers\": [1, 2]}}]}}.\nNode: {node_name} - {node_description}\nMemories:\n{values}"

    @staticmethod
    def _parse_score(response: str) -> float:
        match = re.search(r"(?:score[:\s]*)?(\d*\.?\d+)", response.lower())
        try:
            return max(0.0, min(float(match.group(1)), 1.0)) if match else 0.0
        except (AttributeError, ValueError):
            return 0.0

    def _parse_score_and_reason(self, response: str) -> tuple[float, str]:
        try:
            match = re.search(r"\{[\s\S]*\}", response)
            data = json.loads(match.group()) if match else {}
            return max(0.0, min(float(data.get("score", 0.0)), 1.0)), str(data.get("reason", ""))
        except (json.JSONDecodeError, TypeError, ValueError, AttributeError):
            return self._parse_score(response), ""

    def _parse_batch_scored_results(self, response: str, expected_count: int) -> list[tuple[float, str]]:
        try:
            match = re.search(r"\[[\s\S]*\]", response)
            data = json.loads(match.group()) if match else []
            results = [(max(0.0, min(float(item.get("score", 0.0)), 1.0)), str(item.get("reason", ""))) if isinstance(item, dict) else (max(0.0, min(float(item), 1.0)), "") for item in data[:expected_count]]
            if len(results) == expected_count:
                return results
        except (json.JSONDecodeError, TypeError, ValueError, AttributeError):
            pass
        return [(0.0, "")] * expected_count

    @staticmethod
    def _parse_categorization_response(response: str, memories: list[str], min_items: int) -> list[dict[str, Any]]:
        try:
            match = re.search(r"\{[\s\S]*\}", response)
            categories = json.loads(match.group() if match else response).get("categories", [])
        except (AttributeError, json.JSONDecodeError, TypeError):
            return []
        result = []
        for category in categories:
            items = [memories[number - 1] for number in category.get("memory_numbers", []) if isinstance(number, int) and 1 <= number <= len(memories)]
            if len(items) >= min_items:
                result.append({"name": category.get("name", "Unnamed"), "description": category.get("description", ""), "items": items})
        return result

    @staticmethod
    def _keyword_relevance_fallback(query: str, content: str) -> float:
        terms = {term for term in query.lower().split() if term}
        return min(sum(term in content.lower() for term in terms) / len(terms), 1.0) if terms else 0.0

    def _branch_priority_keyword_fallback(self, query: str, node_name: str, node_description: str, sample_memories: list[str]) -> tuple[float, str]:
        score = self._keyword_relevance_fallback(query, " ".join([node_name, node_description, *sample_memories]))
        return score, "keyword fallback" if score else "no match"

    @staticmethod
    def _categorize_by_keywords(max_categories: int, min_items: int, memories: list[str]) -> list[dict[str, Any]]:
        groups = {"API/Endpoints": ["api", "endpoint", "route", "request"], "Database": ["database", "query", "table", "sql"], "Authentication": ["auth", "login", "token", "password"], "UI/Frontend": ["component", "view", "ui", "render"], "Configuration": ["config", "setting", "env", "yaml", "json"]}
        result = []
        used: set[str] = set()
        for name, keywords in groups.items():
            if len(result) >= max_categories:
                break
            items = [memory for memory in memories if memory not in used and any(keyword in memory.lower() for keyword in keywords)]
            if len(items) >= min_items:
                result.append({"name": name, "description": f"Memories related to {name.lower()}", "items": items})
                used.update(items)
        remaining = [memory for memory in memories if memory not in used]
        if len(remaining) >= min_items and len(result) < max_categories:
            result.append({"name": "General", "description": "Miscellaneous memories", "items": remaining})
        return result


class StrictOpenAILLMClient(OpenAILLMClient):
    def __init__(self, api_key: str | None = None, model: str = "gpt-4o-mini", max_tokens: int = 50, **kwargs: Any) -> None:
        super().__init__(api_key=api_key, model=model, max_tokens=max_tokens, relevance_threshold=0.7, **kwargs)


class RelaxedOpenAILLMClient(OpenAILLMClient):
    def __init__(self, api_key: str | None = None, model: str = "gpt-4o-mini", max_tokens: int = 50, **kwargs: Any) -> None:
        super().__init__(api_key=api_key, model=model, max_tokens=max_tokens, relevance_threshold=0.3, **kwargs)


MemoryLLMClient = OpenAILLMClient
