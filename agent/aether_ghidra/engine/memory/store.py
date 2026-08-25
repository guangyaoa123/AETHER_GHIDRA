from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any
from uuid import uuid4


class MemoryPriority(Enum):
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4


@dataclass
class MemoryItem:
    category: str
    priority: MemoryPriority = MemoryPriority.MEDIUM
    id: str = field(default_factory=lambda: str(uuid4()))
    key: str | None = None
    value: Any = None
    created_at: datetime = field(default_factory=datetime.now)
    updated_at: datetime = field(default_factory=datetime.now)
    tags: list[str] = field(default_factory=list)
    related_ids: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    def get_display_content(self) -> str:
        return f"{self.key}={self.value}" if self.key is not None else str(self.value or "")

    def update(self, *, tags: list[str] | None = None, metadata: dict[str, Any] | None = None, key: str | None = None, value: Any = None) -> None:
        if key is not None:
            self.key = key
        if value is not None:
            self.value = value
        if tags is not None:
            self.tags = list(tags)
        if metadata is not None:
            self.metadata.update(metadata)
        self.updated_at = datetime.now()

    def add_relation(self, memory_id: str) -> None:
        if memory_id not in self.related_ids:
            self.related_ids.append(memory_id)
            self.updated_at = datetime.now()

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id, "key": self.key, "value": self.value, "category": self.category,
            "priority": self.priority.value, "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat(), "tags": list(self.tags),
            "related_ids": list(self.related_ids), "metadata": dict(self.metadata),
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "MemoryItem":
        return cls(
            id=data["id"], key=data.get("key"), value=data.get("value"), category=data["category"],
            priority=MemoryPriority(data.get("priority", MemoryPriority.MEDIUM.value)),
            created_at=datetime.fromisoformat(data["created_at"]) if data.get("created_at") else datetime.now(),
            updated_at=datetime.fromisoformat(data["updated_at"]) if data.get("updated_at") else datetime.now(),
            tags=list(data.get("tags", [])), related_ids=list(data.get("related_ids", [])), metadata=dict(data.get("metadata", {})),
        )


@dataclass
class MemoryNode:
    name: str
    id: str = field(default_factory=lambda: str(uuid4()))
    description: str = ""
    children: list["MemoryNode"] = field(default_factory=list)
    memory_ids: list[str] = field(default_factory=list)
    parent_id: str | None = None

    def needs_reorganization(self, threshold: int) -> bool:
        return len(self.memory_ids) > threshold

    def add_child(self, name: str, description: str = "") -> "MemoryNode":
        child = MemoryNode(name=name, description=description, parent_id=self.id)
        self.children.append(child)
        return child

    def add_memory(self, memory_id: str) -> None:
        if memory_id not in self.memory_ids:
            self.memory_ids.append(memory_id)

    def find_node(self, node_id: str) -> "MemoryNode | None":
        if self.id == node_id:
            return self
        return next((found for child in self.children if (found := child.find_node(node_id)) is not None), None)

    def get_all_memory_ids(self) -> list[str]:
        return self.memory_ids + [memory_id for child in self.children for memory_id in child.get_all_memory_ids()]

    def to_dict(self) -> dict[str, Any]:
        return {"id": self.id, "name": self.name, "description": self.description, "children": [child.to_dict() for child in self.children], "memory_ids": list(self.memory_ids), "parent_id": self.parent_id}

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "MemoryNode":
        node = cls(id=data["id"], name=data["name"], description=data.get("description", ""), memory_ids=list(data.get("memory_ids", [])), parent_id=data.get("parent_id"))
        node.children = [cls.from_dict(child) for child in data.get("children", [])]
        for child in node.children:
            child.parent_id = node.id
        return node


@dataclass
class RetrievalResult:
    memory: MemoryItem
    relevance_score: float
    source_node_id: str
    reason: str = ""


class RetrievalAgent(ABC):
    def __init__(self, memory_store: "MemoryStore") -> None:
        self.store = memory_store

    @abstractmethod
    def retrieve(self, query: str, top_k: int = 10) -> list[RetrievalResult]:
        raise NotImplementedError


class KeywordRetrievalAgent(RetrievalAgent):
    def retrieve(self, query: str, top_k: int = 10) -> list[RetrievalResult]:
        terms = {term for term in query.lower().split() if term}
        results = []
        for memory in self.store.memories.values():
            content = memory.get_display_content().lower()
            matches = sum(term in content for term in terms)
            score = matches / len(terms) if terms else 0.0
            score += sum(any(term in tag.lower() for term in terms) for tag in memory.tags) * 0.1
            if score > 0:
                results.append(RetrievalResult(memory, min(score, 1.0), self._find_memory_node(memory.id) or self.store.root.id, f"Keyword match: {matches} terms"))
        return sorted(results, key=lambda item: item.relevance_score, reverse=True)[:top_k]

    def _find_memory_node(self, memory_id: str) -> str | None:
        def find(node: MemoryNode) -> str | None:
            if memory_id in node.memory_ids:
                return node.id
            return next((found for child in node.children if (found := find(child)) is not None), None)
        return find(self.store.root)


class HierarchicalRetrievalAgent(RetrievalAgent):
    """Duck-typed LLM-guided retrieval with keyword fallback."""

    def __init__(self, memory_store: "MemoryStore", llm_client: Any, max_branches_to_explore: int = 5, samples_per_node: int = 3, relevance_threshold: float = 0.3, branch_threshold: float = 0.2, max_depth: int = 10) -> None:
        super().__init__(memory_store)
        self.llm = llm_client
        self.max_branches_to_explore, self.samples_per_node = max_branches_to_explore, samples_per_node
        self.relevance_threshold, self.branch_threshold, self.max_depth = relevance_threshold, branch_threshold, max_depth

    def retrieve(self, query: str, top_k: int = 10) -> list[RetrievalResult]:
        results: list[RetrievalResult] = []
        self._visit(self.store.root, query, results, set(), 0)
        return sorted(results, key=lambda item: item.relevance_score, reverse=True)[:top_k]

    def _visit(self, node: MemoryNode, query: str, results: list[RetrievalResult], visited: set[str], depth: int) -> None:
        if node.id in visited or depth > self.max_depth:
            return
        visited.add(node.id)
        memories = [self.store.memories[mid] for mid in node.memory_ids if mid in self.store.memories]
        contents = [memory.get_display_content() for memory in memories]
        scores = self._scores(query, contents)
        for memory, (score, reason) in zip(memories, scores, strict=False):
            if score > self.relevance_threshold:
                results.append(RetrievalResult(memory, score, node.id, reason))
        if not node.children:
            return
        branches = [{"node": child, "name": child.name, "description": child.description, "samples": [self.store.memories[mid].get_display_content() for mid in child.memory_ids[:self.samples_per_node] if mid in self.store.memories]} for child in node.children]
        priorities = self._branch_scores(query, branches)
        for branch, (score, _reason) in sorted(zip(branches, priorities, strict=False), key=lambda pair: pair[1][0], reverse=True)[:self.max_branches_to_explore]:
            if score > self.branch_threshold:
                self._visit(branch["node"], query, results, visited, depth + 1)

    def _scores(self, query: str, contents: list[str]) -> list[tuple[float, str]]:
        if hasattr(self.llm, "evaluate_relevance_batch"):
            return self._normalize(self.llm.evaluate_relevance_batch(query=query, contents=contents), len(contents))
        return [(self._keyword(query, content), "Keyword fallback") for content in contents]

    def _branch_scores(self, query: str, branches: list[dict[str, Any]]) -> list[tuple[float, str]]:
        if hasattr(self.llm, "decide_branch_priority_batch"):
            return self._normalize(self.llm.decide_branch_priority_batch(query=query, branches=branches), len(branches))
        return [(self._keyword(query, " ".join([branch["name"], branch["description"], *branch["samples"]])), "Keyword fallback") for branch in branches]

    @staticmethod
    def _normalize(values: Any, count: int) -> list[tuple[float, str]]:
        result = []
        for item in list(values or [])[:count]:
            score, reason = (item[0], item[1] if len(item) > 1 else "") if isinstance(item, tuple) else (item, "")
            try:
                score = max(0.0, min(float(score), 1.0))
            except (TypeError, ValueError):
                score = 0.0
            result.append((score, str(reason)))
        return result + [(0.0, "No score returned")] * (count - len(result))

    @staticmethod
    def _keyword(query: str, content: str) -> float:
        terms = {term for term in query.lower().split() if term}
        return sum(term in content.lower() for term in terms) / len(terms) if terms else 0.0


class ReorganizationPlan:
    def __init__(self, node_id: str, node_name: str, proposed_categories: list[dict[str, Any]], unassigned_memory_ids: list[str] | None = None) -> None:
        self.node_id, self.node_name, self.proposed_categories = node_id, node_name, proposed_categories
        self.unassigned_memory_ids = unassigned_memory_ids or []


class ReorganizationStrategy(ABC):
    @abstractmethod
    def should_reorganize(self, node: MemoryNode, store: "MemoryStore") -> bool: ...

    @abstractmethod
    def create_plan(self, node: MemoryNode, store: "MemoryStore", llm_client: Any) -> ReorganizationPlan | None: ...


class ThresholdReorganizationStrategy(ReorganizationStrategy):
    def __init__(self, threshold: int = 10, max_subcategories: int = 5, min_memories_per_category: int = 2) -> None:
        self.threshold, self.max_subcategories, self.min_memories_per_category = threshold, max_subcategories, min_memories_per_category

    def should_reorganize(self, node: MemoryNode, store: "MemoryStore") -> bool:
        return len(node.memory_ids) > self.threshold

    def create_plan(self, node: MemoryNode, store: "MemoryStore", llm_client: Any) -> ReorganizationPlan | None:
        if not self.should_reorganize(node, store):
            return None
        memories = [store.memories[mid] for mid in node.memory_ids if mid in store.memories]
        if llm_client and hasattr(llm_client, "analyze_and_categorize"):
            categories = llm_client.analyze_and_categorize(node.name, node.description, [item.get_display_content() for item in memories], self.max_subcategories, self.min_memories_per_category)
        else:
            groups: dict[str, list[MemoryItem]] = {}
            for memory in memories:
                groups.setdefault(memory.category or "general", []).append(memory)
            categories = [{"name": name, "description": f"{name} findings", "items": [item.get_display_content() for item in items]} for name, items in groups.items() if len(items) >= self.min_memories_per_category][:self.max_subcategories]
        proposed = []
        assigned: set[str] = set()
        for category in categories:
            ids = [memory.id for memory in memories if memory.get_display_content() in category.get("items", []) and memory.id not in assigned]
            if len(ids) >= self.min_memories_per_category:
                proposed.append({"name": category["name"], "description": category.get("description", ""), "memory_ids": ids})
                assigned.update(ids)
        return ReorganizationPlan(node.id, node.name, proposed, [mid for mid in node.memory_ids if mid not in assigned]) if proposed else None


class LLMReorganizer:
    def __init__(self, store: "MemoryStore", llm_client: Any = None, strategy: ReorganizationStrategy | None = None) -> None:
        self.store, self.llm, self.strategy = store, llm_client, strategy or ThresholdReorganizationStrategy()

    def check_and_reorganize(self, node_id: str | None = None) -> bool:
        nodes = [self.store.root.find_node(node_id)] if node_id else self._nodes(self.store.root)
        changed = False
        for node in nodes:
            if node and (plan := self.strategy.create_plan(node, self.store, self.llm)):
                self._execute(plan)
                changed = True
        return changed

    def _nodes(self, node: MemoryNode) -> list[MemoryNode]:
        return [node, *[child for item in node.children for child in self._nodes(item)]]

    def _execute(self, plan: ReorganizationPlan) -> None:
        node = self.store.root.find_node(plan.node_id)
        if not node:
            return
        for category in plan.proposed_categories:
            child = next((item for item in node.children if item.name == category["name"]), None) or node.add_child(category["name"], category.get("description", ""))
            for memory_id in category["memory_ids"]:
                child.add_memory(memory_id)
                if memory_id in node.memory_ids:
                    node.memory_ids.remove(memory_id)

    def preview_reorganization(self, node_id: str) -> dict[str, Any] | None:
        node = self.store.root.find_node(node_id)
        plan = self.strategy.create_plan(node, self.store, self.llm) if node else None
        return {"node_id": plan.node_id, "node_name": plan.node_name, "current_memory_count": len(node.memory_ids), "proposed_categories": [{"name": item["name"], "description": item["description"], "memory_count": len(item["memory_ids"])} for item in plan.proposed_categories], "unassigned_count": len(plan.unassigned_memory_ids)} if plan else None


class MemoryStore:
    def __init__(self, reorganization_threshold: int = 50, retrieval_agent: RetrievalAgent | None = None, reorganization_strategy: ReorganizationStrategy | None = None, reorganization_llm: Any = None, auto_reorganize: bool = True) -> None:
        self.memories: dict[str, MemoryItem] = {}
        self.root = MemoryNode("root", description="Root of memory hierarchy")
        self.reorganization_threshold, self.auto_reorganize, self.reorganization_llm = reorganization_threshold, auto_reorganize, reorganization_llm
        self.retrieval_agent = retrieval_agent or KeywordRetrievalAgent(self)
        self.reorganization_strategy = reorganization_strategy or ThresholdReorganizationStrategy(reorganization_threshold)
        self.reorganizer = LLMReorganizer(self, reorganization_llm, self.reorganization_strategy)

    def set_retrieval_agent(self, agent: RetrievalAgent) -> None:
        self.retrieval_agent = agent

    def set_reorganization_strategy(self, strategy: ReorganizationStrategy) -> None:
        self.reorganization_strategy, self.reorganizer = strategy, LLMReorganizer(self, self.reorganization_llm, strategy)

    def add_memory(self, key: str | None = None, value: Any = None, category: str = "general", priority: MemoryPriority = MemoryPriority.MEDIUM, tags: list[str] | None = None, metadata: dict[str, Any] | None = None, node_id: str | None = None) -> MemoryItem:
        item = MemoryItem(category=category, priority=priority, key=key, value=value, tags=list(tags or []), metadata=dict(metadata or {}))
        self.memories[item.id] = item
        node = self.root.find_node(node_id) if node_id else self.root
        (node or self.root).add_memory(item.id)
        if self.auto_reorganize:
            self.reorganizer.check_and_reorganize((node or self.root).id)
        return item

    def add_memory_auto(self, key: str, value: Any, category: str, llm_client: Any = None, priority: MemoryPriority = MemoryPriority.MEDIUM, tags: list[str] | None = None, metadata: dict[str, Any] | None = None) -> MemoryItem:
        node_id = None
        nodes = self._non_root_nodes()
        if llm_client and nodes and hasattr(llm_client, "select_best_node"):
            node_id = llm_client.select_best_node(f"{key}={value}", [{"id": node.id, "name": node.name, "description": node.description} for node in nodes])
        return self.add_memory(key, value, category, priority, tags, metadata, node_id)

    def add_memories_auto(self, memories: list[tuple[str, Any, str]], llm_client: Any = None, priority: MemoryPriority = MemoryPriority.MEDIUM) -> list[MemoryItem]:
        return [self.add_memory_auto(key, value, category, llm_client, priority) for key, value, category in memories]

    def _non_root_nodes(self) -> list[MemoryNode]:
        return [node for child in self.root.children for node in self._walk(child)]

    def _walk(self, node: MemoryNode) -> list[MemoryNode]:
        return [node, *[child for item in node.children for child in self._walk(item)]]

    def get_memory(self, memory_id: str) -> MemoryItem | None:
        return self.memories.get(memory_id)

    def update_memory(self, memory_id: str, **changes: Any) -> bool:
        item = self.memories.get(memory_id)
        if not item:
            return False
        item.update(**changes)
        return True

    def delete_memory(self, memory_id: str) -> bool:
        if memory_id not in self.memories:
            return False
        self._remove_from_tree(self.root, memory_id)
        del self.memories[memory_id]
        return True

    def _remove_from_tree(self, node: MemoryNode, memory_id: str) -> None:
        if memory_id in node.memory_ids:
            node.memory_ids.remove(memory_id)
        for child in node.children:
            self._remove_from_tree(child, memory_id)

    def clear(self) -> None:
        self.memories.clear()
        self.root.memory_ids.clear()
        self.root.children.clear()

    def search_memories(self, query: str, top_k: int = 10) -> list[RetrievalResult]:
        try:
            return self.retrieval_agent.retrieve(query, top_k)
        except Exception:
            return KeywordRetrievalAgent(self).retrieve(query, top_k)

    def search(self, query: str, top_k: int = 5) -> list[dict[str, Any]]:
        return [result.memory.to_dict() for result in self.search_memories(query, top_k)]

    def get_memories_by_node(self, node_id: str, include_children: bool = True) -> list[MemoryItem]:
        node = self.root.find_node(node_id)
        ids = node.get_all_memory_ids() if node and include_children else (node.memory_ids if node else [])
        return [self.memories[mid] for mid in ids if mid in self.memories]

    def create_node(self, name: str, description: str = "", parent_id: str | None = None) -> MemoryNode:
        parent = self.root if parent_id is None else self.root.find_node(parent_id)
        if parent is None:
            raise ValueError(f"Parent node with ID {parent_id} not found")
        return parent.add_child(name, description)

    def move_memory_to_node(self, memory_id: str, node_id: str) -> bool:
        node = self.root.find_node(node_id)
        if memory_id not in self.memories or node is None:
            return False
        self._remove_from_tree(self.root, memory_id)
        node.add_memory(memory_id)
        return True

    def get_hierarchy(self) -> dict[str, Any]:
        return self.root.to_dict()

    def get_statistics(self) -> dict[str, Any]:
        categories: dict[str, int] = {}
        priorities: dict[str, int] = {}
        for item in self.memories.values():
            categories[item.category] = categories.get(item.category, 0) + 1
            priorities[item.priority.name] = priorities.get(item.priority.name, 0) + 1
        return {"total_memories": len(self.memories), "categories": categories, "priorities": priorities, "reorganization_threshold": self.reorganization_threshold, "needs_reorganization": len(self.memories) >= self.reorganization_threshold}

    def export_to_dict(self) -> dict[str, Any]:
        return {"memories": {key: item.to_dict() for key, item in self.memories.items()}, "hierarchy": self.root.to_dict(), "reorganization_threshold": self.reorganization_threshold, "auto_reorganize": self.auto_reorganize}

    def import_from_dict(self, data: dict[str, Any]) -> None:
        self.memories = {key: MemoryItem.from_dict(item) for key, item in data.get("memories", {}).items()}
        self.root = MemoryNode.from_dict(data.get("hierarchy", {"id": str(uuid4()), "name": "root", "children": [], "memory_ids": []}))
        self.reorganization_threshold = data.get("reorganization_threshold", self.reorganization_threshold)
        self.auto_reorganize = data.get("auto_reorganize", self.auto_reorganize)
        self.retrieval_agent = KeywordRetrievalAgent(self)
        self.reorganizer = LLMReorganizer(self, self.reorganization_llm, self.reorganization_strategy)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "MemoryStore":
        store = cls(data.get("reorganization_threshold", 50), auto_reorganize=data.get("auto_reorganize", True))
        store.import_from_dict(data)
        return store


InMemoryBackboneStore = MemoryStore
