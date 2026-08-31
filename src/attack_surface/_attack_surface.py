"""Поверхность атаки кросс-репозиторного графа.

Строит направленный граф потоков данных: внутри репозитория — вызовы
(``CALLS``), между репозиториями — подтверждённые связи (``CrossRepoEdge``).
Начиная от серверных интерфейсов (точек, принимающих данные извне),
распространяет достижимость по графу и выделяет межрепозиторные цепочки
атак.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Iterable

from attack_surface._linker import CrossRepoEdge

# Ограничения обхода, чтобы избежать комбинаторного взрыва
_MAX_DEPTH = 8
_MAX_CHAINS = 500
_MAX_CHAINS_PER_SOURCE = 50


# ---------------------------------------------------------------------------
# Модели результата
# ---------------------------------------------------------------------------

@dataclass
class AttackChain:
    """Одна цепочка атак: путь от внешнего источника по графу."""

    source_repo: str
    source_node_id: str
    hops: list[dict[str, Any]] = field(default_factory=list)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "AttackChain":
        """Восстановить цепочку из JSON (см. ``to_dict``)."""
        return cls(
            source_repo=str(data.get("source_repo", "")),
            source_node_id=str(data.get("source_node_id", "")),
            hops=list(data.get("hops", [])),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "source_repo": self.source_repo,
            "source_node_id": self.source_node_id,
            "hops": self.hops,
        }


@dataclass
class ReachabilityResult:
    """Результат анализа достижимости в кросс-репо графе."""

    sources: list[dict[str, Any]] = field(default_factory=list)
    reachable: list[dict[str, Any]] = field(default_factory=list)
    chains: list[AttackChain] = field(default_factory=list)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "ReachabilityResult":
        """Восстановить результат из JSON (см. ``to_dict``)."""
        return cls(
            sources=list(data.get("sources", [])),
            reachable=list(data.get("reachable", [])),
            chains=[
                AttackChain.from_dict(c)
                for c in data.get("chains", [])
                if isinstance(c, dict)
            ],
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "sources": self.sources,
            "reachable": self.reachable,
            "chains": [c.to_dict() for c in self.chains],
        }


# ---------------------------------------------------------------------------
# Вычисление
# ---------------------------------------------------------------------------

def compute_attack_surface(
    call_edges: Iterable[tuple[str, str, str]],
    cross_edges: Iterable[CrossRepoEdge],
    sources: Iterable[tuple[str, str]],
    node_names: dict[tuple[str, str], str],
) -> ReachabilityResult:
    """Вычислить достижимые узлы и цепочки атак.

    :param call_edges: внутриреповые вызовы ``(repo, source_id, target_id)``.
    :param cross_edges: подтверждённые межреповые связи.
    :param sources: внешние источники ``(repo, node_id)``.
    :param node_names: ``(repo, node_id)`` → имя функции.
    """
    # Смежный список: (repo, node) → [(repo, node, kind, link_type)]
    adj: dict[tuple[str, str], list[tuple[str, str, str, str]]] = {}

    def add_edge(src: tuple[str, str], dst: tuple[str, str], kind: str, link_type: str) -> None:
        adj.setdefault(src, []).append((dst[0], dst[1], kind, link_type))

    for repo, source_id, target_id in call_edges:
        if source_id and target_id:
            add_edge((repo, source_id), (repo, target_id), "call", "")

    for edge in cross_edges:
        if edge.client_node_id and edge.server_node_id:
            add_edge(
                (edge.client_repo, edge.client_node_id),
                (edge.server_repo, edge.server_node_id),
                "cross",
                edge.link.type,
            )

    source_nodes: list[tuple[str, str]] = [
        (repo, node_id) for repo, node_id in sources if node_id
    ]

    # Достижимость (BFS)
    reachable: set[tuple[str, str]] = set()
    stack: list[tuple[str, str]] = list(source_nodes)
    while stack:
        current = stack.pop()
        if current in reachable:
            continue
        reachable.add(current)
        for nxt_repo, nxt_node, _kind, _link_type in adj.get(current, []):
            nxt = (nxt_repo, nxt_node)
            if nxt not in reachable:
                stack.append(nxt)

    # Цепочки атак (DFS с ограничением глубины)
    chains: list[AttackChain] = []
    for source in source_nodes:
        _collect_chains(source, adj, node_names, chains)
        if len(chains) >= _MAX_CHAINS:
            break

    reachable_list = sorted(
        (
            {"repo": repo, "node_id": node_id, "function_name": node_names.get((repo, node_id), "")}
            for repo, node_id in reachable
        ),
        key=lambda x: (x["repo"], x["node_id"]),
    )
    source_list = [
        {"repo": repo, "node_id": node_id, "function_name": node_names.get((repo, node_id), "")}
        for repo, node_id in source_nodes
    ]

    return ReachabilityResult(sources=source_list, reachable=reachable_list, chains=chains)


def _collect_chains(
    source: tuple[str, str],
    adj: dict[tuple[str, str], list[tuple[str, str, str, str]]],
    node_names: dict[tuple[str, str], str],
    chains: list[AttackChain],
) -> None:
    """Собрать межрепозиторные цепочки от одного источника (DFS)."""
    if len(chains) >= _MAX_CHAINS:
        return

    start_repo, start_node = source
    start_hop = {
        "repo": start_repo,
        "node_id": start_node,
        "function_name": node_names.get(source, ""),
        "kind": "source",
        "link_type": "",
    }

    def dfs(
        current: tuple[str, str],
        path: list[dict[str, Any]],
        visited: set[tuple[str, str]],
        crossed: bool,
        per_source: list[int],
    ) -> None:
        if len(chains) >= _MAX_CHAINS or per_source[0] >= _MAX_CHAINS_PER_SOURCE:
            return
        if len(path) >= _MAX_DEPTH:
            return

        for nxt_repo, nxt_node, kind, link_type in adj.get(current, []):
            nxt = (nxt_repo, nxt_node)
            if nxt in visited:
                continue
            nxt_hop = {
                "repo": nxt_repo,
                "node_id": nxt_node,
                "function_name": node_names.get(nxt, ""),
                "kind": kind,
                "link_type": link_type,
            }
            next_crossed = crossed or kind == "cross"

            path.append(nxt_hop)
            visited.add(nxt)
            if next_crossed and len(path) > 1:
                chains.append(
                    AttackChain(
                        source_repo=start_repo,
                        source_node_id=start_node,
                        hops=list(path),
                    )
                )
                per_source[0] += 1
            dfs(nxt, path, visited, next_crossed, per_source)
            visited.discard(nxt)
            path.pop()

            if len(chains) >= _MAX_CHAINS or per_source[0] >= _MAX_CHAINS_PER_SOURCE:
                return

    dfs(source, [start_hop], {source}, crossed=False, per_source=[0])
