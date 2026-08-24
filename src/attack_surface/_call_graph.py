"""Построение и фильтрация графа вызовов проекта.

Модуль предоставляет функционал для:
1. Построения полного графа вызовов проекта (обёртка над trailmark)
2. Фильтрации графа по элементам, связанным с поверхностью атаки
"""

from __future__ import annotations

from typing import Set

from trailmark.models import CodeEdge, CodeGraph, CodeUnit, EdgeKind, NodeKind

from attack_surface._models import EntryPointInfo


class CallGraphBuilder:
    """Построение и фильтрация графа вызовов."""

    def __init__(self, graph: CodeGraph):
        self._graph = graph

    def get_full_graph(self) -> CodeGraph:
        """Получить полный граф вызовов проекта (как создаёт trailmark)."""
        return self._graph

    def filter_by_attack_surface(
        self, entry_points: dict[str, EntryPointInfo]
    ) -> CodeGraph:
        """Отфильтровать граф, оставив только элементы связанные с поверхностью атаки.

        Алгоритм:
        1. Начинаем с узлов точек входа
        2. Рекурсивно обходим все вызовы (прямые и обратные)
        3. Собираем все достижимые узлы и рёбра
        4. Создаём новый граф только с этими элементами

        Args:
            entry_points: Словарь точек входа (node_id -> EntryPointInfo)

        Returns:
            Новый CodeGraph содержащий только узлы и рёбра связанные с точками входа
        """
        # Множество ID узлов точек входа
        entry_point_ids = set(entry_points.keys())

        # Собираем все достижимые узлы
        reachable_nodes = self._collect_reachable_nodes(entry_point_ids)

        # Фильтруем узлы и рёбра
        filtered_nodes = {
            node_id: node
            for node_id, node in self._graph.nodes.items()
            if node_id in reachable_nodes
        }

        filtered_edges = [
            edge
            for edge in self._graph.edges
            if edge.source_id in reachable_nodes or edge.target_id in reachable_nodes
        ]

        # Создаём новый граф
        filtered_graph = CodeGraph(
            nodes=filtered_nodes,
            edges=filtered_edges,
            language=self._graph.language,
            root_path=self._graph.root_path,
        )

        # Копируем метаданные
        if hasattr(self._graph, "annotations"):
            filtered_graph.annotations = [
                ann
                for ann in self._graph.annotations
                if ann.target_id in reachable_nodes
            ]

        if hasattr(self._graph, "entrypoints"):
            filtered_graph.entrypoints = [
                ep for ep in self._graph.entrypoints if ep.node_id in reachable_nodes
            ]

        return filtered_graph

    def _collect_reachable_nodes(self, start_ids: Set[str]) -> Set[str]:
        """Собрать все узлы достижимые из стартовых узлов (в обе стороны).

        Args:
            start_ids: Множество ID стартовых узлов

        Returns:
            Множество ID всех достижимых узлов
        """
        reachable = set(start_ids)
        to_visit = list(start_ids)

        # Строим карты вызовов для быстрого поиска
        callers = self._build_caller_map()
        callees = self._build_callee_map()

        while to_visit:
            current_id = to_visit.pop()

            # Обходим вызываемые функции (прямые рёбра)
            for callee_id in callees.get(current_id, set()):
                if callee_id not in reachable and callee_id in self._graph.nodes:
                    reachable.add(callee_id)
                    to_visit.append(callee_id)

            # Обходим вызывающие функции (обратные рёбра)
            for caller_id in callers.get(current_id, set()):
                if caller_id not in reachable and caller_id in self._graph.nodes:
                    reachable.add(caller_id)
                    to_visit.append(caller_id)

        return reachable

    def _build_caller_map(self) -> dict[str, set[str]]:
        """Построить карту callee_id -> {caller_id}."""
        caller_map: dict[str, set[str]] = {}
        for edge in self._graph.edges:
            if edge.kind == EdgeKind.CALLS:
                if edge.target_id not in caller_map:
                    caller_map[edge.target_id] = set()
                caller_map[edge.target_id].add(edge.source_id)
        return caller_map

    def _build_callee_map(self) -> dict[str, set[str]]:
        """Построить карту caller_id -> {callee_id}."""
        callee_map: dict[str, set[str]] = {}
        for edge in self._graph.edges:
            if edge.kind == EdgeKind.CALLS:
                if edge.source_id not in callee_map:
                    callee_map[edge.source_id] = set()
                callee_map[edge.source_id].add(edge.target_id)
        return callee_map

    def get_statistics(self, graph: CodeGraph | None = None) -> dict[str, int]:
        """Получить статистику по графу.

        Args:
            graph: Граф для анализа (по умолчанию self._graph)

        Returns:
            Словарь со статистикой
        """
        g = graph or self._graph

        stats = {
            "total_nodes": len(g.nodes),
            "total_edges": len(g.edges),
            "functions": sum(
                1 for n in g.nodes.values() if n.kind == NodeKind.FUNCTION
            ),
            "methods": sum(1 for n in g.nodes.values() if n.kind == NodeKind.METHOD),
            "classes": sum(1 for n in g.nodes.values() if n.kind == NodeKind.CLASS),
            "modules": sum(1 for n in g.nodes.values() if n.kind == NodeKind.MODULE),
            "call_edges": sum(1 for e in g.edges if e.kind == EdgeKind.CALLS),
            "inherit_edges": sum(1 for e in g.edges if e.kind == EdgeKind.INHERITS),
            "contains_edges": sum(1 for e in g.edges if e.kind == EdgeKind.CONTAINS),
        }

        return stats
