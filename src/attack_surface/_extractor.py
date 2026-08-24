"""Извлечение точек входа из графа кода trailmark.

Модуль анализирует ``CodeGraph``, построенный trailmark, и определяет:
1. Корневые функции (не имеющие вызывающих в проекте).
2. Функции, содержащие вызовы внешних API (сеть, файлы, ввод и т.д.).
"""

from __future__ import annotations

import os
from collections import defaultdict
from pathlib import Path
from typing import Sequence

from trailmark.models import CodeEdge, CodeGraph, CodeUnit, EdgeKind, NodeKind

from attack_surface._languages import LANGUAGE_API_MAPS
from attack_surface._models import EntryPointInfo, ExternalSource


# ---------------------------------------------------------------------------
# Утилиты
# ---------------------------------------------------------------------------

def _read_source_lines(file_path: str, start: int, end: int) -> str:
    """Прочитать строки ``[start, end]`` из файла (нумерация с 1)."""
    try:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as fh:
            lines = fh.readlines()
        return "".join(lines[max(0, start - 1) : end])
    except OSError:
        return ""


def _callee_ids(graph: CodeGraph) -> dict[str, set[str]]:
    """Построить словарь caller_id → {callee_id} по рёбрам CALLS."""
    mapping: dict[str, set[str]] = defaultdict(set)
    for edge in graph.edges:
        if edge.kind == EdgeKind.CALLS:
            mapping[edge.source_id].add(edge.target_id)
    return mapping


def _caller_ids(graph: CodeGraph) -> dict[str, set[str]]:
    """Построить словарь callee_id → {caller_id} по рёбрам CALLS."""
    mapping: dict[str, set[str]] = defaultdict(set)
    node_ids = set(graph.nodes.keys())
    for edge in graph.edges:
        if edge.kind == EdgeKind.CALLS:
            # Учитываем только те target_id, которые соответствуют реальным узлам
            if edge.target_id in node_ids:
                mapping[edge.target_id].add(edge.source_id)
    return mapping


# ---------------------------------------------------------------------------
# Основной экстрактор
# ---------------------------------------------------------------------------

class EntryPointExtractor:
    """Извлекает точки входа из ``CodeGraph`` trailmark."""

    def __init__(self, graph: CodeGraph, language: str) -> None:
        self._graph = graph
        self._language = language
        self._api_map: dict[str, str] = LANGUAGE_API_MAPS.get(language, {})
        self._caller_map = _caller_ids(graph)
        self._callee_map = _callee_ids(graph)

    # ------------------------------------------------------------------
    # Публичные методы
    # ------------------------------------------------------------------

    def extract_root_functions(self) -> list[CodeUnit]:
        """Вернуть функции, у которых нет вызывающих в проекте."""
        roots: list[CodeUnit] = []
        for node in self._graph.nodes.values():
            if node.kind not in (NodeKind.FUNCTION, NodeKind.METHOD):
                continue
            if self._is_test_or_example(node):
                continue
            if node.id not in self._caller_map:
                roots.append(node)
        return roots

    def extract_external_input_functions(self) -> list[tuple[CodeUnit, list[ExternalSource]]]:
        """Вернуть функции, содержащие вызовы внешних API, вместе с источниками."""
        results: list[tuple[CodeUnit, list[ExternalSource]]] = []
        for node in self._graph.nodes.values():
            if node.kind not in (NodeKind.FUNCTION, NodeKind.METHOD):
                continue
            if self._is_test_or_example(node):
                continue
            sources = self._find_external_sources(node)
            if sources:
                results.append((node, sources))
        return results

    def extract_all(self) -> tuple[list[CodeUnit], list[tuple[CodeUnit, list[ExternalSource]]]]:
        """Извлечь корневые функции и функции с внешним вводом."""
        roots = self.extract_root_functions()
        ext_funcs = self.extract_external_input_functions()
        return roots, ext_funcs

    def build_entry_points(
        self,
    ) -> dict[str, EntryPointInfo]:
        """Собрать полный набор кандидатов в точки входа.

        Объединяет корневые функции (с параметрами / main) и функции
        с внешним вводом.
        """
        roots, ext_funcs = self.extract_all()
        candidates: dict[str, EntryPointInfo] = {}

        # Корневые функции с параметрами или main
        for node in roots:
            if node.parameters or node.name in ("main", "Main", "__main__"):
                # Проверяем, что функция не является простой утилитой без внешнего ввода
                sources = self._find_external_sources(node)
                if sources or node.name in ("main", "Main", "__main__"):
                    info = self._node_to_entry_point(node, is_root=True, sources=sources)
                    candidates[node.id] = info

        # Функции с внешним вводом
        for node, sources in ext_funcs:
            if node.id in candidates:
                # Дополняем уже найденный — добавляем источники
                candidates[node.id].external_sources = sources
                if sources:
                    candidates[node.id].entry_point_type = sources[0].entry_point_type
            else:
                info = self._node_to_entry_point(node, is_root=False, sources=sources)
                candidates[node.id] = info

        return candidates

    # ------------------------------------------------------------------
    # Внутренние методы
    # ------------------------------------------------------------------

    def _is_test_or_example(self, node: CodeUnit) -> bool:
        fp = node.location.file_path.lower()
        # Проверяем только имя файла, а не весь путь
        filename = os.path.basename(fp)
        return filename.startswith("test_") or "example" in filename

    def _find_external_sources(self, node: CodeUnit) -> list[ExternalSource]:
        """Найти внешние вызовы API внутри узла по рёбрам CALLS."""
        sources: list[ExternalSource] = []

        # Вариант 1: по рёбрам CALLS из этого узла
        for callee_id in self._callee_map.get(node.id, set()):
            # Проверяем сам callee_id на совпадение с API
            api_type = self._match_api_name(callee_id)
            if api_type:
                # Извлекаем имя API из callee_id
                api_name = self._extract_api_name(callee_id)
                sources.append(
                    ExternalSource(
                        name=api_name,
                        line_number=node.location.start_line if node.location else 0,
                        file_path=node.location.file_path,
                        entry_point_type=api_type,
                    )
                )
                continue
            
            # Если callee_id не совпал, проверяем узел
            callee = self._graph.nodes.get(callee_id)
            if callee is None:
                continue
            api_type = self._match_api_name(callee.name)
            if api_type:
                sources.append(
                    ExternalSource(
                        name=callee.name,
                        line_number=callee.location.start_line if callee.location else 0,
                        file_path=node.location.file_path,
                        entry_point_type=api_type,
                    )
                )

        # Вариант 2: текстовый поиск по исходному коду функции
        src = _read_source_lines(
            node.location.file_path,
            node.location.start_line,
            node.location.end_line,
        )
        if src:
            for api_name, api_type in self._api_map.items():
                if api_name in src:
                    # Избегаем дубликатов уже найденных через граф
                    already = any(s.name == api_name for s in sources)
                    if not already:
                        sources.append(
                            ExternalSource(
                                name=api_name,
                                line_number=node.location.start_line,
                                file_path=node.location.file_path,
                                entry_point_type=api_type,
                            )
                        )

        return sources

    def _match_api_name(self, name: str) -> str | None:
        """Проверить, совпадает ли имя с каким-либо внешним API."""
        # Точное совпадение
        if name in self._api_map:
            return self._api_map[name]
        # Совпадение по последнему сегменту (для method calls вида obj.method)
        short = name.rsplit(".", maxsplit=1)[-1] if "." in name else None
        if short and short in self._api_map:
            return self._api_map[short]
        # Частичное совпадение — ищем API в строке
        for api_name, api_type in self._api_map.items():
            if api_name in name:
                return api_type
        return None
    
    def _extract_api_name(self, callee_id: str) -> str:
        """Извлечь имя API из callee_id (может содержать полное выражение)."""
        # Ищем первое совпадение с известным API
        for api_name in self._api_map.keys():
            if api_name in callee_id:
                return api_name
        # Если не нашли, берём последний сегмент до скобок
        if "(" in callee_id:
            callee_id = callee_id.split("(")[0]
        if "." in callee_id:
            return callee_id.rsplit(".", maxsplit=1)[-1]
        return callee_id

    def _node_to_entry_point(
        self,
        node: CodeUnit,
        *,
        is_root: bool,
        sources: list[ExternalSource] | None = None,
    ) -> EntryPointInfo:
        ep_type = "unknown"
        if sources:
            ep_type = sources[0].entry_point_type
        elif node.name in ("main", "Main", "__main__"):
            ep_type = "main_function"

        return EntryPointInfo(
            node_id=node.id,
            function_name=node.name,
            file_path=node.location.file_path,
            start_line=node.location.start_line,
            end_line=node.location.end_line,
            entry_point_type=ep_type,
            external_sources=sources or [],
            is_root_function=is_root,
        )
