"""Кэш результатов анализа по версиям репозиториев (без БД).

Структура каталога кэша (по умолчанию ``<каталог проекта>/.attack_cache``,
переопределяется ``ATTACK_CACHE_DIR``)::

    <root>/<проект>/
      current.json               # {repos: {имя: версия}, links_hash: ...}
      repos/<имя>/<версия>.json  # точки входа, интерфейсы, проекция графа
      links/<хэш>.json           # подтверждённые связи для совокупной версии

Записи неизменяемы (версия в имени файла), поэтому предыдущие результаты
сохраняются: при откате на старый коммит его верификация подхватывается.
Точки входа и связи, не изменившиеся между версиями, переиспользуются без
повторных LLM-запросов.

Граф trailmark хранится проекцией (узлы: id/name/kind/location; рёбра:
source/target/kind) и восстанавливается совместимыми адаптерами, чтобы
``_node_names``, ``_call_edges`` и ``_resolve_node`` работали как с живым
графом.
"""

from __future__ import annotations

import hashlib
import json
import os
from typing import Any

from trailmark.models import EdgeKind, NodeKind


# ---------------------------------------------------------------------------
# Адаптеры графа из кэша
# ---------------------------------------------------------------------------

class _Location:
    """Адаптер location узла (как в trailmark)."""

    def __init__(self, file_path: str, start_line: int, end_line: int) -> None:
        self.file_path = file_path
        self.start_line = start_line
        self.end_line = end_line


class _CachedNode:
    """Адаптер узла графа: те же атрибуты, что использует пайплайн."""

    def __init__(self, node_id: str, name: str, kind: NodeKind | None, location: _Location) -> None:
        self.id = node_id
        self.name = name
        self.kind = kind
        self.location = location


class _CachedEdge:
    """Адаптер ребра графа."""

    def __init__(self, source_id: str, target_id: str, kind: EdgeKind | None) -> None:
        self.source_id = source_id
        self.target_id = target_id
        self.kind = kind


class CachedGraph:
    """Адаптер графа, восстанавливаемый из проекции кэша."""

    def __init__(
        self,
        nodes: dict[str, _CachedNode],
        edges: list[_CachedEdge],
        language: str,
    ) -> None:
        self.nodes = nodes
        self.edges = edges
        self.language = language


def dump_graph_projection(graph: Any) -> dict[str, Any]:
    """Спроецировать trailmark-граф в JSON-структуру кэша."""
    nodes: list[dict[str, Any]] = []
    for node in graph.nodes.values():
        loc = getattr(node, "location", None)
        nodes.append(
            {
                "id": node.id,
                "name": getattr(node, "name", ""),
                "kind": getattr(node.kind, "value", None) if node.kind is not None else None,
                "file": loc.file_path if loc is not None else "",
                "start_line": loc.start_line if loc is not None else 0,
                "end_line": loc.end_line if loc is not None else 0,
            }
        )
    edges: list[dict[str, Any]] = []
    for edge in graph.edges:
        edges.append(
            {
                "source_id": edge.source_id,
                "target_id": edge.target_id,
                "kind": getattr(edge.kind, "value", None) if edge.kind is not None else None,
            }
        )
    return {"language": graph.language, "nodes": nodes, "edges": edges}


def _parse_kind(value: Any, enum_type: Any) -> Any | None:
    """Восстановить enum-член по строковому значению (или None)."""
    if not value:
        return None
    try:
        return enum_type(value)
    except ValueError:
        return None


def load_graph_projection(data: dict[str, Any]) -> CachedGraph | None:
    """Восстановить адаптер графа из проекции (None, если проекции нет)."""
    nodes: dict[str, _CachedNode] = {}
    for item in data.get("nodes", []):
        if not isinstance(item, dict):
            continue
        nodes[str(item.get("id", ""))] = _CachedNode(
            node_id=str(item.get("id", "")),
            name=str(item.get("name", "")),
            kind=_parse_kind(item.get("kind"), NodeKind),
            location=_Location(
                str(item.get("file", "")),
                int(item.get("start_line", 0)),
                int(item.get("end_line", 0)),
            ),
        )
    edges: list[_CachedEdge] = []
    for item in data.get("edges", []):
        if not isinstance(item, dict):
            continue
        edges.append(
            _CachedEdge(
                source_id=str(item.get("source_id", "")),
                target_id=str(item.get("target_id", "")),
                kind=_parse_kind(item.get("kind"), EdgeKind),
            )
        )
    return CachedGraph(nodes=nodes, edges=edges, language=str(data.get("language", "")))


# ---------------------------------------------------------------------------
# Хранилище
# ---------------------------------------------------------------------------

def links_hash_for(repo_versions: dict[str, str]) -> str:
    """Хэш совокупной версии проекта (по версиям всех репозиториев)."""
    digest = hashlib.sha256()
    for repo in sorted(repo_versions):
        digest.update(f"{repo}={repo_versions[repo]}\0".encode("utf-8"))
    return digest.hexdigest()


class CacheStore:
    """Файловое хранилище кэша для одного проекта."""

    def __init__(self, root: str, project: str) -> None:
        self._root = os.path.join(os.path.abspath(root), project)

    # ------------------------------------------------------------------

    def _path(self, *parts: str) -> str:
        return os.path.join(self._root, *parts)

    def _write_json(self, path: str, data: dict[str, Any]) -> str:
        """Атомарная запись: во временный файл, затем переименование."""
        os.makedirs(os.path.dirname(path), exist_ok=True)
        tmp = f"{path}.tmp"
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(data, fh, ensure_ascii=False)
        os.replace(tmp, path)
        return path

    def _read_json(self, path: str) -> dict[str, Any] | None:
        if not os.path.isfile(path):
            return None
        try:
            with open(path, encoding="utf-8") as fh:
                data = json.load(fh)
        except (OSError, json.JSONDecodeError):
            return None
        return data if isinstance(data, dict) else None

    # ------------------------------------------------------------------
    # current.json
    # ------------------------------------------------------------------

    def load_current(self) -> dict[str, Any] | None:
        """Текущие версии репозиториев и хэш связей."""
        return self._read_json(self._path("current.json"))

    def save_current(self, repo_versions: dict[str, str], links_hash: str) -> str:
        """Сохранить текущие версии и хэш связей."""
        return self._write_json(
            self._path("current.json"),
            {"repos": repo_versions, "links_hash": links_hash},
        )

    # ------------------------------------------------------------------
    # Записи репозиториев
    # ------------------------------------------------------------------

    def repo_entry_path(self, repo: str, version: str) -> str:
        return self._path("repos", repo, f"{version}.json")

    def load_repo(self, repo: str, version: str) -> dict[str, Any] | None:
        """Запись репозитория по версии (None, если её нет)."""
        return self._read_json(self.repo_entry_path(repo, version))

    def save_repo(
        self,
        repo: str,
        version: str,
        entry_points: dict[str, Any],
        interfaces: dict[str, Any],
        graph: dict[str, Any],
        language: str,
    ) -> str:
        """Сохранить результат сканирования репозитория для версии."""
        data = {
            "version": version,
            "language": language,
            "entry_points": entry_points,
            "interfaces": interfaces,
            "graph": graph,
        }
        return self._write_json(self.repo_entry_path(repo, version), data)

    def load_previous_repo(self, repo: str, version: str) -> dict[str, Any] | None:
        """Последняя запись репозитория с другой версией (для сравнения)."""
        dir_path = self._path("repos", repo)
        if not os.path.isdir(dir_path):
            return None
        candidates: list[tuple[float, str]] = []
        for name in os.listdir(dir_path):
            if not name.endswith(".json") or name == f"{version}.json":
                continue
            path = os.path.join(dir_path, name)
            candidates.append((os.path.getmtime(path), path))
        if not candidates:
            return None
        _, path = max(candidates)
        return self._read_json(path)

    # ------------------------------------------------------------------
    # Записи связей
    # ------------------------------------------------------------------

    def links_path(self, links_hash: str) -> str:
        return self._path("links", f"{links_hash}.json")

    def load_links(self, links_hash: str) -> dict[str, Any] | None:
        """Связи для совокупной версии (None, если их нет)."""
        return self._read_json(self.links_path(links_hash))

    def save_links(self, links_hash: str, edges: list[dict[str, Any]]) -> str:
        """Сохранить подтверждённые связи для совокупной версии."""
        return self._write_json(self.links_path(links_hash), {"edges": edges})

    def load_previous_links(self, links_hash: str) -> dict[str, Any] | None:
        """Последние связи для другой совокупной версии (для сравнения)."""
        dir_path = self._path("links")
        if not os.path.isdir(dir_path):
            return None
        candidates: list[tuple[float, str]] = []
        for name in os.listdir(dir_path):
            if not name.endswith(".json") or name == f"{links_hash}.json":
                continue
            path = os.path.join(dir_path, name)
            candidates.append((os.path.getmtime(path), path))
        if not candidates:
            return None
        _, path = max(candidates)
        return self._read_json(path)
