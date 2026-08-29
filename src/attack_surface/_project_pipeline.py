"""Оркестратор мульти-репозиторного анализа поверхности атаки.

Объединяет весь кросс-репозиторный конвейер:

1. сканирование каждого репозитория (trailmark + ``EntryPointExtractor``);
2. LLM-валидация точек входа и определение интерфейсов связи;
3. статическое связывание эндпоинтов между репозиториями (+ обратный проход);
4. LLM-подтверждение найденных связей;
5. вычисление поверхности атаки большого графа (достижимость и цепочки);
6. генерация кросс-репозиторного графа и сохранение результатов.

Функционал обособлен: при отключении (``use_llm=False`` и/или env-флагами)
он не влияет на одиночное сканирование.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from typing import Any

from tqdm import tqdm

from attack_surface._attack_surface import ReachabilityResult, compute_attack_surface
from attack_surface._extractor import EntryPointExtractor, _read_source_lines
from attack_surface._interface_llm import (
    InterfaceBatchAnalyzerLLM,
    InterfaceBatchInput,
    InterfaceBatchOutput,
    InterfaceDescriptor,
    fallback_descriptor,
)
from attack_surface._link_llm import LinkValidatorLLM, confirm_edges
from attack_surface._linker import CrossRepoEdge, CrossRepoLinker
from attack_surface._logger import Logger
from attack_surface._models import EntryPointInfo
from attack_surface._project_config import ProjectConfig, RepoConfig
from attack_surface._project_graph import generate_project_graph


# ---------------------------------------------------------------------------
# Результаты сканирования
# ---------------------------------------------------------------------------

@dataclass
class RepoScanResult:
    """Результат сканирования одного репозитория."""

    repo: RepoConfig
    language: str
    entry_points: dict[str, EntryPointInfo] = field(default_factory=dict)
    interfaces: dict[str, InterfaceDescriptor] = field(default_factory=dict)
    graph: Any = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.repo.name,
            "language": self.language,
            "role": self.repo.role,
            "path": self.repo.path,
            "total_entry_points": len(self.entry_points),
            "entry_points": {k: v.to_dict() for k, v in self.entry_points.items()},
            "interfaces": {k: v.to_dict() for k, v in self.interfaces.items()},
        }


@dataclass
class ProjectScanResult:
    """Итоговый результат мульти-репозиторного сканирования."""

    config: ProjectConfig
    repos: list[RepoScanResult] = field(default_factory=list)
    edges: list[CrossRepoEdge] = field(default_factory=list)
    attack_surface: ReachabilityResult | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "project": self.config.project,
            "repos": [r.to_dict() for r in self.repos],
            "links": [link.to_dict() for link in self.config.links],
            "edges": [e.to_dict() for e in self.edges],
            "attack_surface": self.attack_surface.to_dict() if self.attack_surface else None,
        }


# ---------------------------------------------------------------------------
# Вспомогательные утилиты
# ---------------------------------------------------------------------------

def _env_flag(name: str, default: bool) -> bool:
    """Прочитать логический флаг из переменной окружения."""
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() not in ("0", "false", "no", "off", "")


def _env_int(name: str, default: int) -> int:
    """Прочитать целое число из переменной окружения."""
    value = os.getenv(name)
    if value is None:
        return default
    try:
        return int(value.strip())
    except ValueError:
        return default


def _resolve_node(graph: Any, file_path: str, line: int) -> str:
    """Найти id узла-функции по файлу и строке (ближайший охватывающий диапазон)."""
    norm = os.path.normpath(file_path).replace("\\", "/").lower()
    best_id = ""
    best_span: int | None = None
    for node in graph.nodes.values():
        loc = getattr(node, "location", None)
        if loc is None:
            continue
        node_file = os.path.normpath(loc.file_path).replace("\\", "/").lower()
        if node_file != norm:
            continue
        if loc.start_line <= line <= loc.end_line:
            span = loc.end_line - loc.start_line
            if best_span is None or span < best_span:
                best_span = span
                best_id = node.id
    return best_id


def _node_names(graph: Any) -> dict[str, str]:
    """Имена узлов-функций по id."""
    from trailmark.models import NodeKind

    return {
        node.id: node.name
        for node in graph.nodes.values()
        if node.kind in (NodeKind.FUNCTION, NodeKind.METHOD)
    }


def _call_edges(graph: Any) -> list[tuple[str, str]]:
    """Рёбра вызовов ``(source_id, target_id)`` между функциями/методами."""
    from trailmark.models import EdgeKind, NodeKind

    valid = {
        node.id for node in graph.nodes.values()
        if node.kind in (NodeKind.FUNCTION, NodeKind.METHOD)
    }
    return [
        (edge.source_id, edge.target_id)
        for edge in graph.edges
        if edge.kind == EdgeKind.CALLS
        and edge.source_id in valid
        and edge.target_id in valid
    ]


def _group_batches_by_file(
    entry_points: dict[str, EntryPointInfo], batch_size: int
) -> list[list[tuple[str, EntryPointInfo]]]:
    """Сформировать батчи точек входа пофайлово.

    Файл с большим числом точек входа разбивается на чанки размером
    ``batch_size``, а «хвосты» файлов с малым числом точек добираются
    друг из друга до полного батча.
    """
    by_file: dict[str, list[tuple[str, EntryPointInfo]]] = {}
    for node_id, ep in entry_points.items():
        by_file.setdefault(ep.file_path, []).append((node_id, ep))

    batches: list[list[tuple[str, EntryPointInfo]]] = []
    pending: list[tuple[str, EntryPointInfo]] = []

    for file_path in sorted(by_file):
        eps = by_file[file_path]
        # Полные чанки из большого файла
        full_len = len(eps) - len(eps) % batch_size
        for start in range(0, full_len, batch_size):
            batches.append(eps[start : start + batch_size])
        # Остаток файла — в пул добора
        pending.extend(eps[full_len:])
        while len(pending) >= batch_size:
            batches.append(pending[:batch_size])
            pending = pending[batch_size:]

    if pending:
        batches.append(pending)
    return batches


# ---------------------------------------------------------------------------
# Оркестратор
# ---------------------------------------------------------------------------

class ProjectScanner:
    """Сканирует мульти-репозиторный проект и строит кросс-репо граф."""

    def __init__(
        self,
        config: ProjectConfig,
        logger: Logger,
        *,
        model_name: str = "gpt-4o-mini",
        temperature: float = 0.0,
        max_query_num: int = 3,
        use_llm: bool = True,
        output_dir: str = ".",
        graph_format: str = "svg",
    ) -> None:
        self._config = config
        self._logger = logger
        self._model_name = model_name
        self._temperature = temperature
        self._max_query_num = max_query_num
        self._use_llm = use_llm
        self._output_dir = os.path.abspath(output_dir)
        self._graph_format = graph_format

        self._bidirectional = _env_flag("CROSS_REPO_BIDIRECTIONAL", True)
        self._confirm_links = _env_flag("CROSS_REPO_CONFIRM_LINKS", True)

    # ------------------------------------------------------------------

    def scan(self) -> ProjectScanResult:
        """Выполнить полный кросс-репозиторный анализ."""
        os.makedirs(self._output_dir, exist_ok=True)

        self._logger.print_console(
            f"Мульти-репозиторное сканирование: {self._config.project}"
        )

        repo_results: list[RepoScanResult] = []
        for repo in self._config.repos:
            repo_results.append(self._scan_repo(repo))

        # Связывание эндпоинтов между репозиториями
        repo_interfaces = {r.repo.name: self._repo_interfaces(r) for r in repo_results}
        linker = CrossRepoLinker(self._config, bidirectional=self._bidirectional)

        if self._config.links_authoritative:
            # Связи заданы архитектором — не верифицируем, а сопоставляем эндпоинты
            edges = linker.find_authoritative_links(repo_interfaces)
            self._logger.print_console(f"  Связей по архитектурному конфигу: {len(edges)}")
        else:
            edges = linker.find_links(repo_interfaces)
            self._logger.print_console(f"  Найдено кандидатов связей: {len(edges)}")

            if self._use_llm and self._confirm_links and edges:
                validator = LinkValidatorLLM(
                    self._model_name, self._temperature, "multi", self._max_query_num, self._logger
                )
                edges = confirm_edges(validator, edges)
                self._logger.print_console(f"  Подтверждено связей: {len(edges)}")

        # Сопоставление клиентских функций для достижимости
        for edge in edges:
            client_graph = self._graph_for(repo_results, edge.client_repo)
            if client_graph is not None and not edge.client_node_id:
                node_id = _resolve_node(client_graph, edge.client_file, edge.client_line)
                edge.client_node_id = node_id
                if node_id:
                    edge.client_function_name = _node_names(client_graph).get(node_id, "")

        # Поверхность атаки большого графа
        attack_surface = self._compute_attack_surface(repo_results, edges)

        result = ProjectScanResult(
            config=self._config,
            repos=repo_results,
            edges=edges,
            attack_surface=attack_surface,
        )
        self._save_results(result)
        return result

    # ------------------------------------------------------------------

    def _scan_repo(self, repo: RepoConfig) -> RepoScanResult:
        from trailmark import parse_directory

        self._logger.print_console(f"\nСканирование репозитория '{repo.name}'…")
        if not os.path.isdir(repo.path):
            self._logger.print_console(f"  Каталог не найден, пропуск: {repo.path}")
            return RepoScanResult(repo=repo, language=repo.language)

        graph = parse_directory(repo.path, language=repo.language)
        language = graph.language if graph.language != "polyglot" else repo.language
        self._logger.print_console(
            f"  Узлов: {len(graph.nodes)}, рёбер: {len(graph.edges)}"
        )

        extractor = EntryPointExtractor(graph, language)
        entry_points = extractor.build_entry_points()
        self._logger.print_console(f"  Точек входа: {len(entry_points)}")

        interfaces = self._analyze_interfaces(repo, language, entry_points)
        return RepoScanResult(
            repo=repo,
            language=language,
            entry_points=entry_points,
            interfaces=interfaces,
            graph=graph,
        )

    def _analyze_interfaces(
        self,
        repo: RepoConfig,
        language: str,
        entry_points: dict[str, EntryPointInfo],
    ) -> dict[str, InterfaceDescriptor]:
        """Определить интерфейсы связи батчами по файлам (LLM или фоллбэк).

        Батчи формируются пофайлово: файл с большим числом точек входа
        разбивается на чанки размером ``ENTRY_BATCH_SIZE``, а «хвосты»
        маленьких файлов добираются друг из друга до полного батча.
        """
        interfaces: dict[str, InterfaceDescriptor] = {}
        batch_size = max(1, _env_int("ENTRY_BATCH_SIZE", 5))

        analyzer: InterfaceBatchAnalyzerLLM | None = None
        if self._use_llm:
            analyzer = InterfaceBatchAnalyzerLLM(
                self._model_name, self._temperature, language, self._max_query_num, self._logger
            )

        batches = _group_batches_by_file(entry_points, batch_size)

        bar = tqdm(
            total=len(entry_points),
            desc=f"Валидация точек входа [{repo.name}]",
            unit="ep",
        )
        for batch in batches:
            descriptors: dict[str, InterfaceDescriptor] = {}
            if analyzer is not None:
                inp = InterfaceBatchInput(
                    repo_name=repo.name,
                    repo_role=repo.role,
                    language=language,
                    items=[
                        {
                            "node_id": node_id,
                            "function_name": ep.function_name,
                            "file_path": ep.file_path,
                            "start_line": ep.start_line,
                            "end_line": ep.end_line,
                            "entry_point_type": ep.entry_point_type,
                            "code": _read_source_lines(ep.file_path, ep.start_line, ep.end_line),
                        }
                        for node_id, ep in batch
                    ],
                )
                out = analyzer.invoke(inp, InterfaceBatchOutput)
                if out is not None:
                    descriptors = out.descriptors

            for node_id, ep in batch:
                code = _read_source_lines(ep.file_path, ep.start_line, ep.end_line)
                interfaces[node_id] = descriptors.get(node_id) or fallback_descriptor(
                    ep.entry_point_type, code, language, ep.function_name
                )
            bar.update(len(batch))
        bar.close()

        return interfaces

    @staticmethod
    def _repo_interfaces(result: RepoScanResult) -> list[dict[str, Any]]:
        """Список интерфейсных эндпоинтов репозитория для линкера."""
        items: list[dict[str, Any]] = []
        for node_id, ep in result.entry_points.items():
            desc = result.interfaces.get(node_id)
            if desc is None or not desc.has_interface():
                continue
            items.append(
                {
                    "node_id": node_id,
                    "function_name": ep.function_name,
                    "file_path": ep.file_path,
                    "start_line": ep.start_line,
                    "entry_point_type": ep.entry_point_type,
                    "interface_kind": desc.interface_kind,
                    "interface_role": desc.interface_role,
                    "signature": desc.signature,
                    "signature_aliases": desc.signature_aliases,
                }
            )
        return items

    @staticmethod
    def _graph_for(repo_results: list[RepoScanResult], repo_name: str) -> Any:
        for result in repo_results:
            if result.repo.name == repo_name:
                return result.graph
        return None

    def _compute_attack_surface(
        self,
        repo_results: list[RepoScanResult],
        edges: list[CrossRepoEdge],
    ) -> ReachabilityResult:
        """Построить граф потоков данных и вычислить поверхность атаки."""
        call_edges: list[tuple[str, str, str]] = []
        node_names: dict[tuple[str, str], str] = {}
        sources: list[tuple[str, str]] = []

        for result in repo_results:
            if result.graph is None:
                continue
            names = _node_names(result.graph)
            for node_id, name in names.items():
                node_names[(result.repo.name, node_id)] = name
            for src, dst in _call_edges(result.graph):
                call_edges.append((result.repo.name, src, dst))
            for node_id, desc in result.interfaces.items():
                if desc.is_server():
                    sources.append((result.repo.name, node_id))

        return compute_attack_surface(call_edges, edges, sources, node_names)

    # ------------------------------------------------------------------

    def _save_results(self, result: ProjectScanResult) -> None:
        """Сохранить результаты: JSON по репозиториям, граф и общий отчёт."""
        repos_dir = os.path.join(self._output_dir, "repos")
        os.makedirs(repos_dir, exist_ok=True)

        repo_entry_points: dict[str, dict[str, Any]] = {}
        for repo_result in result.repos:
            eps = {k: v.to_dict() for k, v in repo_result.entry_points.items()}
            repo_entry_points[repo_result.repo.name] = eps
            path = os.path.join(repos_dir, f"{repo_result.repo.name}_entry_points.json")
            with open(path, "w", encoding="utf-8") as fh:
                json.dump(repo_result.to_dict(), fh, indent=2, ensure_ascii=False)

        artifacts = generate_project_graph(
            self._config,
            repo_entry_points,
            result.edges,
            self._output_dir,
            output_format=self._graph_format,
            attack_surface=result.attack_surface,
        )
        for name, path in artifacts.items():
            self._logger.print_console(f"  {name}: {path}")

        summary_path = os.path.join(self._output_dir, "project_scan.json")
        with open(summary_path, "w", encoding="utf-8") as fh:
            json.dump(result.to_dict(), fh, indent=2, ensure_ascii=False)
        self._logger.print_console(f"  Сводка: {summary_path}")
