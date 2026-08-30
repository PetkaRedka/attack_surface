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
from attack_surface._link_llm import LinkBatchValidatorLLM, confirm_edges_batch
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
# Загрузка проверенных точек входа из JSON
# ---------------------------------------------------------------------------

def _find_entrypoints_file(entrypoints_dir: str, repo_name: str) -> str | None:
    """Найти сохранённый файл точек входа репозитория."""
    candidates = [
        os.path.join(entrypoints_dir, "repos", f"{repo_name}_entry_points.json"),
        os.path.join(entrypoints_dir, f"{repo_name}_entry_points.json"),
    ]
    for path in candidates:
        if os.path.isfile(path):
            return path
    return None


def _repo_checkpoint_dict(
    repo: RepoConfig,
    language: str,
    entry_points: dict[str, EntryPointInfo],
    interfaces: dict[str, InterfaceDescriptor],
) -> dict[str, Any]:
    """Словарь промежуточного результата сканирования репозитория."""
    return {
        "name": repo.name,
        "language": language,
        "role": repo.role,
        "path": repo.path,
        "total_entry_points": len(entry_points),
        "entry_points": {k: v.to_dict() for k, v in entry_points.items()},
        "interfaces": {k: v.to_dict() for k, v in interfaces.items()},
    }


def load_repo_scan_results(
    config: ProjectConfig,
    entrypoints_dir: str,
    logger: Logger | None = None,
) -> list[RepoScanResult]:
    """Загрузить проверенные точки входа репозиториев из JSON.

    Ожидаются файлы ``<имя>_entry_points.json`` в ``entrypoints_dir`` или
    в его подкаталоге ``repos`` (именно так их сохраняет ``project``).
    Интерфейсы связи берутся из JSON — исходный код репозиториев не
    читается вовсе, пайплайн сразу переходит к этапу слияния графов
    (линковке эндпоинтов между репозиториями).

    :raises ValueError: если для какого-то репозитория файл не найден.
    """
    results: list[RepoScanResult] = []
    for repo in config.repos:
        path = _find_entrypoints_file(entrypoints_dir, repo.name)
        if path is None:
            raise ValueError(
                f"Не найден файл точек входа для репозитория '{repo.name}': "
                f"ожидался '{repo.name}_entry_points.json' в {entrypoints_dir}"
            )

        with open(path, encoding="utf-8") as fh:
            data = json.load(fh)
        if not isinstance(data, dict):
            raise ValueError(f"Некорректный JSON в файле: {path}")

        entry_points: dict[str, EntryPointInfo] = {}
        for node_id, ep in (data.get("entry_points") or {}).items():
            if isinstance(ep, dict):
                entry_points[str(node_id)] = EntryPointInfo.from_dict(ep)

        interfaces: dict[str, InterfaceDescriptor] = {}
        for node_id, desc in (data.get("interfaces") or {}).items():
            if isinstance(desc, dict):
                interfaces[str(node_id)] = InterfaceDescriptor.from_dict(desc)

        language = str(data.get("language") or repo.language)
        if logger is not None:
            logger.print_console(
                f"  {repo.name}: {len(entry_points)} точек входа "
                f"({len(interfaces)} интерфейсов) из {path}"
            )

        # graph не восстанавливается: код репозиториев не читается, этап
        # слияния использует только точки входа и интерфейсы из JSON
        results.append(
            RepoScanResult(
                repo=repo,
                language=language,
                entry_points=entry_points,
                interfaces=interfaces,
                graph=None,
            )
        )
    return results


def _resolve_node_eps(
    entry_points: dict[str, EntryPointInfo], file_path: str, line: int
) -> str:
    """Найти id точки входа по файлу и строке без графа вызовов.

    Аналог ``_resolve_node`` для режима пересборки из JSON, когда граф
    вызовов недоступен: ищется точка входа с наименьшим охватывающим
    диапазоном строк.
    """
    norm = os.path.normpath(file_path).replace("\\", "/").lower()
    best_id = ""
    best_span: int | None = None
    for node_id, ep in entry_points.items():
        ep_file = os.path.normpath(ep.file_path).replace("\\", "/").lower()
        if ep_file != norm:
            continue
        if ep.start_line <= line <= ep.end_line:
            span = ep.end_line - ep.start_line
            if best_span is None or span < best_span:
                best_span = span
                best_id = node_id
    return best_id


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
        auto_links: bool = False,
        entrypoints_dir: str | None = None,
    ) -> None:
        self._config = config
        self._logger = logger
        self._model_name = model_name
        self._temperature = temperature
        self._max_query_num = max_query_num
        self._use_llm = use_llm
        self._output_dir = os.path.abspath(output_dir)
        self._graph_format = graph_format
        #: Авто-режим связывания: перебор всех пар репозиториев без связей
        #: из конфига (включается флагом или при пустом списке связей).
        self._auto_links = auto_links
        #: Каталог с проверенными точками входа (JSON): этап нахождения
        #: точек входа внутри репозиториев пропускается.
        self._entrypoints_dir = os.path.abspath(entrypoints_dir) if entrypoints_dir else None

        self._bidirectional = _env_flag("CROSS_REPO_BIDIRECTIONAL", True)
        self._confirm_links = _env_flag("CROSS_REPO_CONFIRM_LINKS", True)

    # ------------------------------------------------------------------

    def scan(self) -> ProjectScanResult:
        """Выполнить полный кросс-репозиторный анализ."""
        os.makedirs(self._output_dir, exist_ok=True)

        self._logger.print_console(
            f"Мульти-репозиторное сканирование: {self._config.project}"
        )

        repo_results: list[RepoScanResult]
        if self._entrypoints_dir:
            # Точки входа уже проверены — загружаем их из JSON
            self._logger.print_console(
                "Загрузка проверенных точек входа (этап нахождения пропущен)"
            )
            repo_results = load_repo_scan_results(
                self._config, self._entrypoints_dir, self._logger
            )
        else:
            repo_results = []
            for repo in self._config.repos:
                repo_results.append(self._scan_repo(repo))

        # Связывание эндпоинтов между репозиториями
        repo_interfaces = {r.repo.name: self._repo_interfaces(r) for r in repo_results}
        linker = CrossRepoLinker(self._config, bidirectional=self._bidirectional)

        if self._config.links_authoritative and self._config.links and not self._auto_links:
            # Связи заданы архитектором — не верифицируем, а сопоставляем эндпоинты
            edges = linker.find_authoritative_links(repo_interfaces)
            self._logger.print_console(f"  Связей по архитектурному конфигу: {len(edges)}")
        elif self._auto_links or not self._config.links:
            # Авто-режим: связей в конфиге нет (или они игнорируются) —
            # ищем обращения ко всем серверным эндпоинтам всех пар
            edges = linker.find_auto_links(repo_interfaces)
            self._logger.print_console(f"  Найдено кандидатов связей (авто-перебор): {len(edges)}")

            edges = self._confirm_edges_batch(edges)
        else:
            edges = linker.find_links(repo_interfaces)
            self._logger.print_console(f"  Найдено кандидатов связей: {len(edges)}")

            edges = self._confirm_edges_batch(edges)

        # Сопоставление клиентских функций для достижимости.
        # Без графа вызовов (пересборка из JSON) узел резолвится по точкам входа.
        for edge in edges:
            if edge.client_node_id:
                continue
            client_graph = self._graph_for(repo_results, edge.client_repo)
            if client_graph is not None:
                node_id = _resolve_node(client_graph, edge.client_file, edge.client_line)
                if node_id:
                    edge.client_node_id = node_id
                    edge.client_function_name = _node_names(client_graph).get(node_id, "")
            else:
                node_id = _resolve_node_eps(
                    self._entry_points_for(repo_results, edge.client_repo),
                    edge.client_file,
                    edge.client_line,
                )
                if node_id:
                    edge.client_node_id = node_id
                    edge.client_function_name = self._entry_points_for(
                        repo_results, edge.client_repo
                    )[node_id].function_name

        # Чекпойнт: подтверждённые (или доверенные) межрепо связи
        cross_edges_path = self._save_cross_edges(edges)
        self._logger.print_console(f"  Подтверждённые связи: {cross_edges_path}")

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

    def _save_repo_checkpoint(
        self,
        repo: RepoConfig,
        language: str,
        entry_points: dict[str, EntryPointInfo],
        interfaces: dict[str, InterfaceDescriptor],
    ) -> str:
        """Сохранить промежуточный результат сканирования репозитория.

        Файл ``repos/<имя>_entry_points.json`` пишется на каждом этапе
        (до и после LLM-валидации), чтобы при прерывании анализа можно
        было продолжить с ``--entrypoints-dir``.

        :return: абсолютный путь к файлу.
        """
        repos_dir = os.path.join(self._output_dir, "repos")
        os.makedirs(repos_dir, exist_ok=True)
        path = os.path.join(repos_dir, f"{repo.name}_entry_points.json")
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(
                _repo_checkpoint_dict(repo, language, entry_points, interfaces),
                fh,
                indent=2,
                ensure_ascii=False,
            )
        return path

    def _save_cross_edges(self, edges: list[CrossRepoEdge]) -> str:
        """Сохранить подтверждённые межрепо связи как промежуточный результат."""
        path = os.path.join(self._output_dir, "cross_edges.json")
        with open(path, "w", encoding="utf-8") as fh:
            json.dump([e.to_dict() for e in edges], fh, indent=2, ensure_ascii=False)
        return path

    def _confirm_edges_batch(self, edges: list[CrossRepoEdge]) -> list[CrossRepoEdge]:
        """Подтвердить кандидатов связей батчами (или без LLM)."""
        if not (self._use_llm and self._confirm_links and edges):
            return edges
        batch_size = max(1, _env_int("LINK_BATCH_SIZE", 10))
        validator = LinkBatchValidatorLLM(
            self._model_name, self._temperature, "multi", self._max_query_num, self._logger
        )
        edges = confirm_edges_batch(validator, edges, batch_size)
        self._logger.print_console(f"  Подтверждено связей: {len(edges)}")
        return edges

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

        # Чекпойнт: статически найденные точки входа (до LLM-валидации) —
        # позволяет продолжить анализ при прерывании на валидации
        self._save_repo_checkpoint(repo, language, entry_points, {})

        interfaces = self._analyze_interfaces(repo, language, entry_points)

        # Чекпойнт: верифицированные точки входа и интерфейсы — готовы
        # к пересборке через --entrypoints-dir без повторной валидации
        self._save_repo_checkpoint(repo, language, entry_points, interfaces)

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
        """Список интерфейсных эндпоинтов репозитория для линкера.

        Учитываются только валидированные точки входа (``is_entry_point``),
        у которых определён интерфейс связи: невалидные точки отсекаются
        до процесса стыковки.
        """
        items: list[dict[str, Any]] = []
        for node_id, ep in result.entry_points.items():
            desc = result.interfaces.get(node_id)
            if desc is None or not desc.is_entry_point or not desc.has_interface():
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

    @staticmethod
    def _entry_points_for(
        repo_results: list[RepoScanResult], repo_name: str
    ) -> dict[str, EntryPointInfo]:
        """Точки входа репозитория по имени (пусто, если репозиторий не найден)."""
        for result in repo_results:
            if result.repo.name == repo_name:
                return result.entry_points
        return {}

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
            if result.graph is not None:
                names = _node_names(result.graph)
                for node_id, name in names.items():
                    node_names[(result.repo.name, node_id)] = name
                for src, dst in _call_edges(result.graph):
                    call_edges.append((result.repo.name, src, dst))
            # Без графа (пересборка из JSON) имена берутся из точек входа
            for node_id, ep in result.entry_points.items():
                node_names.setdefault((result.repo.name, node_id), ep.function_name)
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
                json.dump(
                    _repo_checkpoint_dict(
                        repo_result.repo,
                        repo_result.language,
                        repo_result.entry_points,
                        repo_result.interfaces,
                    ),
                    fh,
                    indent=2,
                    ensure_ascii=False,
                )

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
