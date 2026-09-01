"""Автосоставление конфигурации мульти-репозиторного проекта.

Если конфигурационного файла нет (``project --project-path <корень>``),
репозитории обнаруживаются как подкаталоги первого уровня корневого
каталога, язык каждого определяется по файловым маркерам, после чего
формируется ``ProjectConfig``. Формат сохраняемого конфига — наш JSON
или архитектурный YAML Threagile — выбирается на стороне CLI.

Модуль обособлен: автодетект состава проекта можно отключить или
дорабатывать независимо от остального анализа.
"""

from __future__ import annotations

import json
import os

from attack_surface._env import flag as env_flag
from attack_surface._env import int_value as env_int
from attack_surface._linker import _EXCLUDED_DIRS
from attack_surface._project_config import ProjectConfig, RepoConfig


# ---------------------------------------------------------------------------
# Режим обнаружения репозиториев
# ---------------------------------------------------------------------------

#: Искать репозитории по наличию ``.git`` (иначе — по подкаталогам с кодом)
GIT_SUPPORT_DEFAULT = True
#: Максимальная глубина поиска ``.git`` от корня проекта
GIT_DEPTH_DEFAULT = 3


def _git_support() -> bool:
    """Флаг GIT_SUPPORT: репозиториями считаются каталоги с .git."""
    return env_flag("GIT_SUPPORT", GIT_SUPPORT_DEFAULT)


def _git_depth() -> int:
    """Максимальная глубина поиска .git (GIT_DEPTH)."""
    return max(1, env_int("GIT_DEPTH", GIT_DEPTH_DEFAULT))


def _has_git_marker(path: str) -> bool:
    """Содержит ли каталог маркер git-репозитория.

    В обычном репозитории ``.git`` — каталог, в субмодуле — файл-указатель.
    """
    git = os.path.join(path, ".git")
    return os.path.isdir(git) or os.path.isfile(git)


# ---------------------------------------------------------------------------
# Определение языка репозитория
# ---------------------------------------------------------------------------

# Явные маркеры: имя файла → язык. Проверяются в порядке приоритета —
# tsconfig.json важнее package.json, go.mod важнее *.go и т.п.
_LANGUAGE_MARKERS: tuple[tuple[str, str], ...] = (
    ("go.mod", "go"),
    ("tsconfig.json", "typescript"),
    ("pom.xml", "java"),
    ("build.gradle.kts", "java"),
    ("build.gradle", "java"),
    ("CMakeLists.txt", "cpp"),
    ("package.json", "javascript"),
)

# Маркеры-расширения (по имени файла целиком, а не по суффиксу)
_SUFFIX_MARKERS: tuple[tuple[str, str], ...] = (
    (".csproj", "c_sharp"),
    (".sln", "c_sharp"),
)

# Расширения исходников → язык (для мажоритарного определения)
_EXTENSION_LANGUAGE: dict[str, str] = {
    ".py": "python",
    ".ts": "typescript",
    ".tsx": "typescript",
    ".js": "javascript",
    ".jsx": "javascript",
    ".go": "go",
    ".java": "java",
    ".cs": "c_sharp",
    ".cpp": "cpp",
    ".cc": "cpp",
    ".cxx": "cpp",
    ".hpp": "cpp",
    ".c": "c",
    ".h": "c",
}

# Глубина обхода при поиске маркеров (уровни от корня репозитория)
_MAX_MARKER_DEPTH = 3


def _iter_source_files(root: str) -> list[str]:
    """Собрать файлы репозитория верхних уровней, исключая служебные каталоги."""
    files: list[str] = []
    for dirpath, dirnames, filenames in os.walk(root):
        depth = dirpath[len(root):].count(os.sep)
        dirnames[:] = [d for d in dirnames if d not in _EXCLUDED_DIRS]
        if depth >= _MAX_MARKER_DEPTH:
            dirnames[:] = []
        for filename in filenames:
            files.append(os.path.join(dirpath, filename))
    return files


def detect_language(root: str) -> str:
    """Определить основной язык репозитория по файловым маркерам.

    Сначала ищутся явные маркеры (go.mod, tsconfig.json, *.csproj и т.п.),
    затем — мажоритарное расширение исходных файлов. Если язык не
    определяется, возвращается пустая строка.
    """
    files = _iter_source_files(root)
    if not files:
        return ""

    # 1) Явные маркеры
    for filename, language in _LANGUAGE_MARKERS:
        for path in files:
            if os.path.basename(path) == filename:
                return language
    for suffix, language in _SUFFIX_MARKERS:
        for path in files:
            if path.endswith(suffix):
                return language

    # 2) Мажоритарное расширение (с учётом приоритета C++ над C)
    counts: dict[str, int] = {}
    for path in files:
        ext = os.path.splitext(path)[1].lower()
        language = _EXTENSION_LANGUAGE.get(ext)
        if language:
            counts[language] = counts.get(language, 0) + 1
    if not counts:
        return ""
    return max(counts, key=lambda lang: (counts[lang], _EXTENSION_PRIORITY.get(lang, 0)))


# Приоритет при равенстве счётчиков: cpp важнее c (файлы .h могут быть общими)
_EXTENSION_PRIORITY: dict[str, int] = {"cpp": 1}


# ---------------------------------------------------------------------------
# Обнаружение репозиториев
# ---------------------------------------------------------------------------

def discover_repositories(
    root: str,
    *,
    git_support: bool | None = None,
    git_depth: int | None = None,
) -> list[RepoConfig]:
    """Обнаружить репозитории в корневом каталоге проекта.

    При ``git_support=True`` (по умолчанию) репозиторием считается только
    каталог с маркером ``.git``, поиск ведётся на глубину ``git_depth``
    (``GIT_DEPTH``) без спуска внутрь найденных репозиториев. При
    ``git_support=False`` — прежнее поведение: подкаталоги первого уровня
    с определяемым языком.

    :param git_support: переопределяет флаг окружения ``GIT_SUPPORT``
    :param git_depth: переопределяет глубину окружения ``GIT_DEPTH``
    """
    if git_support is None:
        git_support = _git_support()
    if git_support:
        return _discover_by_git(root, git_depth)
    return _discover_by_language(root)


def _discover_by_language(root: str) -> list[RepoConfig]:
    """Подкаталоги первого уровня с определяемым языком.

    Каталоги без определяемого языка (docs, assets и т.п.) пропускаются.
    """
    repos: list[RepoConfig] = []
    for entry in sorted(os.listdir(root)):
        if entry.startswith(".") or entry in _EXCLUDED_DIRS:
            continue
        path = os.path.join(root, entry)
        if not os.path.isdir(path):
            continue
        language = detect_language(path)
        if not language:
            continue
        repos.append(RepoConfig(name=entry, path=path, language=language, role=""))
    return repos


def _discover_by_git(root: str, git_depth: int | None) -> list[RepoConfig]:
    """Репозитории — каталоги с маркером ``.git``.

    Если маркер есть в самом корне, корень считается единственным
    репозиторием. Иначе поиск идёт на глубину ``git_depth``; внутрь
    найденных репозиториев не спускаемся (вложенные репозитории
    не учитываются).
    """
    if git_depth is None:
        git_depth = _git_depth()
    root = os.path.abspath(root)

    if _has_git_marker(root):
        return [
            RepoConfig(
                name=os.path.basename(root.rstrip(os.sep)) or "project",
                path=root,
                language=detect_language(root),
                role="",
            )
        ]

    repos: list[RepoConfig] = []
    stack: list[tuple[str, int]] = [(root, 0)]
    while stack:
        current, depth = stack.pop()
        if depth >= git_depth:
            continue
        try:
            entries = sorted(os.listdir(current))
        except OSError:
            continue
        for entry in entries:
            if entry.startswith(".") or entry in _EXCLUDED_DIRS:
                continue
            path = os.path.join(current, entry)
            if not os.path.isdir(path):
                continue
            if _has_git_marker(path):
                repos.append(
                    RepoConfig(
                        name=entry,
                        path=path,
                        language=detect_language(path),
                        role="",
                    )
                )
            else:
                stack.append((path, depth + 1))
    repos.sort(key=lambda r: r.name)
    return repos


# ---------------------------------------------------------------------------
# Формирование и сохранение конфига
# ---------------------------------------------------------------------------

def build_auto_config(
    root: str,
    project_name: str = "",
    *,
    threagile: bool = False,
    git_support: bool | None = None,
    git_depth: int | None = None,
) -> ProjectConfig:
    """Составить ProjectConfig по корневому каталогу проекта.

    :param root: корневой каталог, содержащий подкаталоги-репозитории
    :param project_name: имя проекта (по умолчанию — имя корневого каталога)
    :param threagile: True — связи будут трактоваться как доверенные
        (семантика архитектурного файла Threagile)
    :param git_support: режим обнаружения по ``.git`` (см. discover_repositories)
    :param git_depth: глубина поиска ``.git`` (см. discover_repositories)
    :raises ValueError: если корневой каталог не существует или в нём
        не обнаружено ни одного репозитория
    """
    root = os.path.abspath(root)
    if not os.path.isdir(root):
        raise ValueError(f"Каталог проекта не найден: {root}")

    repos = discover_repositories(root, git_support=git_support, git_depth=git_depth)
    if not repos:
        raise ValueError(
            f"Не удалось обнаружить репозитории в каталоге: {root}"
        )

    project = (
        project_name.strip()
        or os.path.basename(root.rstrip(os.sep))
        or "project"
    )
    return ProjectConfig(
        project=project,
        repos=repos,
        links=[],
        base_dir=root,
        links_authoritative=threagile,
    )


def save_auto_config(config: ProjectConfig, output_dir: str, fmt: str) -> str:
    """Сохранить автосоставленный конфиг в JSON или YAML Threagile.

    :return: абсолютный путь к созданному файлу.
    """
    from attack_surface._threagile import dump_threagile

    output_dir = os.path.abspath(output_dir)
    os.makedirs(output_dir, exist_ok=True)

    if fmt == "threagile":
        path = os.path.join(output_dir, f"{config.project}.auto.yaml")
        content = dump_threagile(config)
    else:
        path = os.path.join(output_dir, f"{config.project}.auto.json")
        content = json.dumps(config.to_dict(), indent=2, ensure_ascii=False)

    with open(path, "w", encoding="utf-8") as fh:
        fh.write(content)
    return path
