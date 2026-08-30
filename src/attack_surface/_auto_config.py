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

from attack_surface._linker import _EXCLUDED_DIRS
from attack_surface._project_config import ProjectConfig, RepoConfig


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

def discover_repositories(root: str) -> list[RepoConfig]:
    """Обнаружить репозитории как подкаталоги первого уровня.

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


# ---------------------------------------------------------------------------
# Формирование и сохранение конфига
# ---------------------------------------------------------------------------

def build_auto_config(
    root: str,
    project_name: str = "",
    *,
    threagile: bool = False,
) -> ProjectConfig:
    """Составить ProjectConfig по корневому каталогу проекта.

    :param root: корневой каталог, содержащий подкаталоги-репозитории
    :param project_name: имя проекта (по умолчанию — имя корневого каталога)
    :param threagile: True — связи будут трактоваться как доверенные
        (семантика архитектурного файла Threagile)
    :raises ValueError: если корневой каталог не существует или в нём
        не обнаружено ни одного репозитория
    """
    root = os.path.abspath(root)
    if not os.path.isdir(root):
        raise ValueError(f"Каталог проекта не найден: {root}")

    repos = discover_repositories(root)
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
