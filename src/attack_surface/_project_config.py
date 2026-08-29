"""Конфигурация мульти-репозиторного проекта (формат JSON).

Описывает репозитории, входящие в проект, их роли и связи между ними.
Загрузка и валидация вынесены в отдельный модуль, чтобы функционал
кросс-репозиторного анализа был обособлен от одиночного сканирования
и мог быть отключён или доработан независимо.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from enum import Enum
from typing import Any


# ---------------------------------------------------------------------------
# Типы связей между репозиториями
# ---------------------------------------------------------------------------

class LinkType(str, Enum):
    """Тип связи между репозиториями.

    Словарь типов — это семьи взаимодействия, покрывающие все протоколы
    Threagile (см. ``_threagile.THREAGILE_PROTOCOLS`` и таблицу маппинга
    в README). Новые семьи добавлены по протоколам архитектурного файла
    Threagile, чтобы при сращивании репозиториев были доступны все
    варианты взаимодействия, которые допускает архитектор.
    """

    HTTP = "http"
    GRPC = "grpc"
    WEBSOCKET = "websocket"
    SHARED_DB = "shared-db"
    FFI = "ffi"
    PINVOKE = "pinvoke"
    MESSAGE_QUEUE = "message-queue"
    RPC = "rpc"
    FILE = "file"
    # Семьи протоколов Threagile
    REVERSE_PROXY = "reverse-proxy"
    EMAIL = "email"
    SSH = "ssh"
    FTP = "ftp"
    LDAP = "ldap"
    BINARY = "binary"
    TEXT = "text"
    IPC = "ipc"
    CONTAINER = "container"
    NFS = "nfs"


VALID_LINK_TYPES: frozenset[str] = frozenset(t.value for t in LinkType)


# Синонимы имён языков (как в конфиге) → имена trailmark
LANGUAGE_ALIASES: dict[str, str] = {
    "python": "python",
    "py": "python",
    "cpp": "cpp",
    "c++": "cpp",
    "c": "c",
    "go": "go",
    "golang": "go",
    "java": "java",
    "javascript": "javascript",
    "js": "javascript",
    "typescript": "typescript",
    "ts": "typescript",
    "csharp": "c_sharp",
    "c#": "c_sharp",
    "c_sharp": "c_sharp",
}


def normalize_language(name: str) -> str:
    """Привести имя языка из конфига к имени, понятному trailmark."""
    return LANGUAGE_ALIASES.get(name.strip().lower(), name.strip().lower())


# ---------------------------------------------------------------------------
# Модели
# ---------------------------------------------------------------------------

@dataclass
class RepoConfig:
    """Описание одного репозитория проекта."""

    name: str
    path: str
    language: str
    role: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "path": self.path,
            "language": self.language,
            "role": self.role,
        }


@dataclass
class LinkConfig:
    """Связь между двумя репозиториями."""

    from_repo: str
    to_repo: str
    type: str = LinkType.HTTP.value

    def to_dict(self) -> dict[str, Any]:
        return {"from": self.from_repo, "to": self.to_repo, "type": self.type}


@dataclass
class ProjectConfig:
    """Разобранная и провалидированная конфигурация проекта."""

    project: str
    repos: list[RepoConfig] = field(default_factory=list)
    links: list[LinkConfig] = field(default_factory=list)
    base_dir: str = ""
    #: True — связи заданы архитектором (например, из Threagile) и считаются
    #: доверенными: их не нужно верифицировать, а лишь сопоставить с эндпоинтами.
    links_authoritative: bool = False

    def repo_names(self) -> set[str]:
        """Множество имён репозиториев."""
        return {r.name for r in self.repos}

    def get_repo(self, name: str) -> RepoConfig | None:
        """Найти репозиторий по имени."""
        for repo in self.repos:
            if repo.name == name:
                return repo
        return None

    def to_dict(self) -> dict[str, Any]:
        return {
            "project": self.project,
            "repos": [r.to_dict() for r in self.repos],
            "links": [l.to_dict() for l in self.links],
            "links_authoritative": self.links_authoritative,
        }


# ---------------------------------------------------------------------------
# Загрузка и валидация
# ---------------------------------------------------------------------------

def load_project_config(path: str) -> ProjectConfig:
    """Загрузить и провалидировать конфигурацию проекта из JSON.

    :param path: путь к JSON-файлу конфигурации
    :raises ValueError: при неверной структуре или несуществующих путях
    """
    path = os.path.abspath(path)
    if not os.path.isfile(path):
        raise ValueError(f"Файл конфигурации не найден: {path}")

    with open(path, "r", encoding="utf-8") as fh:
        raw = json.load(fh)

    if not isinstance(raw, dict):
        raise ValueError("Конфигурация должна быть JSON-объектом")

    project = str(raw.get("project", "")).strip()
    if not project:
        raise ValueError("Конфигурация должна содержать непустое поле 'project'")

    base_dir = os.path.dirname(path)

    repos = _parse_repos(raw.get("repos", []), base_dir)
    repo_names = {r.name for r in repos}
    links = _parse_links(raw.get("links", []), repo_names)

    return ProjectConfig(project=project, repos=repos, links=links, base_dir=base_dir)


def _parse_repos(raw_repos: Any, base_dir: str) -> list[RepoConfig]:
    if not isinstance(raw_repos, list) or not raw_repos:
        raise ValueError("Конфигурация должна содержать непустой список 'repos'")

    repos: list[RepoConfig] = []
    seen_names: set[str] = set()
    for item in raw_repos:
        if not isinstance(item, dict):
            raise ValueError("Каждый репозиторий должен быть JSON-объектом")

        name = str(item.get("name", "")).strip()
        if not name:
            raise ValueError("Каждый репозиторий должен иметь поле 'name'")
        if name in seen_names:
            raise ValueError(f"Дублирующееся имя репозитория: {name}")
        seen_names.add(name)

        raw_path = str(item.get("path", "")).strip()
        if not raw_path:
            raise ValueError(f"Репозиторий '{name}' должен иметь поле 'path'")
        resolved = raw_path if os.path.isabs(raw_path) else os.path.normpath(
            os.path.join(base_dir, raw_path)
        )
        if not os.path.isdir(resolved):
            raise ValueError(f"Каталог репозитория '{name}' не найден: {resolved}")

        raw_lang = str(item.get("language", "")).strip()
        if not raw_lang:
            raise ValueError(f"Репозиторий '{name}' должен иметь поле 'language'")

        repos.append(
            RepoConfig(
                name=name,
                path=resolved,
                language=normalize_language(raw_lang),
                role=str(item.get("role", "")).strip(),
            )
        )
    return repos


def _parse_links(raw_links: Any, repo_names: set[str]) -> list[LinkConfig]:
    if raw_links is None:
        return []
    if not isinstance(raw_links, list):
        raise ValueError("Поле 'links' должно быть списком")

    links: list[LinkConfig] = []
    for item in raw_links:
        if not isinstance(item, dict):
            raise ValueError("Каждая связь должна быть JSON-объектом")

        from_repo = str(item.get("from", "")).strip()
        to_repo = str(item.get("to", "")).strip()
        if from_repo not in repo_names:
            raise ValueError(f"Связь 'from' ссылается на неизвестный репозиторий: {from_repo}")
        if to_repo not in repo_names:
            raise ValueError(f"Связь 'to' ссылается на неизвестный репозиторий: {to_repo}")
        if from_repo == to_repo:
            raise ValueError(f"Связь не может замыкаться на сам репозиторий: {from_repo}")

        link_type = str(item.get("type", "")).strip()
        if link_type not in VALID_LINK_TYPES:
            raise ValueError(
                f"Неизвестный тип связи '{link_type}' "
                f"(допустимые: {', '.join(sorted(VALID_LINK_TYPES))})"
            )

        links.append(LinkConfig(from_repo=from_repo, to_repo=to_repo, type=link_type))
    return links
