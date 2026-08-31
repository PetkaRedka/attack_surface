"""Поддержка архитектурных файлов Threagile (YAML).

Threagile — инструмент моделирования угроз, в котором архитектор описывает
компоненты (``technical_assets``) и взаимосвязи между ними (``data_flows``)
с указанием протокола. Модуль позволяет:

1. Генерировать ``threagile.yaml`` из ``ProjectConfig`` — переводит репозитории
   в ``technical_assets``, а связи в ``data_flows`` (в рамках доступных полей);
2. Читать ``threagile.yaml`` и преобразовывать его в ``ProjectConfig``, при этом
   связи из ``data_flows`` считаются доверенными (заданы архитектором) и не
   требуют самостоятельной верификации.
"""

from __future__ import annotations

import os
from datetime import date
from typing import Any

import yaml  # type: ignore

from attack_surface._project_config import (
    LinkConfig,
    LinkType,
    ProjectConfig,
    RepoConfig,
    normalize_language,
)


# ---------------------------------------------------------------------------
# Маппинги
# ---------------------------------------------------------------------------

# Язык trailmark → технология Threagile
LANGUAGE_TO_TECHNOLOGY: dict[str, str] = {
    "python": "python",
    "javascript": "javascript",
    "typescript": "typescript",
    "java": "java",
    "go": "go",
    "c": "c",
    "cpp": "cpp",
    "c_sharp": "c-sharp",
}

# Технология Threagile → язык trailmark
TECHNOLOGY_TO_LANGUAGE: dict[str, str] = {
    "python": "python",
    "javascript": "javascript",
    "js": "javascript",
    "typescript": "typescript",
    "ts": "typescript",
    "java": "java",
    "go": "go",
    "golang": "go",
    "c": "c",
    "cpp": "cpp",
    "c++": "cpp",
    "c-sharp": "c_sharp",
    "csharp": "c_sharp",
    "c#": "c_sharp",
}

# Полный перечень допустимых значений ``protocol`` в файле архитектуры
# Threagile (48 значений). Выверен по первоисточнику:
#   https://github.com/Threagile/threagile/blob/master/pkg/types/protocol.go
# (значения дублируются в support/schema.json для валидации в IDE).
THREAGILE_PROTOCOLS: frozenset[str] = frozenset(
    {
        # Базовые
        "unknown-protocol", "http", "https", "ws", "wss",
        "reverse-proxy-web-protocol", "reverse-proxy-web-protocol-encrypted",
        # Базы данных
        "jdbc", "jdbc-encrypted", "odbc", "odbc-encrypted",
        "sql-access-protocol", "sql-access-protocol-encrypted",
        "nosql-access-protocol", "nosql-access-protocol-encrypted",
        # Потоковые / бинарные
        "binary", "binary-encrypted", "text", "text-encrypted",
        "mqtt", "jms", "xmpp",
        # Удалённый доступ и передача файлов
        "ssh", "ssh-tunnel", "sftp", "scp", "ftp", "ftps",
        # Почта
        "smtp", "smtp-encrypted", "pop3", "pop3-encrypted",
        "imap", "imap-encrypted",
        # Каталоги
        "ldap", "ldaps",
        # Файловые системы
        "nfs", "smb", "smb-encrypted", "local-file-access",
        # Локальные вызовы и процессы
        "in-process-library-call", "inter-process-communication",
        "container-spawning",
        # Прочие
        "nrpe", "iiop", "iiop-encrypted", "jrmp", "jrmp-encrypted",
    }
)

# Тип связи → протокол Threagile (только допустимые значения Threagile).
# Для шифруемых протоколов по умолчанию берётся шифрованный вариант
# (https/wss/ftps/ldaps) — консервативный выбор для модели угроз.
LINK_TYPE_TO_PROTOCOL: dict[str, str] = {
    "http": "https",
    # В Threagile нет gRPC — он работает поверх HTTP/2, поэтому используем https
    "grpc": "https",
    "websocket": "wss",
    "shared-db": "sql-access-protocol",
    "ffi": "in-process-library-call",
    "pinvoke": "in-process-library-call",
    "message-queue": "mqtt",
    "rpc": "unknown-protocol",
    "file": "local-file-access",
    "reverse-proxy": "reverse-proxy-web-protocol-encrypted",
    "email": "smtp-encrypted",
    "ssh": "ssh",
    "ftp": "ftps",
    "ldap": "ldaps",
    "binary": "binary",
    "text": "text",
    "ipc": "inter-process-communication",
    "container": "container-spawning",
    "nfs": "nfs",
}

# Протокол Threagile → тип связи. Покрывает все 48 допустимых значений
# плюс легаси-алиасы из старых конфигов (grpc, rest, amqp, kafka, sql),
# которые не являются значениями Threagile, но встречаются в существующих
# проектах и не должны ломать загрузку.
PROTOCOL_TO_LINK_TYPE: dict[str, str] = {
    # Базовые
    "unknown-protocol": "rpc",
    "http": "http",
    "https": "http",
    "ws": "websocket",
    "wss": "websocket",
    "reverse-proxy-web-protocol": "reverse-proxy",
    "reverse-proxy-web-protocol-encrypted": "reverse-proxy",
    # Базы данных
    "jdbc": "shared-db",
    "jdbc-encrypted": "shared-db",
    "odbc": "shared-db",
    "odbc-encrypted": "shared-db",
    "sql-access-protocol": "shared-db",
    "sql-access-protocol-encrypted": "shared-db",
    "nosql-access-protocol": "shared-db",
    "nosql-access-protocol-encrypted": "shared-db",
    # Потоковые / бинарные
    "binary": "binary",
    "binary-encrypted": "binary",
    "text": "text",
    "text-encrypted": "text",
    "mqtt": "message-queue",
    "jms": "message-queue",
    "xmpp": "text",
    # Удалённый доступ и передача файлов
    "ssh": "ssh",
    "ssh-tunnel": "ssh",
    "sftp": "ftp",
    "scp": "ssh",
    "ftp": "ftp",
    "ftps": "ftp",
    # Почта
    "smtp": "email",
    "smtp-encrypted": "email",
    "pop3": "email",
    "pop3-encrypted": "email",
    "imap": "email",
    "imap-encrypted": "email",
    # Каталоги
    "ldap": "ldap",
    "ldaps": "ldap",
    # Файловые системы
    "nfs": "nfs",
    "smb": "nfs",
    "smb-encrypted": "nfs",
    "local-file-access": "file",
    # Локальные вызовы и процессы
    "in-process-library-call": "ffi",
    "inter-process-communication": "ipc",
    "container-spawning": "container",
    # Прочие
    "nrpe": "rpc",
    "iiop": "rpc",
    "iiop-encrypted": "rpc",
    "jrmp": "rpc",
    "jrmp-encrypted": "rpc",
    # Легаси-алиасы (не являются значениями Threagile)
    "rest": "http",
    "grpc": "grpc",
    "grpc-web": "grpc",
    "amqp": "message-queue",
    "kafka": "message-queue",
    "sql": "shared-db",
}


def technology_for_language(language: str) -> str:
    """Язык trailmark → технология Threagile."""
    return LANGUAGE_TO_TECHNOLOGY.get(language, language)


def language_for_technology(technology: str) -> str:
    """Технология Threagile → язык trailmark."""
    return TECHNOLOGY_TO_LANGUAGE.get(
        (technology or "").strip().lower(),
        normalize_language(technology or ""),
    )


def protocol_for_link_type(link_type: str) -> str:
    """Тип связи → протокол Threagile."""
    return LINK_TYPE_TO_PROTOCOL.get(link_type, "unknown-protocol")


def link_type_for_protocol(protocol: str) -> str:
    """Протокол Threagile → тип связи."""
    return PROTOCOL_TO_LINK_TYPE.get(
        (protocol or "").strip().lower(),
        LinkType.RPC.value,
    )


# ---------------------------------------------------------------------------
# Чтение Threagile
# ---------------------------------------------------------------------------

def load_threagile(path: str) -> ProjectConfig:
    """Загрузить архитектурный файл Threagile и преобразовать в ProjectConfig.

    ``technical_assets`` становятся репозиториями (``id`` → имя репозитория,
    каталог резолвится относительно расположения файла), ``data_flows`` —
    связями. Связи считаются доверенными (``links_authoritative=True``).
    """
    path = os.path.abspath(path)
    if not os.path.isfile(path):
        raise ValueError(f"Файл Threagile не найден: {path}")

    with open(path, encoding="utf-8") as fh:
        data = yaml.safe_load(fh) or {}
    if not isinstance(data, dict):
        raise ValueError("Threagile-файл должен быть YAML-объектом")

    base_dir = os.path.dirname(path)
    project = str(data.get("title") or os.path.splitext(os.path.basename(path))[0]).strip()

    repos: list[RepoConfig] = []
    for asset in data.get("technical_assets", []) or []:
        if not isinstance(asset, dict):
            continue
        name = str(asset.get("id", "")).strip()
        if not name:
            continue
        technology = str(asset.get("technology", "")).strip()
        role = str(asset.get("description", "")).strip() or str(asset.get("type", "")).strip()
        repos.append(
            RepoConfig(
                name=name,
                path=os.path.join(base_dir, name),
                language=language_for_technology(technology),
                role=role,
            )
        )

    repo_names = {r.name for r in repos}
    links: list[LinkConfig] = []
    for flow in data.get("data_flows", []) or []:
        if not isinstance(flow, dict):
            continue
        from_repo = str(flow.get("source", "")).strip()
        to_repo = str(flow.get("target", "")).strip()
        if from_repo not in repo_names or to_repo not in repo_names:
            continue
        if from_repo == to_repo:
            continue
        links.append(
            LinkConfig(
                from_repo=from_repo,
                to_repo=to_repo,
                type=link_type_for_protocol(str(flow.get("protocol", ""))),
            )
        )

    return ProjectConfig(
        project=project,
        repos=repos,
        links=links,
        base_dir=base_dir,
        links_authoritative=True,
    )


# ---------------------------------------------------------------------------
# Генерация Threagile
# ---------------------------------------------------------------------------

def build_threagile_model(config: ProjectConfig) -> dict[str, Any]:
    """Построить модель Threagile из ProjectConfig (в рамках доступных полей)."""
    assets: list[dict[str, Any]] = []
    for repo in config.repos:
        assets.append(
            {
                "id": repo.name,
                "description": repo.role or repo.name,
                "type": "process",
                "technology": technology_for_language(repo.language),
                "tags": [],
            }
        )

    flows: list[dict[str, Any]] = []
    for index, link in enumerate(config.links, 1):
        flows.append(
            {
                "id": f"flow-{index}",
                "description": f"{link.from_repo} → {link.to_repo} ({link.type})",
                "source": link.from_repo,
                "target": link.to_repo,
                "protocol": protocol_for_link_type(link.type),
                "tags": [],
            }
        )

    return {
        "threagile_version": "1.0",
        "title": config.project,
        "date": date.today().isoformat(),
        "author": {"name": "", "homepage": ""},
        "technical_overview": {"description": ""},
        "data_assets": [],
        "technical_assets": assets,
        "trust_boundaries": [],
        "shared_runtimes": [],
        "data_flows": flows,
    }


def dump_threagile(config: ProjectConfig) -> str:
    """Сериализовать ProjectConfig в YAML-строку Threagile."""
    return yaml.safe_dump(
        build_threagile_model(config),
        sort_keys=False,
        allow_unicode=True,
    )


def save_threagile(config: ProjectConfig, output_path: str) -> str:
    """Сохранить ProjectConfig в файл Threagile (YAML).

    :return: абсолютный путь к созданному файлу.
    """
    output_path = os.path.abspath(output_path)
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as fh:
        fh.write(dump_threagile(config))
    return output_path


def update_threagile_data_flows(
    config: ProjectConfig,
    edges: list[Any],
    output_path: str,
) -> str:
    """Дополнить ``data_flows`` архитектурного файла найденными связями.

    Автосоставленный Threagile-файл создаётся до анализа с пустыми
    ``data_flows``; после линковки найденные связи записываются в него,
    чтобы архитектор видел реальные взаимодействия. Существующие потоки
    сохраняются, дубликаты по паре ``(source, target, protocol)``
    исключаются.

    :param edges: подтверждённые межрепо связи (``CrossRepoEdge``).
    :return: абсолютный путь к обновлённому файлу.
    """
    output_path = os.path.abspath(output_path)
    with open(output_path, encoding="utf-8") as fh:
        data = yaml.safe_load(fh) or {}
    if not isinstance(data, dict):
        raise ValueError(f"Некорректный Threagile-файл: {output_path}")

    flows: list[dict[str, Any]] = list(data.get("data_flows") or [])
    by_key: dict[tuple[str, str, str], dict[str, Any]] = {}
    for flow in flows:
        if isinstance(flow, dict):
            key = (
                str(flow.get("source", "")),
                str(flow.get("target", "")),
                str(flow.get("protocol", "")),
            )
            by_key[key] = flow

    for edge in edges:
        link = getattr(edge, "link", None)
        if link is None:
            continue
        protocol = protocol_for_link_type(link.type)
        key = (link.from_repo, link.to_repo, protocol)
        if key in by_key:
            continue
        by_key[key] = {
            "id": f"flow-{len(by_key) + 1}",
            "description": f"{link.from_repo} → {link.to_repo} ({link.type})",
            "source": link.from_repo,
            "target": link.to_repo,
            "protocol": protocol,
            "tags": [],
        }

    data["data_flows"] = list(by_key.values())
    with open(output_path, "w", encoding="utf-8") as fh:
        yaml.safe_dump(data, fh, sort_keys=False, allow_unicode=True)
    return output_path
