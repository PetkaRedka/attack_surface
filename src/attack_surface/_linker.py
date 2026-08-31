"""Кросс-репозиторное связывание эндпоинтов (статические эвристики).

Определяет, используются ли серверные эндпоинты одного репозитория в коде
другого, сопоставляя сигнатуры интерфейсов. Работает в обе стороны:

- **прямой проход** — сигнатуры серверных эндпоинтов ``to``-репозитория
  ищутся в исходном коде ``from``-репозитория;
- **обратный проход** — сигнатуры клиентских эндпоинтов ``from``-репозитория
  ищутся в ``to``-репозитории как дополнительное средство валидации
  (включается флагом ``bidirectional``).

Результатом являются кандидаты ``CrossRepoEdge``, которые затем могут быть
подтверждены через LLM (см. ``_link_llm``).
"""

from __future__ import annotations

import os
import re
from collections.abc import Iterator
from dataclasses import dataclass
from typing import Any

from attack_surface._project_config import LinkConfig, LinkType, ProjectConfig, VALID_LINK_TYPES


# ---------------------------------------------------------------------------
# Модель кандидата связи
# ---------------------------------------------------------------------------

@dataclass
class CrossRepoEdge:
    """Найденная связь между эндпоинтами разных репозиториев."""

    link: LinkConfig
    server_repo: str
    server_node_id: str
    server_function_name: str
    server_signature: str
    client_repo: str
    client_file: str
    client_line: int
    client_snippet: str = ""
    client_node_id: str = ""
    client_function_name: str = ""
    match_kind: str = "exact"        # exact | normalized | symbol | reverse
    confidence: str = "medium"       # high | medium | low
    direction: str = "forward"       # forward | reverse

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "CrossRepoEdge":
        """Восстановить ребро из JSON (см. ``to_dict``)."""
        return cls(
            link=LinkConfig.from_dict(data.get("link", {})),
            server_repo=str(data.get("server_repo", "")),
            server_node_id=str(data.get("server_node_id", "")),
            server_function_name=str(data.get("server_function_name", "")),
            server_signature=str(data.get("server_signature", "")),
            client_repo=str(data.get("client_repo", "")),
            client_file=str(data.get("client_file", "")),
            client_line=int(data.get("client_line", 0)),
            client_snippet=str(data.get("client_snippet", "")),
            client_node_id=str(data.get("client_node_id", "")),
            client_function_name=str(data.get("client_function_name", "")),
            match_kind=str(data.get("match_kind", "exact")),
            confidence=str(data.get("confidence", "medium")),
            direction=str(data.get("direction", "forward")),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "link": self.link.to_dict(),
            "server_repo": self.server_repo,
            "server_node_id": self.server_node_id,
            "server_function_name": self.server_function_name,
            "server_signature": self.server_signature,
            "client_repo": self.client_repo,
            "client_file": self.client_file,
            "client_line": self.client_line,
            "client_snippet": self.client_snippet,
            "client_node_id": self.client_node_id,
            "client_function_name": self.client_function_name,
            "match_kind": self.match_kind,
            "confidence": self.confidence,
            "direction": self.direction,
        }


# ---------------------------------------------------------------------------
# Расширения исходников по языкам
# ---------------------------------------------------------------------------

LANGUAGE_EXTENSIONS: dict[str, tuple[str, ...]] = {
    "python": (".py",),
    "c": (".c", ".h"),
    "cpp": (".cpp", ".cc", ".cxx", ".h", ".hpp", ".hh"),
    "go": (".go",),
    "java": (".java",),
    "javascript": (".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx"),
    "typescript": (".ts", ".tsx", ".js", ".jsx"),
    "c_sharp": (".cs",),
}

_EXCLUDED_DIRS: frozenset[str] = frozenset(
    {
        "node_modules", "venv", ".venv", "env", "dist", "build", "bin", "obj",
        ".git", "__pycache__", "target", ".next", "vendor", "coverage", "out",
        ".idea", ".vscode", ".mypy_cache", ".pytest_cache", ".tox",
    }
)

_EXCLUDED_FILE_MARKERS: tuple[str, ...] = ("test", "spec", "example", "mock", "fixture")

_URL_LINK_TYPES: frozenset[str] = frozenset(
    ("http", "grpc", "websocket", "rpc", "reverse-proxy")
)
_SYMBOL_LINK_TYPES: frozenset[str] = frozenset(("ffi", "pinvoke"))

# Максимальные ограничения, чтобы не уходить в бесконечный перебор
_MAX_FILES_SCANNED = 5000
_MAX_MATCHES_PER_PATTERN = 50


# ---------------------------------------------------------------------------
# Совместимость interface_kind ↔ link.type
# ---------------------------------------------------------------------------

_KIND_COMPATIBILITY: dict[str, set[str]] = {
    "http": {"http", "reverse-proxy"},
    "grpc": {"grpc", "rpc"},
    "websocket": {"websocket"},
    "shared-db": {"shared-db"},
    "ffi": {"ffi", "pinvoke"},
    "pinvoke": {"ffi", "pinvoke"},
    "message-queue": {"message-queue"},
    "rpc": {"rpc", "grpc"},
    "file": {"file", "nfs"},
    # Семьи протоколов Threagile (см. _threagile.PROTOCOL_TO_LINK_TYPE)
    "reverse-proxy": {"reverse-proxy", "http"},
    "email": {"email"},
    "ssh": {"ssh"},
    "ftp": {"ftp"},
    "ldap": {"ldap"},
    "binary": {"binary"},
    "text": {"text"},
    "ipc": {"ipc"},
    "container": {"container"},
    "nfs": {"nfs", "file"},
}


def kind_compatible(kind: str, link_type: str) -> bool:
    """Совместим ли интерфейс ``kind`` с типом связи ``link_type``."""
    if kind in ("", "none"):
        return False
    return link_type in _KIND_COMPATIBILITY.get(kind, set())


def link_type_for_kind(kind: str) -> str:
    """Тип связи по умолчанию для ``interface_kind`` эндпоинта.

    Используется в авто-режиме связывания, когда тип связи не задан
    в конфиге, а определяется по интерфейсу найденного эндпоинта.
    """
    if kind in VALID_LINK_TYPES:
        return kind
    if kind in _KIND_COMPATIBILITY:
        return next(iter(sorted(_KIND_COMPATIBILITY[kind])), LinkType.RPC.value)
    return LinkType.RPC.value


# ---------------------------------------------------------------------------
# Построение паттернов поиска
# ---------------------------------------------------------------------------

def _strip_http_method(s: str) -> str:
    """Убрать HTTP-метод (например ``POST /api/x`` → ``/api/x``)."""
    m = re.match(r"^[A-Za-z]+\s+(.+)$", s)
    return m.group(1) if m else s


def _last_path_segment(url: str) -> str:
    """Последний сегмент URL-подобного пути без плейсхолдеров."""
    if "/" not in url:
        return ""
    seg = url.rstrip("/").split("/")[-1]
    seg = re.sub(r"\{[^}]*\}", "", seg)
    return seg.strip()


def build_patterns(signature: str, aliases: list[str], link_type: str) -> list[str]:
    """Собрать набор нормализованных строк для поиска в исходном коде."""
    patterns: list[str] = []
    for raw in [signature, *aliases]:
        s = (raw or "").strip()
        if not s:
            continue
        patterns.append(s)

        if link_type in _URL_LINK_TYPES:
            url = _strip_http_method(s)
            if url and url != s:
                patterns.append(url)
            seg = _last_path_segment(url)
            if seg and seg != url and len(seg) >= 3:
                patterns.append(seg)
        elif link_type in _SYMBOL_LINK_TYPES:
            # Имя символа без префиксов модуля/библиотеки
            for sep in ("::", "."):
                if sep in s:
                    patterns.append(s.rsplit(sep, maxsplit=1)[-1])

    # Дедупликация с сохранением порядка
    seen: set[str] = set()
    result: list[str] = []
    for p in patterns:
        if p not in seen:
            seen.add(p)
            result.append(p)
    return result


def signatures_overlap(pattern: str, endpoint: dict[str, Any]) -> bool:
    """Пересекается ли ``pattern`` с сигнатурой/алиасами эндпоинта."""
    pat = pattern.lower()
    candidates = [str(endpoint.get("signature", "")).lower()]
    candidates.extend(str(a).lower() for a in endpoint.get("signature_aliases", []))
    for sig in candidates:
        if not sig:
            continue
        if pat in sig or sig in pat:
            return True
    return False


# ---------------------------------------------------------------------------
# Обход исходников
# ---------------------------------------------------------------------------

def iter_source_files(root: str, language: str) -> Iterator[str]:
    """Обойти исходные файлы репозитория с учётом исключений."""
    extensions = LANGUAGE_EXTENSIONS.get(language, ())
    scanned = 0
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in _EXCLUDED_DIRS]
        for filename in filenames:
            if scanned >= _MAX_FILES_SCANNED:
                return
            low = filename.lower()
            if any(marker in low for marker in _EXCLUDED_FILE_MARKERS):
                continue
            if extensions and not low.endswith(extensions):
                continue
            scanned += 1
            yield os.path.join(dirpath, filename)


def find_in_file(path: str, pattern: str) -> list[tuple[int, str]]:
    """Найти вхождения ``pattern`` в файле; вернуть список ``(номер, строка)``."""
    matches: list[tuple[int, str]] = []
    low_pattern = pattern.lower()
    use_word = len(pattern) < 4
    try:
        with open(path, encoding="utf-8", errors="ignore") as fh:
            for num, line in enumerate(fh, 1):
                if low_pattern in line.lower():
                    if use_word and not re.search(
                        rf"\b{re.escape(low_pattern)}\b", line.lower()
                    ):
                        continue
                    matches.append((num, line.rstrip("\n")))
                    if len(matches) >= _MAX_MATCHES_PER_PATTERN:
                        break
    except OSError:
        pass
    return matches


# ---------------------------------------------------------------------------
# Линкер
# ---------------------------------------------------------------------------

class CrossRepoLinker:
    """Сопоставляет эндпоинты репозиториев по сигнатурам интерфейсов."""

    def __init__(self, config: ProjectConfig, *, bidirectional: bool = True) -> None:
        self._config: ProjectConfig = config
        self._bidirectional: bool = bidirectional
        self._repo_paths: dict[str, str] = {r.name: r.path for r in config.repos}
        self._repo_languages: dict[str, str] = {r.name: r.language for r in config.repos}

    # ------------------------------------------------------------------

    def find_links(
        self, repo_interfaces: dict[str, list[dict[str, Any]]]
    ) -> list[CrossRepoEdge]:
        """Найти связи между репозиториями.

        :param repo_interfaces: имя репозитория → список интерфейсных эндпоинтов
            (dict с ключами node_id, function_name, file_path, start_line,
            entry_point_type, interface_kind, interface_role, signature,
            signature_aliases).
        """
        edges: list[CrossRepoEdge] = []
        for link in self._config.links:
            server_eps = self._server_endpoints(
                repo_interfaces.get(link.to_repo, []), link.type
            )
            client_root = self._repo_paths.get(link.from_repo, "")
            if not server_eps or not client_root:
                continue

            for ep in server_eps:
                edges.extend(self._search_forward(link, ep, client_root))

            if self._bidirectional:
                edges.extend(
                    self._search_reverse(
                        link,
                        repo_interfaces.get(link.from_repo, []),
                        server_eps,
                    )
                )
        return edges

    # ------------------------------------------------------------------

    @staticmethod
    def _server_endpoints(
        endpoints: list[dict[str, Any]], link_type: str | None
    ) -> list[dict[str, Any]]:
        """Серверные эндпоинты, совместимые с типом связи.

        Если ``link_type`` не задан (авто-режим), фильтр по типу
        пропускается — подходят все эндпоинты с сигнатурой.
        """
        result: list[dict[str, Any]] = []
        for ep in endpoints:
            role = str(ep.get("interface_role", ""))
            kind = str(ep.get("interface_kind", ""))
            if (
                role in ("server", "both")
                and (link_type is None or kind_compatible(kind, link_type))
                and ep.get("signature")
            ):
                result.append(ep)
        return result

    @staticmethod
    def _client_endpoints(
        endpoints: list[dict[str, Any]], link_type: str | None
    ) -> list[dict[str, Any]]:
        """Клиентские эндпоинты, совместимые с типом связи.

        Если ``link_type`` не задан (авто-режим), фильтр по типу
        пропускается — подходят все эндпоинты с сигнатурой.
        """
        result: list[dict[str, Any]] = []
        for ep in endpoints:
            role = str(ep.get("interface_role", ""))
            kind = str(ep.get("interface_kind", ""))
            if (
                role in ("client", "both")
                and (link_type is None or kind_compatible(kind, link_type))
                and ep.get("signature")
            ):
                result.append(ep)
        return result

    def _search_forward(
        self, link: LinkConfig, server_ep: dict[str, Any], client_root: str
    ) -> list[CrossRepoEdge]:
        """Искать сигнатуры серверного эндпоинта в коде клиента."""
        patterns = build_patterns(
            server_ep.get("signature", ""),
            server_ep.get("signature_aliases", []),
            link.type,
        )
        client_lang = self._repo_languages.get(link.from_repo, "")

        edges: list[CrossRepoEdge] = []
        for pattern in patterns:
            for file_path in iter_source_files(client_root, client_lang):
                for line_no, line_text in find_in_file(file_path, pattern):
                    edges.append(
                        CrossRepoEdge(
                            link=link,
                            server_repo=link.to_repo,
                            server_node_id=server_ep.get("node_id", ""),
                            server_function_name=server_ep.get("function_name", ""),
                            server_signature=server_ep.get("signature", ""),
                            client_repo=link.from_repo,
                            client_file=file_path,
                            client_line=line_no,
                            client_snippet=line_text.strip(),
                            match_kind=_classify_match(pattern, server_ep.get("signature", "")),
                            confidence="medium",
                            direction="forward",
                        )
                    )
        return edges

    def _search_reverse(
        self,
        link: LinkConfig,
        client_eps: list[dict[str, Any]],
        server_eps: list[dict[str, Any]],
    ) -> list[CrossRepoEdge]:
        """Обратный проход: сигнатуры клиентов ищем в коде серверов."""
        if not server_eps:
            return []
        server_root = self._repo_paths.get(link.to_repo, "")
        server_lang = self._repo_languages.get(link.to_repo, "")
        if not server_root:
            return []

        edges: list[CrossRepoEdge] = []
        for cep in self._client_endpoints(client_eps, link.type):
            patterns = build_patterns(
                cep.get("signature", ""), cep.get("signature_aliases", []), link.type
            )
            for pattern in patterns:
                matches: list[tuple[int, str]] = []
                for file_path in iter_source_files(server_root, server_lang):
                    matches.extend(find_in_file(file_path, pattern))
                    if matches:
                        break
                if not matches:
                    continue
                for sep in server_eps:
                    if signatures_overlap(pattern, sep):
                        edges.append(
                            CrossRepoEdge(
                                link=link,
                                server_repo=link.to_repo,
                                server_node_id=sep.get("node_id", ""),
                                server_function_name=sep.get("function_name", ""),
                                server_signature=sep.get("signature", ""),
                                client_repo=link.from_repo,
                                client_file=cep.get("file_path", ""),
                                client_line=int(cep.get("start_line", 0)),
                                client_snippet=matches[0][1].strip(),
                                match_kind="reverse",
                                confidence="medium",
                                direction="reverse",
                            )
                        )
                        break
        return edges

    # ------------------------------------------------------------------

    def find_auto_links(
        self, repo_interfaces: dict[str, list[dict[str, Any]]]
    ) -> list[CrossRepoEdge]:
        """Авто-режим: перебор всех пар репозиториев без связей из конфига.

        Для каждой упорядоченной пары ``(from, to)`` ищет обращения к
        серверным эндпоинтам ``to`` в коде ``from`` (и обратный проход
        при ``bidirectional``). Тип связи определяется по ``interface_kind``
        найденного эндпоинта, дубликаты отбрасываются.
        """
        edges: list[CrossRepoEdge] = []
        seen: set[tuple[str, str, str, str, str, int]] = set()
        repo_names = sorted(self._config.repo_names())

        for from_repo in repo_names:
            client_root = self._repo_paths.get(from_repo, "")
            if not client_root:
                continue
            for to_repo in repo_names:
                if from_repo == to_repo:
                    continue
                server_eps = self._server_endpoints(
                    repo_interfaces.get(to_repo, []), None
                )
                if not server_eps:
                    continue

                for server_ep in server_eps:
                    link = LinkConfig(
                        from_repo=from_repo,
                        to_repo=to_repo,
                        type=link_type_for_kind(str(server_ep.get("interface_kind", ""))),
                    )
                    for edge in self._search_forward(link, server_ep, client_root):
                        key = (
                            edge.client_repo,
                            edge.server_repo,
                            edge.link.type,
                            edge.server_node_id,
                            edge.client_file,
                            edge.client_line,
                        )
                        if key in seen:
                            continue
                        seen.add(key)
                        edges.append(edge)

                if self._bidirectional:
                    client_eps = self._client_endpoints(
                        repo_interfaces.get(from_repo, []), None
                    )
                    for client_ep in client_eps:
                        link = LinkConfig(
                            from_repo=from_repo,
                            to_repo=to_repo,
                            type=link_type_for_kind(
                                str(client_ep.get("interface_kind", ""))
                            ),
                        )
                        for edge in self._search_reverse(
                            link, [client_ep], server_eps
                        ):
                            key = (
                                edge.client_repo,
                                edge.server_repo,
                                edge.link.type,
                                edge.server_node_id,
                                edge.client_file,
                                edge.client_line,
                            )
                            if key in seen:
                                continue
                            seen.add(key)
                            edges.append(edge)
        return edges

    # ------------------------------------------------------------------

    def find_authoritative_links(
        self, repo_interfaces: dict[str, list[dict[str, Any]]]
    ) -> list[CrossRepoEdge]:
        """Сопоставить эндпоинты по доверенным связям из архитектурного конфига.

        Для каждой связи ``(from → to, type)`` ищет пары (серверный эндпоинт
        в ``to``, клиентский в ``from``) с пересекающимися сигнатурами.
        Если такие пары не найдены, связь фиксируется на уровне репозиториев
        (с пустыми ``node_id``) — она задана архитектором и не отбрасывается.
        """
        edges: list[CrossRepoEdge] = []
        for link in self._config.links:
            server_eps = self._server_endpoints(
                repo_interfaces.get(link.to_repo, []), link.type
            )
            client_eps = self._client_endpoints(
                repo_interfaces.get(link.from_repo, []), link.type
            )

            matched = False
            for server_ep in server_eps:
                for client_ep in client_eps:
                    if self._signatures_intersect(server_ep, client_ep):
                        edges.append(self._authoritative_edge(link, server_ep, client_ep))
                        matched = True

            if not matched:
                edges.append(self._authoritative_edge(link, None, None))
        return edges

    @staticmethod
    def _signatures_intersect(
        server_ep: dict[str, Any], client_ep: dict[str, Any]
    ) -> bool:
        """Пересекаются ли сигнатуры серверного и клиентского эндпоинтов."""
        return signatures_overlap(
            server_ep.get("signature", ""), client_ep
        ) or signatures_overlap(client_ep.get("signature", ""), server_ep)

    @staticmethod
    def _authoritative_edge(
        link: LinkConfig,
        server_ep: dict[str, Any] | None,
        client_ep: dict[str, Any] | None,
    ) -> CrossRepoEdge:
        """Построить ребро на основе доверенной связи и сопоставленных эндпоинтов."""
        server_ep = server_ep or {}
        client_ep = client_ep or {}
        return CrossRepoEdge(
            link=link,
            server_repo=link.to_repo,
            server_node_id=server_ep.get("node_id", ""),
            server_function_name=server_ep.get("function_name", ""),
            server_signature=server_ep.get("signature", ""),
            client_repo=link.from_repo,
            client_file=client_ep.get("file_path", ""),
            client_line=int(client_ep.get("start_line", 0)),
            client_node_id=client_ep.get("node_id", ""),
            client_function_name=client_ep.get("function_name", ""),
            match_kind="authoritative",
            confidence="high",
            direction="authoritative",
        )


# ---------------------------------------------------------------------------
# Классификация совпадения
# ---------------------------------------------------------------------------

def _classify_match(pattern: str, signature: str) -> str:
    """Определить вид совпадения: точное, нормализованное или символьное."""
    if pattern == signature:
        return "exact"
    if pattern in signature:
        return "normalized"
    return "symbol"
