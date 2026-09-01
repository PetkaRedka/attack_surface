"""Генерация кросс-репозиторного графа проекта.

Объединяет графы отдельных репозиториев в единый граф: репозитории
представлены группами, внутри них — модули с внешними интерфейсами (EXT),
между репозиториями — подтверждённые связи (``CrossRepoEdge``).

Результат сохраняется в машиночитаемом ``project_graph.json`` и, по
запросу, в визуальном формате CERT JSON (GoJS) или SVG.
"""

from __future__ import annotations

import json
import os
from collections import defaultdict
from typing import Any

from attack_surface._attack_surface import ReachabilityResult
from attack_surface._graph import _group_into_modules, module_name_for_path
from attack_surface._linker import CrossRepoEdge
from attack_surface._project_config import (
    LinkConfig,
    ProjectConfig,
    RepoConfig,
)


def _source_module(repo: RepoConfig, file_path: str) -> str:
    """Самый глубокий модуль репозитория, которому принадлежит исходник.

    Привязка идёт по самому длинному совпадающему префиксу пути
    (``pizda/bobik`` важнее ``pizda``); пусто — исходник вне модулей.
    """
    if not file_path or not repo.modules:
        return ""
    norm = os.path.normpath(file_path).replace("\\", "/").lower()
    base = os.path.normpath(repo.path).replace("\\", "/").lower()
    best = ""
    for module in repo.modules:
        prefix = f"{base}/{module.rstrip('/').replace(chr(92), '/').lower()}/"
        if norm.startswith(prefix) and len(module) > len(best):
            best = module
    return best


# ---------------------------------------------------------------------------
# Машиночитаемая модель графа
# ---------------------------------------------------------------------------

def build_project_graph_model(
    config: ProjectConfig,
    repo_entry_points: dict[str, dict[str, Any]],
    cross_edges: list[CrossRepoEdge],
    attack_surface: ReachabilityResult | None = None,
) -> dict[str, Any]:
    """Построить машиночитаемую модель кросс-репо графа.

    Иерархия: репозиторий → модули (git-поддиректории) и исходники
    (каталоги с точками входа). Исходник, лежащий внутри каталога
    модуля, привязывается к нему полем ``module``.
    """
    repos: list[dict[str, Any]] = []
    for repo in config.repos:
        eps = repo_entry_points.get(repo.name, {})
        modules_map = _group_into_modules(eps, repo.language)
        sources: list[dict[str, Any]] = []
        for mod_name, mod_data in modules_map.items():
            types = {t for ep in mod_data["entry_points"] for t in ep.get("types", [])}
            first_file = mod_data["entry_points"][0].get("file", "") if mod_data["entry_points"] else ""
            sources.append(
                {
                    "name": mod_name,
                    "types": sorted(types),
                    "module": _source_module(repo, first_file),
                }
            )
        sources.sort(key=lambda s: s["name"])
        repos.append(
            {
                "name": repo.name,
                "language": repo.language,
                "role": repo.role,
                "path": repo.path,
                "total_entry_points": len(eps),
                "modules": list(repo.modules),
                "sources": sources,
            }
        )

    # Сгруппировать подтверждённые связи по (from, to, type)
    link_groups: dict[tuple[str, str, str], list[dict[str, Any]]] = defaultdict(list)
    for edge in cross_edges:
        key = (edge.link.from_repo, edge.link.to_repo, edge.link.type)
        link_groups[key].append(edge.to_dict())

    links: list[dict[str, Any]] = []
    for link in config.links:
        key = (link.from_repo, link.to_repo, link.type)
        links.append(
            {
                "from": link.from_repo,
                "to": link.to_repo,
                "type": link.type,
                "edges": link_groups.get(key, []),
            }
        )

    return {
        "project": config.project,
        "repos": repos,
        "links": links,
        "attack_surface": attack_surface.to_dict() if attack_surface else None,
    }


# ---------------------------------------------------------------------------
# Единая точка входа
# ---------------------------------------------------------------------------

def generate_project_graph(
    config: ProjectConfig,
    repo_entry_points: dict[str, dict[str, Any]],
    cross_edges: list[CrossRepoEdge],
    output_dir: str,
    *,
    output_format: str = "svg",
    attack_surface: ReachabilityResult | None = None,
) -> dict[str, str]:
    """Сгенерировать кросс-репозиторный граф.

    :return: словарь ``{имя_файла: путь}`` для созданных артефактов.
    """
    os.makedirs(output_dir, exist_ok=True)
    model = build_project_graph_model(config, repo_entry_points, cross_edges, attack_surface)

    # Сопоставление node_id → путь к файлу (для привязки рёбер к модулям)
    node_to_file: dict[str, str] = {}
    for eps in repo_entry_points.values():
        for node_id, ep in eps.items():
            node_to_file[node_id] = ep.get("file_path", "")

    artifacts: dict[str, str] = {}
    json_path = os.path.join(output_dir, "project_graph.json")
    with open(json_path, "w", encoding="utf-8") as fh:
        json.dump(model, fh, indent=2, ensure_ascii=False)
    artifacts["project_graph.json"] = json_path

    if output_format == "cert":
        artifacts["project_attack_surface.json"] = _generate_cert(model, node_to_file, output_dir)
    elif output_format == "svg":
        artifacts["project_attack_surface.svg"] = _generate_svg(model, output_dir)

    return artifacts


# ---------------------------------------------------------------------------
# CERT JSON (GoJS GraphLinksModel)
# ---------------------------------------------------------------------------

def _generate_cert(
    model: dict[str, Any],
    node_to_file: dict[str, str],
    output_dir: str,
    basename: str = "project_attack_surface",
) -> str:
    node_data: list[dict[str, Any]] = []
    link_data: list[dict[str, Any]] = []

    node_data.append({"text": model["project"], "isGroup": True, "key": -1, "dash": [1, 5]})

    group_key = -2
    node_key = 1
    source_keys: dict[tuple[str, str], int] = {}
    repo_group_keys: dict[str, int] = {}

    repo_y = 80
    for repo in model["repos"]:
        gkey = group_key
        group_key -= 1
        repo_group_keys[repo["name"]] = gkey
        node_data.append(
            {
                "text": f"{repo['name']} ({repo['role'] or repo['language']})",
                "isGroup": True,
                "key": gkey,
                "group": -1,
                "dash": [4, 4],
            }
        )

        # Группы git-модулей репозитория
        module_group_keys: dict[str, int] = {}
        for module in repo.get("modules", []):
            mkey = group_key
            group_key -= 1
            module_group_keys[module] = mkey
            node_data.append(
                {
                    "text": f"модуль {module}",
                    "isGroup": True,
                    "key": mkey,
                    "group": gkey,
                    "dash": [2, 2],
                }
            )

        # Исходники: внутри модуля — в его группу, иначе — в группу репозитория
        for i, src in enumerate(repo.get("sources", [])):
            mk = node_key
            node_key += 1
            source_keys[(repo["name"], src["name"])] = mk
            node_data.append(
                {
                    "key": mk,
                    "name": src["name"],
                    "loc": f"{180 + i * 220} {repo_y + 60}",
                    "group": module_group_keys.get(src.get("module", ""), gkey),
                    "mod": "mod",
                    "lang": (repo["language"][:2] if repo["language"] else ""),
                }
            )
        repo_y += 240

    # Рёбра связей между модулями разных репозиториев.
    # Если конкретные эндпоинты не сопоставлены (пустой ``edges``) —
    # связь рисуется на уровне репозиториев (между группами).
    for link in model["links"]:
        if link["edges"]:
            for edge in link["edges"]:
                client_mod = module_name_for_path(edge.get("client_file", ""))
                server_mod = module_name_for_path(node_to_file.get(edge.get("server_node_id", ""), ""))
                src_key = source_keys.get((edge.get("client_repo", ""), client_mod))
                dst_key = source_keys.get((edge.get("server_repo", ""), server_mod))
                if src_key is None or dst_key is None or src_key == dst_key:
                    continue
                link_data.append(
                    {
                        "from": src_key,
                        "to": dst_key,
                        "text": link["type"],
                        "dash": [2, 2],
                    }
                )
            continue
        src_key = repo_group_keys.get(link["from"])
        dst_key = repo_group_keys.get(link["to"])
        if src_key is None or dst_key is None or src_key == dst_key:
            continue
        link_data.append(
            {
                "from": src_key,
                "to": dst_key,
                "text": link["type"],
                "dash": [2, 2],
            }
        )

    cert = {
        "class": "GraphLinksModel",
        "copiesArrays": True,
        "copiesArrayObjects": True,
        "nodeDataArray": node_data,
        "linkDataArray": link_data,
    }
    out_file = os.path.join(output_dir, f"{basename}.json")
    with open(out_file, "w", encoding="utf-8") as fh:
        json.dump(cert, fh, ensure_ascii=False)
    return out_file


# ---------------------------------------------------------------------------
# SVG
# ---------------------------------------------------------------------------

def _generate_svg(
    model: dict[str, Any], output_dir: str, basename: str = "project_attack_surface"
) -> str:
    repos = model["repos"]
    repo_h = 120
    repo_gap = 60
    width = 640
    height = 60 + len(repos) * (repo_h + repo_gap)

    svg = (
        f'<?xml version="1.0" encoding="UTF-8"?>\n'
        f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {width} {height}" '
        f'width="{width}" height="{height}">\n'
        f'  <defs>\n'
        f'    <marker id="arrowhead" markerWidth="8" markerHeight="6" refX="7" refY="3" '
        f'orient="auto">\n'
        f'      <polygon points="0 0, 8 3, 0 6" fill="#000"/>\n'
        f'    </marker>\n'
        f'  </defs>\n'
        f'  <rect width="100%" height="100%" fill="white"/>\n'
        f'  <text x="{width / 2}" y="25" text-anchor="middle" font-family="Arial, sans-serif" '
        f'font-size="14" fill="#000">{model["project"]}</text>\n'
    )

    repo_centers: dict[str, tuple[float, float]] = {}
    y = 50
    for repo in repos:
        cy = y + repo_h / 2
        repo_centers[repo["name"]] = (width / 2, cy)
        mods = ", ".join(s["name"] for s in repo["sources"][:6])
        if repo.get("modules"):
            mods = f"модули: {', '.join(repo['modules'][:3])}; " + mods
        svg += (
            f'  <rect x="120" y="{y}" width="{width - 240}" height="{repo_h}" '
            f'fill="white" stroke="#000" stroke-width="2"/>\n'
            f'  <text x="{width / 2}" y="{y + 20}" text-anchor="middle" '
            f'font-family="Arial, sans-serif" font-size="12" fill="#000">'
            f'{repo["name"]} ({repo["role"] or repo["language"]})</text>\n'
            f'  <text x="{width / 2}" y="{y + 40}" text-anchor="middle" '
            f'font-family="Arial, sans-serif" font-size="9" fill="#666">{mods}</text>\n'
        )
        y += repo_h + repo_gap

    # Рёбра связей. Если конкретные эндпоинты не сопоставлены —
    # связь рисуется на уровне репозиториев (без пометки числа рёбер).
    for link in model["links"]:
        src = repo_centers.get(link["from"])
        dst = repo_centers.get(link["to"])
        if src is None or dst is None:
            continue
        label = (
            f'{link["type"]} ({len(link["edges"])})'
            if link["edges"]
            else link["type"]
        )
        svg += (
            f'  <line x1="{src[0]}" y1="{src[1] + 55}" x2="{dst[0]}" y2="{dst[1] - 55}" '
            f'stroke="#000" stroke-width="1" marker-end="url(#arrowhead)"/>\n'
            f'  <text x="{(src[0] + dst[0]) / 2 + 8}" y="{(src[1] + dst[1]) / 2}" '
            f'font-family="Arial, sans-serif" font-size="9" fill="#000">'
            f'{label}</text>\n'
        )

    svg += "</svg>\n"

    out_file = os.path.join(output_dir, f"{basename}.svg")
    with open(out_file, "w", encoding="utf-8") as fh:
        fh.write(svg)
    return out_file


# ---------------------------------------------------------------------------
# Пересборка из project_scan.json и топология из конфига
# ---------------------------------------------------------------------------

def generate_project_graph_from_scan(
    scan_path: str,
    output_dir: str,
    *,
    output_format: str = "svg",
) -> dict[str, str]:
    """Пересобрать кросс-репо граф (CERT/SVG) из сохранённого ``project_scan.json``.

    Сканирование, LLM-валидация и линковка не выполняются: точки входа,
    найденные связи и поверхность атаки восстанавливаются из JSON.

    :return: словарь ``{имя_файла: путь}`` для созданных артефактов.
    """
    scan_path = os.path.abspath(scan_path)
    if not os.path.isfile(scan_path):
        raise ValueError(f"Файл project_scan.json не найден: {scan_path}")
    with open(scan_path, encoding="utf-8") as fh:
        data = json.load(fh)
    if not isinstance(data, dict):
        raise ValueError(f"Некорректный JSON в файле: {scan_path}")

    config = _config_from_scan(data, os.path.dirname(scan_path))
    repo_entry_points: dict[str, dict[str, Any]] = {
        repo["name"]: repo.get("entry_points") or {}
        for repo in data.get("repos", [])
        if isinstance(repo, dict)
    }
    edges = [
        CrossRepoEdge.from_dict(edge)
        for edge in data.get("edges", [])
        if isinstance(edge, dict)
    ]
    attack_surface = (
        ReachabilityResult.from_dict(data["attack_surface"])
        if isinstance(data.get("attack_surface"), dict)
        else None
    )

    return generate_project_graph(
        config,
        repo_entry_points,
        edges,
        output_dir,
        output_format=output_format,
        attack_surface=attack_surface,
    )


def generate_repo_topology_graph(
    config: ProjectConfig,
    output_dir: str,
    *,
    output_format: str = "both",
) -> dict[str, str]:
    """Отрисовать схему топологии репозиториев из конфига без анализа кода.

    Узлы — репозитории, рёбра — связи из конфига (для Threagile —
    ``data_flows``). Используется для быстрой визуализации архитектурного
    файла, в том числе после того, как в него записаны найденные связи.

    :return: словарь ``{имя_файла: путь}`` для созданных артефактов.
    """
    os.makedirs(output_dir, exist_ok=True)
    model = build_project_graph_model(config, {}, [], None)

    artifacts: dict[str, str] = {}
    if output_format in ("cert", "both"):
        artifacts["project_topology.json"] = _generate_cert(
            model, {}, output_dir, basename="project_topology"
        )
    if output_format in ("svg", "both"):
        artifacts["project_topology.svg"] = _generate_svg(
            model, output_dir, basename="project_topology"
        )
    return artifacts


def _config_from_scan(data: dict[str, Any], base_dir: str) -> ProjectConfig:
    """Восстановить ProjectConfig из содержимого project_scan.json."""
    repos: list[RepoConfig] = []
    for repo in data.get("repos", []):
        if not isinstance(repo, dict):
            continue
        repos.append(
            RepoConfig(
                name=str(repo.get("name", "")),
                path=str(repo.get("path", "")),
                language=str(repo.get("language", "")),
                role=str(repo.get("role", "")),
                modules=[str(m) for m in (repo.get("modules") or []) if str(m).strip()],
            )
        )
    links = [
        LinkConfig.from_dict(link)
        for link in data.get("links", [])
        if isinstance(link, dict)
    ]
    return ProjectConfig(
        project=str(data.get("project", "project")),
        repos=repos,
        links=links,
        base_dir=base_dir,
    )
