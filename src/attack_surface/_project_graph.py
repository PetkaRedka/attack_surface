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
from attack_surface._project_config import ProjectConfig


# ---------------------------------------------------------------------------
# Машиночитаемая модель графа
# ---------------------------------------------------------------------------

def build_project_graph_model(
    config: ProjectConfig,
    repo_entry_points: dict[str, dict[str, Any]],
    cross_edges: list[CrossRepoEdge],
    attack_surface: ReachabilityResult | None = None,
) -> dict[str, Any]:
    """Построить машиночитаемую модель кросс-репо графа."""
    repos: list[dict[str, Any]] = []
    for repo in config.repos:
        eps = repo_entry_points.get(repo.name, {})
        modules_map = _group_into_modules(eps, repo.language)
        modules: list[dict[str, Any]] = []
        for mod_name, mod_data in modules_map.items():
            types = {t for ep in mod_data["entry_points"] for t in ep.get("types", [])}
            modules.append({"name": mod_name, "types": sorted(types)})
        modules.sort(key=lambda m: m["name"])
        repos.append(
            {
                "name": repo.name,
                "language": repo.language,
                "role": repo.role,
                "path": repo.path,
                "total_entry_points": len(eps),
                "modules": modules,
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
    model: dict[str, Any], node_to_file: dict[str, str], output_dir: str
) -> str:
    node_data: list[dict[str, Any]] = []
    link_data: list[dict[str, Any]] = []

    node_data.append({"text": model["project"], "isGroup": True, "key": -1, "dash": [1, 5]})

    group_key = -2
    node_key = 1
    module_keys: dict[tuple[str, str], int] = {}

    repo_y = 80
    for repo in model["repos"]:
        gkey = group_key
        group_key -= 1
        node_data.append(
            {
                "text": f"{repo['name']} ({repo['role'] or repo['language']})",
                "isGroup": True,
                "key": gkey,
                "group": -1,
                "dash": [4, 4],
            }
        )

        for i, mod in enumerate(repo["modules"]):
            mk = node_key
            node_key += 1
            module_keys[(repo["name"], mod["name"])] = mk
            node_data.append(
                {
                    "key": mk,
                    "name": mod["name"],
                    "loc": f"{180 + i * 220} {repo_y + 60}",
                    "group": gkey,
                    "mod": "mod",
                    "lang": (repo["language"][:2] if repo["language"] else ""),
                }
            )
        repo_y += 240

    # Рёбра связей между модулями разных репозиториев
    for link in model["links"]:
        for edge in link["edges"]:
            client_mod = module_name_for_path(edge.get("client_file", ""))
            server_mod = module_name_for_path(node_to_file.get(edge.get("server_node_id", ""), ""))
            src_key = module_keys.get((edge.get("client_repo", ""), client_mod))
            dst_key = module_keys.get((edge.get("server_repo", ""), server_mod))
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
    out_file = os.path.join(output_dir, "project_attack_surface.json")
    with open(out_file, "w", encoding="utf-8") as fh:
        json.dump(cert, fh, ensure_ascii=False)
    return out_file


# ---------------------------------------------------------------------------
# SVG
# ---------------------------------------------------------------------------

def _generate_svg(model: dict[str, Any], output_dir: str) -> str:
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
        mods = ", ".join(m["name"] for m in repo["modules"][:6])
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

    # Рёбра связей
    for link in model["links"]:
        if not link["edges"]:
            continue
        src = repo_centers.get(link["from"])
        dst = repo_centers.get(link["to"])
        if src is None or dst is None:
            continue
        svg += (
            f'  <line x1="{src[0]}" y1="{src[1] + 55}" x2="{dst[0]}" y2="{dst[1] - 55}" '
            f'stroke="#000" stroke-width="1" marker-end="url(#arrowhead)"/>\n'
            f'  <text x="{(src[0] + dst[0]) / 2 + 8}" y="{(src[1] + dst[1]) / 2}" '
            f'font-family="Arial, sans-serif" font-size="9" fill="#000">'
            f'{link["type"]} ({len(link["edges"])})</text>\n'
        )

    svg += "</svg>\n"

    out_file = os.path.join(output_dir, "project_attack_surface.svg")
    with open(out_file, "w", encoding="utf-8") as fh:
        fh.write(svg)
    return out_file
