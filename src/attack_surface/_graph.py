"""Генерация графа поверхности атаки в форматах SVG и CERT JSON (GoJS GraphLinksModel).

Граф отображает модули проекта, их внешние интерфейсы (EXT) и межмодульные связи.
"""

from __future__ import annotations

import json
import math
import os
from collections import defaultdict
from typing import Any

from tqdm import tqdm

from attack_surface._ext_minimizer import EXTMinimizer, EXTMinimizerInput, EXTMinimizerOutput
from attack_surface._logger import Logger
from attack_surface._models import ENTRY_POINT_DISPLAY_NAMES


# ---------------------------------------------------------------------------
# Внешние имена EXT
# ---------------------------------------------------------------------------

_EXT_NAME_MAP: dict[str, str] = {
    "http_request": "EXT_HTTP",
    "environment_variable": "EXT_ENV",
    "file_read": "EXT_FILE",
    "file_write": "EXT_FILE",
    "command_line_args": "EXT_CLI",
    "user_input": "EXT_INPUT",
    "database_query": "EXT_DB",
    "socket": "EXT_SOCKET",
    "websocket": "EXT_WS",
    "deserialization": "EXT_DESER",
    "event_handler": "EXT_EVENT",
}


def _ext_interface_name(ep_type: str, counter: int) -> str:
    return _EXT_NAME_MAP.get(ep_type, f"EXT.{counter}")


# ---------------------------------------------------------------------------
# Ортогональные пути для CERT-ссылок
# ---------------------------------------------------------------------------

def _orthogonal_lr(
    x1: float, y1: float, x2: float, y2: float, direction: str,
) -> list[float]:
    mid_x = (x1 + x2) / 2
    return [x1, y1, mid_x, y1, mid_x, y2, x2, y2]


def _orthogonal(x1: float, y1: float, x2: float, y2: float) -> list[float]:
    mid_x = (x1 + x2) / 2
    return [x1, y1, x1 + 10, y1, mid_x, y1, mid_x, y2, x2 - 10, y2, x2, y2]


# ---------------------------------------------------------------------------
# Группировка модулей
# ---------------------------------------------------------------------------

def module_name_for_path(file_path: str) -> str:
    """Определить имя модуля по пути к файлу (по структуре каталогов)."""
    parts = file_path.replace("\\", "/").split("/")

    module_name = "root"
    for i, part in enumerate(parts):
        if part in ("src", "lib", "app", "source", "modules"):
            if i + 1 < len(parts) - 1:
                module_name = parts[i + 1]
            break
    if module_name == "root" and len(parts) > 2:
        module_name = parts[-2]
    return module_name


def _group_into_modules(
    entry_points: dict[str, Any],
    language: str,
) -> dict[str, dict[str, Any]]:
    """Группировка точек входа по модулям (каталогам)."""
    modules: dict[str, dict[str, Any]] = defaultdict(
        lambda: {
            "functions": set(),
            "entry_points": [],
            "calls_to": set(),
            "calls_from": set(),
            "language": language,
        }
    )

    for ep_id, ep_info in entry_points.items():
        module_name = module_name_for_path(ep_info.get("file_path", ""))

        ep_types: set[str] = set()
        for src in ep_info.get("external_input_sources", []):
            if src.get("entry_point_type"):
                ep_types.add(src["entry_point_type"])
        if not ep_types:
            ep_types.add(ep_info.get("entry_point_type", "unknown"))

        modules[module_name]["entry_points"].append({
            "name": ep_info.get("function_name", "?"),
            "types": list(ep_types),
            "file": ep_info.get("file_path", ""),
        })

    return dict(modules)


def _minimize_ext(
    modules: dict[str, Any],
    model_name: str,
    logger: Logger,
) -> dict[str, Any]:
    """Минимизация EXT через LLM."""
    minimizer = EXTMinimizer(
        model_name=model_name,
        temperature=0.0,
        max_query_num=3,
        logger=logger,
    )

    for mod_name, mod_data in tqdm(
        modules.items(), desc="Минимизация EXT", unit="модуль"
    ):
        if not mod_data.get("entry_points"):
            continue

        all_types = {t for ep in mod_data["entry_points"] for t in ep.get("types", [])}
        if len(all_types) <= 1:
            continue

        logger.print_log(f"Модуль {mod_name}: {len(all_types)} EXT-типов до минимизации")

        inp = EXTMinimizerInput(
            module_name=mod_name,
            ext_types=list(all_types),
            entry_points=mod_data["entry_points"],
        )
        out = minimizer.invoke(inp, EXTMinimizerOutput)
        if out is None:
            continue

        mapping: dict[str, str] = {}
        for group in out.grouped_exts:
            rep = group.get("representative_type")
            for orig in group.get("grouped_types", []):
                mapping[orig] = rep

        for ep in mod_data["entry_points"]:
            original = ep.get("types", [])
            ep["types"] = list({mapping.get(t, t) for t in original})
            ep["original_types"] = original

        unique = {t for ep in mod_data["entry_points"] for t in ep["types"]}
        logger.print_console(f"✓ Модуль {mod_name}: {len(all_types)} → {len(unique)} EXT")

    return modules


# ---------------------------------------------------------------------------
# Группировка подсистем
# ---------------------------------------------------------------------------

def _group_subsystems(modules_dict: dict[str, Any]) -> dict[str, dict[str, Any]]:
    groups: dict[str, list[str]] = defaultdict(list)
    for name in modules_dict:
        parts = name.replace("-", "_").replace(".", "_").split("_")
        subsys = parts[0] if parts and len(name) >= 4 else name
        groups[subsys].append(name)

    result: dict[str, dict[str, Any]] = {}
    for subsys, mods in groups.items():
        if len(mods) == 1:
            result[mods[0]] = {"modules": [mods[0]], "is_group": False}
        else:
            result[subsys] = {"modules": mods, "is_group": True}
    return result


# ---------------------------------------------------------------------------
# CERT JSON
# ---------------------------------------------------------------------------

def generate_cert_graph(
    entry_points: dict[str, Any],
    output_path: str,
    project_name: str,
    language: str,
    minimize_ext: bool = True,
    model_name: str = "gpt-4o-mini",
    logger: Logger | None = None,
) -> str:
    """Генерация графа в CERT JSON (GoJS GraphLinksModel)."""
    modules = _group_into_modules(entry_points, language)
    modules_with_eps = {k: v for k, v in modules.items() if v.get("entry_points")}
    if not modules_with_eps:
        modules_with_eps = modules

    if minimize_ext and logger:
        modules_with_eps = _minimize_ext(modules_with_eps, model_name, logger)

    node_data: list[dict[str, Any]] = []
    link_data: list[dict[str, Any]] = []

    node_key = 1
    group_key = -1
    link_counter = 1

    # Главная группа
    os_group_key = group_key
    node_data.append({"text": project_name, "isGroup": True, "key": os_group_key, "dash": [1, 5]})
    group_key -= 1

    subsystems = _group_subsystems(modules_with_eps)

    # Раскладка
    mod_w, mod_h = 150, 60
    ext_w, ext_h = 120, 105
    subsys_h_sp, subsys_v_sp = 600, 500
    mod_h_sp, mod_v_sp = 150, 100
    pad = 30

    grid_cols = max(1, math.ceil(math.sqrt(len(subsystems))))
    left_ext_margin = 150
    center_x = left_ext_margin + 50
    start_y = 80

    subsys_info: list[dict[str, Any]] = []
    mod_info: list[dict[str, Any]] = []
    mod_positions: dict[str, tuple[float, float]] = {}

    for idx, (subsys_name, subsys_data) in enumerate(subsystems.items()):
        row, col = divmod(idx, grid_cols)
        mods = subsys_data["modules"]
        n = len(mods)
        mc = max(1, math.ceil(math.sqrt(n)))
        mr = math.ceil(n / mc)

        sw = mc * mod_w + (mc - 1) * mod_h_sp + 2 * pad
        sh = mr * mod_h + (mr - 1) * mod_v_sp + 2 * pad
        sx = center_x + col * subsys_h_sp
        sy = start_y + row * subsys_v_sp

        for mi, mn in enumerate(mods):
            mrow, mcol = divmod(mi, mc)
            mx = sx + pad + mcol * (mod_w + mod_h_sp)
            my = sy + pad + mrow * (mod_h + mod_v_sp)
            utypes = {t for ep in modules_with_eps[mn].get("entry_points", []) for t in ep.get("types", [])}

            mod_info.append({
                "name": mn, "subsystem": subsys_name, "is_grouped": subsys_data["is_group"],
                "subsys_col": col, "subsys_row": row, "x": mx, "y": my,
                "types": sorted(utypes), "num_ext": len(utypes),
            })
            mod_positions[mn] = (mx, my)

        subsys_info.append({
            "name": subsys_name, "is_group": subsys_data["is_group"], "modules": mods,
            "x": sx, "y": sy, "width": sw, "height": sh, "col": col, "row": row,
        })

    max_x = max((s["x"] + s["width"] for s in subsys_info), default=0)
    graph_right = max_x + 50

    module_keys: dict[str, int] = {}
    subsys_keys: dict[str, int] = {}
    lang_label = language[:2].lower() if language else ""

    for s in subsys_info:
        if s["is_group"]:
            subsys_keys[s["name"]] = group_key
            node_data.append({
                "text": f"Подсистема {s['name']}", "isGroup": True,
                "key": group_key, "group": os_group_key, "dash": [4, 4],
            })
            group_key -= 1

    for info in mod_info:
        parent = subsys_keys[info["subsystem"]] if info["is_grouped"] else os_group_key
        module_keys[info["name"]] = node_key
        node_data.append({
            "key": node_key, "name": info["name"],
            "loc": f"{info['x']} {info['y']}",
            "leftArray": [{"portColor": "#66d6d1", "portId": "left0"}],
            "topArray": [], "bottomArray": [],
            "rightArray": [{"portColor": "#6cafdb", "portId": "right0"}],
            "group": parent, "mod": "mod", "lang": lang_label,
        })
        node_key += 1

    # EXT-узлы
    left_used: list[tuple[float, float]] = []
    right_used: list[tuple[float, float]] = []
    mid_col = grid_cols / 2.0

    def _avail_y(used: list[tuple[float, float]], pref: float, h: float) -> float:
        if not used:
            return pref
        for ys, ye in sorted(used):
            if pref + h < ys or pref > ye:
                continue
            pref = max(pref, ye + 5)
        return pref

    for info in mod_info:
        mk = module_keys[info["name"]]
        is_left = info["subsys_col"] < mid_col

        for j, ep_type in enumerate(info["types"]):
            ek = node_key
            en = _ext_interface_name(ep_type, link_counter)
            pref_y = info["y"] + j * 50

            if is_left:
                ex, ey = 0, _avail_y(left_used, pref_y, ext_h)
                left_used.append((ey, ey + ext_h))
                node_data.append({
                    "key": ek, "name": en, "loc": f"{ex} {ey}",
                    "leftArray": [], "topArray": [], "bottomArray": [],
                    "rightArray": [{"portColor": "#6cafdb", "portId": "right0"}],
                    "figure": "Arrow4", "mod": "mod",
                })
                link_data.append({
                    "from": ek, "to": mk, "fromPort": "right0", "toPort": "left0",
                    "points": _orthogonal_lr(ex + ext_w, ey + ext_h / 2, info["x"], info["y"] + mod_h / 2, "right_to_left"),
                    "text": f"d{link_counter}", "dash": None,
                })
            else:
                ex, ey = graph_right + 90, _avail_y(right_used, pref_y, ext_h)
                right_used.append((ey, ey + ext_h))
                node_data.append({
                    "key": ek, "name": en, "loc": f"{ex} {ey}",
                    "leftArray": [{"portColor": "#6cafdb", "portId": "left0"}],
                    "topArray": [], "bottomArray": [], "rightArray": [],
                    "figure": "Arrow3", "angle": 180, "mod": "mod",
                })
                link_data.append({
                    "from": ek, "to": mk, "fromPort": "left0", "toPort": "right0",
                    "points": _orthogonal_lr(ex, ey + ext_h / 2, info["x"] + mod_w, info["y"] + mod_h / 2, "left_to_right"),
                    "text": f"d{link_counter}", "dash": None,
                })

            node_key += 1
            link_counter += 1

    cert = {
        "class": "GraphLinksModel",
        "copiesArrays": True, "copiesArrayObjects": True,
        "linkFromPortIdProperty": "fromPort", "linkToPortIdProperty": "toPort",
        "nodeDataArray": node_data, "linkDataArray": link_data,
    }

    os.makedirs(output_path, exist_ok=True)
    out_file = os.path.join(output_path, "attack_surface.json")
    with open(out_file, "w", encoding="utf-8") as f:
        json.dump(cert, f, ensure_ascii=False)
    return out_file


# ---------------------------------------------------------------------------
# SVG
# ---------------------------------------------------------------------------

def generate_svg_graph(
    entry_points: dict[str, Any],
    output_path: str,
    project_name: str,
    language: str,
    minimize_ext: bool = True,
    model_name: str = "gpt-4o-mini",
    logger: Logger | None = None,
) -> str:
    """Генерация графа поверхности атаки в формате SVG."""
    modules = _group_into_modules(entry_points, language)
    modules_with_eps = {k: v for k, v in modules.items() if v.get("entry_points")}

    if not modules_with_eps:
        os.makedirs(output_path, exist_ok=True)
        svg_path = os.path.join(output_path, "attack_surface.svg")
        with open(svg_path, "w", encoding="utf-8") as f:
            f.write(
                '<?xml version="1.0" encoding="UTF-8"?>\n'
                '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 400 200" width="400" height="200">\n'
                '  <rect width="100%" height="100%" fill="white"/>\n'
                '  <text x="200" y="100" text-anchor="middle" font-family="Arial" font-size="14">'
                'Точки входа не найдены</text>\n'
                '</svg>'
            )
        return svg_path

    if minimize_ext and logger:
        modules_with_eps = _minimize_ext(modules_with_eps, model_name, logger)

    mod_w, mod_h, ext_w, ext_h = 100, 35, 80, 25
    left_margin, subsys_w, v_sp, top_margin = 120, 150, 20, 50

    subsystem_data: list[dict[str, Any]] = []
    for mn, md in modules_with_eps.items():
        utypes = sorted({t for ep in md["entry_points"] for t in ep["types"]})
        h = max(70, 40 + len(utypes) * 35)
        subsystem_data.append({"name": mn, "data": md, "types": utypes, "height": h})

    cur_y = top_margin
    positions: list[dict[str, Any]] = []
    for sub in subsystem_data:
        positions.append({
            "sub_x": left_margin, "sub_y": cur_y, "sub_height": sub["height"],
            "mod_x": left_margin + 25, "mod_y": cur_y + 25, **sub,
        })
        cur_y += sub["height"] + v_sp

    svg_w = left_margin + subsys_w + 50
    svg_h = cur_y + 30
    lang_label = language[:2].lower() if language else ""

    svg = (
        f'<?xml version="1.0" encoding="UTF-8"?>\n'
        f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {svg_w} {svg_h}" '
        f'width="{svg_w}" height="{svg_h}">\n'
        f'  <defs>\n'
        f'    <marker id="arrowhead" markerWidth="8" markerHeight="6" refX="7" refY="3" orient="auto">\n'
        f'      <polygon points="0 0, 8 3, 0 6" fill="#000"/>\n'
        f'    </marker>\n'
        f'  </defs>\n'
        f'  <rect width="100%" height="100%" fill="white"/>\n'
        f'  <text x="{svg_w / 2}" y="25" text-anchor="middle" font-family="Arial, sans-serif" '
        f'font-size="14" fill="#000">{project_name}</text>\n'
    )

    lc = 1
    for pos in positions:
        sx, sy, sh = pos["sub_x"], pos["sub_y"], pos["sub_height"]
        mx, my, mn = pos["mod_x"], pos["mod_y"], pos["name"]
        types = pos["types"]

        svg += (
            f'  <rect x="{sx}" y="{sy}" width="{subsys_w}" height="{sh}" '
            f'fill="none" stroke="#000" stroke-width="1" stroke-dasharray="4,4"/>\n'
            f'  <text x="{sx + 5}" y="{sy + 12}" font-family="Arial, sans-serif" '
            f'font-size="8" fill="#000">Подсистема {mn}</text>\n'
            f'  <rect x="{mx}" y="{my}" width="{mod_w}" height="{mod_h}" '
            f'fill="white" stroke="#000" stroke-width="2"/>\n'
            f'  <text x="{mx + mod_w / 2}" y="{my + mod_h / 2 + 4}" text-anchor="middle" '
            f'font-family="Arial, sans-serif" font-size="9" fill="#000">{mn[:10]}</text>\n'
            f'  <text x="{mx + mod_w - 3}" y="{my + 10}" text-anchor="end" '
            f'font-family="Arial, sans-serif" font-size="7" fill="#666">{lang_label}</text>\n'
        )

        for j, ep_type in enumerate(types):
            en = _ext_interface_name(ep_type, lc)
            ex, ey = 10, sy + 20 + j * 35

            svg += (
                f'  <polygon points="{ex},{ey} {ex + ext_w - 15},{ey} {ex + ext_w},{ey + ext_h / 2} '
                f'{ex + ext_w - 15},{ey + ext_h} {ex},{ey + ext_h}" '
                f'fill="white" stroke="#000" stroke-width="1"/>\n'
                f'  <text x="{ex + ext_w / 2 - 7}" y="{ey + ext_h / 2 + 3}" text-anchor="middle" '
                f'font-family="Arial, sans-serif" font-size="7" fill="#000">{en}</text>\n'
            )

            atx = ex + ext_w
            aty = ey + ext_h / 2
            cx = atx + 8
            mcy = my + mod_h / 2
            tx = sx - 5

            svg += (
                f'  <circle cx="{cx}" cy="{aty}" r="3" fill="white" stroke="#000" stroke-width="1"/>\n'
                f'  <line x1="{atx}" y1="{aty}" x2="{cx - 3}" y2="{aty}" stroke="#000" stroke-width="1"/>\n'
                f'  <path d="M {cx + 3} {aty} L {tx} {aty} L {tx} {mcy} L {mx} {mcy}" '
                f'fill="none" stroke="#000" stroke-width="1" marker-end="url(#arrowhead)"/>\n'
                f'  <text x="{cx + 5}" y="{aty - 4}" font-family="Arial, sans-serif" '
                f'font-size="6" fill="#000">d{lc}</text>\n'
            )
            lc += 1

    svg += "</svg>\n"

    os.makedirs(output_path, exist_ok=True)
    svg_path = os.path.join(output_path, "attack_surface.svg")
    with open(svg_path, "w", encoding="utf-8") as f:
        f.write(svg)
    return svg_path


# ---------------------------------------------------------------------------
# Единая точка входа
# ---------------------------------------------------------------------------

def generate_attack_surface_graph(
    entry_points: dict[str, Any],
    output_path: str,
    project_name: str,
    language: str = "python",
    output_format: str = "svg",
    minimize_ext: bool = True,
    model_name: str = "gpt-4o-mini",
    logger: Logger | None = None,
) -> str:
    """Сгенерировать граф поверхности атаки.

    :param output_format: ``"svg"`` или ``"cert"``
    """
    if output_format == "cert":
        return generate_cert_graph(
            entry_points, output_path, project_name, language,
            minimize_ext=minimize_ext, model_name=model_name, logger=logger,
        )
    return generate_svg_graph(
        entry_points, output_path, project_name, language,
        minimize_ext=minimize_ext, model_name=model_name, logger=logger,
    )
