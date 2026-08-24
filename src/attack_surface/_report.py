"""Генерация HTML-отчёта по точкам входа."""

from __future__ import annotations

import os
from collections import defaultdict
from typing import Any

from attack_surface._models import ENTRY_POINT_DISPLAY_NAMES, display_name


def generate_html_report(
    entry_points: dict[str, Any],
    output_path: str,
    project_name: str,
    language: str,
) -> str:
    """Сгенерировать HTML-отчёт с интерфейсами точек входа.

    :returns: путь к созданному HTML-файлу.
    """
    by_type: dict[str, list[dict[str, Any]]] = defaultdict(list)

    for _fid, ep in entry_points.items():
        ep_type = ep.get("entry_point_type", "unknown")
        for src in ep.get("external_input_sources", []):
            src_type = src.get("entry_point_type")
            if src_type:
                by_type[src_type].append({
                    "function_name": ep["function_name"],
                    "file_path": ep["file_path"],
                    "start_line": ep["start_line"],
                    "source_name": src["name"],
                    "source_line": src["line_number"],
                })
        if not ep.get("external_input_sources"):
            by_type[ep_type].append({
                "function_name": ep["function_name"],
                "file_path": ep["file_path"],
                "start_line": ep["start_line"],
                "source_name": "",
                "source_line": ep["start_line"],
            })

    html = _HEADER.format(
        project_name=project_name,
        language=language,
        type_count=len(by_type),
        ep_count=len(entry_points),
        source_count=sum(len(v) for v in by_type.values()),
    )

    for ep_type, functions in sorted(by_type.items(), key=lambda x: -len(x[1])):
        dn = display_name(ep_type)
        html += f"""
        <div class="interface-type">
            <div class="interface-header" onclick="toggleContent(this)">
                <span>{dn}</span>
                <span>
                    <span class="interface-count">{len(functions)}</span>
                    <span class="arrow">▼</span>
                </span>
            </div>
            <div class="interface-content">
"""
        for func in functions:
            rel = func["file_path"].replace("\\", "/").split("/")[-3:]
            rel_str = "/".join(rel)
            html += f"""
                <div class="function-item">
                    <span class="function-name">{func["function_name"]}</span>
                    <span class="function-location">{rel_str}:{func["start_line"]}</span>
                </div>
"""
        html += "            </div>\n        </div>\n"

    html += _FOOTER

    os.makedirs(output_path, exist_ok=True)
    html_path = os.path.join(output_path, "entry_points_report.html")
    with open(html_path, "w", encoding="utf-8") as f:
        f.write(html)
    return html_path


# ---------------------------------------------------------------------------
# Шаблоны
# ---------------------------------------------------------------------------

_HEADER = """<!DOCTYPE html>
<html lang="ru">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Отчёт по точкам входа — {project_name}</title>
    <style>
        * {{ box-sizing: border-box; margin: 0; padding: 0; }}
        body {{ font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
               background: #f5f5f5; padding: 20px; line-height: 1.6; }}
        .container {{ max-width: 1200px; margin: 0 auto; }}
        h1 {{ color: #333; margin-bottom: 10px; border-bottom: 3px solid #007bff; padding-bottom: 10px; }}
        .meta {{ color: #666; margin-bottom: 30px; font-size: 14px; }}
        .interface-type {{ background: white; border: 2px solid #333; border-radius: 8px; margin-bottom: 15px; overflow: hidden; }}
        .interface-header {{ background: #333; color: white; padding: 15px 20px; cursor: pointer;
                            display: flex; justify-content: space-between; align-items: center; font-weight: bold; }}
        .interface-header:hover {{ background: #444; }}
        .interface-count {{ background: #007bff; padding: 3px 10px; border-radius: 12px; font-size: 12px; }}
        .interface-content {{ display: none; padding: 0; }}
        .interface-content.active {{ display: block; }}
        .function-item {{ padding: 12px 20px; border-bottom: 1px solid #eee;
                         display: flex; justify-content: space-between; align-items: center; }}
        .function-item:last-child {{ border-bottom: none; }}
        .function-item:hover {{ background: #f8f9fa; }}
        .function-name {{ font-weight: 600; color: #007bff; }}
        .function-location {{ color: #666; font-size: 13px; font-family: 'Consolas', monospace; }}
        .arrow {{ transition: transform 0.3s; }}
        .arrow.rotated {{ transform: rotate(180deg); }}
        .summary {{ background: white; border: 2px solid #333; border-radius: 8px; padding: 20px; margin-bottom: 30px; }}
        .summary h2 {{ margin-bottom: 15px; color: #333; }}
        .summary-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 15px; }}
        .summary-item {{ background: #f8f9fa; padding: 15px; border-radius: 5px; text-align: center; }}
        .summary-value {{ font-size: 32px; font-weight: bold; color: #007bff; }}
        .summary-label {{ color: #666; font-size: 14px; }}
    </style>
</head>
<body>
    <div class="container">
        <h1>Отчёт по точкам входа</h1>
        <div class="meta">
            <strong>Проект:</strong> {project_name} |
            <strong>Язык:</strong> {language} |
            <strong>Типов интерфейсов:</strong> {type_count}
        </div>
        <div class="summary">
            <h2>Сводка</h2>
            <div class="summary-grid">
                <div class="summary-item">
                    <div class="summary-value">{ep_count}</div>
                    <div class="summary-label">Всего точек входа</div>
                </div>
                <div class="summary-item">
                    <div class="summary-value">{type_count}</div>
                    <div class="summary-label">Типов интерфейсов</div>
                </div>
                <div class="summary-item">
                    <div class="summary-value">{source_count}</div>
                    <div class="summary-label">Внешних источников</div>
                </div>
            </div>
        </div>
"""

_FOOTER = """
    </div>
    <script>
        function toggleContent(header) {
            const content = header.nextElementSibling;
            const arrow = header.querySelector('.arrow');
            content.classList.toggle('active');
            arrow.classList.toggle('rotated');
        }
    </script>
</body>
</html>
"""
