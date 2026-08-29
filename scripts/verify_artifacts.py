"""Проверка артефактов, созданных CLI-верификацией attack-surface.

Проходит по каталогу результатов и проверяет:
- JSON-файлы корректно парсятся и имеют ожидаемую структуру;
- CERT-графы (GoJS GraphLinksModel) содержат nodeDataArray/linkDataArray;
- HTML-отчёты и SVG-файлы существуют;
- YAML-экспорт Threagile содержит технические активы и потоки данных.

Запуск: python verify_artifacts.py <каталог-результатов>
"""

from __future__ import annotations

import json
import sys
from pathlib import Path


def _check_json(path: Path, required_keys: tuple[str, ...]) -> list[str]:
    """Проверить, что файл — валидный JSON с требуемыми ключами."""
    try:
        with open(path, encoding="utf-8") as fh:
            data = json.load(fh)
    except (OSError, json.JSONDecodeError) as exc:
        return [f"{path}: невалидный JSON: {exc}"]

    errors = [f"{path}: отсутствует ключ '{key}'" for key in required_keys if key not in data]
    return errors


def _check_cert(path: Path) -> list[str]:
    """Проверить CERT-граф (GoJS GraphLinksModel)."""
    errors = _check_json(path, ("class", "nodeDataArray", "linkDataArray"))
    if errors:
        return errors
    try:
        with open(path, encoding="utf-8") as fh:
            data = json.load(fh)
    except (OSError, json.JSONDecodeError) as exc:
        return [f"{path}: невалидный JSON: {exc}"]
    if data.get("class") != "GraphLinksModel":
        return [f"{path}: class != GraphLinksModel"]
    return []


def _check_svg(path: Path) -> list[str]:
    """Проверить, что файл — SVG с декларацией."""
    if not path.exists():
        return [f"{path}: файл не найден"]
    content = path.read_text(encoding="utf-8", errors="ignore")
    if "<svg" not in content:
        return [f"{path}: нет тега <svg>"]
    return []


def _check_html(path: Path) -> list[str]:
    """Проверить HTML-отчёт."""
    if not path.exists():
        return [f"{path}: файл не найден"]
    content = path.read_text(encoding="utf-8", errors="ignore")
    if "<html" not in content and "<!doctype" not in content.lower():
        return [f"{path}: нет признаков HTML"]
    return []


def _check_yaml(path: Path) -> list[str]:
    """Проверить YAML-экспорт Threagile (наличие ключевых секций)."""
    if not path.exists():
        return [f"{path}: файл не найден"]
    content = path.read_text(encoding="utf-8", errors="ignore")
    errors: list[str] = []
    for section in ("technical_assets:", "data_flows:"):
        if section not in content:
            errors.append(f"{path}: отсутствует секция {section}")
    return errors


def main(root: str) -> int:
    root_dir = Path(root)
    if not root_dir.is_dir():
        print(f"Каталог результатов не найден: {root_dir}")
        return 1

    errors: list[str] = []
    paths = sorted(root_dir.rglob("*"))

    # Ключевые имена артефактов → проверка
    for path in paths:
        name = path.name
        if not path.is_file():
            continue
        if name == "entry_points.json":
            errors.extend(_check_json(path, ("project", "language", "entry_points")))
        elif name == "attack_surface.json":
            errors.extend(_check_cert(path))
        elif name == "attack_surface.svg":
            errors.extend(_check_svg(path))
        elif name == "entry_points_report.html":
            errors.extend(_check_html(path))
        elif name == "project_graph.json":
            errors.extend(_check_json(path, ("project", "repos", "links")))
        elif name == "project_scan.json":
            errors.extend(_check_json(path, ("project", "repos", "edges")))
        elif name == "project_attack_surface.json":
            errors.extend(_check_cert(path))
        elif name == "project_attack_surface.svg":
            errors.extend(_check_svg(path))
        elif name.endswith("_call_graph.json"):
            errors.extend(_check_cert(path))
        elif name.endswith("_call_graph_stats.json"):
            errors.extend(_check_json(path, ("total_nodes",)))
        elif name == "threagile-export.yaml":
            errors.extend(_check_yaml(path))

    # Дополнительная проверка: нашлись ли какие-то артефакты вообще
    known = ["entry_points.json", "attack_surface.json", "project_scan.json"]
    if not any(path.name in known for path in paths):
        errors.append(f"{root_dir}: не найдено ни одного известного артефакта")

    if errors:
        print(f"Ошибок проверки артефактов: {len(errors)}")
        for error in errors:
            print(f"  - {error}")
        return 1

    print(f"Артефакты проверены успешно ({sum(1 for p in paths if p.is_file())} файлов).")
    return 0


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Использование: python verify_artifacts.py <каталог-результатов>")
        sys.exit(2)
    sys.exit(main(sys.argv[1]))
