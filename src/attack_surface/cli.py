"""CLI-интерфейс для модуля поверхности атаки."""

from __future__ import annotations

import argparse
import json
import os
import sys

from attack_surface._call_graph import CallGraphBuilder
from attack_surface._extractor import EntryPointExtractor
from attack_surface._graph import generate_attack_surface_graph
from attack_surface._logger import Logger
from attack_surface._report import generate_html_report


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="attack-surface",
        description="Построение поверхности атаки проекта на базе trailmark.",
    )
    sub = p.add_subparsers(dest="command", required=True)

    # --- scan -----------------------------------------------------------
    scan = sub.add_parser("scan", help="Сканировать проект и найти точки входа")
    scan.add_argument("--project-path", required=True, help="Путь к исходному коду")
    scan.add_argument("--language", default="auto", help="Язык (auto|python|cpp|…)")
    scan.add_argument("--output-dir", default="./attack_surface_output", help="Каталог результатов")
    scan.add_argument("--html-report", action="store_true", help="Генерировать HTML-отчёт")
    scan.add_argument("--graph", action="store_true", help="Генерировать граф поверхности атаки")
    scan.add_argument(
        "--graph-format", choices=["svg", "cert"], default="svg",
        help="Формат графа: svg или cert (JSON GoJS)",
    )
    scan.add_argument("--model-name", default=None, help="Имя LLM-модели для минимизации EXT")
    scan.add_argument("--no-minimize-ext", action="store_true", help="Не минимизировать EXT")

    # --- graph-from-json ------------------------------------------------
    gfj = sub.add_parser("graph-from-json", help="Построить граф из существующего JSON")
    gfj.add_argument("--entrypoints-json", required=True, help="Путь к entry_points.json")
    gfj.add_argument("--output-dir", required=True, help="Каталог результатов")
    gfj.add_argument("--project-name", default="Project", help="Имя проекта")
    gfj.add_argument("--language", default="python", help="Язык проекта")
    gfj.add_argument(
        "--graph-format", choices=["svg", "cert"], default="svg",
        help="Формат графа",
    )
    gfj.add_argument("--model-name", default=None, help="Имя LLM-модели")
    gfj.add_argument("--no-minimize-ext", action="store_true", help="Не минимизировать EXT")

    # --- call-graph -----------------------------------------------------
    cg = sub.add_parser("call-graph", help="Построить граф вызовов всего проекта")
    cg.add_argument("--project-path", required=True, help="Путь к исходному коду")
    cg.add_argument("--language", default="auto", help="Язык (auto|python|cpp|…)")
    cg.add_argument("--output-dir", default="./call_graph_output", help="Каталог результатов")
    cg.add_argument(
        "--filter-by-attack-surface", action="store_true",
        help="Фильтровать граф по элементам связанным с поверхностью атаки"
    )
    cg.add_argument(
        "--format", choices=["svg", "cert", "stats"], default="svg",
        help="Формат вывода: svg (визуализация), cert (CERT JSON GoJS), stats (статистика)"
    )

    return p


def main(argv: list[str] | None = None) -> None:
    """Точка входа CLI."""
    args = _build_parser().parse_args(argv)

    if args.command == "scan":
        _cmd_scan(args)
    elif args.command == "graph-from-json":
        _cmd_graph_from_json(args)
    elif args.command == "call-graph":
        _cmd_call_graph(args)


# ---------------------------------------------------------------------------
# Команды
# ---------------------------------------------------------------------------

def _cmd_scan(args: argparse.Namespace) -> None:
    from trailmark import parse_directory

    project_path = os.path.abspath(args.project_path)
    project_name = os.path.basename(project_path)
    output_dir = os.path.abspath(args.output_dir)
    os.makedirs(output_dir, exist_ok=True)

    log_path = os.path.join(output_dir, "log", "attack_surface.log")
    logger = Logger(log_path)

    logger.print_console(f"Сканирование проекта: {project_name}")
    logger.print_console(f"Язык: {args.language}")

    # Построить граф кода через trailmark
    logger.print_console("[1/3] Построение графа кода через trailmark…")
    graph = parse_directory(project_path, language=args.language)
    logger.print_console(f"  Узлов: {len(graph.nodes)}, рёбер: {len(graph.edges)}")

    language = graph.language if graph.language != "polyglot" else args.language

    # Извлечь точки входа
    logger.print_console("[2/3] Извлечение точек входа…")
    extractor = EntryPointExtractor(graph, language)
    candidates = extractor.build_entry_points()
    logger.print_console(f"  Найдено кандидатов: {len(candidates)}")

    # Сохранить JSON
    result = {
        "project": project_name,
        "language": language,
        "total_entry_points": len(candidates),
        "entry_points": {k: v.to_dict() for k, v in candidates.items()},
    }
    json_path = os.path.join(output_dir, "entry_points.json")
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(result, f, indent=4, ensure_ascii=False)
    logger.print_console(f"  Результаты: {json_path}")

    ep_dicts = result["entry_points"]

    # Отчёты
    logger.print_console("[3/3] Генерация отчётов…")
    if args.html_report and ep_dicts:
        hp = generate_html_report(ep_dicts, output_dir, project_name, language)
        logger.print_console(f"  HTML-отчёт: {hp}")

    if args.graph and ep_dicts:
        model = args.model_name or os.getenv("OPENAI_MODEL_NAME", "gpt-4o-mini")
        gp = generate_attack_surface_graph(
            ep_dicts, output_dir, project_name, language,
            output_format=args.graph_format,
            minimize_ext=not args.no_minimize_ext,
            model_name=model,
            logger=logger,
        )
        logger.print_console(f"  Граф: {gp}")

    logger.print_console("Готово.")


def _cmd_graph_from_json(args: argparse.Namespace) -> None:
    output_dir = os.path.abspath(args.output_dir)
    os.makedirs(output_dir, exist_ok=True)
    log_path = os.path.join(output_dir, "log", "attack_surface.log")
    logger = Logger(log_path)

    logger.print_console(f"Загрузка точек входа из: {args.entrypoints_json}")
    with open(args.entrypoints_json, "r", encoding="utf-8") as f:
        data = json.load(f)

    ep = data.get("entry_points", {})
    language = data.get("language", args.language)
    logger.print_console(f"Загружено {len(ep)} точек входа")

    model = args.model_name or os.getenv("OPENAI_MODEL_NAME", "gpt-4o-mini")
    gp = generate_attack_surface_graph(
        ep, output_dir, args.project_name, language,
        output_format=args.graph_format,
        minimize_ext=not args.no_minimize_ext,
        model_name=model,
        logger=logger,
    )
    logger.print_console(f"Граф сохранён: {gp}")


def _cmd_call_graph(args: argparse.Namespace) -> None:
    """Построить граф вызовов всего проекта."""
    from trailmark import parse_directory
    from trailmark.diagram import emit_call_graph, build_engine

    project_path = os.path.abspath(args.project_path)
    project_name = os.path.basename(project_path)
    output_dir = os.path.abspath(args.output_dir)
    os.makedirs(output_dir, exist_ok=True)

    log_path = os.path.join(output_dir, "log", "call_graph.log")
    logger = Logger(log_path)

    logger.print_console(f"Построение графа вызовов: {project_name}")
    logger.print_console(f"Язык: {args.language}")

    # Построить полный граф через trailmark
    logger.print_console("[1/3] Построение графа кода через trailmark…")
    graph = parse_directory(project_path, language=args.language)
    logger.print_console(f"  Узлов: {len(graph.nodes)}, рёбер: {len(graph.edges)}")

    language = graph.language if graph.language != "polyglot" else args.language
    builder = CallGraphBuilder(graph)

    # Получить статистику полного графа
    full_stats = builder.get_statistics()
    logger.print_console(f"  Функций: {full_stats['functions']}, методов: {full_stats['methods']}")
    logger.print_console(f"  Рёбер вызовов: {full_stats['call_edges']}")

    # Фильтрация по поверхности атаки (если требуется)
    target_graph = graph
    if args.filter_by_attack_surface:
        logger.print_console("[2/3] Извлечение поверхности атаки…")
        extractor = EntryPointExtractor(graph, language)
        entry_points = extractor.build_entry_points()
        logger.print_console(f"  Найдено точек входа: {len(entry_points)}")

        if entry_points:
            logger.print_console("[3/3] Фильтрация графа по поверхности атаки…")
            target_graph = builder.filter_by_attack_surface(entry_points)
            filtered_stats = builder.get_statistics(target_graph)
            logger.print_console(f"  Отфильтрованный граф:")
            logger.print_console(f"    Узлов: {filtered_stats['total_nodes']} (было {full_stats['total_nodes']})")
            logger.print_console(f"    Рёбер: {filtered_stats['total_edges']} (было {full_stats['total_edges']})")
            logger.print_console(f"    Функций: {filtered_stats['functions']} (было {full_stats['functions']})")
        else:
            logger.print_console("  Точки входа не найдены, используется полный граф")
    else:
        logger.print_console("[2/3] Пропуск фильтрации (используется полный граф)")

    # Экспорт графа
    logger.print_console(f"[{'3' if not args.filter_by_attack_surface else '4'}/3] Экспорт графа…")
    
    if args.format == "svg":
        # Генерируем Mermaid диаграмму и сохраняем как текст
        output_path = os.path.join(output_dir, f"{project_name}_call_graph.mmd")
        engine = build_engine(project_path, args.language)
        mermaid_content = emit_call_graph(engine, focus=None, depth=10, direction="TB")
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(mermaid_content)
        logger.print_console(f"  Mermaid диаграмма: {output_path}")
        logger.print_console(f"  Используйте https://mermaid.live для визуализации")
    
    elif args.format == "cert":
        output_path = os.path.join(output_dir, f"{project_name}_call_graph.json")
        _export_cert_format(target_graph, output_path, project_name, language)
        logger.print_console(f"  CERT JSON граф: {output_path}")
    
    elif args.format == "stats":
        stats = builder.get_statistics(target_graph)
        output_path = os.path.join(output_dir, f"{project_name}_call_graph_stats.json")
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(stats, f, indent=4, ensure_ascii=False)
        logger.print_console(f"  Статистика:")
        for key, value in stats.items():
            logger.print_console(f"    {key}: {value}")
        logger.print_console(f"  Сохранено в: {output_path}")

    logger.print_console("Готово.")


def _export_cert_format(graph, output_path: str, project_name: str, language: str) -> None:
    """Экспорт графа в формат CERT JSON (GoJS GraphLinksModel)."""
    from trailmark.models import EdgeKind, NodeKind
    
    node_data_array = []
    link_data_array = []
    
    # Создать узлы для функций/методов
    node_key_map = {}
    key_counter = 1
    
    for node_id, node in graph.nodes.items():
        if node.kind in (NodeKind.FUNCTION, NodeKind.METHOD):
            loc_str = ""
            if node.location:
                loc_str = f"{node.location.file_path}:{node.location.start_line}"
            
            node_data_array.append({
                "key": key_counter,
                "text": node.name,
                "mod": "func",
                "loc": loc_str,
            })
            node_key_map[node_id] = key_counter
            key_counter += 1
    
    # Создать рёбра вызовов
    for edge in graph.edges:
        if edge.kind == EdgeKind.CALLS:
            from_key = node_key_map.get(edge.source_id)
            to_key = node_key_map.get(edge.target_id)
            
            if from_key and to_key:
                link_data_array.append({
                    "from": from_key,
                    "to": to_key,
                })
    
    # Создать JSON структуру
    cert_data = {
        "class": "GraphLinksModel",
        "nodeDataArray": node_data_array,
        "linkDataArray": link_data_array,
    }
    
    # Сохранить в файл
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(cert_data, f, indent=2, ensure_ascii=False)


if __name__ == "__main__":
    main()
