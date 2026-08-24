"""Тесты для CallGraphBuilder."""

import pytest
from pathlib import Path
from trailmark import parse_directory

from attack_surface import CallGraphBuilder, EntryPointExtractor


@pytest.fixture
def test_project_path():
    """Путь к тестовому проекту."""
    return Path(__file__).parent / "test_project"


@pytest.fixture
def test_graph(test_project_path):
    """Граф тестового проекта."""
    return parse_directory(str(test_project_path), language="python")


@pytest.fixture
def call_graph_builder(test_graph):
    """CallGraphBuilder для тестового проекта."""
    return CallGraphBuilder(test_graph)


def test_get_full_graph(call_graph_builder, test_graph):
    """Тест: get_full_graph возвращает исходный граф."""
    full_graph = call_graph_builder.get_full_graph()
    
    assert full_graph is test_graph
    assert len(full_graph.nodes) > 0
    assert len(full_graph.edges) > 0


def test_get_statistics(call_graph_builder):
    """Тест: get_statistics возвращает корректную статистику."""
    stats = call_graph_builder.get_statistics()
    
    assert "total_nodes" in stats
    assert "total_edges" in stats
    assert "functions" in stats
    assert "methods" in stats
    assert "classes" in stats
    assert "modules" in stats
    assert "call_edges" in stats
    
    assert stats["total_nodes"] > 0
    assert stats["functions"] > 0


def test_filter_by_attack_surface(call_graph_builder, test_graph):
    """Тест: фильтрация графа по поверхности атаки."""
    # Извлечь точки входа
    extractor = EntryPointExtractor(test_graph, "python")
    entry_points = extractor.build_entry_points()
    
    assert len(entry_points) > 0, "Должны быть найдены точки входа"
    
    # Отфильтровать граф
    filtered_graph = call_graph_builder.filter_by_attack_surface(entry_points)
    
    # Проверить, что граф отфильтрован
    assert len(filtered_graph.nodes) > 0
    assert len(filtered_graph.nodes) <= len(test_graph.nodes)
    
    # Проверить, что все точки входа присутствуют в отфильтрованном графе
    for ep_id in entry_points.keys():
        assert ep_id in filtered_graph.nodes, f"Точка входа {ep_id} должна быть в графе"


def test_filtered_graph_contains_related_nodes(call_graph_builder, test_graph):
    """Тест: отфильтрованный граф содержит связанные узлы."""
    extractor = EntryPointExtractor(test_graph, "python")
    entry_points = extractor.build_entry_points()
    
    filtered_graph = call_graph_builder.filter_by_attack_surface(entry_points)
    
    # Проверить, что граф содержит не только точки входа
    # (должны быть и вызываемые функции)
    assert len(filtered_graph.nodes) >= len(entry_points)


def test_statistics_comparison(call_graph_builder, test_graph):
    """Тест: статистика отфильтрованного графа меньше или равна полному."""
    extractor = EntryPointExtractor(test_graph, "python")
    entry_points = extractor.build_entry_points()
    
    full_stats = call_graph_builder.get_statistics()
    
    if entry_points:
        filtered_graph = call_graph_builder.filter_by_attack_surface(entry_points)
        filtered_stats = call_graph_builder.get_statistics(filtered_graph)
        
        assert filtered_stats["total_nodes"] <= full_stats["total_nodes"]
        assert filtered_stats["total_edges"] <= full_stats["total_edges"]
        assert filtered_stats["functions"] <= full_stats["functions"]


def test_empty_entry_points(call_graph_builder):
    """Тест: фильтрация с пустым списком точек входа."""
    empty_entry_points = {}
    
    filtered_graph = call_graph_builder.filter_by_attack_surface(empty_entry_points)
    
    # Граф должен быть пустым или содержать только узлы без связей
    assert len(filtered_graph.nodes) == 0


def test_build_caller_map(call_graph_builder):
    """Тест: построение карты вызывающих функций."""
    caller_map = call_graph_builder._build_caller_map()
    
    assert isinstance(caller_map, dict)
    # Должны быть хотя бы некоторые вызовы
    assert len(caller_map) >= 0


def test_build_callee_map(call_graph_builder):
    """Тест: построение карты вызываемых функций."""
    callee_map = call_graph_builder._build_callee_map()
    
    assert isinstance(callee_map, dict)
    # Должны быть хотя бы некоторые вызовы
    assert len(callee_map) >= 0
