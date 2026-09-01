"""Тесты кэша результатов по версиям."""

import json
from types import SimpleNamespace

from trailmark.models import EdgeKind, NodeKind

from attack_surface._cache import (
    CacheStore,
    dump_graph_projection,
    links_hash_for,
    load_graph_projection,
)


def _fake_graph():
    """Небольшой граф с атрибутами, как у trailmark."""
    nodes = {
        "n1": SimpleNamespace(
            id="n1", name="handler", kind=NodeKind.FUNCTION,
            location=SimpleNamespace(file_path="a.py", start_line=1, end_line=5),
        ),
        "n2": SimpleNamespace(
            id="n2", name="helper", kind=NodeKind.FUNCTION,
            location=SimpleNamespace(file_path="a.py", start_line=7, end_line=9),
        ),
        "c1": SimpleNamespace(
            id="c1", name="Klass", kind=NodeKind.CLASS,
            location=SimpleNamespace(file_path="a.py", start_line=11, end_line=20),
        ),
    }
    edges = [
        SimpleNamespace(source_id="n1", target_id="n2", kind=EdgeKind.CALLS),
        SimpleNamespace(source_id="n2", target_id="c1", kind=EdgeKind.TYPE_USES),
    ]
    return SimpleNamespace(nodes=nodes, edges=edges, language="python")


def test_links_hash_for():
    """Тест: хэш совокупной версии зависит от версий всех репозиториев."""
    first = links_hash_for({"a": "v1", "b": "v2"})
    assert first == links_hash_for({"b": "v2", "a": "v1"})  # порядок не важен
    assert first != links_hash_for({"a": "v1", "b": "v3"})
    assert first != links_hash_for({"a": "v1"})


def test_graph_projection_roundtrip():
    """Тест: проекция графа восстанавливается в совместимый адаптер."""
    data = dump_graph_projection(_fake_graph())

    graph = load_graph_projection(data)

    assert graph.language == "python"
    assert set(graph.nodes) == {"n1", "n2", "c1"}
    assert graph.nodes["n1"].name == "handler"
    assert graph.nodes["n1"].kind == NodeKind.FUNCTION
    assert graph.nodes["n1"].location.file_path == "a.py"
    assert graph.edges[0].kind == EdgeKind.CALLS
    assert graph.edges[1].kind == EdgeKind.TYPE_USES


def test_graph_projection_supports_pipeline_helpers():
    """Тест: адаптер графа работает с хелперами пайплайна."""
    from attack_surface._project_pipeline import _call_edges, _node_names, _resolve_node

    graph = load_graph_projection(dump_graph_projection(_fake_graph()))

    assert _node_names(graph) == {"n1": "handler", "n2": "helper"}
    assert _call_edges(graph) == [("n1", "n2")]
    assert _resolve_node(graph, "a.py", 2) == "n1"
    assert _resolve_node(graph, "a.py", 15) == "c1"


def _store(tmp_path, project="demo") -> CacheStore:
    return CacheStore(str(tmp_path), project)


def test_save_load_repo(tmp_path):
    """Тест: запись репозитория сохраняется и загружается по версии."""
    store = _store(tmp_path)
    store.save_repo("backend", "v1", {"n1": {}}, {"n1": {}}, {"nodes": [], "edges": []}, "python")

    cached = store.load_repo("backend", "v1")

    assert cached is not None
    assert cached["version"] == "v1"
    assert cached["language"] == "python"
    assert store.load_repo("backend", "v2") is None


def test_load_previous_repo(tmp_path):
    """Тест: загружается последняя запись с другой версией."""
    store = _store(tmp_path)
    store.save_repo("backend", "v1", {"a": {}}, {}, {"nodes": [], "edges": []}, "python")
    store.save_repo("backend", "v2", {"b": {}}, {}, {"nodes": [], "edges": []}, "python")

    prev = store.load_previous_repo("backend", "v3")

    assert prev is not None
    assert prev["version"] == "v2"


def test_save_load_links(tmp_path):
    """Тест: связи сохраняются и загружаются по хэшу совокупной версии."""
    store = _store(tmp_path)
    store.save_links("hash1", [{"server_repo": "b"}])

    assert store.load_links("hash1") == {"edges": [{"server_repo": "b"}]}
    assert store.load_links("hash2") is None


def test_load_previous_links(tmp_path):
    """Тест: загружаются последние связи другой совокупной версии."""
    store = _store(tmp_path)
    store.save_links("hash1", [{"server_repo": "b"}])
    store.save_links("hash2", [{"server_repo": "c"}])

    prev = store.load_previous_links("hash3")

    assert prev == {"edges": [{"server_repo": "c"}]}


def test_current_roundtrip(tmp_path):
    """Тест: текущие версии и хэш связей сохраняются и читаются."""
    store = _store(tmp_path)
    store.save_current({"a": "v1"}, "hash1")

    current = store.load_current()

    assert current == {"repos": {"a": "v1"}, "links_hash": "hash1"}


def test_save_is_atomic(tmp_path):
    """Тест: запись не оставляет временных файлов."""
    store = _store(tmp_path)
    path = store.save_repo("backend", "v1", {}, {}, {"nodes": [], "edges": []}, "python")

    assert path.endswith("v1.json")
    assert not path.endswith(".tmp")
    import os

    assert os.listdir(os.path.dirname(path)) == ["v1.json"]
