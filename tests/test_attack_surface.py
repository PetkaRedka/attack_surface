"""Тесты вычисления поверхности атаки кросс-репо графа."""

from attack_surface._attack_surface import compute_attack_surface
from attack_surface._linker import CrossRepoEdge
from attack_surface._project_config import LinkConfig


def _cross_edge():
    return CrossRepoEdge(
        link=LinkConfig(from_repo="frontend", to_repo="backend", type="http"),
        server_repo="backend",
        server_node_id="b1",
        server_function_name="CreateOrder",
        server_signature="/api/v1/orders",
        client_repo="frontend",
        client_file="api.js",
        client_line=1,
        client_node_id="f1",
    )


def test_reachability_through_cross_edge():
    """Тест: достижимость распространяется через межрепо-связь."""
    call_edges = [("backend", "b1", "b2"), ("backend", "b2", "b3")]
    cross_edges = [_cross_edge()]
    sources = [("frontend", "f1"), ("backend", "b1")]
    node_names = {
        ("frontend", "f1"): "app",
        ("backend", "b1"): "CreateOrder",
        ("backend", "b2"): "SaveOrder",
        ("backend", "b3"): "WriteDb",
    }

    result = compute_attack_surface(call_edges, cross_edges, sources, node_names)

    reachable = {(r["repo"], r["node_id"]) for r in result.reachable}
    assert ("backend", "b3") in reachable
    assert ("frontend", "f1") in reachable


def test_chains_contain_cross_hop():
    """Тест: цепочки атак содержат межрепо-переход."""
    call_edges = [("backend", "b1", "b2")]
    cross_edges = [_cross_edge()]
    sources = [("frontend", "f1")]
    node_names = {
        ("frontend", "f1"): "app",
        ("backend", "b1"): "CreateOrder",
        ("backend", "b2"): "SaveOrder",
    }

    result = compute_attack_surface(call_edges, cross_edges, sources, node_names)

    assert len(result.chains) >= 1
    chain = result.chains[0]
    assert chain.source_repo == "frontend"
    kinds = [hop["kind"] for hop in chain.hops]
    assert "cross" in kinds


def test_sources_exposed_even_without_clients():
    """Тест: серверные эндпоинты без клиентов всё равно попадают в источники."""
    result = compute_attack_surface([], [], [("backend", "b1")], {("backend", "b1"): "Api"})

    assert len(result.sources) == 1
    assert result.sources[0]["node_id"] == "b1"
    assert ("backend", "b1") in {(r["repo"], r["node_id"]) for r in result.reachable}
