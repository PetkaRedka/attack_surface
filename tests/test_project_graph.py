"""Тесты генерации кросс-репозиторного графа."""

import json
import os

from attack_surface._attack_surface import ReachabilityResult
from attack_surface._linker import CrossRepoEdge
from attack_surface._project_config import LinkConfig, ProjectConfig, RepoConfig
from attack_surface._project_graph import (
    build_project_graph_model,
    generate_project_graph,
    generate_project_graph_from_scan,
    generate_repo_topology_graph,
)


def _config(tmp_path):
    for name in ("frontend", "backend"):
        (tmp_path / name).mkdir(exist_ok=True)
    repos = [
        RepoConfig(name="frontend", path=str(tmp_path / "frontend"), language="javascript", role="ui"),
        RepoConfig(name="backend", path=str(tmp_path / "backend"), language="csharp", role="api"),
    ]
    links = [LinkConfig(from_repo="frontend", to_repo="backend", type="http")]
    return ProjectConfig(project="x", repos=repos, links=links)


def _entry_points():
    return {
        "frontend": {
            "f1": {
                "function_name": "fetchOrders",
                "file_path": "/frontend/src/api.js",
                "start_line": 1,
                "end_line": 3,
                "entry_point_type": "http_request",
                "external_input_sources": [{"name": "fetch", "entry_point_type": "http_request"}],
            }
        },
        "backend": {
            "b1": {
                "function_name": "CreateOrder",
                "file_path": "/backend/Orders.cs",
                "start_line": 10,
                "end_line": 20,
                "entry_point_type": "http_request",
                "external_input_sources": [],
            }
        },
    }


def _edge():
    return CrossRepoEdge(
        link=LinkConfig(from_repo="frontend", to_repo="backend", type="http"),
        server_repo="backend",
        server_node_id="b1",
        server_function_name="CreateOrder",
        server_signature="/api/v1/orders",
        client_repo="frontend",
        client_file="/frontend/src/api.js",
        client_line=2,
    )


def test_build_model_structure(tmp_path):
    """Тест: модель графа содержит репозитории и связи."""
    model = build_project_graph_model(_config(tmp_path), _entry_points(), [_edge()])

    assert model["project"] == "x"
    assert {r["name"] for r in model["repos"]} == {"frontend", "backend"}
    assert len(model["links"]) == 1
    assert model["links"][0]["type"] == "http"
    assert len(model["links"][0]["edges"]) == 1


def test_generate_project_graph_svg(tmp_path):
    """Тест: генерация машиночитаемого JSON и SVG."""
    output_dir = str(tmp_path / "out")
    artifacts = generate_project_graph(
        _config(tmp_path),
        _entry_points(),
        [_edge()],
        output_dir,
        output_format="svg",
    )

    assert "project_graph.json" in artifacts
    assert "project_attack_surface.svg" in artifacts
    assert os.path.exists(artifacts["project_graph.json"])

    with open(artifacts["project_graph.json"], "r", encoding="utf-8") as fh:
        data = json.load(fh)
    assert data["project"] == "x"


def test_generate_project_graph_cert(tmp_path):
    """Тест: генерация CERT-графа (GoJS GraphLinksModel)."""
    output_dir = str(tmp_path / "out")
    artifacts = generate_project_graph(
        _config(tmp_path),
        _entry_points(),
        [_edge()],
        output_dir,
        output_format="cert",
    )

    assert "project_attack_surface.json" in artifacts
    with open(artifacts["project_attack_surface.json"], "r", encoding="utf-8") as fh:
        data = json.load(fh)
    assert data["class"] == "GraphLinksModel"
    assert "nodeDataArray" in data
    assert "linkDataArray" in data


def test_generate_project_graph_from_scan(tmp_path):
    """Тест: пересборка CERT/SVG из сохранённого project_scan.json."""
    config = _config(tmp_path)
    edges = [_edge()]
    attack_surface = ReachabilityResult(
        sources=[{"repo": "backend", "node_id": "b1"}],
        reachable=[{"repo": "backend", "node_id": "b1"}],
        chains=[],
    )

    # Формируем project_scan.json так же, как это делает project
    scan = {
        "project": "x",
        "repos": [
            {
                "name": "frontend", "language": "javascript", "role": "ui",
                "path": str(tmp_path / "frontend"),
                "entry_points": _entry_points()["frontend"],
                "interfaces": {},
            },
            {
                "name": "backend", "language": "c_sharp", "role": "api",
                "path": str(tmp_path / "backend"),
                "entry_points": _entry_points()["backend"],
                "interfaces": {},
            },
        ],
        "links": [link.to_dict() for link in config.links],
        "edges": [e.to_dict() for e in edges],
        "attack_surface": attack_surface.to_dict(),
    }
    scan_path = tmp_path / "project_scan.json"
    with open(scan_path, "w", encoding="utf-8") as fh:
        json.dump(scan, fh)

    output_dir = str(tmp_path / "out")
    artifacts = generate_project_graph_from_scan(
        str(scan_path), output_dir, output_format="cert"
    )

    assert "project_graph.json" in artifacts
    assert "project_attack_surface.json" in artifacts
    with open(artifacts["project_attack_surface.json"], "r", encoding="utf-8") as fh:
        data = json.load(fh)
    assert data["class"] == "GraphLinksModel"
    assert len(data["linkDataArray"]) == 1


def test_generate_repo_topology_graph(tmp_path):
    """Тест: топология из конфига рисует связи на уровне репозиториев."""
    output_dir = str(tmp_path / "out")
    artifacts = generate_repo_topology_graph(
        _config(tmp_path), output_dir, output_format="both"
    )

    assert "project_topology.json" in artifacts
    assert "project_topology.svg" in artifacts

    with open(artifacts["project_topology.json"], "r", encoding="utf-8") as fh:
        cert = json.load(fh)
    assert cert["class"] == "GraphLinksModel"
    assert len(cert["linkDataArray"]) == 1  # связь между группами репозиториев

    with open(artifacts["project_topology.svg"], "r", encoding="utf-8") as fh:
        svg = fh.read()
    assert "http" in svg  # подпись ребра на уровне репозиториев
