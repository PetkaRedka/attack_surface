"""Тесты кросс-репозиторного связывания эндпоинтов."""

from attack_surface._linker import CrossRepoLinker, build_patterns, kind_compatible
from attack_surface._project_config import LinkConfig, ProjectConfig, RepoConfig


def _make_config(tmp_path, links):
    for name in ("frontend", "backend"):
        (tmp_path / name).mkdir(exist_ok=True)
    repos = [
        RepoConfig(name="frontend", path=str(tmp_path / "frontend"), language="javascript", role="ui"),
        RepoConfig(name="backend", path=str(tmp_path / "backend"), language="csharp", role="api"),
    ]
    link_configs = [
        LinkConfig(from_repo=l["from"], to_repo=l["to"], type=l["type"]) for l in links
    ]
    return ProjectConfig(project="x", repos=repos, links=link_configs)


def _server_ep():
    return {
        "node_id": "b1",
        "function_name": "CreateOrder",
        "file_path": "/backend/Orders.cs",
        "start_line": 10,
        "entry_point_type": "http_request",
        "interface_kind": "http",
        "interface_role": "server",
        "signature": "POST /api/v1/orders",
        "signature_aliases": ["/api/v1/orders", "orders"],
    }


def test_build_patterns_http():
    """Тест: построение паттернов для HTTP-сигнатуры."""
    patterns = build_patterns("POST /api/v1/orders", ["orders"], "http")
    assert "/api/v1/orders" in patterns
    assert "orders" in patterns
    assert "POST /api/v1/orders" in patterns


def test_kind_compatible():
    """Тест: совместимость interface_kind и типа связи."""
    assert kind_compatible("http", "http")
    assert kind_compatible("pinvoke", "ffi")
    assert kind_compatible("http", "reverse-proxy")
    assert kind_compatible("file", "nfs")
    assert kind_compatible("email", "email")
    assert not kind_compatible("http", "grpc")
    assert not kind_compatible("email", "http")
    assert not kind_compatible("", "http")


def test_find_links_forward(tmp_path):
    """Тест: прямой проход находит обращение к эндпоинту."""
    config = _make_config(tmp_path, [{"from": "frontend", "to": "backend", "type": "http"}])
    (tmp_path / "frontend" / "api.js").write_text("fetch('/api/v1/orders');\n", encoding="utf-8")

    linker = CrossRepoLinker(config, bidirectional=False)
    edges = linker.find_links({"backend": [_server_ep()], "frontend": []})

    assert len(edges) >= 1
    assert edges[0].server_node_id == "b1"
    assert edges[0].client_file.endswith("api.js")


def test_no_links_when_no_match(tmp_path):
    """Тест: без совпадений связи не создаются."""
    config = _make_config(tmp_path, [{"from": "frontend", "to": "backend", "type": "http"}])
    (tmp_path / "frontend" / "api.js").write_text("fetch('/other/path');\n", encoding="utf-8")

    linker = CrossRepoLinker(config, bidirectional=False)
    edges = linker.find_links({"backend": [_server_ep()], "frontend": []})

    assert len(edges) == 0


def _client_ep():
    return {
        "node_id": "f1",
        "function_name": "fetchOrders",
        "file_path": "/frontend/src/api.js",
        "start_line": 3,
        "entry_point_type": "http_request",
        "interface_kind": "http",
        "interface_role": "client",
        "signature": "GET /api/v1/orders",
        "signature_aliases": ["/api/v1/orders"],
    }


def test_find_authoritative_links(tmp_path):
    """Тест: доверенная связь сопоставляет серверные и клиентские эндпоинты."""
    config = _make_config(tmp_path, [{"from": "frontend", "to": "backend", "type": "http"}])

    linker = CrossRepoLinker(config)
    edges = linker.find_authoritative_links({
        "backend": [_server_ep()],
        "frontend": [_client_ep()],
    })

    assert len(edges) == 1
    edge = edges[0]
    assert edge.match_kind == "authoritative"
    assert edge.server_node_id == "b1"
    assert edge.client_node_id == "f1"


def test_find_authoritative_links_without_endpoints(tmp_path):
    """Тест: связь без найденных эндпоинтов фиксируется на уровне репозиториев."""
    config = _make_config(tmp_path, [{"from": "frontend", "to": "backend", "type": "http"}])

    linker = CrossRepoLinker(config)
    edges = linker.find_authoritative_links({"backend": [], "frontend": []})

    assert len(edges) == 1
    assert edges[0].server_node_id == ""
    assert edges[0].client_node_id == ""
    assert edges[0].server_repo == "backend"
    assert edges[0].client_repo == "frontend"


def test_find_authoritative_links_matches_by_signature(tmp_path):
    """Тест: эндпоинты сопоставляются по пересечению сигнатур."""
    config = _make_config(tmp_path, [{"from": "frontend", "to": "backend", "type": "http"}])
    server = {**_server_ep(), "signature_aliases": ["/api/v1/orders"]}
    client = {**_client_ep(), "signature": "GET /api/v1/orders", "signature_aliases": ["/api/v1/orders"]}

    linker = CrossRepoLinker(config)
    edges = linker.find_authoritative_links({"backend": [server], "frontend": [client]})

    assert len(edges) == 1
    assert edges[0].server_node_id == "b1"
    assert edges[0].client_node_id == "f1"


def test_find_authoritative_links_no_signature_match(tmp_path):
    """Тест: при несовпадающих сигнатурах связь остаётся на уровне репозиториев."""
    config = _make_config(tmp_path, [{"from": "frontend", "to": "backend", "type": "http"}])
    server = {**_server_ep(), "signature_aliases": []}
    client = {**_client_ep(), "signature": "GET /api/v1/users", "signature_aliases": []}

    linker = CrossRepoLinker(config)
    edges = linker.find_authoritative_links({"backend": [server], "frontend": [client]})

    assert len(edges) == 1
    assert edges[0].server_node_id == ""
    assert edges[0].client_node_id == ""
