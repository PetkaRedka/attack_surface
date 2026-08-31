"""Тесты поддержки архитектурных файлов Threagile."""

import os

import yaml

from attack_surface._linker import CrossRepoEdge
from attack_surface._project_config import (
    LinkConfig,
    LinkType,
    ProjectConfig,
    RepoConfig,
    VALID_LINK_TYPES,
)
from attack_surface._threagile import (
    LINK_TYPE_TO_PROTOCOL,
    PROTOCOL_TO_LINK_TYPE,
    THREAGILE_PROTOCOLS,
    build_threagile_model,
    dump_threagile,
    link_type_for_protocol,
    load_threagile,
    protocol_for_link_type,
    save_threagile,
    update_threagile_data_flows,
)


def _config():
    return ProjectConfig(
        project="my-product",
        repos=[
            RepoConfig(name="frontend", path="/x/frontend", language="javascript", role="ui"),
            RepoConfig(name="backend", path="/x/backend", language="c_sharp", role="api"),
        ],
        links=[LinkConfig(from_repo="frontend", to_repo="backend", type="http")],
    )


def test_load_threagile(tmp_path):
    """Тест: чтение threagile.yaml в ProjectConfig."""
    content = """\
threagile_version: "1.0"
title: my-product
technical_assets:
  - id: frontend
    description: ui
    technology: javascript
  - id: backend
    description: api
    technology: c-sharp
data_flows:
  - id: flow-1
    source: frontend
    target: backend
    protocol: https
"""
    path = tmp_path / "threagile.yaml"
    path.write_text(content, encoding="utf-8")

    config = load_threagile(str(path))

    assert config.project == "my-product"
    assert config.links_authoritative is True
    assert {r.name for r in config.repos} == {"frontend", "backend"}
    assert config.get_repo("backend").language == "c_sharp"
    assert len(config.links) == 1
    assert config.links[0].type == "http"


def test_dump_threagile_structure():
    """Тест: генерация YAML содержит технические активы и потоки данных."""
    text = dump_threagile(_config())
    data = yaml.safe_load(text)

    assert data["title"] == "my-product"
    assert len(data["technical_assets"]) == 2
    assert data["technical_assets"][0]["id"] == "frontend"
    assert data["technical_assets"][1]["technology"] == "c-sharp"
    assert data["data_flows"][0]["source"] == "frontend"
    assert data["data_flows"][0]["target"] == "backend"


def test_save_threagile(tmp_path):
    """Тест: сохранение threagile.yaml в файл."""
    output = tmp_path / "out" / "threagile.yaml"
    path = save_threagile(_config(), str(output))

    assert os.path.exists(path)
    assert path.endswith("threagile.yaml")


def test_protocol_mappings():
    """Тест: маппинги между протоколами и типами связей."""
    assert link_type_for_protocol("https") == "http"
    assert link_type_for_protocol("grpc") == "grpc"
    assert link_type_for_protocol("mqtt") == "message-queue"
    assert link_type_for_protocol("smtp") == "email"
    assert link_type_for_protocol("ssh") == "ssh"
    assert link_type_for_protocol("ldaps") == "ldap"
    assert link_type_for_protocol("in-process-library-call") == "ffi"
    assert link_type_for_protocol("container-spawning") == "container"
    assert protocol_for_link_type("ffi") == "in-process-library-call"
    assert protocol_for_link_type("http") == "https"
    assert protocol_for_link_type("email") == "smtp-encrypted"


def test_protocols_exhaustive():
    """Тест: каждый протокол Threagile покрыт, а генерируемые значения валидны."""
    # Каждый допустимый протокол Threagile отображается на известный тип связи
    for protocol in THREAGILE_PROTOCOLS:
        assert link_type_for_protocol(protocol) in VALID_LINK_TYPES, protocol
    # Генерация даёт только допустимые протоколы Threagile
    for link_type in VALID_LINK_TYPES:
        assert protocol_for_link_type(link_type) in THREAGILE_PROTOCOLS, link_type


def test_protocol_round_trip():
    """Тест: протокол → тип → протокол стабилен для всех семей."""
    for protocol, link_type in PROTOCOL_TO_LINK_TYPE.items():
        if protocol in THREAGILE_PROTOCOLS and link_type != "rpc":
            # rpc отображается в unknown-protocol — обходной путь, проверяется отдельно
            assert protocol_for_link_type(link_type) in THREAGILE_PROTOCOLS
    assert protocol_for_link_type("rpc") == "unknown-protocol"
    assert link_type_for_protocol("unknown-protocol") == "rpc"


def test_build_threagile_model():
    """Тест: модель Threagile содержит ожидаемые ключи."""
    model = build_threagile_model(_config())
    assert "threagile_version" in model
    assert "technical_assets" in model
    assert "data_flows" in model


def _edge() -> CrossRepoEdge:
    return CrossRepoEdge(
        link=LinkConfig(from_repo="frontend", to_repo="backend", type="http"),
        server_repo="backend",
        server_node_id="b1",
        server_function_name="CreateOrder",
        server_signature="/api/v1/orders",
        client_repo="frontend",
        client_file="/frontend/api.js",
        client_line=2,
    )


def test_update_threagile_data_flows(tmp_path):
    """Тест: найденные связи записываются в data_flows архитектурного файла."""
    path = save_threagile(_config(), str(tmp_path / "threagile.yaml"))

    update_threagile_data_flows(_config(), [_edge()], path)

    data = yaml.safe_load(open(path, encoding="utf-8"))
    flows = data["data_flows"]
    assert len(flows) == 1
    assert flows[0]["source"] == "frontend"
    assert flows[0]["target"] == "backend"
    assert flows[0]["protocol"] == "https"  # http → https (шифрованный дефолт)


def test_update_threagile_data_flows_keeps_existing(tmp_path):
    """Тест: существующие data_flows сохраняются, дубликаты исключаются."""
    path = save_threagile(_config(), str(tmp_path / "threagile.yaml"))

    update_threagile_data_flows(_config(), [_edge(), _edge()], path)

    data = yaml.safe_load(open(path, encoding="utf-8"))
    assert len(data["data_flows"]) == 1  # дубликат по (source, target, protocol) отброшен
