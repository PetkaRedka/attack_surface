"""Тесты батчевого подтверждения связей и фильтра невалидных точек."""

from attack_surface._interface_llm import InterfaceDescriptor
from attack_surface._link_llm import (
    LinkBatchOutput,
    LinkValidatorOutput,
    confirm_edges_batch,
    parse_batch_response,
)
from attack_surface._linker import CrossRepoEdge
from attack_surface._models import EntryPointInfo
from attack_surface._project_config import LinkConfig
from attack_surface._project_pipeline import ProjectScanner, RepoScanResult


# ---------------------------------------------------------------------------
# Батчевое подтверждение связей
# ---------------------------------------------------------------------------

def _edge(client_file, client_line, server_signature="POST /api/v1/orders"):
    return CrossRepoEdge(
        link=LinkConfig(from_repo="frontend", to_repo="backend", type="http"),
        server_repo="backend",
        server_node_id="b1",
        server_function_name="CreateOrder",
        server_signature=server_signature,
        client_repo="frontend",
        client_file=client_file,
        client_line=client_line,
        client_snippet="fetch('/api/v1/orders');",
        match_kind="exact",
        confidence="medium",
        direction="forward",
    )


class _FakeBatchValidator:
    """Возвращает готовый ответ на каждый вызов батча."""

    def __init__(self, answer):
        self.answer = answer  # callable(items) -> dict[int, (is_match, confidence)]
        self.calls: list[int] = []

    def invoke(self, inp, out_cls):
        self.calls.append(len(inp.items))
        items = inp.items
        results = {}
        for index, (is_match, confidence) in self.answer(items).items():
            results[index] = LinkValidatorOutput(is_match, confidence, "")
        return LinkBatchOutput(results=results)


def test_parse_batch_response():
    """Тест: разбор батчевого ответа LLM."""
    response = (
        '{"results": ['
        '{"index": 0, "is_match": true, "confidence": "high", "explanation": "a"},'
        '{"index": 1, "is_match": false, "confidence": "low", "explanation": "b"}'
        "]}"
    )

    results = parse_batch_response(response)

    assert results is not None
    assert set(results) == {0, 1}
    assert results[0].is_match is True
    assert results[0].confidence == "high"
    assert results[1].is_match is False


def test_parse_batch_response_invalid():
    """Тест: невалидный ответ возвращает None."""
    assert parse_batch_response("без json") is None
    assert parse_batch_response('{"results": []}') is None


def test_confirm_edges_batch_groups_and_confirms():
    """Тест: дубликаты в одном файле сворачиваются в одну связь и подтверждаются."""
    edges = [
        _edge("/frontend/api.js", 10),
        _edge("/frontend/api.js", 12),
        _edge("/frontend/other.js", 5),
    ]
    validator = _FakeBatchValidator(
        lambda items: {i: (True, "high") for i in range(len(items))}
    )

    confirmed = confirm_edges_batch(validator, edges, batch_size=10)

    # 2 группы (две разные клиентские строки-файлы) → 2 вызова LLM,
    # но в результате остаются все 3 места вызова
    assert validator.calls == [2]
    assert len(confirmed) == 3
    assert all(e.confidence == "high" for e in confirmed)


def test_confirm_edges_batch_rejects_group():
    """Тест: отклонённая группа исключается целиком."""
    edges = [_edge("/frontend/api.js", 10), _edge("/frontend/api.js", 12)]
    validator = _FakeBatchValidator(lambda items: {0: (False, "low")})

    confirmed = confirm_edges_batch(validator, edges, batch_size=10)

    assert confirmed == []


def test_confirm_edges_batch_split_by_batch_size():
    """Тест: группы разбиваются по размеру батча."""
    edges = [_edge(f"/frontend/f{i}.js", 10) for i in range(3)]
    validator = _FakeBatchValidator(
        lambda items: {i: (True, "high") for i in range(len(items))}
    )

    confirmed = confirm_edges_batch(validator, edges, batch_size=2)

    assert validator.calls == [2, 1]
    assert len(confirmed) == 3


def test_confirm_edges_batch_keeps_on_missing_answer():
    """Тест: без ответа LLM кандидаты сохраняются с прежней уверенностью."""
    edges = [_edge("/frontend/api.js", 10)]
    validator = _FakeBatchValidator(lambda items: {})

    confirmed = confirm_edges_batch(validator, edges, batch_size=10)

    assert len(confirmed) == 1
    assert confirmed[0].confidence == "medium"


# ---------------------------------------------------------------------------
# Фильтр невалидных точек входа
# ---------------------------------------------------------------------------

def test_repo_interfaces_filters_invalid_entry_points():
    """Тест: точки с is_entry_point=False не участвуют в стыковке."""
    ep = EntryPointInfo(
        node_id="n1", function_name="f", file_path="/x/f.py",
        start_line=1, end_line=3,
    )
    valid = InterfaceDescriptor(
        is_entry_point=True, interface_role="server",
        interface_kind="http", signature="/api/v1",
    )
    invalid = InterfaceDescriptor(
        is_entry_point=False, interface_role="server",
        interface_kind="http", signature="/api/v1",
    )
    result = RepoScanResult(
        repo=_repo_config(),
        language="python",
        entry_points={"n1": ep, "n2": ep},
        interfaces={"n1": valid, "n2": invalid},
    )

    items = ProjectScanner._repo_interfaces(result)

    assert [i["node_id"] for i in items] == ["n1"]


def test_repo_interfaces_skips_without_interface():
    """Тест: точки без интерфейса (kind=none) не попадают в стыковку."""
    ep = EntryPointInfo(
        node_id="n1", function_name="f", file_path="/x/f.py",
        start_line=1, end_line=3,
    )
    no_interface = InterfaceDescriptor(interface_role="none", interface_kind="none")
    result = RepoScanResult(
        repo=_repo_config(),
        language="python",
        entry_points={"n1": ep},
        interfaces={"n1": no_interface},
    )

    items = ProjectScanner._repo_interfaces(result)

    assert items == []


def _repo_config():
    from attack_surface._project_config import RepoConfig

    return RepoConfig(name="backend", path="/x/backend", language="python")
