"""Тесты пофайловой группировки батчей валидации и загрузки из JSON."""

import json

from attack_surface._interface_llm import InterfaceDescriptor
from attack_surface._models import EntryPointInfo
from attack_surface._project_config import ProjectConfig, RepoConfig
from attack_surface._project_pipeline import (
    _group_batches_by_file,
    load_repo_scan_results,
)


def _ep(node_id: str, file_path: str) -> EntryPointInfo:
    return EntryPointInfo(
        node_id=node_id,
        function_name=node_id,
        file_path=file_path,
        start_line=1,
        end_line=2,
    )


def test_batch_full_file_splits():
    """Тест: файл с 20 точками разбивается на 4 батча по 5."""
    entry_points = {f"n{i}": _ep(f"n{i}", "/x/a.py") for i in range(20)}

    batches = _group_batches_by_file(entry_points, 5)

    assert len(batches) == 4
    assert all(len(batch) == 5 for batch in batches)


def test_batch_tails_merge():
    """Тест: хвосты файлов с одной точкой добираются друг из друга."""
    entry_points = {f"n{i}": _ep(f"n{i}", f"/x/f{i}.py") for i in range(7)}

    batches = _group_batches_by_file(entry_points, 5)

    assert len(batches) == 2
    assert len(batches[0]) == 5
    assert len(batches[1]) == 2


def test_batch_mixed_files():
    """Тест: большой файл + хвосты маленьких файлов."""
    entry_points = {}
    for i in range(3):
        entry_points[f"a{i}"] = _ep(f"a{i}", "/x/a.py")
    entry_points["b0"] = _ep("b0", "/x/b.py")
    for i in range(6):
        entry_points[f"c{i}"] = _ep(f"c{i}", "/x/c.py")

    batches = _group_batches_by_file(entry_points, 5)

    # c: 5 полных + 1 в хвост; a(3) + b(1) + c-хвост(1) = 5 → один батч
    assert len(batches) == 2
    assert all(len(batch) == 5 for batch in batches)


# ---------------------------------------------------------------------------
# Загрузка проверенных точек входа из JSON
# ---------------------------------------------------------------------------

def _repo_config(tmp_path) -> ProjectConfig:
    repo = RepoConfig(name="backend", path=str(tmp_path / "backend"), language="python")
    (tmp_path / "backend").mkdir(exist_ok=True)
    return ProjectConfig(project="p", repos=[repo], base_dir=str(tmp_path))


def test_load_repo_scan_results_roundtrip(tmp_path):
    """Тест: точки входа и интерфейсы восстанавливаются из JSON."""
    ep = EntryPointInfo(
        node_id="n1", function_name="handle", file_path="main.py",
        start_line=1, end_line=3, entry_point_type="http_request",
    )
    desc = InterfaceDescriptor(
        is_entry_point=True, interface_role="server",
        interface_kind="http", signature="/api/v1",
        signature_aliases=["/api/v1"],
    )
    data = {
        "name": "backend",
        "language": "python",
        "entry_points": {"n1": ep.to_dict()},
        "interfaces": {"n1": desc.to_dict()},
    }
    (tmp_path / "repos").mkdir()
    with open(tmp_path / "repos" / "backend_entry_points.json", "w", encoding="utf-8") as fh:
        json.dump(data, fh)

    results = load_repo_scan_results(_repo_config(tmp_path), str(tmp_path))

    assert len(results) == 1
    result = results[0]
    assert result.language == "python"
    assert result.graph is None  # код репозитория не читается при пересборке
    assert result.entry_points["n1"].function_name == "handle"
    assert result.entry_points["n1"].entry_point_type == "http_request"
    assert result.interfaces["n1"].signature == "/api/v1"
    assert result.interfaces["n1"].signature_aliases == ["/api/v1"]


def test_load_repo_scan_results_missing_file(tmp_path):
    """Тест: отсутствующий файл точек входа вызывает ошибку."""
    config = _repo_config(tmp_path)

    try:
        load_repo_scan_results(config, str(tmp_path))
        assert False, "ожидалась ошибка ValueError"
    except ValueError:
        pass


def test_load_repo_scan_results_in_repos_subdir(tmp_path):
    """Тест: файл ищется и в подкаталоге repos."""
    ep = EntryPointInfo(
        node_id="n1", function_name="f", file_path="f.py",
        start_line=1, end_line=2,
    )
    data = {"name": "backend", "language": "python",
            "entry_points": {"n1": ep.to_dict()}, "interfaces": {}}
    (tmp_path / "repos").mkdir()
    with open(tmp_path / "repos" / "backend_entry_points.json", "w", encoding="utf-8") as fh:
        json.dump(data, fh)

    results = load_repo_scan_results(_repo_config(tmp_path), str(tmp_path / "repos"))

    assert len(results) == 1
    assert results[0].repo.name == "backend"
