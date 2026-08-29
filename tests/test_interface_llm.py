"""Тесты статических эвристик анализа интерфейсов."""

from attack_surface._interface_llm import InterfaceDescriptor, fallback_descriptor


def test_fallback_extracts_url_signature():
    """Тест: URL-литерал в коде функции становится HTTP-сигнатурой."""
    desc = fallback_descriptor(
        "deserialization",
        code='def handler(payload):\n    endpoint = "/api/v1/orders"\n    return endpoint',
        language="python",
        function_name="handler",
    )

    assert isinstance(desc, InterfaceDescriptor)
    assert desc.interface_kind == "http"
    assert desc.signature == "/api/v1/orders"
    assert desc.is_server()


def test_fallback_ffi_export():
    """Тест: экспорт нативной функции распознаётся как FFI-интерфейс."""
    desc = fallback_descriptor(
        "environment_variable",
        code='extern "C" void process_order(const char *json) { }',
        language="cpp",
        function_name="process_order",
    )

    assert desc.interface_kind == "ffi"
    assert desc.signature == "process_order"
    assert desc.is_server()


def test_fallback_pinvoke_import():
    """Тест: DllImport распознаётся как P/Invoke-интерфейс."""
    desc = fallback_descriptor(
        "unknown",
        code="[DllImport(\"native.dll\")] static extern int run();",
        language="c_sharp",
        function_name="run",
    )

    assert desc.interface_kind == "pinvoke"


def test_fallback_falls_back_to_type():
    """Тест: без сигнатур дескриптор строится по статическому типу."""
    desc = fallback_descriptor("file_read", code="", language="python", function_name="reader")

    assert desc.interface_kind == "file"
    assert desc.signature == ""


def test_parse_batch_response():
    """Тест: разбор батчевого ответа LLM."""
    from attack_surface._interface_llm import parse_batch_response

    items = [
        {"node_id": "n1", "entry_point_type": "http_request", "function_name": "f1",
         "file_path": "/x/f1.py", "start_line": 1, "end_line": 3, "code": "x = 1"},
        {"node_id": "n2", "entry_point_type": "file_read", "function_name": "f2",
         "file_path": "/x/f2.py", "start_line": 1, "end_line": 3, "code": "y = 2"},
    ]
    response = (
        '{"results": ['
        '{"index": 0, "is_entry_point": true, "interface_role": "server", '
        '"interface_kind": "http", "signature": "/api/v1", "signature_aliases": [], '
        '"explanation": "x"},'
        '{"index": 1, "is_entry_point": false, "interface_role": "none", '
        '"interface_kind": "none", "signature": "", "signature_aliases": [], '
        '"explanation": "y"}'
        "]}"
    )

    descriptors = parse_batch_response(response, items)

    assert descriptors is not None
    assert set(descriptors) == {"n1", "n2"}
    assert descriptors["n1"].interface_kind == "http"
    assert descriptors["n2"].is_entry_point is False


def test_parse_batch_response_invalid():
    """Тест: невалидный ответ возвращает None."""
    from attack_surface._interface_llm import parse_batch_response

    assert parse_batch_response("без json", []) is None
    assert parse_batch_response('{"results": []}', []) is None
