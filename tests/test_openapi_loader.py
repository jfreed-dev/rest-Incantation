from load_openapi_documentation import load_openapi_documentation


def test_load_openapi_json(tmp_path):
    data = {"openapi": "3.0.0", "info": {"title": "Example", "version": "1.0"}}
    file_path = tmp_path / "openapi.json"
    file_path.write_text(
        '{"openapi": "3.0.0", "info": {"title": "Example", "version": "1.0"}}'
    )

    loaded = load_openapi_documentation(str(file_path))

    assert loaded == data


def test_load_openapi_yaml(tmp_path):
    file_path = tmp_path / "openapi.yaml"
    file_path.write_text("openapi: 3.0.0\ninfo:\n  title: Example\n  version: 1.0\n")

    loaded = load_openapi_documentation(str(file_path))

    assert loaded["openapi"] == "3.0.0"
    assert loaded["info"]["title"] == "Example"
