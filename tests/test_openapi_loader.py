from load_openapi_documentation import load_openapi_documentation


def test_load_openapi_json(tmp_path):
    data = {"openapi": "3.0.0", "info": {"title": "Example", "version": "1.0"}}
    file_path = tmp_path / "openapi.json"
    file_path.write_text('{"openapi": "3.0.0", "info": {"title": "Example", "version": "1.0"}}')

    loaded = load_openapi_documentation(str(file_path))

    assert loaded == data


def test_load_openapi_yaml(tmp_path):
    file_path = tmp_path / "openapi.yaml"
    file_path.write_text("openapi: 3.0.0\ninfo:\n  title: Example\n  version: 1.0\n")

    loaded = load_openapi_documentation(str(file_path))

    assert loaded["openapi"] == "3.0.0"
    assert loaded["info"]["title"] == "Example"


def test_load_openapi_yml_extension(tmp_path):
    """Test that .yml extension is also supported."""
    file_path = tmp_path / "openapi.yml"
    file_path.write_text("openapi: 3.0.0\ninfo:\n  title: YML Test\n")

    loaded = load_openapi_documentation(str(file_path))

    assert loaded["openapi"] == "3.0.0"
    assert loaded["info"]["title"] == "YML Test"


def test_load_openapi_unsupported_format(tmp_path):
    """Test that unsupported file formats return None."""
    file_path = tmp_path / "openapi.txt"
    file_path.write_text("openapi: 3.0.0")

    loaded = load_openapi_documentation(str(file_path))

    assert loaded is None


def test_load_openapi_file_not_found():
    """Test that missing files return None."""
    loaded = load_openapi_documentation("/nonexistent/path/openapi.json")

    assert loaded is None


def test_load_openapi_invalid_json(tmp_path):
    """Test that invalid JSON returns None."""
    file_path = tmp_path / "invalid.json"
    file_path.write_text("{invalid json content")

    loaded = load_openapi_documentation(str(file_path))

    assert loaded is None


def test_load_openapi_invalid_yaml(tmp_path):
    """Test that invalid YAML returns None."""
    file_path = tmp_path / "invalid.yaml"
    file_path.write_text("invalid: yaml: [unclosed")

    loaded = load_openapi_documentation(str(file_path))

    assert loaded is None
