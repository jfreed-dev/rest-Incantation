"""Tests for Postman Collection Importer."""

import json
import pytest

from importers.postman import (
    ImportedCollection,
    PostmanAuth,
    PostmanCollectionImporter,
    PostmanRequest,
    PostmanVariable,
)


@pytest.fixture
def sample_collection_v21():
    """Sample Postman Collection v2.1 for testing."""
    return {
        "info": {
            "name": "Test API Collection",
            "description": "A test collection for REST Incantation",
            "schema": "https://schema.getpostman.com/json/collection/v2.1.0/collection.json",
        },
        "variable": [
            {"key": "base_url", "value": "https://api.example.com", "type": "string"},
            {"key": "api_version", "value": "v1", "type": "string"},
        ],
        "auth": {
            "type": "bearer",
            "bearer": [{"key": "token", "value": "{{access_token}}", "type": "string"}],
        },
        "item": [
            {
                "name": "Get Users",
                "request": {
                    "method": "GET",
                    "url": "{{base_url}}/{{api_version}}/users",
                    "header": [
                        {"key": "Accept", "value": "application/json"},
                        {"key": "X-Custom-Header", "value": "test", "disabled": False},
                    ],
                },
            },
            {
                "name": "User Management",
                "item": [
                    {
                        "name": "Create User",
                        "request": {
                            "method": "POST",
                            "url": {
                                "raw": "{{base_url}}/{{api_version}}/users",
                                "protocol": "https",
                                "host": ["api", "example", "com"],
                                "path": ["{{api_version}}", "users"],
                            },
                            "header": [{"key": "Content-Type", "value": "application/json"}],
                            "body": {
                                "mode": "raw",
                                "raw": '{"name": "John Doe", "email": "john@example.com"}',
                                "options": {"raw": {"language": "json"}},
                            },
                            "auth": {
                                "type": "apikey",
                                "apikey": [
                                    {"key": "key", "value": "X-API-Key"},
                                    {"key": "value", "value": "secret-key-123"},
                                    {"key": "in", "value": "header"},
                                ],
                            },
                        },
                    },
                ],
            },
        ],
    }


@pytest.fixture
def sample_environment():
    """Sample Postman Environment for testing."""
    return {
        "name": "Test Environment",
        "values": [
            {"key": "access_token", "value": "test-token-123", "enabled": True},
            {"key": "base_url", "value": "https://api.test.com", "enabled": True},
            {"key": "disabled_var", "value": "should-not-import", "enabled": False},
        ],
    }


@pytest.fixture
def importer():
    """Create a PostmanCollectionImporter instance."""
    return PostmanCollectionImporter()


def test_load_collection_from_dict(importer, sample_collection_v21):
    """Test loading collection from dictionary."""
    result = importer.load_collection(sample_collection_v21)

    assert isinstance(result, ImportedCollection)
    assert result.name == "Test API Collection"
    assert result.description == "A test collection for REST Incantation"
    assert len(result.requests) == 2
    assert len(result.variables) == 2
    assert result.auth_config is not None
    assert result.auth_config.type == "bearer"


def test_load_collection_from_json_string(importer, sample_collection_v21):
    """Test loading collection from JSON string."""
    json_string = json.dumps(sample_collection_v21)
    result = importer.load_collection(json_string)

    assert isinstance(result, ImportedCollection)
    assert result.name == "Test API Collection"


def test_load_collection_invalid_json(importer):
    """Test loading collection with invalid JSON."""
    with pytest.raises(ValueError, match="Invalid JSON"):
        importer.load_collection("not valid json {")


def test_load_collection_missing_info(importer):
    """Test loading collection without info field."""
    invalid_collection = {"item": []}

    with pytest.raises(ValueError, match="missing 'info' field"):
        importer.load_collection(invalid_collection)


def test_parse_variables(importer, sample_collection_v21):
    """Test parsing collection variables."""
    result = importer.load_collection(sample_collection_v21)

    assert len(result.variables) == 2
    assert result.variables[0].key == "base_url"
    assert result.variables[0].value == "https://api.example.com"
    assert result.variables[1].key == "api_version"
    assert result.variables[1].value == "v1"


def test_parse_collection_auth(importer, sample_collection_v21):
    """Test parsing collection-level authentication."""
    result = importer.load_collection(sample_collection_v21)

    assert result.auth_config is not None
    assert result.auth_config.type == "bearer"
    assert "token" in result.auth_config.params


def test_parse_request_basic(importer, sample_collection_v21):
    """Test parsing basic request."""
    result = importer.load_collection(sample_collection_v21)

    request = result.requests[0]
    assert isinstance(request, PostmanRequest)
    assert request.name == "Get Users"
    assert request.method == "GET"
    assert "{{base_url}}" in request.url
    assert len(request.headers) == 2
    assert request.headers["Accept"] == "application/json"


def test_parse_request_in_folder(importer, sample_collection_v21):
    """Test parsing request inside a folder."""
    result = importer.load_collection(sample_collection_v21)

    request = result.requests[1]
    assert request.name == "Create User"
    assert request.method == "POST"
    assert request.folder_path == ["User Management"]
    assert request.auth is not None
    assert request.auth.type == "apikey"


def test_parse_request_with_body(importer, sample_collection_v21):
    """Test parsing request with body."""
    result = importer.load_collection(sample_collection_v21)

    request = result.requests[1]
    assert request.body is not None
    assert request.body["mode"] == "raw"
    assert "John Doe" in request.body["content"]
    assert request.body["content_type"] == "json"


def test_parse_request_auth_override(importer, sample_collection_v21):
    """Test request-level auth overriding collection auth."""
    result = importer.load_collection(sample_collection_v21)

    # First request inherits collection auth (bearer)
    request1 = result.requests[0]
    assert request1.auth is not None
    assert request1.auth.type == "bearer"

    # Second request has its own auth (apikey)
    request2 = result.requests[1]
    assert request2.auth is not None
    assert request2.auth.type == "apikey"


def test_load_environment(importer, sample_environment):
    """Test loading Postman environment."""
    variables = importer.load_environment(sample_environment)

    assert len(variables) == 3
    assert variables[0].key == "access_token"
    assert variables[0].value == "test-token-123"
    assert variables[0].enabled is True


def test_load_environment_from_json_string(importer, sample_environment):
    """Test loading environment from JSON string."""
    json_string = json.dumps(sample_environment)
    variables = importer.load_environment(json_string)

    assert len(variables) == 3


def test_load_environment_invalid(importer):
    """Test loading invalid environment."""
    with pytest.raises(ValueError, match="missing 'values' field"):
        importer.load_environment({"name": "test"})


def test_map_auth_apikey(importer):
    """Test mapping API Key auth."""
    postman_auth = PostmanAuth(
        type="apikey",
        params={"key": "X-API-Key", "value": "secret-123", "in": "header"},
    )

    result = importer.map_auth_to_rest_incantation(postman_auth)

    assert result["scheme_type"] == "apiKey"
    assert result["values"]["api_key"] == "secret-123"
    assert result["values"]["key_name"] == "X-API-Key"
    assert result["values"]["location"] == "header"


def test_map_auth_bearer(importer):
    """Test mapping Bearer token auth."""
    postman_auth = PostmanAuth(type="bearer", params={"token": "bearer-token-123"})

    result = importer.map_auth_to_rest_incantation(postman_auth)

    assert result["scheme_type"] == "bearer"
    assert result["values"]["token"] == "bearer-token-123"


def test_map_auth_basic(importer):
    """Test mapping Basic auth."""
    postman_auth = PostmanAuth(
        type="basic",
        params={"username": "admin", "password": "secret"},
    )

    result = importer.map_auth_to_rest_incantation(postman_auth)

    assert result["scheme_type"] == "basic"
    assert result["values"]["username"] == "admin"
    assert result["values"]["password"] == "secret"


def test_map_auth_oauth2(importer):
    """Test mapping OAuth2 auth."""
    postman_auth = PostmanAuth(
        type="oauth2",
        params={
            "grant_type": "authorization_code",
            "accessTokenUrl": "https://auth.example.com/token",
            "authUrl": "https://auth.example.com/authorize",
            "clientId": "client-123",
            "clientSecret": "secret-456",
            "scope": "read write",
        },
    )

    result = importer.map_auth_to_rest_incantation(postman_auth)

    assert result["scheme_type"] == "oauth2"
    assert result["values"]["grant_type"] == "authorization_code"
    assert result["values"]["access_token_url"] == "https://auth.example.com/token"
    assert result["values"]["client_id"] == "client-123"


def test_get_import_summary(importer, sample_collection_v21):
    """Test generating import summary."""
    result = importer.load_collection(sample_collection_v21)
    summary = importer.get_import_summary(result)

    assert summary["name"] == "Test API Collection"
    assert summary["total_requests"] == 2
    assert summary["total_folders"] == 1
    assert summary["total_variables"] == 2
    assert summary["has_collection_auth"] is True
    assert "bearer" in summary["auth_types"]
    assert "apikey" in summary["auth_types"]


def test_build_url_from_object(importer):
    """Test building URL from Postman URL object."""
    url_obj = {
        "raw": "https://api.example.com/v1/users?limit=10",
        "protocol": "https",
        "host": ["api", "example", "com"],
        "path": ["v1", "users"],
        "query": [
            {"key": "limit", "value": "10", "disabled": False},
            {"key": "offset", "value": "0", "disabled": True},
        ],
    }

    url = importer._build_url_from_object(url_obj)

    # Should prefer raw URL
    assert url == "https://api.example.com/v1/users?limit=10"


def test_build_url_without_raw(importer):
    """Test building URL without raw field."""
    url_obj = {
        "protocol": "https",
        "host": ["api", "example", "com"],
        "path": ["v1", "users"],
        "query": [{"key": "limit", "value": "10"}],
    }

    url = importer._build_url_from_object(url_obj)

    assert url.startswith("https://api.example.com/v1/users")
    assert "limit=10" in url


def test_parse_body_modes(importer):
    """Test parsing different body modes."""
    # Raw body
    raw_body = {
        "mode": "raw",
        "raw": '{"test": "data"}',
        "options": {"raw": {"language": "json"}},
    }
    result = importer._parse_body(raw_body)
    assert result["mode"] == "raw"
    assert result["content"] == '{"test": "data"}'
    assert result["content_type"] == "json"

    # Form data
    form_body = {"mode": "formdata", "formdata": [{"key": "field1", "value": "value1"}]}
    result = importer._parse_body(form_body)
    assert result["mode"] == "formdata"

    # URL encoded
    urlencoded_body = {
        "mode": "urlencoded",
        "urlencoded": [{"key": "field1", "value": "value1"}],
    }
    result = importer._parse_body(urlencoded_body)
    assert result["mode"] == "urlencoded"


def test_auth_type_mapping(importer):
    """Test auth type mapping constants."""
    assert importer.AUTH_TYPE_MAPPING["apikey"] == "apiKey"
    assert importer.AUTH_TYPE_MAPPING["bearer"] == "bearer"
    assert importer.AUTH_TYPE_MAPPING["basic"] == "basic"
    assert importer.AUTH_TYPE_MAPPING["oauth2"] == "oauth2"
    assert importer.AUTH_TYPE_MAPPING["noauth"] is None


def test_unsupported_collection_version_warning(importer, caplog):
    """Test warning for potentially unsupported collection version."""
    collection = {
        "info": {
            "name": "Test",
            "schema": "https://schema.getpostman.com/json/collection/v1.0.0/collection.json",
        },
        "item": [],
    }

    with caplog.at_level("WARNING"):
        importer.load_collection(collection)

    assert "may not be fully supported" in caplog.text


def test_folders_hierarchy(importer):
    """Test nested folders are properly tracked."""
    collection = {
        "info": {"name": "Test", "schema": "v2.1.0"},
        "item": [
            {
                "name": "Folder1",
                "item": [
                    {
                        "name": "Folder2",
                        "item": [
                            {"name": "Request1", "request": {"method": "GET", "url": "https://test.com"}},
                        ],
                    },
                ],
            },
        ],
    }

    result = importer.load_collection(collection)

    assert "Folder1" in result.folders
    assert "Folder1/Folder2" in result.folders
    assert result.requests[0].folder_path == ["Folder1", "Folder2"]


def test_disabled_headers_excluded(importer):
    """Test that disabled headers are not imported."""
    collection = {
        "info": {"name": "Test", "schema": "v2.1.0"},
        "item": [
            {
                "name": "Request",
                "request": {
                    "method": "GET",
                    "url": "https://test.com",
                    "header": [
                        {"key": "Accept", "value": "application/json", "disabled": False},
                        {"key": "X-Disabled", "value": "should-not-import", "disabled": True},
                    ],
                },
            },
        ],
    }

    result = importer.load_collection(collection)

    assert "Accept" in result.requests[0].headers
    assert "X-Disabled" not in result.requests[0].headers

def test_collection_size_limit(importer):
    """Test that oversized collections are rejected."""
    # Create a collection that exceeds size limit
    large_value = "x" * (11 * 1024 * 1024)  # 11MB string
    collection = {
        "info": {"name": "Large Collection", "schema": "v2.1.0"},
        "variable": [{"key": "large_var", "value": large_value}],
        "item": [],
    }
    
    collection_json = json.dumps(collection)
    
    with pytest.raises(ValueError, match="exceeds maximum size"):
        importer.load_collection(collection_json)


def test_max_variables_limit(importer):
    """Test that collections with too many variables are rejected."""
    from importers.postman import MAX_VARIABLES_PER_COLLECTION
    
    collection = {
        "info": {"name": "Too Many Vars", "schema": "v2.1.0"},
        "variable": [
            {"key": f"var_{i}", "value": f"value_{i}"}
            for i in range(MAX_VARIABLES_PER_COLLECTION + 10)
        ],
        "item": [],
    }
    
    with pytest.raises(ValueError, match="exceeds maximum variables limit"):
        importer.load_collection(collection)


def test_max_requests_limit(importer):
    """Test that collections with too many requests are handled."""
    from importers.postman import MAX_REQUESTS_PER_COLLECTION
    
    collection = {
        "info": {"name": "Too Many Requests", "schema": "v2.1.0"},
        "item": [
            {
                "name": f"Request_{i}",
                "request": {"method": "GET", "url": f"https://api.test.com/endpoint{i}"},
            }
            for i in range(MAX_REQUESTS_PER_COLLECTION + 10)
        ],
    }
    
    result = importer.load_collection(collection)
    
    # Should limit to MAX_REQUESTS_PER_COLLECTION
    assert len(result.requests) == MAX_REQUESTS_PER_COLLECTION


def test_folder_depth_limit(importer):
    """Test that deeply nested folders are handled."""
    from importers.postman import MAX_FOLDER_DEPTH
    
    # Create deeply nested folder structure
    item = {"name": "DeepFolder", "item": []}
    for i in range(MAX_FOLDER_DEPTH + 5):
        item = {"name": f"Folder_{i}", "item": [item]}
    
    collection = {
        "info": {"name": "Deep Nesting", "schema": "v2.1.0"},
        "item": [item],
    }
    
    result = importer.load_collection(collection)
    
    # Folders beyond MAX_FOLDER_DEPTH should be skipped
    assert len(result.folders) <= MAX_FOLDER_DEPTH