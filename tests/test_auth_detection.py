from unittest.mock import patch

from credential_method import find_authentication_method, get_detailed_auth_methods


def test_find_authentication_method_returns_mapping():
    api_documentation = {
        "components": {
            "securitySchemes": {
                "ApiKeyAuth": {"type": "apiKey"},
                "OAuth2": {"type": "oauth2"},
            }
        }
    }

    auth_methods = find_authentication_method(api_documentation)

    assert auth_methods == {"ApiKeyAuth": "apiKey", "OAuth2": "oauth2"}


def test_find_authentication_method_handles_missing():
    auth_methods = find_authentication_method({})

    assert auth_methods == {}


def test_find_authentication_method_handles_exception():
    """Test that exceptions during parsing are caught and logged."""
    with patch(
        "credential_method.parse_security_schemes",
        side_effect=Exception("Parsing failed"),
    ):
        auth_methods = find_authentication_method({"components": {}})

    assert auth_methods == {}


def test_get_detailed_auth_methods_returns_schemes():
    """Test that get_detailed_auth_methods returns parsed schemes."""
    api_documentation = {
        "components": {
            "securitySchemes": {
                "ApiKeyAuth": {"type": "apiKey", "in": "header", "name": "X-API-Key"},
            }
        }
    }

    schemes = get_detailed_auth_methods(api_documentation)

    assert "ApiKeyAuth" in schemes
    assert schemes["ApiKeyAuth"].name == "ApiKeyAuth"
    assert schemes["ApiKeyAuth"].parameter_name == "X-API-Key"
    assert schemes["ApiKeyAuth"].location == "header"


def test_get_detailed_auth_methods_handles_missing():
    """Test that missing security schemes returns empty dict."""
    schemes = get_detailed_auth_methods({})

    assert schemes == {}


def test_get_detailed_auth_methods_handles_exception():
    """Test that exceptions during parsing are caught and logged."""
    with patch(
        "credential_method.parse_security_schemes",
        side_effect=Exception("Parsing failed"),
    ):
        schemes = get_detailed_auth_methods({"components": {}})

    assert schemes == {}
