from credential_method import find_authentication_method


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
