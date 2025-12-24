"""Tests for auth.schemes module."""


from auth.schemes import (
    APIKeyScheme,
    HTTPScheme,
    OAuth2Flow,
    OAuth2Scheme,
    OpenIDConnectScheme,
    get_scheme_type_string,
    parse_security_schemes,
)
from credential_method import find_authentication_method, get_detailed_auth_methods


class TestAPIKeyScheme:
    """Tests for API Key scheme parsing."""

    def test_parse_apikey_in_header(self):
        api_doc = {
            "components": {
                "securitySchemes": {
                    "ApiKeyAuth": {
                        "type": "apiKey",
                        "in": "header",
                        "name": "X-API-Key",
                        "description": "API key in header",
                    }
                }
            }
        }

        schemes = parse_security_schemes(api_doc)

        assert "ApiKeyAuth" in schemes
        scheme = schemes["ApiKeyAuth"]
        assert isinstance(scheme, APIKeyScheme)
        assert scheme.name == "ApiKeyAuth"
        assert scheme.location == "header"
        assert scheme.parameter_name == "X-API-Key"
        assert scheme.description == "API key in header"
        assert scheme.scheme_type == "apiKey"

    def test_parse_apikey_in_query(self):
        api_doc = {
            "components": {
                "securitySchemes": {
                    "QueryKey": {
                        "type": "apiKey",
                        "in": "query",
                        "name": "api_key",
                    }
                }
            }
        }

        schemes = parse_security_schemes(api_doc)
        scheme = schemes["QueryKey"]

        assert scheme.location == "query"
        assert scheme.parameter_name == "api_key"

    def test_parse_apikey_in_cookie(self):
        api_doc = {
            "components": {
                "securitySchemes": {
                    "CookieAuth": {
                        "type": "apiKey",
                        "in": "cookie",
                        "name": "session_id",
                    }
                }
            }
        }

        schemes = parse_security_schemes(api_doc)
        scheme = schemes["CookieAuth"]

        assert scheme.location == "cookie"
        assert scheme.parameter_name == "session_id"

    def test_parse_apikey_defaults(self):
        """Test default values when optional fields are missing."""
        api_doc = {
            "components": {
                "securitySchemes": {
                    "MinimalKey": {
                        "type": "apiKey",
                    }
                }
            }
        }

        schemes = parse_security_schemes(api_doc)
        scheme = schemes["MinimalKey"]

        assert scheme.location == "header"  # default
        assert scheme.parameter_name == "MinimalKey"  # falls back to scheme name
        assert scheme.description is None


class TestHTTPScheme:
    """Tests for HTTP authentication scheme parsing."""

    def test_parse_http_basic(self):
        api_doc = {
            "components": {
                "securitySchemes": {
                    "BasicAuth": {
                        "type": "http",
                        "scheme": "basic",
                        "description": "HTTP Basic Authentication",
                    }
                }
            }
        }

        schemes = parse_security_schemes(api_doc)
        scheme = schemes["BasicAuth"]

        assert isinstance(scheme, HTTPScheme)
        assert scheme.name == "BasicAuth"
        assert scheme.scheme == "basic"
        assert scheme.bearer_format is None
        assert scheme.description == "HTTP Basic Authentication"
        assert scheme.scheme_type == "http"

    def test_parse_http_bearer(self):
        api_doc = {
            "components": {
                "securitySchemes": {
                    "BearerAuth": {
                        "type": "http",
                        "scheme": "bearer",
                        "bearerFormat": "JWT",
                    }
                }
            }
        }

        schemes = parse_security_schemes(api_doc)
        scheme = schemes["BearerAuth"]

        assert scheme.scheme == "bearer"
        assert scheme.bearer_format == "JWT"

    def test_parse_http_digest(self):
        api_doc = {
            "components": {
                "securitySchemes": {
                    "DigestAuth": {
                        "type": "http",
                        "scheme": "digest",
                    }
                }
            }
        }

        schemes = parse_security_schemes(api_doc)
        scheme = schemes["DigestAuth"]

        assert scheme.scheme == "digest"


class TestOAuth2Scheme:
    """Tests for OAuth 2.0 scheme parsing."""

    def test_parse_oauth2_client_credentials(self):
        api_doc = {
            "components": {
                "securitySchemes": {
                    "OAuth2CC": {
                        "type": "oauth2",
                        "description": "OAuth2 client credentials",
                        "flows": {
                            "clientCredentials": {
                                "tokenUrl": "https://auth.example.com/token",
                                "scopes": {
                                    "read": "Read access",
                                    "write": "Write access",
                                },
                            }
                        },
                    }
                }
            }
        }

        schemes = parse_security_schemes(api_doc)
        scheme = schemes["OAuth2CC"]

        assert isinstance(scheme, OAuth2Scheme)
        assert scheme.name == "OAuth2CC"
        assert scheme.scheme_type == "oauth2"
        assert "clientCredentials" in scheme.flows

        flow = scheme.flows["clientCredentials"]
        assert isinstance(flow, OAuth2Flow)
        assert flow.flow_type == "clientCredentials"
        assert flow.token_url == "https://auth.example.com/token"
        assert flow.authorization_url is None
        assert flow.scopes == {"read": "Read access", "write": "Write access"}

    def test_parse_oauth2_authorization_code(self):
        api_doc = {
            "components": {
                "securitySchemes": {
                    "OAuth2AuthCode": {
                        "type": "oauth2",
                        "flows": {
                            "authorizationCode": {
                                "authorizationUrl": "https://auth.example.com/authorize",
                                "tokenUrl": "https://auth.example.com/token",
                                "refreshUrl": "https://auth.example.com/refresh",
                                "scopes": {
                                    "openid": "OpenID scope",
                                    "profile": "Profile access",
                                },
                            }
                        },
                    }
                }
            }
        }

        schemes = parse_security_schemes(api_doc)
        flow = schemes["OAuth2AuthCode"].flows["authorizationCode"]

        assert flow.flow_type == "authorizationCode"
        assert flow.authorization_url == "https://auth.example.com/authorize"
        assert flow.token_url == "https://auth.example.com/token"
        assert flow.refresh_url == "https://auth.example.com/refresh"

    def test_parse_oauth2_implicit(self):
        api_doc = {
            "components": {
                "securitySchemes": {
                    "OAuth2Implicit": {
                        "type": "oauth2",
                        "flows": {
                            "implicit": {
                                "authorizationUrl": "https://auth.example.com/authorize",
                                "scopes": {"read": "Read access"},
                            }
                        },
                    }
                }
            }
        }

        schemes = parse_security_schemes(api_doc)
        flow = schemes["OAuth2Implicit"].flows["implicit"]

        assert flow.flow_type == "implicit"
        assert flow.authorization_url == "https://auth.example.com/authorize"
        assert flow.token_url is None

    def test_parse_oauth2_password(self):
        api_doc = {
            "components": {
                "securitySchemes": {
                    "OAuth2Password": {
                        "type": "oauth2",
                        "flows": {
                            "password": {
                                "tokenUrl": "https://auth.example.com/token",
                                "scopes": {},
                            }
                        },
                    }
                }
            }
        }

        schemes = parse_security_schemes(api_doc)
        flow = schemes["OAuth2Password"].flows["password"]

        assert flow.flow_type == "password"

    def test_parse_oauth2_multiple_flows(self):
        api_doc = {
            "components": {
                "securitySchemes": {
                    "OAuth2Multi": {
                        "type": "oauth2",
                        "flows": {
                            "clientCredentials": {
                                "tokenUrl": "https://auth.example.com/token",
                                "scopes": {},
                            },
                            "authorizationCode": {
                                "authorizationUrl": "https://auth.example.com/authorize",
                                "tokenUrl": "https://auth.example.com/token",
                                "scopes": {},
                            },
                        },
                    }
                }
            }
        }

        schemes = parse_security_schemes(api_doc)
        scheme = schemes["OAuth2Multi"]

        assert len(scheme.flows) == 2
        assert "clientCredentials" in scheme.flows
        assert "authorizationCode" in scheme.flows
        assert scheme.available_flow_types == ["clientCredentials", "authorizationCode"]

    def test_parse_oauth2_empty_flows(self):
        api_doc = {
            "components": {
                "securitySchemes": {
                    "OAuth2Empty": {
                        "type": "oauth2",
                        "flows": {},
                    }
                }
            }
        }

        schemes = parse_security_schemes(api_doc)
        scheme = schemes["OAuth2Empty"]

        assert scheme.flows == {}


class TestOpenIDConnectScheme:
    """Tests for OpenID Connect scheme parsing."""

    def test_parse_openid_connect(self):
        api_doc = {
            "components": {
                "securitySchemes": {
                    "OIDC": {
                        "type": "openIdConnect",
                        "openIdConnectUrl": "https://auth.example.com/.well-known/openid-configuration",
                        "description": "OpenID Connect",
                    }
                }
            }
        }

        schemes = parse_security_schemes(api_doc)
        scheme = schemes["OIDC"]

        assert isinstance(scheme, OpenIDConnectScheme)
        assert scheme.name == "OIDC"
        assert scheme.openid_connect_url == "https://auth.example.com/.well-known/openid-configuration"
        assert scheme.description == "OpenID Connect"
        assert scheme.scheme_type == "openIdConnect"


class TestSwagger2Compatibility:
    """Tests for Swagger 2.x format compatibility."""

    def test_parse_swagger2_basic_auth(self):
        """Swagger 2.x uses type: basic directly."""
        api_doc = {
            "swagger": "2.0",
            "securityDefinitions": {
                "BasicAuth": {
                    "type": "basic",
                    "description": "HTTP Basic Authentication",
                }
            },
        }

        schemes = parse_security_schemes(api_doc)
        scheme = schemes["BasicAuth"]

        assert isinstance(scheme, HTTPScheme)
        assert scheme.scheme == "basic"

    def test_parse_swagger2_apikey(self):
        api_doc = {
            "swagger": "2.0",
            "securityDefinitions": {
                "ApiKey": {
                    "type": "apiKey",
                    "name": "X-API-Key",
                    "in": "header",
                }
            },
        }

        schemes = parse_security_schemes(api_doc)
        scheme = schemes["ApiKey"]

        assert isinstance(scheme, APIKeyScheme)
        assert scheme.parameter_name == "X-API-Key"
        assert scheme.location == "header"

    def test_parse_swagger2_oauth2_application(self):
        """Swagger 2.x uses 'application' for client credentials flow."""
        api_doc = {
            "swagger": "2.0",
            "securityDefinitions": {
                "OAuth2": {
                    "type": "oauth2",
                    "flow": "application",
                    "tokenUrl": "https://auth.example.com/token",
                    "scopes": {
                        "read": "Read access",
                    },
                }
            },
        }

        schemes = parse_security_schemes(api_doc)
        scheme = schemes["OAuth2"]

        assert isinstance(scheme, OAuth2Scheme)
        assert "clientCredentials" in scheme.flows
        flow = scheme.flows["clientCredentials"]
        assert flow.token_url == "https://auth.example.com/token"

    def test_parse_swagger2_oauth2_accesscode(self):
        """Swagger 2.x uses 'accessCode' for authorization code flow."""
        api_doc = {
            "swagger": "2.0",
            "securityDefinitions": {
                "OAuth2": {
                    "type": "oauth2",
                    "flow": "accessCode",
                    "authorizationUrl": "https://auth.example.com/authorize",
                    "tokenUrl": "https://auth.example.com/token",
                    "scopes": {},
                }
            },
        }

        schemes = parse_security_schemes(api_doc)
        flow = schemes["OAuth2"].flows["authorizationCode"]

        assert flow.flow_type == "authorizationCode"
        assert flow.authorization_url == "https://auth.example.com/authorize"

    def test_parse_swagger2_oauth2_implicit(self):
        api_doc = {
            "swagger": "2.0",
            "securityDefinitions": {
                "OAuth2": {
                    "type": "oauth2",
                    "flow": "implicit",
                    "authorizationUrl": "https://auth.example.com/authorize",
                    "scopes": {},
                }
            },
        }

        schemes = parse_security_schemes(api_doc)
        flow = schemes["OAuth2"].flows["implicit"]

        assert flow.flow_type == "implicit"

    def test_parse_swagger2_oauth2_password(self):
        api_doc = {
            "swagger": "2.0",
            "securityDefinitions": {
                "OAuth2": {
                    "type": "oauth2",
                    "flow": "password",
                    "tokenUrl": "https://auth.example.com/token",
                    "scopes": {},
                }
            },
        }

        schemes = parse_security_schemes(api_doc)
        flow = schemes["OAuth2"].flows["password"]

        assert flow.flow_type == "password"


class TestMultipleSchemes:
    """Tests for documents with multiple security schemes."""

    def test_parse_multiple_schemes(self):
        api_doc = {
            "components": {
                "securitySchemes": {
                    "ApiKeyAuth": {
                        "type": "apiKey",
                        "in": "header",
                        "name": "X-API-Key",
                    },
                    "BasicAuth": {
                        "type": "http",
                        "scheme": "basic",
                    },
                    "OAuth2": {
                        "type": "oauth2",
                        "flows": {
                            "clientCredentials": {
                                "tokenUrl": "https://auth.example.com/token",
                                "scopes": {},
                            }
                        },
                    },
                }
            }
        }

        schemes = parse_security_schemes(api_doc)

        assert len(schemes) == 3
        assert isinstance(schemes["ApiKeyAuth"], APIKeyScheme)
        assert isinstance(schemes["BasicAuth"], HTTPScheme)
        assert isinstance(schemes["OAuth2"], OAuth2Scheme)


class TestEdgeCases:
    """Tests for edge cases and error handling."""

    def test_parse_empty_document(self):
        schemes = parse_security_schemes({})
        assert schemes == {}

    def test_parse_missing_security_schemes(self):
        api_doc = {"components": {}}
        schemes = parse_security_schemes(api_doc)
        assert schemes == {}

    def test_parse_unknown_type(self):
        """Unknown scheme types should be skipped with a warning."""
        api_doc = {
            "components": {
                "securitySchemes": {
                    "UnknownAuth": {
                        "type": "unknownType",
                    }
                }
            }
        }

        schemes = parse_security_schemes(api_doc)
        assert "UnknownAuth" not in schemes

    def test_get_scheme_type_string(self):
        """Test backward compatibility helper."""
        api_key = APIKeyScheme(name="test", location="header", parameter_name="X-Key")
        http = HTTPScheme(name="test", scheme="basic")
        oauth2 = OAuth2Scheme(name="test")
        oidc = OpenIDConnectScheme(name="test", openid_connect_url="https://example.com")

        assert get_scheme_type_string(api_key) == "apiKey"
        assert get_scheme_type_string(http) == "http"
        assert get_scheme_type_string(oauth2) == "oauth2"
        assert get_scheme_type_string(oidc) == "openIdConnect"


class TestBackwardCompatibility:
    """Tests to ensure backward compatibility with existing code."""

    def test_find_authentication_method_unchanged(self):
        """Original function should still work the same way."""
        api_doc = {
            "components": {
                "securitySchemes": {
                    "ApiKeyAuth": {"type": "apiKey"},
                    "OAuth2": {"type": "oauth2"},
                }
            }
        }

        auth_methods = find_authentication_method(api_doc)

        assert auth_methods == {"ApiKeyAuth": "apiKey", "OAuth2": "oauth2"}

    def test_find_authentication_method_empty(self):
        auth_methods = find_authentication_method({})
        assert auth_methods == {}

    def test_get_detailed_auth_methods(self):
        """New function should return full scheme objects."""
        api_doc = {
            "components": {
                "securitySchemes": {
                    "ApiKeyAuth": {
                        "type": "apiKey",
                        "in": "header",
                        "name": "X-API-Key",
                    }
                }
            }
        }

        schemes = get_detailed_auth_methods(api_doc)

        assert "ApiKeyAuth" in schemes
        scheme = schemes["ApiKeyAuth"]
        assert isinstance(scheme, APIKeyScheme)
        assert scheme.parameter_name == "X-API-Key"
