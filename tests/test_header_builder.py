"""Tests for auth.header_builder module."""

import base64

import pytest

from auth.header_builder import (
    AuthenticationResult,
    CustomHeaderManager,
    build_api_key_auth,
    build_auth_for_scheme,
    build_basic_auth_header,
    build_bearer_auth_header,
    build_http_auth,
    build_oauth2_auth,
    build_request_headers,
)
from auth.schemes import APIKeyScheme, HTTPScheme, OAuth2Scheme, OpenIDConnectScheme


class TestAuthenticationResult:
    """Tests for AuthenticationResult dataclass."""

    def test_empty_result(self):
        result = AuthenticationResult()
        assert result.headers == {}
        assert result.query_params == {}
        assert result.cookies == {}

    def test_merge_results(self):
        result1 = AuthenticationResult(
            headers={"X-Header-1": "value1"},
            query_params={"param1": "value1"},
        )
        result2 = AuthenticationResult(
            headers={"X-Header-2": "value2"},
            cookies={"cookie1": "value1"},
        )

        merged = result1.merge(result2)

        assert merged.headers == {"X-Header-1": "value1", "X-Header-2": "value2"}
        assert merged.query_params == {"param1": "value1"}
        assert merged.cookies == {"cookie1": "value1"}

    def test_merge_overwrites(self):
        """Later merge should overwrite earlier values."""
        result1 = AuthenticationResult(headers={"X-Key": "old"})
        result2 = AuthenticationResult(headers={"X-Key": "new"})

        merged = result1.merge(result2)
        assert merged.headers["X-Key"] == "new"


class TestBasicAuthHeader:
    """Tests for build_basic_auth_header."""

    def test_basic_auth(self):
        header = build_basic_auth_header("user", "password")

        expected = base64.b64encode(b"user:password").decode()
        assert header == f"Basic {expected}"

    def test_empty_password(self):
        header = build_basic_auth_header("user", "")

        expected = base64.b64encode(b"user:").decode()
        assert header == f"Basic {expected}"

    def test_special_characters(self):
        header = build_basic_auth_header("user@domain", "pass:word")

        expected = base64.b64encode(b"user@domain:pass:word").decode()
        assert header == f"Basic {expected}"


class TestBearerAuthHeader:
    """Tests for build_bearer_auth_header."""

    def test_bearer_auth(self):
        header = build_bearer_auth_header("token123")
        assert header == "Bearer token123"

    def test_empty_token(self):
        header = build_bearer_auth_header("")
        assert header == "Bearer "


class TestAPIKeyAuth:
    """Tests for build_api_key_auth."""

    def test_api_key_in_header(self):
        scheme = APIKeyScheme(
            name="ApiKey",
            location="header",
            parameter_name="X-API-Key",
        )

        result = build_api_key_auth(scheme, "secret123")

        assert result.headers == {"X-API-Key": "secret123"}
        assert result.query_params == {}
        assert result.cookies == {}

    def test_api_key_in_query(self):
        scheme = APIKeyScheme(
            name="ApiKey",
            location="query",
            parameter_name="api_key",
        )

        result = build_api_key_auth(scheme, "secret123")

        assert result.headers == {}
        assert result.query_params == {"api_key": "secret123"}

    def test_api_key_in_cookie(self):
        scheme = APIKeyScheme(
            name="ApiKey",
            location="cookie",
            parameter_name="session",
        )

        result = build_api_key_auth(scheme, "secret123")

        assert result.headers == {}
        assert result.cookies == {"session": "secret123"}

    def test_api_key_unknown_location(self):
        """Unknown location should default to header."""
        scheme = APIKeyScheme(
            name="ApiKey",
            location="unknown",
            parameter_name="key",
        )

        result = build_api_key_auth(scheme, "secret")
        assert result.headers == {"key": "secret"}


class TestHTTPAuth:
    """Tests for build_http_auth."""

    def test_basic_auth(self):
        scheme = HTTPScheme(name="BasicAuth", scheme="basic")
        credentials = {"username": "user", "password": "pass"}

        result = build_http_auth(scheme, credentials)

        expected = base64.b64encode(b"user:pass").decode()
        assert result.headers["Authorization"] == f"Basic {expected}"

    def test_bearer_auth(self):
        scheme = HTTPScheme(name="BearerAuth", scheme="bearer")
        credentials = {"token": "mytoken"}

        result = build_http_auth(scheme, credentials)

        assert result.headers["Authorization"] == "Bearer mytoken"

    def test_bearer_with_format(self):
        scheme = HTTPScheme(name="JWT", scheme="bearer", bearer_format="JWT")
        credentials = {"token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."}

        result = build_http_auth(scheme, credentials)

        assert result.headers["Authorization"].startswith("Bearer ")

    def test_digest_auth(self):
        """Digest auth falls back to Basic-style for initial request."""
        scheme = HTTPScheme(name="DigestAuth", scheme="digest")
        credentials = {"username": "user", "password": "pass"}

        result = build_http_auth(scheme, credentials)

        # Should have some Authorization header
        assert "Authorization" in result.headers

    def test_unknown_scheme_with_token(self):
        scheme = HTTPScheme(name="Custom", scheme="custom")
        credentials = {"token": "mytoken"}

        result = build_http_auth(scheme, credentials)

        assert result.headers["Authorization"] == "Custom mytoken"


class TestOAuth2Auth:
    """Tests for build_oauth2_auth."""

    def test_oauth2_with_token(self):
        scheme = OAuth2Scheme(name="OAuth2")
        credentials = {"access_token": "token123"}

        result = build_oauth2_auth(scheme, credentials)

        assert result.headers["Authorization"] == "Bearer token123"

    def test_oauth2_no_token(self):
        scheme = OAuth2Scheme(name="OAuth2")
        credentials = {}

        result = build_oauth2_auth(scheme, credentials)

        assert result.headers == {}


class TestBuildAuthForScheme:
    """Tests for build_auth_for_scheme dispatcher."""

    def test_api_key_scheme(self):
        scheme = APIKeyScheme(
            name="ApiKey",
            location="header",
            parameter_name="X-API-Key",
        )
        credentials = {"api_key": "secret"}

        result = build_auth_for_scheme(scheme, credentials)

        assert result.headers["X-API-Key"] == "secret"

    def test_api_key_with_value_key(self):
        """Test that 'value' key is also accepted for API keys."""
        scheme = APIKeyScheme(
            name="ApiKey",
            location="header",
            parameter_name="X-API-Key",
        )
        credentials = {"value": "secret"}

        result = build_auth_for_scheme(scheme, credentials)

        assert result.headers["X-API-Key"] == "secret"

    def test_http_scheme(self):
        scheme = HTTPScheme(name="BasicAuth", scheme="basic")
        credentials = {"username": "user", "password": "pass"}

        result = build_auth_for_scheme(scheme, credentials)

        assert "Authorization" in result.headers

    def test_oauth2_scheme(self):
        scheme = OAuth2Scheme(name="OAuth2")
        credentials = {"access_token": "token"}

        result = build_auth_for_scheme(scheme, credentials)

        assert result.headers["Authorization"] == "Bearer token"

    def test_oidc_scheme(self):
        scheme = OpenIDConnectScheme(
            name="OIDC",
            openid_connect_url="https://example.com/.well-known/openid-configuration",
        )
        credentials = {"access_token": "token"}

        result = build_auth_for_scheme(scheme, credentials)

        assert result.headers["Authorization"] == "Bearer token"

    def test_unknown_scheme_type(self):
        """Unknown scheme type should return empty result."""

        class UnknownScheme:
            pass

        result = build_auth_for_scheme(UnknownScheme(), {})

        assert result.headers == {}


class TestCustomHeaderManager:
    """Tests for CustomHeaderManager class."""

    @pytest.fixture
    def manager(self):
        return CustomHeaderManager()

    def test_add_header(self, manager):
        manager.add_header("api1", "X-Custom", "value")

        headers = manager.get_headers("api1")
        assert headers == {"X-Custom": "value"}

    def test_add_multiple_headers(self, manager):
        manager.add_header("api1", "X-Header-1", "value1")
        manager.add_header("api1", "X-Header-2", "value2")

        headers = manager.get_headers("api1")
        assert headers == {"X-Header-1": "value1", "X-Header-2": "value2"}

    def test_overwrite_header(self, manager):
        manager.add_header("api1", "X-Custom", "old")
        manager.add_header("api1", "X-Custom", "new")

        headers = manager.get_headers("api1")
        assert headers["X-Custom"] == "new"

    def test_remove_header(self, manager):
        manager.add_header("api1", "X-Custom", "value")
        removed = manager.remove_header("api1", "X-Custom")

        assert removed is True
        assert manager.get_headers("api1") == {}

    def test_remove_nonexistent_header(self, manager):
        removed = manager.remove_header("api1", "X-Nonexistent")
        assert removed is False

    def test_remove_nonexistent_api(self, manager):
        removed = manager.remove_header("nonexistent", "X-Header")
        assert removed is False

    def test_get_headers_returns_copy(self, manager):
        manager.add_header("api1", "X-Custom", "value")

        headers = manager.get_headers("api1")
        headers["X-New"] = "modified"

        # Original should not be affected
        assert "X-New" not in manager.get_headers("api1")

    def test_get_headers_unknown_api(self, manager):
        headers = manager.get_headers("nonexistent")
        assert headers == {}

    def test_set_headers(self, manager):
        manager.set_headers("api1", {"X-One": "1", "X-Two": "2"})

        headers = manager.get_headers("api1")
        assert headers == {"X-One": "1", "X-Two": "2"}

    def test_set_headers_replaces(self, manager):
        manager.add_header("api1", "X-Old", "old")
        manager.set_headers("api1", {"X-New": "new"})

        headers = manager.get_headers("api1")
        assert headers == {"X-New": "new"}

    def test_clear_headers(self, manager):
        manager.add_header("api1", "X-Custom", "value")
        manager.clear_headers("api1")

        assert manager.get_headers("api1") == {}

    def test_list_apis(self, manager):
        manager.add_header("api1", "X-1", "1")
        manager.add_header("api2", "X-2", "2")

        apis = manager.list_apis()
        assert set(apis) == {"api1", "api2"}

    def test_list_apis_empty(self, manager):
        apis = manager.list_apis()
        assert apis == []

    def test_multiple_apis_isolated(self, manager):
        manager.add_header("api1", "X-Custom", "value1")
        manager.add_header("api2", "X-Custom", "value2")

        assert manager.get_headers("api1")["X-Custom"] == "value1"
        assert manager.get_headers("api2")["X-Custom"] == "value2"


class TestBuildRequestHeaders:
    """Tests for build_request_headers function."""

    def test_single_scheme(self):
        schemes = {
            "ApiKey": APIKeyScheme(
                name="ApiKey",
                location="header",
                parameter_name="X-API-Key",
            )
        }
        credentials = {"ApiKey": {"api_key": "secret"}}

        headers, params, cookies = build_request_headers(schemes, credentials)

        assert headers == {"X-API-Key": "secret"}
        assert params == {}
        assert cookies == {}

    def test_multiple_schemes(self):
        schemes = {
            "ApiKey": APIKeyScheme(
                name="ApiKey",
                location="header",
                parameter_name="X-API-Key",
            ),
            "Bearer": HTTPScheme(name="Bearer", scheme="bearer"),
        }
        credentials = {
            "ApiKey": {"api_key": "key123"},
            "Bearer": {"token": "token123"},
        }

        headers, params, cookies = build_request_headers(schemes, credentials)

        assert headers["X-API-Key"] == "key123"
        assert headers["Authorization"] == "Bearer token123"

    def test_with_custom_headers(self):
        schemes = {
            "ApiKey": APIKeyScheme(
                name="ApiKey",
                location="header",
                parameter_name="X-API-Key",
            )
        }
        credentials = {"ApiKey": {"api_key": "secret"}}
        custom = {"X-Custom": "value", "X-Request-ID": "123"}

        headers, _, _ = build_request_headers(schemes, credentials, custom)

        assert headers["X-API-Key"] == "secret"
        assert headers["X-Custom"] == "value"
        assert headers["X-Request-ID"] == "123"

    def test_custom_headers_override(self):
        """Custom headers should override auth headers."""
        schemes = {
            "Bearer": HTTPScheme(name="Bearer", scheme="bearer"),
        }
        credentials = {"Bearer": {"token": "auth_token"}}
        custom = {"Authorization": "Custom override"}

        headers, _, _ = build_request_headers(schemes, credentials, custom)

        assert headers["Authorization"] == "Custom override"

    def test_missing_credentials(self):
        """Missing credentials for a scheme should be skipped."""
        schemes = {
            "ApiKey": APIKeyScheme(
                name="ApiKey",
                location="header",
                parameter_name="X-API-Key",
            )
        }
        credentials = {}  # No credentials

        headers, params, cookies = build_request_headers(schemes, credentials)

        assert headers == {}

    def test_empty_schemes(self):
        headers, params, cookies = build_request_headers({}, {})

        assert headers == {}
        assert params == {}
        assert cookies == {}

    def test_mixed_locations(self):
        """Test API keys in different locations."""
        schemes = {
            "HeaderKey": APIKeyScheme(
                name="HeaderKey",
                location="header",
                parameter_name="X-Header-Key",
            ),
            "QueryKey": APIKeyScheme(
                name="QueryKey",
                location="query",
                parameter_name="api_key",
            ),
            "CookieKey": APIKeyScheme(
                name="CookieKey",
                location="cookie",
                parameter_name="session",
            ),
        }
        credentials = {
            "HeaderKey": {"api_key": "header_val"},
            "QueryKey": {"api_key": "query_val"},
            "CookieKey": {"api_key": "cookie_val"},
        }

        headers, params, cookies = build_request_headers(schemes, credentials)

        assert headers == {"X-Header-Key": "header_val"}
        assert params == {"api_key": "query_val"}
        assert cookies == {"session": "cookie_val"}
