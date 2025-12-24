import importlib
import os
import warnings
from unittest.mock import Mock, patch

import pytest
import requests

from app import OPENAPI_CANDIDATE_PATHS, app, fetch_openapi_documentation, load_secrets


@pytest.fixture
def client():
    app.config["TESTING"] = True
    with app.test_client() as client:
        yield client


class TestIndexRoute:
    def test_index_returns_form(self, client):
        response = client.get("/")

        assert response.status_code == 200
        assert b"API Base URL" in response.data


class TestSubmitUrlRoute:
    def test_submit_url_no_urls_provided(self, client):
        response = client.post("/submit-url", data={})

        assert response.status_code == 200
        assert b"Provide a base URL or an OpenAPI URL" in response.data

    def test_submit_url_empty_strings(self, client):
        response = client.post("/submit-url", data={"base_url": "  ", "openapi_url": "  "})

        assert response.status_code == 200
        assert b"Provide a base URL or an OpenAPI URL" in response.data

    def test_submit_url_fetch_fails(self, client):
        with patch("app.fetch_openapi_documentation") as mock_fetch:
            mock_fetch.return_value = (None, None, "Connection failed")

            response = client.post("/submit-url", data={"base_url": "https://api.example.com"})

        assert response.status_code == 200
        assert b"Connection failed" in response.data

    def test_submit_url_success_redirects_to_credentials(self, client):
        mock_openapi = {
            "openapi": "3.0.0",
            "components": {"securitySchemes": {"api_key": {"type": "apiKey", "name": "X-API-Key"}}},
        }
        with patch("app.fetch_openapi_documentation") as mock_fetch:
            mock_fetch.return_value = (
                mock_openapi,
                "https://api.example.com/openapi.json",
                None,
            )

            response = client.post("/submit-url", data={"base_url": "https://api.example.com"})

        assert response.status_code == 302
        assert "/credentials" in response.location

    def test_submit_url_with_explicit_openapi_url(self, client):
        mock_openapi = {"openapi": "3.0.0", "components": {"securitySchemes": {}}}
        with patch("app.fetch_openapi_documentation") as mock_fetch:
            mock_fetch.return_value = (
                mock_openapi,
                "https://other.example.com/spec.json",
                None,
            )

            response = client.post(
                "/submit-url",
                data={
                    "base_url": "https://api.example.com",
                    "openapi_url": "https://other.example.com/spec.json",
                },
            )

        assert response.status_code == 302
        mock_fetch.assert_called_once_with(
            "https://api.example.com", "https://other.example.com/spec.json"
        )


class TestCredentialsRoute:
    def test_credentials_get_redirects_without_auth_methods(self, client):
        response = client.get("/credentials")

        assert response.status_code == 302
        assert "/" in response.location

    def test_credentials_get_shows_form_with_auth_methods(self, client):
        with client.session_transaction() as sess:
            sess["auth_methods"] = {"api_key": "apiKey", "oauth": "oauth2"}

        response = client.get("/credentials")

        assert response.status_code == 200
        assert b"Configure Authentication" in response.data
        assert b"api_key" in response.data
        assert b"oauth" in response.data

    def test_credentials_post_stores_and_shows_request_builder(self, client):
        with client.session_transaction() as sess:
            sess["auth_methods"] = {"api_key": "apiKey"}
            sess["base_url"] = "https://api.example.com"
            sess["openapi_url"] = "https://api.example.com/openapi.json"

        response = client.post("/credentials", data={"api_key": "secret123"})

        assert response.status_code == 200
        assert b"Request Builder" in response.data
        assert b"api_key" in response.data
        assert b"secret123" in response.data


class TestFetchOpenapiDocumentation:
    def test_fetch_with_explicit_url(self):
        mock_response = Mock()
        mock_response.text = '{"openapi": "3.0.0"}'
        mock_response.headers = {"content-type": "application/json"}

        with patch("app.requests.get", return_value=mock_response) as mock_get:
            doc, url, error = fetch_openapi_documentation(
                "https://api.example.com", "https://explicit.example.com/spec.json"
            )

        assert doc == {"openapi": "3.0.0"}
        assert url == "https://explicit.example.com/spec.json"
        assert error is None
        mock_get.assert_called_once_with("https://explicit.example.com/spec.json", timeout=10)

    def test_fetch_with_json_url(self):
        mock_response = Mock()
        mock_response.text = '{"openapi": "3.0.0"}'
        mock_response.headers = {"content-type": "application/json"}

        with patch("app.requests.get", return_value=mock_response):
            doc, url, error = fetch_openapi_documentation("https://api.example.com/openapi.json")

        assert doc == {"openapi": "3.0.0"}
        assert error is None

    def test_fetch_with_yaml_url(self):
        mock_response = Mock()
        mock_response.text = "openapi: '3.0.0'"
        mock_response.headers = {"content-type": "application/yaml"}

        with patch("app.requests.get", return_value=mock_response):
            doc, url, error = fetch_openapi_documentation("https://api.example.com/openapi.yaml")

        assert doc == {"openapi": "3.0.0"}
        assert error is None

    def test_fetch_tries_multiple_urls(self):
        mock_response = Mock()
        mock_response.text = '{"openapi": "3.0.0"}'
        mock_response.headers = {"content-type": "application/json"}

        call_count = 0

        def side_effect(url, timeout):
            nonlocal call_count
            call_count += 1
            if call_count < 3:
                raise requests.RequestException("Not found")
            return mock_response

        with patch("app.requests.get", side_effect=side_effect):
            doc, url, error = fetch_openapi_documentation("https://api.example.com")

        assert doc == {"openapi": "3.0.0"}
        # Third candidate is openapi.yml
        assert url == "https://api.example.com/openapi.yml"
        assert error is None

    def test_fetch_finds_rest_prefixed_spec(self):
        """Test that /rest/openapi.json path is discovered (e.g., EcoStruxure IT API)."""
        mock_response = Mock()
        mock_response.text = '{"openapi": "3.0.0", "info": {"title": "REST API"}}'
        mock_response.headers = {"content-type": "application/json"}

        def side_effect(url, timeout):
            if "/rest/openapi.json" in url:
                return mock_response
            raise requests.RequestException("Not found")

        with patch("app.requests.get", side_effect=side_effect):
            doc, url, error = fetch_openapi_documentation("https://api.example.com")

        assert doc == {"openapi": "3.0.0", "info": {"title": "REST API"}}
        assert url == "https://api.example.com/rest/openapi.json"
        assert error is None

    def test_fetch_finds_swagger_json(self):
        """Test that swagger.json path is discovered."""
        mock_response = Mock()
        mock_response.text = '{"swagger": "2.0"}'
        mock_response.headers = {"content-type": "application/json"}

        def side_effect(url, timeout):
            if url.endswith("/swagger.json"):
                return mock_response
            raise requests.RequestException("Not found")

        with patch("app.requests.get", side_effect=side_effect):
            doc, url, error = fetch_openapi_documentation("https://api.example.com")

        assert doc == {"swagger": "2.0"}
        assert url == "https://api.example.com/swagger.json"
        assert error is None

    def test_fetch_finds_spring_api_docs(self):
        """Test that Spring/SpringDoc paths are discovered."""
        mock_response = Mock()
        mock_response.text = '{"openapi": "3.0.0"}'
        mock_response.headers = {"content-type": "application/json"}

        def side_effect(url, timeout):
            if "/v3/api-docs" in url:
                return mock_response
            raise requests.RequestException("Not found")

        with patch("app.requests.get", side_effect=side_effect):
            doc, url, error = fetch_openapi_documentation("https://api.example.com")

        assert doc == {"openapi": "3.0.0"}
        assert url == "https://api.example.com/v3/api-docs"
        assert error is None


class TestOpenapiCandidatePaths:
    def test_candidate_paths_includes_common_locations(self):
        """Verify that common OpenAPI/Swagger spec locations are included."""
        assert "/openapi.json" in OPENAPI_CANDIDATE_PATHS
        assert "/openapi.yaml" in OPENAPI_CANDIDATE_PATHS
        assert "/swagger.json" in OPENAPI_CANDIDATE_PATHS
        assert "/rest/openapi.json" in OPENAPI_CANDIDATE_PATHS
        assert "/api/openapi.json" in OPENAPI_CANDIDATE_PATHS
        assert "/v3/api-docs" in OPENAPI_CANDIDATE_PATHS
        assert "/swagger/v1/swagger.json" in OPENAPI_CANDIDATE_PATHS
        assert "/.well-known/openapi.json" in OPENAPI_CANDIDATE_PATHS

    def test_candidate_paths_prioritizes_openapi_over_swagger(self):
        """OpenAPI paths should come before Swagger paths for modern APIs."""
        openapi_idx = OPENAPI_CANDIDATE_PATHS.index("/openapi.json")
        swagger_idx = OPENAPI_CANDIDATE_PATHS.index("/swagger.json")
        assert openapi_idx < swagger_idx

    def test_fetch_all_urls_fail(self):
        with patch("app.requests.get") as mock_get:
            mock_get.side_effect = requests.RequestException("Connection failed")

            doc, url, error = fetch_openapi_documentation("https://api.example.com")

        assert doc is None
        assert url is None
        assert "Connection failed" in error

    def test_fetch_yaml_content_type(self):
        mock_response = Mock()
        mock_response.text = "openapi: '3.0.0'\ninfo:\n  title: Test"
        mock_response.headers = {"content-type": "text/yaml"}

        with patch("app.requests.get", return_value=mock_response):
            doc, url, error = fetch_openapi_documentation("https://api.example.com/spec")

        assert doc["openapi"] == "3.0.0"
        assert doc["info"]["title"] == "Test"

    def test_fetch_falls_back_to_yaml_parsing(self):
        mock_response = Mock()
        mock_response.text = "openapi: '3.0.0'"
        mock_response.headers = {"content-type": "text/plain"}

        with patch("app.requests.get", return_value=mock_response):
            doc, url, error = fetch_openapi_documentation("https://api.example.com/spec")

        assert doc == {"openapi": "3.0.0"}


class TestLoadSecrets:
    def test_load_secrets_success(self, tmp_path):
        secrets_file = tmp_path / "secrets.yaml"
        secrets_file.write_text("flask_secret_key: mysecret\nclient_id: myid\n")

        secrets = load_secrets(str(secrets_file))

        assert secrets["flask_secret_key"] == "mysecret"
        assert secrets["client_id"] == "myid"

    def test_load_secrets_missing_file(self, tmp_path):
        secrets = load_secrets(str(tmp_path / "nonexistent.yaml"))

        assert secrets == {}

    def test_load_secrets_invalid_yaml(self, tmp_path):
        secrets_file = tmp_path / "invalid.yaml"
        secrets_file.write_text("invalid: yaml: [")

        secrets = load_secrets(str(secrets_file))

        assert secrets == {}


class TestSecretKeyWarning:
    def test_secret_key_warning_when_no_key_configured(self):
        """Verify a warning is issued when using the default insecure secret key."""
        import app as app_module

        env_backup = os.environ.get("FLASK_SECRET_KEY")
        secrets_backup = os.environ.get("REST_INCANTATION_SECRETS")

        try:
            os.environ.pop("FLASK_SECRET_KEY", None)
            os.environ["REST_INCANTATION_SECRETS"] = "/nonexistent/path/secrets.yaml"

            with warnings.catch_warnings(record=True) as w:
                warnings.simplefilter("always")
                importlib.reload(app_module)

                assert len(w) == 1
                assert "insecure default secret key" in str(w[0].message)
        finally:
            if env_backup is not None:
                os.environ["FLASK_SECRET_KEY"] = env_backup
            else:
                os.environ.pop("FLASK_SECRET_KEY", None)
            if secrets_backup is not None:
                os.environ["REST_INCANTATION_SECRETS"] = secrets_backup
            else:
                os.environ.pop("REST_INCANTATION_SECRETS", None)
            importlib.reload(app_module)


class TestOAuthCallbackRoute:
    """Tests for the /oauth/callback route."""

    def test_oauth_callback_with_error_param(self, client):
        """OAuth callback should display error when error parameter is present."""
        with client.session_transaction() as sess:
            sess["base_url"] = "https://api.example.com"
            sess["openapi_url"] = "https://api.example.com/openapi.json"

        response = client.get(
            "/oauth/callback?error=access_denied&error_description=User%20denied%20access"
        )

        assert response.status_code == 200
        assert b"OAuth error" in response.data
        assert b"access_denied" in response.data

    def test_oauth_callback_without_code(self, client):
        """OAuth callback should error when no code is provided."""
        with client.session_transaction() as sess:
            sess["base_url"] = "https://api.example.com"

        response = client.get("/oauth/callback")

        assert response.status_code == 200
        assert b"No authorization code received" in response.data

    def test_oauth_callback_state_mismatch(self, client):
        """OAuth callback should error on state mismatch (CSRF protection)."""
        with client.session_transaction() as sess:
            sess["base_url"] = "https://api.example.com"
            sess["oauth_state"] = {"state": "expected_state"}

        response = client.get("/oauth/callback?code=auth_code&state=wrong_state")

        assert response.status_code == 200
        assert b"state mismatch" in response.data

    def test_oauth_callback_missing_config(self, client):
        """OAuth callback should error when session config is missing."""
        with client.session_transaction() as sess:
            sess["base_url"] = "https://api.example.com"
            sess["oauth_state"] = {"state": "test_state"}

        response = client.get("/oauth/callback?code=auth_code&state=test_state")

        assert response.status_code == 200
        assert b"Missing OAuth configuration" in response.data

    def test_oauth_callback_success(self, client):
        """OAuth callback should exchange code for token and redirect."""
        mock_token_response = Mock()
        mock_token_response.access_token = "test_access_token"
        mock_token_response.refresh_token = "test_refresh_token"

        with client.session_transaction() as sess:
            sess["base_url"] = "https://api.example.com"
            sess["oauth_state"] = {
                "state": "test_state",
                "scheme_name": "oauth2",
                "token_url": "https://auth.example.com/token",
                "client_id": "test_client",
                "client_secret": "test_secret",
                "redirect_uri": "http://localhost/oauth/callback",
                "code_verifier": "test_verifier",
            }

        with patch("app.AuthorizationCodeFlow") as mock_flow_class:
            mock_flow = Mock()
            mock_flow.exchange_code.return_value = mock_token_response
            mock_flow_class.return_value = mock_flow

            response = client.get("/oauth/callback?code=auth_code&state=test_state")

        assert response.status_code == 302
        assert "/request-builder" in response.location

    def test_oauth_callback_token_exchange_error(self, client):
        """OAuth callback should handle token exchange errors."""
        from auth.oauth2_flows import OAuth2Error

        with client.session_transaction() as sess:
            sess["base_url"] = "https://api.example.com"
            sess["oauth_state"] = {
                "state": "test_state",
                "scheme_name": "oauth2",
                "token_url": "https://auth.example.com/token",
                "client_id": "test_client",
                "client_secret": "test_secret",
                "redirect_uri": "http://localhost/oauth/callback",
            }

        with patch("app.AuthorizationCodeFlow") as mock_flow_class:
            mock_flow = Mock()
            mock_flow.exchange_code.side_effect = OAuth2Error("Invalid grant")
            mock_flow_class.return_value = mock_flow

            response = client.get("/oauth/callback?code=invalid_code&state=test_state")

        assert response.status_code == 200
        assert b"Token exchange failed" in response.data


class TestOAuthAuthorizeRoute:
    """Tests for the /oauth/authorize/<scheme_name> route."""

    def test_oauth_authorize_invalid_scheme(self, client):
        """OAuth authorize should redirect when scheme is invalid."""
        with client.session_transaction() as sess:
            sess["auth_schemes"] = {}
            sess["auth_methods"] = {}

        response = client.get("/oauth/authorize/nonexistent")

        assert response.status_code == 302
        assert "/credentials" in response.location

    def test_oauth_authorize_non_oauth_scheme(self, client):
        """OAuth authorize should redirect for non-OAuth schemes."""
        with client.session_transaction() as sess:
            sess["auth_schemes"] = {"api_key": {"scheme_type": "apiKey", "name": "X-API-Key"}}
            sess["auth_methods"] = {"api_key": "apiKey"}

        response = client.get("/oauth/authorize/api_key")

        assert response.status_code == 302
        assert "/credentials" in response.location

    def test_oauth_authorize_missing_auth_url(self, client):
        """OAuth authorize should return to credentials when auth URL is missing."""
        with client.session_transaction() as sess:
            sess["auth_schemes"] = {
                "oauth2": {
                    "scheme_type": "oauth2",
                    "flows": {"clientCredentials": {"tokenUrl": "https://auth.example.com/token"}},
                }
            }
            sess["auth_methods"] = {"oauth2": "oauth2"}

        response = client.get("/oauth/authorize/oauth2")

        # Returns credentials page (template doesn't display error param)
        assert response.status_code == 200
        assert b"Configure Authentication" in response.data

    def test_oauth_authorize_missing_client_id(self, client):
        """OAuth authorize should return to credentials when client ID is missing."""
        with client.session_transaction() as sess:
            sess["auth_schemes"] = {
                "oauth2": {
                    "scheme_type": "oauth2",
                    "flows": {
                        "authorizationCode": {
                            "authorizationUrl": "https://auth.example.com/authorize",
                            "tokenUrl": "https://auth.example.com/token",
                        }
                    },
                }
            }
            sess["auth_methods"] = {"oauth2": "oauth2"}
            sess["credentials"] = {}

        response = client.get("/oauth/authorize/oauth2")

        # Returns credentials page (template doesn't display error param)
        assert response.status_code == 200
        assert b"Configure Authentication" in response.data

    def test_oauth_authorize_success_redirects(self, client):
        """OAuth authorize should redirect to authorization URL with PKCE."""
        with client.session_transaction() as sess:
            sess["auth_schemes"] = {
                "oauth2": {
                    "scheme_type": "oauth2",
                    "flows": {
                        "authorizationCode": {
                            "authorizationUrl": "https://auth.example.com/authorize",
                            "tokenUrl": "https://auth.example.com/token",
                            "scopes": {"read": "Read access", "write": "Write access"},
                        }
                    },
                }
            }
            sess["auth_methods"] = {"oauth2": "oauth2"}
            sess["credentials"] = {"oauth2_client_id": "test_client_id"}

        response = client.get("/oauth/authorize/oauth2")

        assert response.status_code == 302
        assert "https://auth.example.com/authorize" in response.location
        assert "client_id=test_client_id" in response.location
        assert "response_type=code" in response.location
        assert "code_challenge=" in response.location
        assert "code_challenge_method=S256" in response.location

    def test_oauth_authorize_implicit_flow(self, client):
        """OAuth authorize should work with implicit flow."""
        with client.session_transaction() as sess:
            sess["auth_schemes"] = {
                "oauth2": {
                    "scheme_type": "oauth2",
                    "flows": {
                        "implicit": {
                            "authorizationUrl": "https://auth.example.com/authorize",
                        }
                    },
                }
            }
            sess["auth_methods"] = {"oauth2": "oauth2"}
            sess["credentials"] = {"oauth2_client_id": "test_client_id"}

        response = client.get("/oauth/authorize/oauth2")

        assert response.status_code == 302
        assert "https://auth.example.com/authorize" in response.location


class TestTokenRefreshRoute:
    """Tests for the /api/token/refresh route."""

    def test_token_refresh_no_refresh_token(self, client):
        """Token refresh should error when no refresh token is available."""
        with client.session_transaction() as sess:
            sess["credentials"] = {}
            sess["auth_schemes"] = {}

        response = client.post("/api/token/refresh")

        assert response.status_code == 400
        data = response.get_json()
        assert data["success"] is False
        assert "No refresh token available" in data["error"]

    def test_token_refresh_success(self, client):
        """Token refresh should successfully refresh and store new token."""
        mock_token_response = Mock()
        mock_token_response.access_token = "new_access_token"
        mock_token_response.refresh_token = "new_refresh_token"

        with client.session_transaction() as sess:
            sess["credentials"] = {
                "oauth2": "old_access_token",
                "oauth2_refresh_token": "old_refresh_token",
                "oauth2_client_id": "test_client",
                "oauth2_client_secret": "test_secret",
            }
            sess["auth_schemes"] = {
                "oauth2": {
                    "scheme_type": "oauth2",
                    "flows": {
                        "authorizationCode": {
                            "tokenUrl": "https://auth.example.com/token",
                        }
                    },
                }
            }

        with patch("app.RefreshTokenFlow") as mock_flow_class:
            mock_flow = Mock()
            mock_flow.refresh.return_value = mock_token_response
            mock_flow_class.return_value = mock_flow

            response = client.post("/api/token/refresh")

        assert response.status_code == 200
        data = response.get_json()
        assert data["success"] is True
        assert data["message"] == "Token refreshed"

    def test_token_refresh_error(self, client):
        """Token refresh should handle OAuth errors gracefully."""
        from auth.oauth2_flows import OAuth2Error

        with client.session_transaction() as sess:
            sess["credentials"] = {
                "oauth2": "old_access_token",
                "oauth2_refresh_token": "expired_refresh_token",
            }
            sess["auth_schemes"] = {
                "oauth2": {
                    "scheme_type": "oauth2",
                    "flows": {
                        "authorizationCode": {
                            "tokenUrl": "https://auth.example.com/token",
                        }
                    },
                }
            }

        with patch("app.RefreshTokenFlow") as mock_flow_class:
            mock_flow = Mock()
            mock_flow.refresh.side_effect = OAuth2Error("Refresh token expired")
            mock_flow_class.return_value = mock_flow

            response = client.post("/api/token/refresh")

        assert response.status_code == 400
        data = response.get_json()
        assert data["success"] is False
        assert "Refresh token expired" in data["error"]


class TestRequestBuilderRoute:
    """Tests for the /request-builder route."""

    def test_request_builder_redirects_without_credentials(self, client):
        """Request builder should redirect to credentials when none exist."""
        response = client.get("/request-builder")

        assert response.status_code == 302
        assert "/credentials" in response.location

    def test_request_builder_shows_page_with_credentials(self, client):
        """Request builder should display when credentials are present."""
        with client.session_transaction() as sess:
            sess["credentials"] = {"api_key": "test_key"}
            sess["base_url"] = "https://api.example.com"
            sess["openapi_url"] = "https://api.example.com/openapi.json"

        response = client.get("/request-builder")

        assert response.status_code == 200
        assert b"Request Builder" in response.data
