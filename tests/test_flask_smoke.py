import importlib
import os
import warnings
from unittest.mock import Mock, patch

import pytest
import requests

from app import app, fetch_openapi_documentation, load_secrets


@pytest.fixture
def client():
    app.config["TESTING"] = True
    with app.test_client() as client:
        yield client


class TestIndexRoute:
    def test_index_returns_form(self, client):
        response = client.get("/")

        assert response.status_code == 200
        assert b"Enter Base API URL" in response.data


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
        assert b"Enter Credentials" in response.data
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
        assert url == "https://api.example.com/openapi.yml"
        assert error is None

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
