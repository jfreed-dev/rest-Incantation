from unittest.mock import Mock, patch

import requests

from bearer_tokens import (
    get_token,
    load_secrets,
    load_token,
    renew_token,
    save_token,
    start_token_renewal,
)


class TestSaveAndLoadToken:
    def test_save_and_load_token(self, tmp_path):
        token_file = tmp_path / "token.json"
        token_info = {"access_token": "abc123", "token_type": "Bearer"}

        save_token(token_info, token_file=str(token_file))
        loaded = load_token(token_file=str(token_file))

        assert loaded == token_info

    def test_load_token_missing_file(self, tmp_path):
        token_file = tmp_path / "nonexistent.json"

        result = load_token(token_file=str(token_file))

        assert result is None


class TestLoadSecrets:
    def test_load_secrets_success(self, tmp_path):
        secrets_file = tmp_path / "secrets.yaml"
        secrets_file.write_text(
            "token_endpoint: https://auth.example.com/token\n"
            "client_id: my_client\n"
            "client_secret: my_secret\n"
        )

        secrets = load_secrets(str(secrets_file))

        assert secrets["token_endpoint"] == "https://auth.example.com/token"
        assert secrets["client_id"] == "my_client"
        assert secrets["client_secret"] == "my_secret"

    def test_load_secrets_missing_file(self, tmp_path):
        secrets_file = tmp_path / "nonexistent.yaml"

        secrets = load_secrets(str(secrets_file))

        assert secrets == {}

    def test_load_secrets_invalid_yaml(self, tmp_path):
        secrets_file = tmp_path / "invalid.yaml"
        secrets_file.write_text("invalid: yaml: content: [")

        secrets = load_secrets(str(secrets_file))

        assert secrets == {}

    def test_load_secrets_empty_file(self, tmp_path):
        secrets_file = tmp_path / "empty.yaml"
        secrets_file.write_text("")

        secrets = load_secrets(str(secrets_file))

        assert secrets == {}


class TestRenewToken:
    def test_renew_token_success(self, tmp_path):
        secrets_file = tmp_path / "secrets.yaml"
        secrets_file.write_text(
            "token_endpoint: https://auth.example.com/token\n"
            "client_id: my_client\n"
            "client_secret: my_secret\n"
        )
        token_file = tmp_path / "token.json"

        mock_response = Mock()
        mock_response.json.return_value = {
            "access_token": "new_token",
            "token_type": "Bearer",
        }

        with patch("bearer_tokens.requests.post", return_value=mock_response) as mock_post:
            result = renew_token(
                token_file=str(token_file),
                secrets_file=str(secrets_file),
            )

            mock_post.assert_called_once_with(
                "https://auth.example.com/token",
                data={"grant_type": "client_credentials"},
                auth=("my_client", "my_secret"),
                timeout=10,
            )

        assert result == {"access_token": "new_token", "token_type": "Bearer"}
        assert load_token(str(token_file)) == result

    def test_renew_token_with_explicit_params(self, tmp_path):
        token_file = tmp_path / "token.json"
        secrets_file = tmp_path / "empty_secrets.yaml"
        secrets_file.write_text("")

        mock_response = Mock()
        mock_response.json.return_value = {"access_token": "explicit_token"}

        with patch("bearer_tokens.requests.post", return_value=mock_response):
            result = renew_token(
                token_endpoint="https://explicit.example.com/token",
                client_id="explicit_client",
                client_secret="explicit_secret",
                token_file=str(token_file),
                secrets_file=str(secrets_file),
            )

        assert result["access_token"] == "explicit_token"

    def test_renew_token_missing_config(self, tmp_path):
        secrets_file = tmp_path / "incomplete.yaml"
        secrets_file.write_text("token_endpoint: https://auth.example.com/token\n")
        token_file = tmp_path / "token.json"

        result = renew_token(
            token_file=str(token_file),
            secrets_file=str(secrets_file),
        )

        assert result is None

    def test_renew_token_request_failure(self, tmp_path):
        secrets_file = tmp_path / "secrets.yaml"
        secrets_file.write_text(
            "token_endpoint: https://auth.example.com/token\n"
            "client_id: my_client\n"
            "client_secret: my_secret\n"
        )
        token_file = tmp_path / "token.json"

        with patch("bearer_tokens.requests.post") as mock_post:
            mock_post.side_effect = requests.RequestException("Connection error")

            result = renew_token(
                token_file=str(token_file),
                secrets_file=str(secrets_file),
            )

        assert result is None


class TestGetToken:
    def test_get_token_from_existing_file(self, tmp_path):
        token_file = tmp_path / "token.json"
        save_token({"access_token": "cached_token"}, str(token_file))

        token = get_token(token_file=str(token_file))

        assert token == "cached_token"

    def test_get_token_triggers_renewal(self, tmp_path):
        token_file = tmp_path / "token.json"

        with patch("bearer_tokens.renew_token") as mock_renew:
            mock_renew.return_value = {"access_token": "renewed_token"}

            token = get_token(token_file=str(token_file))

        assert token == "renewed_token"
        mock_renew.assert_called_once()

    def test_get_token_renewal_fails(self, tmp_path):
        token_file = tmp_path / "token.json"

        with patch("bearer_tokens.renew_token") as mock_renew:
            mock_renew.return_value = None

            token = get_token(token_file=str(token_file))

        assert token is None

    def test_get_token_missing_access_token_key(self, tmp_path):
        token_file = tmp_path / "token.json"
        save_token({"token_type": "Bearer"}, str(token_file))

        with patch("bearer_tokens.renew_token") as mock_renew:
            mock_renew.return_value = {"access_token": "new_token"}

            token = get_token(token_file=str(token_file))

        assert token == "new_token"
        mock_renew.assert_called_once()


class TestStartTokenRenewal:
    def test_start_token_renewal_creates_scheduler(self):
        mock_renew_fn = Mock()

        with patch("bearer_tokens.BackgroundScheduler") as mock_scheduler_class:
            mock_scheduler = Mock()
            mock_scheduler_class.return_value = mock_scheduler

            scheduler = start_token_renewal(mock_renew_fn, interval_hours=2)

            mock_scheduler.add_job.assert_called_once_with(mock_renew_fn, "interval", hours=2)
            mock_scheduler.start.assert_called_once()
            assert scheduler == mock_scheduler
