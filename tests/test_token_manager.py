"""Tests for auth.token_manager module."""

from datetime import datetime
from unittest.mock import Mock, patch

import pytest

from auth.oauth2_flows import OAuth2Error, TokenResponse
from auth.storage import SessionStorage, StoredToken
from auth.token_manager import TokenConfig, TokenManager


class TestTokenConfig:
    """Tests for TokenConfig dataclass."""

    def test_create_config(self):
        config = TokenConfig(
            oauth2_flow="client_credentials",
            token_url="https://auth.example.com/token",
            client_id="client123",
            client_secret="secret123",
            scopes=["read", "write"],
            renewal_interval_minutes=15,
        )

        assert config.oauth2_flow == "client_credentials"
        assert config.token_url == "https://auth.example.com/token"
        assert config.scopes == ["read", "write"]
        assert config.renewal_interval_minutes == 15

    def test_defaults(self):
        config = TokenConfig(
            oauth2_flow="client_credentials",
            token_url="https://auth.example.com/token",
            client_id="client",
        )

        assert config.client_secret is None
        assert config.scopes == []
        assert config.renewal_interval_minutes == 0
        assert config.buffer_seconds == 60

    def test_to_dict(self):
        config = TokenConfig(
            oauth2_flow="client_credentials",
            token_url="https://auth.example.com/token",
            client_id="client",
            client_secret="secret",
        )
        data = config.to_dict()

        assert data["oauth2_flow"] == "client_credentials"
        assert data["client_id"] == "client"

    def test_from_dict(self):
        data = {
            "oauth2_flow": "password",
            "token_url": "https://auth.example.com/token",
            "client_id": "client",
            "username": "user",
            "password": "pass",
        }
        config = TokenConfig.from_dict(data)

        assert config.oauth2_flow == "password"
        assert config.username == "user"


class TestTokenManager:
    """Tests for TokenManager class."""

    @pytest.fixture
    def storage(self):
        """Create a session storage with mock session dict."""
        return SessionStorage({})

    @pytest.fixture
    def manager(self, storage):
        """Create a token manager with the storage."""
        manager = TokenManager(storage)
        yield manager
        manager.shutdown()

    @pytest.fixture
    def sample_config(self):
        return TokenConfig(
            oauth2_flow="client_credentials",
            token_url="https://auth.example.com/token",
            client_id="client123",
            client_secret="secret123",
        )

    @pytest.fixture
    def sample_token(self):
        return TokenResponse(
            access_token="access123",
            token_type="Bearer",
            expires_in=3600,
            refresh_token="refresh123",
        )

    def test_register_api(self, manager, sample_config):
        manager.register_api("api1", sample_config)

        assert manager.get_config("api1") == sample_config
        assert manager.get_failure_count("api1") == 0

    def test_register_with_initial_token(self, manager, sample_config, sample_token):
        manager.register_api("api1", sample_config, initial_token=sample_token)

        stored = manager.get_full_token("api1")
        assert stored is not None
        assert stored.access_token == "access123"

    def test_unregister_api(self, manager, sample_config):
        manager.register_api("api1", sample_config)
        manager.unregister_api("api1")

        assert manager.get_config("api1") is None

    def test_get_token_missing_api(self, manager):
        token = manager.get_token("nonexistent")
        assert token is None

    @patch("auth.token_manager.ClientCredentialsFlow")
    def test_get_token_auto_renew(self, mock_flow_class, manager, sample_config):
        mock_flow = Mock()
        mock_flow.authenticate.return_value = TokenResponse(
            access_token="new_token",
            expires_in=3600,
        )
        mock_flow_class.return_value = mock_flow

        manager.register_api("api1", sample_config)
        token = manager.get_token("api1")

        assert token == "new_token"
        mock_flow.authenticate.assert_called_once()

    def test_get_token_cached(self, manager, sample_config, sample_token):
        manager.register_api("api1", sample_config, initial_token=sample_token)

        # Should return cached token without renewal
        token = manager.get_token("api1")
        assert token == "access123"

    def test_schedule_renewal(self, manager, sample_config):
        manager.register_api("api1", sample_config)
        manager.schedule_renewal("api1", 15)

        assert manager.is_renewal_active("api1")

    def test_cancel_renewal(self, manager, sample_config):
        manager.register_api("api1", sample_config)
        manager.schedule_renewal("api1", 15)
        manager.cancel_renewal("api1")

        assert not manager.is_renewal_active("api1")

    @patch("auth.token_manager.ClientCredentialsFlow")
    def test_renew_now_success(self, mock_flow_class, manager, sample_config):
        mock_flow = Mock()
        mock_flow.authenticate.return_value = TokenResponse(
            access_token="renewed_token",
            expires_in=3600,
        )
        mock_flow_class.return_value = mock_flow

        manager.register_api("api1", sample_config)
        result = manager.renew_now("api1")

        assert result.access_token == "renewed_token"
        assert manager.get_failure_count("api1") == 0

    def test_renew_now_unregistered(self, manager):
        with pytest.raises(ValueError) as exc_info:
            manager.renew_now("nonexistent")

        assert "not registered" in str(exc_info.value)

    @patch("auth.token_manager.ClientCredentialsFlow")
    def test_renewal_failure_increments_count(self, mock_flow_class, manager, sample_config):
        mock_flow = Mock()
        mock_flow.authenticate.side_effect = OAuth2Error("server_error")
        mock_flow_class.return_value = mock_flow

        manager.register_api("api1", sample_config)

        # Trigger the internal renewal job
        manager._renewal_job("api1")

        assert manager.get_failure_count("api1") == 1

    @patch("auth.token_manager.ClientCredentialsFlow")
    def test_renewal_callback(self, mock_flow_class, manager, sample_config):
        mock_flow = Mock()
        new_token = TokenResponse(access_token="token", expires_in=3600)
        mock_flow.authenticate.return_value = new_token
        mock_flow_class.return_value = mock_flow

        callback = Mock()
        manager.register_api("api1", sample_config)
        manager.set_renewal_callback("api1", callback)
        manager.renew_now("api1")

        callback.assert_called_once_with("api1", new_token)

    @patch("auth.token_manager.RefreshTokenFlow")
    def test_refresh_token_used(self, mock_flow_class, manager, sample_config, sample_token):
        mock_flow = Mock()
        mock_flow.refresh.return_value = TokenResponse(
            access_token="new_access",
            refresh_token="new_refresh",
            expires_in=3600,
        )
        mock_flow_class.return_value = mock_flow

        manager.register_api("api1", sample_config, initial_token=sample_token)
        manager.renew_now("api1")

        mock_flow.refresh.assert_called_once()
        call_kwargs = mock_flow.refresh.call_args[1]
        assert call_kwargs["refresh_token"] == "refresh123"

    @patch("auth.token_manager.RefreshTokenFlow")
    @patch("auth.token_manager.ClientCredentialsFlow")
    def test_refresh_token_fallback(
        self, mock_cc_class, mock_refresh_class, manager, sample_config, sample_token
    ):
        """If refresh token is invalid, fall back to client credentials."""
        mock_refresh = Mock()
        mock_refresh.refresh.side_effect = OAuth2Error("invalid_grant")
        mock_refresh_class.return_value = mock_refresh

        mock_cc = Mock()
        mock_cc.authenticate.return_value = TokenResponse(
            access_token="cc_token",
            expires_in=3600,
        )
        mock_cc_class.return_value = mock_cc

        manager.register_api("api1", sample_config, initial_token=sample_token)
        result = manager.renew_now("api1")

        # Should have tried refresh first, then client credentials
        mock_refresh.refresh.assert_called_once()
        mock_cc.authenticate.assert_called_once()
        assert result.access_token == "cc_token"

    def test_password_flow_requires_credentials(self, manager):
        config = TokenConfig(
            oauth2_flow="password",
            token_url="https://auth.example.com/token",
            client_id="client",
            # Missing username and password
        )
        manager.register_api("api1", config)

        with pytest.raises(ValueError) as exc_info:
            manager.renew_now("api1")

        assert "username and password" in str(exc_info.value)

    @patch("auth.token_manager.PasswordFlow")
    def test_password_flow(self, mock_flow_class, manager):
        mock_flow = Mock()
        mock_flow.authenticate.return_value = TokenResponse(
            access_token="token",
            expires_in=3600,
        )
        mock_flow_class.return_value = mock_flow

        config = TokenConfig(
            oauth2_flow="password",
            token_url="https://auth.example.com/token",
            client_id="client",
            username="user",
            password="pass",
        )
        manager.register_api("api1", config)
        result = manager.renew_now("api1")

        assert result.access_token == "token"
        call_kwargs = mock_flow.authenticate.call_args[1]
        assert call_kwargs["username"] == "user"
        assert call_kwargs["password"] == "pass"

    def test_unsupported_flow_for_auto_renewal(self, manager):
        config = TokenConfig(
            oauth2_flow="authorization_code",
            token_url="https://auth.example.com/token",
            client_id="client",
        )
        manager.register_api("api1", config)

        with pytest.raises(ValueError) as exc_info:
            manager.renew_now("api1")

        assert "requires user interaction" in str(exc_info.value)

    def test_auto_schedule_based_on_expires_in(self, manager, sample_config, sample_token):
        """Token with expires_in should auto-schedule renewal."""
        manager.register_api("api1", sample_config, initial_token=sample_token)

        # Should have scheduled renewal
        assert manager.is_renewal_active("api1")


class TestTokenManagerBackoff:
    """Tests for exponential backoff on failure."""

    @pytest.fixture
    def storage(self):
        return SessionStorage({})

    @pytest.fixture
    def manager(self, storage):
        manager = TokenManager(storage)
        yield manager
        manager.shutdown()

    @patch("auth.token_manager.ClientCredentialsFlow")
    def test_backoff_increases(self, mock_flow_class, manager):
        mock_flow = Mock()
        mock_flow.authenticate.side_effect = OAuth2Error("server_error")
        mock_flow_class.return_value = mock_flow

        config = TokenConfig(
            oauth2_flow="client_credentials",
            token_url="https://auth.example.com/token",
            client_id="client",
            client_secret="secret",
        )
        manager.register_api("api1", config)
        manager.schedule_renewal("api1", 1)

        # Simulate failures
        manager._renewal_job("api1")
        assert manager.get_failure_count("api1") == 1

        manager._renewal_job("api1")
        assert manager.get_failure_count("api1") == 2

    @patch("auth.token_manager.ClientCredentialsFlow")
    def test_max_failures_disables_renewal(self, mock_flow_class, manager):
        mock_flow = Mock()
        mock_flow.authenticate.side_effect = OAuth2Error("server_error")
        mock_flow_class.return_value = mock_flow

        config = TokenConfig(
            oauth2_flow="client_credentials",
            token_url="https://auth.example.com/token",
            client_id="client",
            client_secret="secret",
        )
        manager.register_api("api1", config)
        manager.schedule_renewal("api1", 1)

        # Trigger 5 failures (MAX_FAILURES)
        for _ in range(5):
            manager._renewal_job("api1")

        # Renewal should be disabled
        assert not manager.is_renewal_active("api1")
        assert manager.get_failure_count("api1") == 5

    @patch("auth.token_manager.ClientCredentialsFlow")
    def test_success_resets_failure_count(self, mock_flow_class, manager):
        mock_flow = Mock()
        # First call fails, second succeeds
        mock_flow.authenticate.side_effect = [
            OAuth2Error("server_error"),
            TokenResponse(access_token="token", expires_in=3600),
        ]
        mock_flow_class.return_value = mock_flow

        config = TokenConfig(
            oauth2_flow="client_credentials",
            token_url="https://auth.example.com/token",
            client_id="client",
            client_secret="secret",
        )
        manager.register_api("api1", config)

        # First renewal fails
        manager._renewal_job("api1")
        assert manager.get_failure_count("api1") == 1

        # Second renewal succeeds
        manager._renewal_job("api1")
        assert manager.get_failure_count("api1") == 0
