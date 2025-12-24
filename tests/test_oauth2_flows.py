"""Tests for auth.oauth2_flows module."""

from datetime import datetime, timedelta
from unittest.mock import Mock, patch
from urllib.parse import parse_qs, urlparse

import pytest

from auth.oauth2_flows import (
    AuthorizationCodeFlow,
    ClientCredentialsFlow,
    ImplicitFlow,
    OAuth2Error,
    PasswordFlow,
    RefreshTokenFlow,
    TokenResponse,
    get_flow_handler,
)


class TestTokenResponse:
    """Tests for TokenResponse dataclass."""

    def test_create_token_response(self):
        token = TokenResponse(
            access_token="access123",
            token_type="Bearer",
            expires_in=3600,
            refresh_token="refresh123",
            scope="read write",
        )

        assert token.access_token == "access123"
        assert token.token_type == "Bearer"
        assert token.expires_in == 3600
        assert token.refresh_token == "refresh123"

    def test_defaults(self):
        token = TokenResponse(access_token="test")

        assert token.token_type == "Bearer"
        assert token.expires_in is None
        assert token.refresh_token is None

    def test_is_expired_no_expiry(self):
        """Token without expires_in is never expired."""
        token = TokenResponse(access_token="test")
        assert not token.is_expired()

    def test_is_expired_fresh(self):
        """Fresh token should not be expired."""
        token = TokenResponse(
            access_token="test",
            expires_in=3600,
            obtained_at=datetime.now(),
        )
        assert not token.is_expired()

    def test_is_expired_old(self):
        """Old token should be expired."""
        token = TokenResponse(
            access_token="test",
            expires_in=3600,
            obtained_at=datetime.now() - timedelta(hours=2),
        )
        assert token.is_expired()

    def test_is_expired_with_buffer(self):
        """Token about to expire should be considered expired with buffer."""
        token = TokenResponse(
            access_token="test",
            expires_in=3600,
            obtained_at=datetime.now() - timedelta(seconds=3550),
        )
        # Should be expired with 60s buffer (default)
        assert token.is_expired(buffer_seconds=60)
        # Should not be expired with 0 buffer
        assert not token.is_expired(buffer_seconds=0)

    def test_from_response(self):
        """Test creating from OAuth response dict."""
        data = {
            "access_token": "token123",
            "token_type": "Bearer",
            "expires_in": 3600,
            "refresh_token": "refresh123",
            "scope": "read",
            "id_token": "id123",
        }

        token = TokenResponse.from_response(data)

        assert token.access_token == "token123"
        assert token.refresh_token == "refresh123"
        assert token.id_token == "id123"
        assert token.raw_response == data

    def test_to_dict(self):
        token = TokenResponse(
            access_token="test",
            expires_in=3600,
        )
        data = token.to_dict()

        assert data["access_token"] == "test"
        assert data["expires_in"] == 3600
        assert "obtained_at" in data


class TestClientCredentialsFlow:
    """Tests for ClientCredentialsFlow."""

    @pytest.fixture
    def flow(self):
        return ClientCredentialsFlow()

    def test_get_flow_type(self, flow):
        assert flow.get_flow_type() == "client_credentials"

    @patch("auth.oauth2_flows.requests.post")
    def test_authenticate_success(self, mock_post, flow):
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "access_token": "token123",
            "token_type": "Bearer",
            "expires_in": 3600,
        }
        mock_post.return_value = mock_response

        result = flow.authenticate(
            token_url="https://auth.example.com/token",
            client_id="client123",
            client_secret="secret123",
        )

        assert result.access_token == "token123"
        assert result.expires_in == 3600

        # Verify request
        mock_post.assert_called_once()
        call_kwargs = mock_post.call_args[1]
        assert call_kwargs["auth"] == ("client123", "secret123")
        assert call_kwargs["data"]["grant_type"] == "client_credentials"

    @patch("auth.oauth2_flows.requests.post")
    def test_authenticate_with_scopes(self, mock_post, flow):
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"access_token": "token"}
        mock_post.return_value = mock_response

        flow.authenticate(
            token_url="https://auth.example.com/token",
            client_id="client",
            client_secret="secret",
            scopes=["read", "write"],
        )

        call_kwargs = mock_post.call_args[1]
        assert call_kwargs["data"]["scope"] == "read write"

    @patch("auth.oauth2_flows.requests.post")
    def test_authenticate_error(self, mock_post, flow):
        mock_response = Mock()
        mock_response.status_code = 400
        mock_response.json.return_value = {
            "error": "invalid_client",
            "error_description": "Client authentication failed",
        }
        mock_post.return_value = mock_response

        with pytest.raises(OAuth2Error) as exc_info:
            flow.authenticate(
                token_url="https://auth.example.com/token",
                client_id="bad_client",
                client_secret="bad_secret",
            )

        assert exc_info.value.error == "invalid_client"
        assert "Client authentication failed" in str(exc_info.value)


class TestAuthorizationCodeFlow:
    """Tests for AuthorizationCodeFlow."""

    @pytest.fixture
    def flow(self):
        return AuthorizationCodeFlow()

    def test_get_flow_type(self, flow):
        assert flow.get_flow_type() == "authorization_code"

    def test_generate_pkce_pair(self, flow):
        verifier, challenge = flow.generate_pkce_pair()

        # Verifier should be URL-safe base64
        assert len(verifier) > 40
        # Challenge should also be URL-safe base64
        assert len(challenge) > 40
        # They should be different
        assert verifier != challenge

    def test_generate_state(self, flow):
        state1 = flow.generate_state()
        state2 = flow.generate_state()

        # Should be random
        assert state1 != state2
        # Should be URL-safe
        assert len(state1) > 40

    def test_build_authorization_url(self, flow):
        url, state = flow.build_authorization_url(
            authorization_url="https://auth.example.com/authorize",
            client_id="client123",
            redirect_uri="https://app.example.com/callback",
            scopes=["openid", "profile"],
        )

        parsed = urlparse(url)
        params = parse_qs(parsed.query)

        assert parsed.netloc == "auth.example.com"
        assert parsed.path == "/authorize"
        assert params["response_type"] == ["code"]
        assert params["client_id"] == ["client123"]
        assert params["redirect_uri"] == ["https://app.example.com/callback"]
        assert params["scope"] == ["openid profile"]
        assert params["state"] == [state]

    def test_build_authorization_url_with_pkce(self, flow):
        verifier, challenge = flow.generate_pkce_pair()

        url, state = flow.build_authorization_url(
            authorization_url="https://auth.example.com/authorize",
            client_id="client123",
            redirect_uri="https://app.example.com/callback",
            code_challenge=challenge,
        )

        parsed = urlparse(url)
        params = parse_qs(parsed.query)

        assert params["code_challenge"] == [challenge]
        assert params["code_challenge_method"] == ["S256"]

    def test_build_authorization_url_with_state(self, flow):
        """Test that provided state is used."""
        url, state = flow.build_authorization_url(
            authorization_url="https://auth.example.com/authorize",
            client_id="client123",
            redirect_uri="https://app.example.com/callback",
            state="my_custom_state",
        )

        assert state == "my_custom_state"
        assert "state=my_custom_state" in url

    @patch("auth.oauth2_flows.requests.post")
    def test_exchange_code_success(self, mock_post, flow):
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "access_token": "access123",
            "refresh_token": "refresh123",
            "expires_in": 3600,
        }
        mock_post.return_value = mock_response

        result = flow.exchange_code(
            token_url="https://auth.example.com/token",
            code="auth_code_123",
            redirect_uri="https://app.example.com/callback",
            client_id="client123",
            client_secret="secret123",
        )

        assert result.access_token == "access123"
        assert result.refresh_token == "refresh123"

    @patch("auth.oauth2_flows.requests.post")
    def test_exchange_code_with_pkce(self, mock_post, flow):
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"access_token": "token"}
        mock_post.return_value = mock_response

        flow.exchange_code(
            token_url="https://auth.example.com/token",
            code="auth_code",
            redirect_uri="https://app.example.com/callback",
            client_id="client123",
            code_verifier="verifier123",
        )

        call_kwargs = mock_post.call_args[1]
        assert call_kwargs["data"]["code_verifier"] == "verifier123"
        # No auth header for PKCE public client
        assert call_kwargs["auth"] is None

    @patch("auth.oauth2_flows.requests.post")
    def test_exchange_code_error(self, mock_post, flow):
        mock_response = Mock()
        mock_response.status_code = 400
        mock_response.json.return_value = {
            "error": "invalid_grant",
            "error_description": "Authorization code expired",
        }
        mock_post.return_value = mock_response

        with pytest.raises(OAuth2Error) as exc_info:
            flow.exchange_code(
                token_url="https://auth.example.com/token",
                code="expired_code",
                redirect_uri="https://app.example.com/callback",
                client_id="client123",
            )

        assert exc_info.value.error == "invalid_grant"


class TestImplicitFlow:
    """Tests for ImplicitFlow."""

    @pytest.fixture
    def flow(self):
        return ImplicitFlow()

    def test_get_flow_type(self, flow):
        assert flow.get_flow_type() == "implicit"

    def test_build_authorization_url(self, flow):
        url, state = flow.build_authorization_url(
            authorization_url="https://auth.example.com/authorize",
            client_id="client123",
            redirect_uri="https://app.example.com/callback",
            scopes=["read"],
        )

        parsed = urlparse(url)
        params = parse_qs(parsed.query)

        # Implicit flow uses response_type=token
        assert params["response_type"] == ["token"]
        assert params["client_id"] == ["client123"]

    def test_parse_fragment_response_success(self, flow):
        fragment = "access_token=token123&token_type=Bearer&expires_in=3600&scope=read"

        result = flow.parse_fragment_response(fragment)

        assert result.access_token == "token123"
        assert result.token_type == "Bearer"
        assert result.expires_in == 3600
        assert result.scope == "read"

    def test_parse_fragment_response_error(self, flow):
        fragment = "error=access_denied&error_description=User%20denied%20access"

        with pytest.raises(OAuth2Error) as exc_info:
            flow.parse_fragment_response(fragment)

        assert exc_info.value.error == "access_denied"

    def test_parse_fragment_response_missing_token(self, flow):
        fragment = "token_type=Bearer"

        with pytest.raises(OAuth2Error) as exc_info:
            flow.parse_fragment_response(fragment)

        assert exc_info.value.error == "invalid_response"


class TestPasswordFlow:
    """Tests for PasswordFlow."""

    @pytest.fixture
    def flow(self):
        return PasswordFlow()

    def test_get_flow_type(self, flow):
        assert flow.get_flow_type() == "password"

    @patch("auth.oauth2_flows.requests.post")
    def test_authenticate_success(self, mock_post, flow):
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "access_token": "token123",
            "refresh_token": "refresh123",
        }
        mock_post.return_value = mock_response

        result = flow.authenticate(
            token_url="https://auth.example.com/token",
            username="user@example.com",
            password="password123",
            client_id="client123",
        )

        assert result.access_token == "token123"

        call_kwargs = mock_post.call_args[1]
        assert call_kwargs["data"]["grant_type"] == "password"
        assert call_kwargs["data"]["username"] == "user@example.com"
        assert call_kwargs["data"]["password"] == "password123"

    @patch("auth.oauth2_flows.requests.post")
    def test_authenticate_with_secret(self, mock_post, flow):
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"access_token": "token"}
        mock_post.return_value = mock_response

        flow.authenticate(
            token_url="https://auth.example.com/token",
            username="user",
            password="pass",
            client_id="client123",
            client_secret="secret123",
        )

        call_kwargs = mock_post.call_args[1]
        assert call_kwargs["auth"] == ("client123", "secret123")

    @patch("auth.oauth2_flows.requests.post")
    def test_authenticate_error(self, mock_post, flow):
        mock_response = Mock()
        mock_response.status_code = 401
        mock_response.json.return_value = {
            "error": "invalid_grant",
            "error_description": "Invalid credentials",
        }
        mock_post.return_value = mock_response

        with pytest.raises(OAuth2Error) as exc_info:
            flow.authenticate(
                token_url="https://auth.example.com/token",
                username="user",
                password="wrong",
                client_id="client",
            )

        assert exc_info.value.error == "invalid_grant"


class TestRefreshTokenFlow:
    """Tests for RefreshTokenFlow."""

    @pytest.fixture
    def flow(self):
        return RefreshTokenFlow()

    def test_get_flow_type(self, flow):
        assert flow.get_flow_type() == "refresh_token"

    @patch("auth.oauth2_flows.requests.post")
    def test_refresh_success(self, mock_post, flow):
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "access_token": "new_token",
            "refresh_token": "new_refresh",
            "expires_in": 3600,
        }
        mock_post.return_value = mock_response

        result = flow.refresh(
            token_url="https://auth.example.com/token",
            refresh_token="old_refresh",
            client_id="client123",
        )

        assert result.access_token == "new_token"
        assert result.refresh_token == "new_refresh"

        call_kwargs = mock_post.call_args[1]
        assert call_kwargs["data"]["grant_type"] == "refresh_token"
        assert call_kwargs["data"]["refresh_token"] == "old_refresh"

    @patch("auth.oauth2_flows.requests.post")
    def test_refresh_with_scopes(self, mock_post, flow):
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"access_token": "token"}
        mock_post.return_value = mock_response

        flow.refresh(
            token_url="https://auth.example.com/token",
            refresh_token="refresh",
            client_id="client",
            scopes=["read"],
        )

        call_kwargs = mock_post.call_args[1]
        assert call_kwargs["data"]["scope"] == "read"

    @patch("auth.oauth2_flows.requests.post")
    def test_refresh_error(self, mock_post, flow):
        mock_response = Mock()
        mock_response.status_code = 400
        mock_response.json.return_value = {
            "error": "invalid_grant",
            "error_description": "Refresh token expired",
        }
        mock_post.return_value = mock_response

        with pytest.raises(OAuth2Error) as exc_info:
            flow.refresh(
                token_url="https://auth.example.com/token",
                refresh_token="expired",
                client_id="client",
            )

        assert exc_info.value.error == "invalid_grant"


class TestGetFlowHandler:
    """Tests for get_flow_handler factory function."""

    def test_client_credentials(self):
        handler = get_flow_handler("client_credentials")
        assert isinstance(handler, ClientCredentialsFlow)

    def test_client_credentials_camel_case(self):
        handler = get_flow_handler("clientCredentials")
        assert isinstance(handler, ClientCredentialsFlow)

    def test_authorization_code(self):
        handler = get_flow_handler("authorization_code")
        assert isinstance(handler, AuthorizationCodeFlow)

    def test_authorization_code_camel_case(self):
        handler = get_flow_handler("authorizationCode")
        assert isinstance(handler, AuthorizationCodeFlow)

    def test_implicit(self):
        handler = get_flow_handler("implicit")
        assert isinstance(handler, ImplicitFlow)

    def test_password(self):
        handler = get_flow_handler("password")
        assert isinstance(handler, PasswordFlow)

    def test_refresh_token(self):
        handler = get_flow_handler("refresh_token")
        assert isinstance(handler, RefreshTokenFlow)

    def test_unknown_flow(self):
        with pytest.raises(ValueError) as exc_info:
            get_flow_handler("unknown")

        assert "Unknown OAuth2 flow type" in str(exc_info.value)


class TestOAuth2Error:
    """Tests for OAuth2Error exception."""

    def test_basic_error(self):
        error = OAuth2Error("access_denied")
        assert error.error == "access_denied"
        assert str(error) == "access_denied"

    def test_error_with_description(self):
        error = OAuth2Error("invalid_request", "Missing required parameter")
        assert error.error_description == "Missing required parameter"
        assert "Missing required parameter" in str(error)

    def test_error_with_uri(self):
        error = OAuth2Error(
            "server_error",
            "Internal error",
            "https://example.com/error",
        )
        assert error.error_uri == "https://example.com/error"
