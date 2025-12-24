"""OAuth 2.0 flow implementations.

Provides implementations for all standard OAuth 2.0 grant types:
- Client Credentials (RFC 6749 Section 4.4)
- Authorization Code (RFC 6749 Section 4.1) with PKCE support
- Implicit (RFC 6749 Section 4.2)
- Resource Owner Password Credentials (RFC 6749 Section 4.3)
- Refresh Token (RFC 6749 Section 6)
"""

from __future__ import annotations

import base64
import hashlib
import logging
import secrets
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional
from urllib.parse import urlencode

import requests

logger = logging.getLogger(__name__)

# Default timeout for HTTP requests
DEFAULT_TIMEOUT = 30


@dataclass
class TokenResponse:
    """OAuth 2.0 token response.

    Attributes:
        access_token: The access token string
        token_type: Token type, usually "Bearer"
        expires_in: Token lifetime in seconds
        refresh_token: Optional refresh token for obtaining new access tokens
        scope: Space-separated list of granted scopes
        obtained_at: Timestamp when the token was obtained
        id_token: Optional OpenID Connect ID token
        raw_response: Full response data from the token endpoint
    """

    access_token: str
    token_type: str = "Bearer"
    expires_in: Optional[int] = None
    refresh_token: Optional[str] = None
    scope: Optional[str] = None
    obtained_at: datetime = field(default_factory=datetime.now)
    id_token: Optional[str] = None
    raw_response: Dict[str, Any] = field(default_factory=dict)

    def is_expired(self, buffer_seconds: int = 60) -> bool:
        """Check if the token is expired.

        Args:
            buffer_seconds: Consider token expired this many seconds before
                actual expiration to allow for clock skew and request time.

        Returns:
            True if token is expired or will expire within buffer_seconds.
        """
        if self.expires_in is None:
            return False

        elapsed = (datetime.now() - self.obtained_at).total_seconds()
        return elapsed >= (self.expires_in - buffer_seconds)

    @classmethod
    def from_response(cls, response_data: Dict[str, Any]) -> "TokenResponse":
        """Create TokenResponse from OAuth token endpoint response.

        Args:
            response_data: JSON response from token endpoint

        Returns:
            TokenResponse instance
        """
        return cls(
            access_token=response_data.get("access_token", ""),
            token_type=response_data.get("token_type", "Bearer"),
            expires_in=response_data.get("expires_in"),
            refresh_token=response_data.get("refresh_token"),
            scope=response_data.get("scope"),
            id_token=response_data.get("id_token"),
            raw_response=response_data,
        )

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for storage."""
        return {
            "access_token": self.access_token,
            "token_type": self.token_type,
            "expires_in": self.expires_in,
            "refresh_token": self.refresh_token,
            "scope": self.scope,
            "obtained_at": self.obtained_at.isoformat(),
            "id_token": self.id_token,
        }


class OAuth2Error(Exception):
    """OAuth 2.0 error response."""

    def __init__(
        self,
        error: str,
        error_description: Optional[str] = None,
        error_uri: Optional[str] = None,
    ):
        self.error = error
        self.error_description = error_description
        self.error_uri = error_uri
        message = error
        if error_description:
            message = f"{error}: {error_description}"
        super().__init__(message)


class OAuth2FlowHandler(ABC):
    """Abstract base class for OAuth 2.0 flow handlers."""

    @abstractmethod
    def get_flow_type(self) -> str:
        """Return the flow type identifier."""
        pass


class ClientCredentialsFlow(OAuth2FlowHandler):
    """OAuth 2.0 Client Credentials Grant (RFC 6749 Section 4.4).

    Used for machine-to-machine authentication where the client
    is acting on its own behalf, not on behalf of a user.
    """

    def get_flow_type(self) -> str:
        return "client_credentials"

    def authenticate(
        self,
        token_url: str,
        client_id: str,
        client_secret: str,
        scopes: Optional[List[str]] = None,
        extra_params: Optional[Dict[str, str]] = None,
        timeout: int = DEFAULT_TIMEOUT,
    ) -> TokenResponse:
        """Exchange client credentials for an access token.

        Args:
            token_url: OAuth 2.0 token endpoint URL
            client_id: Client identifier
            client_secret: Client secret
            scopes: List of requested scopes
            extra_params: Additional parameters to include in the request
            timeout: Request timeout in seconds

        Returns:
            TokenResponse with access token

        Raises:
            OAuth2Error: If token request fails
            requests.RequestException: If HTTP request fails
        """
        data = {
            "grant_type": "client_credentials",
        }
        if scopes:
            data["scope"] = " ".join(scopes)
        if extra_params:
            data.update(extra_params)

        response = requests.post(
            token_url,
            data=data,
            auth=(client_id, client_secret),
            timeout=timeout,
        )

        return self._handle_token_response(response)

    def _handle_token_response(self, response: requests.Response) -> TokenResponse:
        """Handle token endpoint response."""
        try:
            data = response.json()
        except ValueError:
            raise OAuth2Error("invalid_response", "Token endpoint returned non-JSON response")

        if response.status_code != 200:
            raise OAuth2Error(
                data.get("error", "unknown_error"),
                data.get("error_description"),
                data.get("error_uri"),
            )

        return TokenResponse.from_response(data)


class AuthorizationCodeFlow(OAuth2FlowHandler):
    """OAuth 2.0 Authorization Code Grant (RFC 6749 Section 4.1).

    Used for user authentication with browser-based authorization.
    Supports PKCE (RFC 7636) for enhanced security.
    """

    def get_flow_type(self) -> str:
        return "authorization_code"

    def generate_pkce_pair(self) -> tuple[str, str]:
        """Generate PKCE code verifier and challenge.

        Returns:
            Tuple of (code_verifier, code_challenge)
        """
        # Generate 32-byte random verifier
        code_verifier = secrets.token_urlsafe(32)

        # Create S256 challenge
        digest = hashlib.sha256(code_verifier.encode()).digest()
        code_challenge = base64.urlsafe_b64encode(digest).rstrip(b"=").decode()

        return code_verifier, code_challenge

    def generate_state(self) -> str:
        """Generate random state parameter for CSRF protection."""
        return secrets.token_urlsafe(32)

    def build_authorization_url(
        self,
        authorization_url: str,
        client_id: str,
        redirect_uri: str,
        scopes: Optional[List[str]] = None,
        state: Optional[str] = None,
        code_challenge: Optional[str] = None,
        extra_params: Optional[Dict[str, str]] = None,
    ) -> tuple[str, str]:
        """Build the authorization URL for user redirect.

        Args:
            authorization_url: OAuth 2.0 authorization endpoint
            client_id: Client identifier
            redirect_uri: URI to redirect to after authorization
            scopes: List of requested scopes
            state: CSRF protection state (generated if not provided)
            code_challenge: PKCE code challenge (for PKCE flow)
            extra_params: Additional parameters to include

        Returns:
            Tuple of (authorization_url, state)
        """
        if state is None:
            state = self.generate_state()

        params = {
            "response_type": "code",
            "client_id": client_id,
            "redirect_uri": redirect_uri,
            "state": state,
        }

        if scopes:
            params["scope"] = " ".join(scopes)

        if code_challenge:
            params["code_challenge"] = code_challenge
            params["code_challenge_method"] = "S256"

        if extra_params:
            params.update(extra_params)

        url = f"{authorization_url}?{urlencode(params)}"
        return url, state

    def exchange_code(
        self,
        token_url: str,
        code: str,
        redirect_uri: str,
        client_id: str,
        client_secret: Optional[str] = None,
        code_verifier: Optional[str] = None,
        timeout: int = DEFAULT_TIMEOUT,
    ) -> TokenResponse:
        """Exchange authorization code for tokens.

        Args:
            token_url: OAuth 2.0 token endpoint
            code: Authorization code from callback
            redirect_uri: Same redirect_uri used in authorization request
            client_id: Client identifier
            client_secret: Client secret (not required for PKCE public clients)
            code_verifier: PKCE code verifier (required if PKCE was used)
            timeout: Request timeout in seconds

        Returns:
            TokenResponse with access token and optionally refresh token

        Raises:
            OAuth2Error: If token request fails
        """
        data = {
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": redirect_uri,
            "client_id": client_id,
        }

        if code_verifier:
            data["code_verifier"] = code_verifier

        # Use client authentication if secret provided
        auth = None
        if client_secret:
            auth = (client_id, client_secret)

        response = requests.post(
            token_url,
            data=data,
            auth=auth,
            timeout=timeout,
        )

        return self._handle_token_response(response)

    def _handle_token_response(self, response: requests.Response) -> TokenResponse:
        """Handle token endpoint response."""
        try:
            data = response.json()
        except ValueError:
            raise OAuth2Error("invalid_response", "Token endpoint returned non-JSON response")

        if response.status_code != 200:
            raise OAuth2Error(
                data.get("error", "unknown_error"),
                data.get("error_description"),
                data.get("error_uri"),
            )

        return TokenResponse.from_response(data)


class ImplicitFlow(OAuth2FlowHandler):
    """OAuth 2.0 Implicit Grant (RFC 6749 Section 4.2).

    Note: This flow is deprecated in OAuth 2.1 due to security concerns.
    The token is returned directly in the URL fragment, making it
    vulnerable to token leakage. Use Authorization Code with PKCE instead.
    """

    def get_flow_type(self) -> str:
        return "implicit"

    def generate_state(self) -> str:
        """Generate random state parameter for CSRF protection."""
        return secrets.token_urlsafe(32)

    def build_authorization_url(
        self,
        authorization_url: str,
        client_id: str,
        redirect_uri: str,
        scopes: Optional[List[str]] = None,
        state: Optional[str] = None,
        extra_params: Optional[Dict[str, str]] = None,
    ) -> tuple[str, str]:
        """Build the authorization URL for implicit grant.

        Args:
            authorization_url: OAuth 2.0 authorization endpoint
            client_id: Client identifier
            redirect_uri: URI to redirect to after authorization
            scopes: List of requested scopes
            state: CSRF protection state (generated if not provided)
            extra_params: Additional parameters

        Returns:
            Tuple of (authorization_url, state)
        """
        if state is None:
            state = self.generate_state()

        params = {
            "response_type": "token",
            "client_id": client_id,
            "redirect_uri": redirect_uri,
            "state": state,
        }

        if scopes:
            params["scope"] = " ".join(scopes)

        if extra_params:
            params.update(extra_params)

        url = f"{authorization_url}?{urlencode(params)}"
        return url, state

    def parse_fragment_response(self, fragment: str) -> TokenResponse:
        """Parse token from URL fragment.

        The implicit flow returns the token in the URL fragment (after #).
        This method parses that fragment into a TokenResponse.

        Args:
            fragment: URL fragment string (without the #)

        Returns:
            TokenResponse with access token

        Raises:
            OAuth2Error: If fragment contains an error or is invalid
        """
        from urllib.parse import parse_qs

        params = parse_qs(fragment)

        # Check for error response
        if "error" in params:
            raise OAuth2Error(
                params["error"][0],
                params.get("error_description", [None])[0],
                params.get("error_uri", [None])[0],
            )

        if "access_token" not in params:
            raise OAuth2Error("invalid_response", "No access_token in fragment")

        return TokenResponse(
            access_token=params["access_token"][0],
            token_type=params.get("token_type", ["Bearer"])[0],
            expires_in=int(params["expires_in"][0]) if "expires_in" in params else None,
            scope=params.get("scope", [None])[0],
        )


class PasswordFlow(OAuth2FlowHandler):
    """OAuth 2.0 Resource Owner Password Credentials Grant (RFC 6749 Section 4.3).

    Warning: This flow should only be used when there is a high degree of
    trust between the user and the client, such as first-party applications.
    It exposes the user's credentials to the client.
    """

    def get_flow_type(self) -> str:
        return "password"

    def authenticate(
        self,
        token_url: str,
        username: str,
        password: str,
        client_id: str,
        client_secret: Optional[str] = None,
        scopes: Optional[List[str]] = None,
        timeout: int = DEFAULT_TIMEOUT,
    ) -> TokenResponse:
        """Exchange username and password for tokens.

        Args:
            token_url: OAuth 2.0 token endpoint
            username: Resource owner username
            password: Resource owner password
            client_id: Client identifier
            client_secret: Client secret (optional for public clients)
            scopes: List of requested scopes
            timeout: Request timeout in seconds

        Returns:
            TokenResponse with access token

        Raises:
            OAuth2Error: If authentication fails
        """
        data = {
            "grant_type": "password",
            "username": username,
            "password": password,
            "client_id": client_id,
        }

        if scopes:
            data["scope"] = " ".join(scopes)

        auth = None
        if client_secret:
            auth = (client_id, client_secret)

        response = requests.post(
            token_url,
            data=data,
            auth=auth,
            timeout=timeout,
        )

        return self._handle_token_response(response)

    def _handle_token_response(self, response: requests.Response) -> TokenResponse:
        """Handle token endpoint response."""
        try:
            data = response.json()
        except ValueError:
            raise OAuth2Error("invalid_response", "Token endpoint returned non-JSON response")

        if response.status_code != 200:
            raise OAuth2Error(
                data.get("error", "unknown_error"),
                data.get("error_description"),
                data.get("error_uri"),
            )

        return TokenResponse.from_response(data)


class RefreshTokenFlow(OAuth2FlowHandler):
    """OAuth 2.0 Refresh Token Grant (RFC 6749 Section 6).

    Used to obtain new access tokens using a refresh token,
    without requiring user interaction.
    """

    def get_flow_type(self) -> str:
        return "refresh_token"

    def refresh(
        self,
        token_url: str,
        refresh_token: str,
        client_id: str,
        client_secret: Optional[str] = None,
        scopes: Optional[List[str]] = None,
        timeout: int = DEFAULT_TIMEOUT,
    ) -> TokenResponse:
        """Exchange refresh token for new access token.

        Args:
            token_url: OAuth 2.0 token endpoint
            refresh_token: Valid refresh token
            client_id: Client identifier
            client_secret: Client secret (optional for public clients)
            scopes: List of requested scopes (must be subset of original)
            timeout: Request timeout in seconds

        Returns:
            TokenResponse with new access token (may include new refresh token)

        Raises:
            OAuth2Error: If refresh fails
        """
        data = {
            "grant_type": "refresh_token",
            "refresh_token": refresh_token,
            "client_id": client_id,
        }

        if scopes:
            data["scope"] = " ".join(scopes)

        auth = None
        if client_secret:
            auth = (client_id, client_secret)

        response = requests.post(
            token_url,
            data=data,
            auth=auth,
            timeout=timeout,
        )

        return self._handle_token_response(response)

    def _handle_token_response(self, response: requests.Response) -> TokenResponse:
        """Handle token endpoint response."""
        try:
            data = response.json()
        except ValueError:
            raise OAuth2Error("invalid_response", "Token endpoint returned non-JSON response")

        if response.status_code != 200:
            raise OAuth2Error(
                data.get("error", "unknown_error"),
                data.get("error_description"),
                data.get("error_uri"),
            )

        return TokenResponse.from_response(data)


# Convenience functions for getting flow handlers
def get_flow_handler(flow_type: str) -> OAuth2FlowHandler:
    """Get the appropriate flow handler for a flow type.

    Args:
        flow_type: One of "client_credentials", "authorization_code",
            "implicit", "password", "refresh_token"

    Returns:
        OAuth2FlowHandler instance

    Raises:
        ValueError: If flow_type is not recognized
    """
    handlers = {
        "client_credentials": ClientCredentialsFlow,
        "clientCredentials": ClientCredentialsFlow,
        "authorization_code": AuthorizationCodeFlow,
        "authorizationCode": AuthorizationCodeFlow,
        "implicit": ImplicitFlow,
        "password": PasswordFlow,
        "refresh_token": RefreshTokenFlow,
    }

    handler_class = handlers.get(flow_type)
    if handler_class is None:
        raise ValueError(f"Unknown OAuth2 flow type: {flow_type}")

    return handler_class()
