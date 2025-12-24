"""HTTP header construction from authentication credentials.

Builds appropriate HTTP headers, query parameters, and cookies
based on security scheme types and user-provided credentials.
"""

from __future__ import annotations

import base64
import logging
from dataclasses import dataclass, field
from typing import Any, Dict, Optional, Tuple

from auth.schemes import APIKeyScheme, HTTPScheme, OAuth2Scheme, OpenIDConnectScheme

logger = logging.getLogger(__name__)


@dataclass
class AuthenticationResult:
    """Result of building authentication for a request.

    Attributes:
        headers: HTTP headers to include
        query_params: Query parameters to include
        cookies: Cookies to include
    """

    headers: Dict[str, str] = field(default_factory=dict)
    query_params: Dict[str, str] = field(default_factory=dict)
    cookies: Dict[str, str] = field(default_factory=dict)

    def merge(self, other: "AuthenticationResult") -> "AuthenticationResult":
        """Merge another result into this one."""
        return AuthenticationResult(
            headers={**self.headers, **other.headers},
            query_params={**self.query_params, **other.query_params},
            cookies={**self.cookies, **other.cookies},
        )


def build_basic_auth_header(username: str, password: str) -> str:
    """Build HTTP Basic Authentication header value.

    Args:
        username: Username
        password: Password

    Returns:
        Header value string (e.g., "Basic dXNlcjpwYXNz")
    """
    credentials = f"{username}:{password}"
    encoded = base64.b64encode(credentials.encode()).decode()
    return f"Basic {encoded}"


def build_bearer_auth_header(token: str) -> str:
    """Build HTTP Bearer Authentication header value.

    Args:
        token: Bearer token

    Returns:
        Header value string (e.g., "Bearer abc123")
    """
    return f"Bearer {token}"


def build_api_key_auth(
    scheme: APIKeyScheme,
    api_key: str,
) -> AuthenticationResult:
    """Build authentication for API Key scheme.

    Args:
        scheme: API Key scheme definition
        api_key: The API key value

    Returns:
        AuthenticationResult with headers, params, or cookies
    """
    result = AuthenticationResult()

    if scheme.location == "header":
        result.headers[scheme.parameter_name] = api_key
    elif scheme.location == "query":
        result.query_params[scheme.parameter_name] = api_key
    elif scheme.location == "cookie":
        result.cookies[scheme.parameter_name] = api_key
    else:
        logger.warning("Unknown API key location: %s", scheme.location)
        # Default to header
        result.headers[scheme.parameter_name] = api_key

    return result


def build_http_auth(
    scheme: HTTPScheme,
    credentials: Dict[str, str],
) -> AuthenticationResult:
    """Build authentication for HTTP scheme.

    Args:
        scheme: HTTP scheme definition
        credentials: Credential values. Expected keys depend on scheme:
            - basic: "username", "password"
            - bearer: "token"
            - digest: "username", "password" (basic support)

    Returns:
        AuthenticationResult with Authorization header
    """
    result = AuthenticationResult()

    if scheme.scheme == "basic":
        username = credentials.get("username", "")
        password = credentials.get("password", "")
        result.headers["Authorization"] = build_basic_auth_header(username, password)

    elif scheme.scheme == "bearer":
        token = credentials.get("token", "")
        result.headers["Authorization"] = build_bearer_auth_header(token)

    elif scheme.scheme == "digest":
        # Digest auth is complex and typically handled by HTTP client
        # For now, we just set username/password for the client to use
        username = credentials.get("username", "")
        password = credentials.get("password", "")
        # Some clients accept Basic-style for initial request
        result.headers["Authorization"] = build_basic_auth_header(username, password)
        logger.info("Digest auth configured - client should handle challenge-response")

    else:
        # Unknown HTTP scheme, try bearer format
        token = credentials.get("token", "")
        if token:
            result.headers["Authorization"] = f"{scheme.scheme.title()} {token}"
        else:
            logger.warning("Unknown HTTP auth scheme: %s", scheme.scheme)

    return result


def build_oauth2_auth(
    scheme: OAuth2Scheme,
    credentials: Dict[str, str],
) -> AuthenticationResult:
    """Build authentication for OAuth2 scheme.

    Args:
        scheme: OAuth2 scheme definition
        credentials: Expected key: "access_token"

    Returns:
        AuthenticationResult with Authorization header
    """
    result = AuthenticationResult()
    access_token = credentials.get("access_token", "")

    if access_token:
        result.headers["Authorization"] = build_bearer_auth_header(access_token)
    else:
        logger.warning("No access_token provided for OAuth2 scheme %s", scheme.name)

    return result


def build_openid_connect_auth(
    scheme: OpenIDConnectScheme,
    credentials: Dict[str, str],
) -> AuthenticationResult:
    """Build authentication for OpenID Connect scheme.

    Args:
        scheme: OIDC scheme definition
        credentials: Expected keys: "access_token", optionally "id_token"

    Returns:
        AuthenticationResult with Authorization header
    """
    result = AuthenticationResult()
    access_token = credentials.get("access_token", "")

    if access_token:
        result.headers["Authorization"] = build_bearer_auth_header(access_token)
    else:
        logger.warning("No access_token provided for OIDC scheme %s", scheme.name)

    return result


def build_auth_for_scheme(
    scheme: Any,
    credentials: Dict[str, str],
) -> AuthenticationResult:
    """Build authentication for any security scheme type.

    Args:
        scheme: Security scheme (APIKeyScheme, HTTPScheme, OAuth2Scheme, etc.)
        credentials: Credential values appropriate for the scheme type

    Returns:
        AuthenticationResult with appropriate auth data
    """
    if isinstance(scheme, APIKeyScheme):
        api_key = credentials.get("api_key", credentials.get("value", ""))
        return build_api_key_auth(scheme, api_key)

    elif isinstance(scheme, HTTPScheme):
        return build_http_auth(scheme, credentials)

    elif isinstance(scheme, OAuth2Scheme):
        return build_oauth2_auth(scheme, credentials)

    elif isinstance(scheme, OpenIDConnectScheme):
        return build_openid_connect_auth(scheme, credentials)

    else:
        logger.warning("Unknown scheme type: %s", type(scheme).__name__)
        return AuthenticationResult()


class CustomHeaderManager:
    """Manages user-defined custom HTTP headers per API.

    Allows users to add, remove, and retrieve custom headers
    that will be included with API requests.
    """

    def __init__(self):
        """Initialize the header manager."""
        self._headers: Dict[str, Dict[str, str]] = {}

    def add_header(self, api_id: str, name: str, value: str) -> None:
        """Add a custom header for an API.

        Args:
            api_id: API identifier
            name: Header name
            value: Header value
        """
        if api_id not in self._headers:
            self._headers[api_id] = {}
        self._headers[api_id][name] = value

    def remove_header(self, api_id: str, name: str) -> bool:
        """Remove a custom header for an API.

        Args:
            api_id: API identifier
            name: Header name to remove

        Returns:
            True if header was removed, False if not found
        """
        if api_id in self._headers and name in self._headers[api_id]:
            del self._headers[api_id][name]
            return True
        return False

    def get_headers(self, api_id: str) -> Dict[str, str]:
        """Get all custom headers for an API.

        Args:
            api_id: API identifier

        Returns:
            Dictionary of header name -> value
        """
        return self._headers.get(api_id, {}).copy()

    def set_headers(self, api_id: str, headers: Dict[str, str]) -> None:
        """Set all custom headers for an API (replacing existing).

        Args:
            api_id: API identifier
            headers: Dictionary of header name -> value
        """
        self._headers[api_id] = headers.copy()

    def clear_headers(self, api_id: str) -> None:
        """Clear all custom headers for an API.

        Args:
            api_id: API identifier
        """
        self._headers.pop(api_id, None)

    def list_apis(self) -> list[str]:
        """List all APIs with custom headers.

        Returns:
            List of API identifiers
        """
        return list(self._headers.keys())


def build_request_headers(
    schemes: Dict[str, Any],
    credentials: Dict[str, Dict[str, str]],
    custom_headers: Optional[Dict[str, str]] = None,
) -> Tuple[Dict[str, str], Dict[str, str], Dict[str, str]]:
    """Build complete request headers from all authentication sources.

    Args:
        schemes: Dictionary of scheme_name -> scheme object
        credentials: Dictionary of scheme_name -> credential values
        custom_headers: Optional custom headers to include

    Returns:
        Tuple of (headers, query_params, cookies)
    """
    result = AuthenticationResult()

    # Process each scheme
    for scheme_name, scheme in schemes.items():
        scheme_creds = credentials.get(scheme_name, {})
        if scheme_creds:
            auth_result = build_auth_for_scheme(scheme, scheme_creds)
            result = result.merge(auth_result)

    # Add custom headers
    if custom_headers:
        result.headers.update(custom_headers)

    return result.headers, result.query_params, result.cookies
