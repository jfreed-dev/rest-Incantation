"""Authentication module for REST Incantation.

This package provides comprehensive authentication handling including:
- Security scheme parsing from OpenAPI/Swagger specs
- OAuth 2.0 flow implementations
- Token management with automatic renewal
- HTTP header construction
- Credential storage (session and file-based)
"""

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
from auth.oauth2_flows import (
    AuthorizationCodeFlow,
    ClientCredentialsFlow,
    ImplicitFlow,
    OAuth2Error,
    OAuth2FlowHandler,
    PasswordFlow,
    RefreshTokenFlow,
    TokenResponse,
    get_flow_handler,
)
from auth.schemes import (
    APIKeyScheme,
    HTTPScheme,
    OAuth2Flow,
    OAuth2Scheme,
    OpenIDConnectScheme,
    parse_security_schemes,
)
from auth.storage import (
    FileStorage,
    HybridStorage,
    SessionStorage,
    StorageBackend,
    StoredCredentials,
    StoredToken,
    generate_api_id,
)
from auth.token_manager import TokenConfig, TokenManager

__all__ = [
    # Schemes
    "APIKeyScheme",
    "HTTPScheme",
    "OAuth2Scheme",
    "OAuth2Flow",
    "OpenIDConnectScheme",
    "parse_security_schemes",
    # Storage
    "StorageBackend",
    "SessionStorage",
    "FileStorage",
    "HybridStorage",
    "StoredToken",
    "StoredCredentials",
    "generate_api_id",
    # OAuth2 Flows
    "OAuth2FlowHandler",
    "ClientCredentialsFlow",
    "AuthorizationCodeFlow",
    "ImplicitFlow",
    "PasswordFlow",
    "RefreshTokenFlow",
    "TokenResponse",
    "OAuth2Error",
    "get_flow_handler",
    # Token Manager
    "TokenConfig",
    "TokenManager",
    # Header Builder
    "AuthenticationResult",
    "CustomHeaderManager",
    "build_api_key_auth",
    "build_auth_for_scheme",
    "build_basic_auth_header",
    "build_bearer_auth_header",
    "build_http_auth",
    "build_oauth2_auth",
    "build_request_headers",
]
