"""Security scheme dataclasses and OpenAPI parser.

Parses OpenAPI 3.x and Swagger 2.x security schemes into typed objects.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any, Dict, Optional, Union

logger = logging.getLogger(__name__)


@dataclass
class APIKeyScheme:
    """API Key authentication scheme.

    Attributes:
        name: Security scheme name from OpenAPI spec
        location: Where the key is sent - "header", "query", or "cookie"
        parameter_name: The name of the header, query param, or cookie
        description: Optional description from the spec
    """

    name: str
    location: str  # "header", "query", or "cookie"
    parameter_name: str
    description: Optional[str] = None

    @property
    def scheme_type(self) -> str:
        return "apiKey"


@dataclass
class HTTPScheme:
    """HTTP authentication scheme (Basic, Bearer, Digest, etc.).

    Attributes:
        name: Security scheme name from OpenAPI spec
        scheme: The HTTP auth scheme - "basic", "bearer", "digest", etc.
        bearer_format: Format hint for bearer tokens (e.g., "JWT")
        description: Optional description from the spec
    """

    name: str
    scheme: str  # "basic", "bearer", "digest", etc.
    bearer_format: Optional[str] = None
    description: Optional[str] = None

    @property
    def scheme_type(self) -> str:
        return "http"


@dataclass
class OAuth2Flow:
    """OAuth 2.0 flow configuration.

    Attributes:
        flow_type: One of "clientCredentials", "authorizationCode", "implicit", "password"
        token_url: URL to obtain tokens (required for most flows)
        authorization_url: URL for user authorization (auth code, implicit)
        refresh_url: URL for token refresh
        scopes: Available scopes with descriptions
    """

    flow_type: str
    token_url: Optional[str] = None
    authorization_url: Optional[str] = None
    refresh_url: Optional[str] = None
    scopes: Dict[str, str] = field(default_factory=dict)


@dataclass
class OAuth2Scheme:
    """OAuth 2.0 authentication scheme.

    Attributes:
        name: Security scheme name from OpenAPI spec
        flows: Available OAuth2 flows keyed by flow type
        description: Optional description from the spec
    """

    name: str
    flows: Dict[str, OAuth2Flow] = field(default_factory=dict)
    description: Optional[str] = None

    @property
    def scheme_type(self) -> str:
        return "oauth2"

    @property
    def available_flow_types(self) -> list[str]:
        """Return list of available flow types."""
        return list(self.flows.keys())


@dataclass
class OpenIDConnectScheme:
    """OpenID Connect authentication scheme.

    Attributes:
        name: Security scheme name from OpenAPI spec
        openid_connect_url: URL to OpenID Connect discovery document
        description: Optional description from the spec
    """

    name: str
    openid_connect_url: str
    description: Optional[str] = None

    @property
    def scheme_type(self) -> str:
        return "openIdConnect"


SecurityScheme = Union[APIKeyScheme, HTTPScheme, OAuth2Scheme, OpenIDConnectScheme]


def _parse_oauth2_flow(flow_type: str, flow_data: Dict[str, Any]) -> OAuth2Flow:
    """Parse a single OAuth2 flow from OpenAPI spec."""
    return OAuth2Flow(
        flow_type=flow_type,
        token_url=flow_data.get("tokenUrl"),
        authorization_url=flow_data.get("authorizationUrl"),
        refresh_url=flow_data.get("refreshUrl"),
        scopes=flow_data.get("scopes", {}),
    )


def _parse_oauth2_flows_v3(flows_data: Dict[str, Any]) -> Dict[str, OAuth2Flow]:
    """Parse OAuth2 flows from OpenAPI 3.x format."""
    result = {}
    flow_type_map = {
        "clientCredentials": "clientCredentials",
        "authorizationCode": "authorizationCode",
        "implicit": "implicit",
        "password": "password",
    }
    for flow_key, flow_type in flow_type_map.items():
        if flow_key in flows_data:
            result[flow_type] = _parse_oauth2_flow(flow_type, flows_data[flow_key])
    return result


def _parse_oauth2_flows_v2(scheme_data: Dict[str, Any]) -> Dict[str, OAuth2Flow]:
    """Parse OAuth2 flows from Swagger 2.x format.

    Swagger 2.x uses a 'flow' field instead of nested flow objects.
    """
    flow_type = scheme_data.get("flow", "")
    scopes = scheme_data.get("scopes", {})

    # Map Swagger 2.x flow names to OpenAPI 3.x names
    flow_type_map = {
        "application": "clientCredentials",
        "accessCode": "authorizationCode",
        "implicit": "implicit",
        "password": "password",
    }
    normalized_flow = flow_type_map.get(flow_type, flow_type)

    flow = OAuth2Flow(
        flow_type=normalized_flow,
        token_url=scheme_data.get("tokenUrl"),
        authorization_url=scheme_data.get("authorizationUrl"),
        scopes=scopes,
    )
    return {normalized_flow: flow}


def _parse_security_scheme(
    name: str, scheme_data: Dict[str, Any], is_swagger_v2: bool = False
) -> Optional[SecurityScheme]:
    """Parse a single security scheme definition."""
    scheme_type = scheme_data.get("type", "")
    description = scheme_data.get("description")

    if scheme_type == "apiKey":
        location = scheme_data.get("in", "header")
        param_name = scheme_data.get("name", name)
        return APIKeyScheme(
            name=name,
            location=location,
            parameter_name=param_name,
            description=description,
        )

    elif scheme_type == "http":
        scheme = scheme_data.get("scheme", "").lower()
        bearer_format = scheme_data.get("bearerFormat")
        return HTTPScheme(
            name=name,
            scheme=scheme,
            bearer_format=bearer_format,
            description=description,
        )

    elif scheme_type == "basic":
        # Swagger 2.x uses type: basic directly
        return HTTPScheme(
            name=name,
            scheme="basic",
            description=description,
        )

    elif scheme_type == "oauth2":
        if is_swagger_v2:
            flows = _parse_oauth2_flows_v2(scheme_data)
        else:
            flows_data = scheme_data.get("flows", {})
            flows = _parse_oauth2_flows_v3(flows_data)
        return OAuth2Scheme(
            name=name,
            flows=flows,
            description=description,
        )

    elif scheme_type == "openIdConnect":
        oidc_url = scheme_data.get("openIdConnectUrl", "")
        return OpenIDConnectScheme(
            name=name,
            openid_connect_url=oidc_url,
            description=description,
        )

    else:
        logger.warning("Unknown security scheme type: %s for scheme %s", scheme_type, name)
        return None


def parse_security_schemes(
    api_documentation: Dict[str, Any],
) -> Dict[str, SecurityScheme]:
    """Parse all security schemes from an OpenAPI/Swagger document.

    Supports both OpenAPI 3.x (components/securitySchemes) and
    Swagger 2.x (securityDefinitions) formats.

    Args:
        api_documentation: Parsed OpenAPI/Swagger document

    Returns:
        Dictionary mapping scheme names to SecurityScheme objects
    """
    result: Dict[str, SecurityScheme] = {}

    # Detect spec version
    is_swagger_v2 = api_documentation.get("swagger", "").startswith("2.")

    # Get security schemes from appropriate location
    if is_swagger_v2:
        schemes = api_documentation.get("securityDefinitions", {})
    else:
        schemes = api_documentation.get("components", {}).get("securitySchemes", {})

    if not schemes:
        return result

    for name, scheme_data in schemes.items():
        try:
            scheme = _parse_security_scheme(name, scheme_data, is_swagger_v2)
            if scheme:
                result[name] = scheme
        except Exception as exc:
            logger.error("Error parsing security scheme %s: %s", name, exc)

    return result


def get_scheme_type_string(scheme: SecurityScheme) -> str:
    """Get the type string for backward compatibility with find_authentication_method."""
    return scheme.scheme_type
