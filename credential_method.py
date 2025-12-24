"""Credential method detection from OpenAPI specifications.

This module provides functions to extract authentication methods from
OpenAPI/Swagger documents. It supports both simple type extraction
(for backward compatibility) and detailed scheme parsing.
"""

import logging
from typing import Any, Dict, Union

from auth.schemes import (
    APIKeyScheme,
    HTTPScheme,
    OAuth2Scheme,
    OpenIDConnectScheme,
    get_scheme_type_string,
    parse_security_schemes,
)

logger = logging.getLogger(__name__)

# Type alias for security schemes
SecurityScheme = Union[APIKeyScheme, HTTPScheme, OAuth2Scheme, OpenIDConnectScheme]


def find_authentication_method(api_documentation: Dict[str, Any]) -> Dict[str, str]:
    """Return a mapping of security scheme names to auth types.

    This function maintains backward compatibility with existing code
    that expects a simple {name: type_string} mapping.

    Args:
        api_documentation: Parsed OpenAPI/Swagger document

    Returns:
        Dictionary mapping scheme names to type strings
        (e.g., {"ApiKeyAuth": "apiKey", "OAuth2": "oauth2"})
    """
    try:
        schemes = parse_security_schemes(api_documentation)
        return {name: get_scheme_type_string(scheme) for name, scheme in schemes.items()}
    except Exception as exc:
        logger.error("Error processing API documentation: %s", exc)
        return {}


def get_detailed_auth_methods(
    api_documentation: Dict[str, Any],
) -> Dict[str, SecurityScheme]:
    """Return fully-parsed security schemes with all OpenAPI details.

    Use this function when you need the complete scheme information
    including locations, parameter names, OAuth flows, scopes, etc.

    Args:
        api_documentation: Parsed OpenAPI/Swagger document

    Returns:
        Dictionary mapping scheme names to SecurityScheme objects
        (APIKeyScheme, HTTPScheme, OAuth2Scheme, or OpenIDConnectScheme)
    """
    try:
        return parse_security_schemes(api_documentation)
    except Exception as exc:
        logger.error("Error processing API documentation: %s", exc)
        return {}
