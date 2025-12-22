import logging
from typing import Any, Dict


def find_authentication_method(api_documentation: Dict[str, Any]) -> Dict[str, str]:
    """
    Return a mapping of security scheme names to auth types.
    """
    try:
        security_schemes = api_documentation.get("components", {}).get("securitySchemes", {})
        if not security_schemes:
            return {}
        auth_methods: Dict[str, str] = {}
        for name, details in security_schemes.items():
            auth_type = details.get("type", "")
            auth_methods[name] = auth_type
        return auth_methods
    except Exception as exc:
        logging.error("Error processing API documentation: %s", exc)
        return {}
