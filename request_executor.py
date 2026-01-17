"""Request executor for imported Postman collections."""

import re
from typing import Any, Dict, List, Optional
import requests
from requests.auth import HTTPBasicAuth


class VariableResolver:
    """Resolves Postman variables in requests."""

    def __init__(self, variables: List[Dict[str, str]]):
        """Initialize with collection variables.
        
        Args:
            variables: List of {key: str, value: str} dicts
        """
        self.variables = {var["key"]: var["value"] for var in variables}

    def resolve(self, text: str) -> str:
        """Resolve all {{variable}} placeholders in text.
        
        Args:
            text: Text containing {{variable}} placeholders
            
        Returns:
            Text with all variables resolved
        """
        if not text:
            return text
            
        # Pattern to match {{variable_name}}
        pattern = r'\{\{([^}]+)\}\}'
        
        def replace_variable(match):
            var_name = match.group(1).strip()
            return self.variables.get(var_name, match.group(0))
        
        return re.sub(pattern, replace_variable, text)


class RequestExecutor:
    """Executes HTTP requests with authentication and variable resolution."""

    def __init__(self, variables: Optional[List[Dict[str, str]]] = None):
        """Initialize executor.
        
        Args:
            variables: Optional list of environment variables
        """
        self.resolver = VariableResolver(variables or [])

    def execute(
        self,
        method: str,
        url: str,
        headers: Optional[Dict[str, str]] = None,
        body: Optional[str] = None,
        auth_type: Optional[str] = None,
        auth_params: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Execute an HTTP request with variable resolution.
        
        Args:
            method: HTTP method (GET, POST, etc.)
            url: Request URL (may contain {{variables}})
            headers: Optional request headers (may contain {{variables}})
            body: Optional request body (may contain {{variables}})
            auth_type: Optional authentication type (bearer, basic, apikey)
            auth_params: Optional authentication parameters
            
        Returns:
            Dict with response data:
            {
                "status_code": int,
                "headers": dict,
                "body": str or dict,
                "time_ms": float,
                "size_bytes": int,
                "error": str (if failed)
            }
        """
        try:
            # Resolve variables in URL
            resolved_url = self.resolver.resolve(url)
            
            # Resolve variables in headers
            resolved_headers = {}
            if headers:
                for key, value in headers.items():
                    resolved_headers[key] = self.resolver.resolve(value)
            
            # Resolve variables in body
            resolved_body = None
            if body:
                resolved_body = self.resolver.resolve(body)
            
            # Add authentication
            auth = None
            if auth_type and auth_params:
                if auth_type.lower() == "bearer":
                    token = self.resolver.resolve(auth_params.get("token", ""))
                    resolved_headers["Authorization"] = f"Bearer {token}"
                elif auth_type.lower() == "basic":
                    username = self.resolver.resolve(auth_params.get("username", ""))
                    password = self.resolver.resolve(auth_params.get("password", ""))
                    auth = HTTPBasicAuth(username, password)
                elif auth_type.lower() == "apikey":
                    key = auth_params.get("key", "")
                    value = self.resolver.resolve(auth_params.get("value", ""))
                    in_location = auth_params.get("in", "header")
                    if in_location == "header":
                        resolved_headers[key] = value
            
            # Execute request with timeout
            import time
            start_time = time.time()
            
            response = requests.request(
                method=method.upper(),
                url=resolved_url,
                headers=resolved_headers or None,
                data=resolved_body.encode('utf-8') if resolved_body else None,
                auth=auth,
                timeout=30,
                allow_redirects=True,
            )
            
            elapsed_ms = (time.time() - start_time) * 1000
            
            # Parse response body
            try:
                response_body = response.json()
            except ValueError:
                response_body = response.text
            
            # Build result
            result = {
                "success": True,
                "status_code": response.status_code,
                "status_text": response.reason,
                "headers": dict(response.headers),
                "body": response_body,
                "time_ms": round(elapsed_ms, 2),
                "size_bytes": len(response.content),
                "resolved_url": resolved_url,
            }
            
            return result
            
        except requests.exceptions.Timeout:
            return {
                "success": False,
                "error": "Request timeout (30s)",
                "error_type": "timeout",
            }
        except requests.exceptions.ConnectionError as e:
            return {
                "success": False,
                "error": f"Connection error: {str(e)}",
                "error_type": "connection",
            }
        except requests.exceptions.RequestException as e:
            return {
                "success": False,
                "error": f"Request failed: {str(e)}",
                "error_type": "request",
            }
        except Exception as e:
            return {
                "success": False,
                "error": f"Unexpected error: {str(e)}",
                "error_type": "unknown",
            }


def find_request_in_collection(
    collection: Dict[str, Any], request_name: str
) -> Optional[Dict[str, Any]]:
    """Find a request by name in a collection.
    
    Args:
        collection: Collection dict with 'requests' list
        request_name: Name of request to find
        
    Returns:
        Request dict or None if not found
    """
    for req in collection.get("requests", []):
        if req.get("name") == request_name:
            return req
    return None
