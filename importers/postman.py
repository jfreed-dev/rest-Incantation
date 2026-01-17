"""Postman Collection v2.1 Importer.

Converts Postman collections to REST Incantation format, including:
- Requests (method, URL, headers, body)
- Variables and environments
- Authentication configurations
- Folder structure

Security: Sensitive data (tokens, credentials) are NOT logged.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

# Limits for collections to prevent abuse
MAX_COLLECTION_SIZE_MB = 10  # Max 10MB
MAX_FOLDER_DEPTH = 10  # Max nesting depth
MAX_REQUESTS_PER_COLLECTION = 1000
MAX_VARIABLES_PER_COLLECTION = 500

# Sensitive keys that should not be logged
SENSITIVE_KEYS = {"token", "password", "key", "secret", "apikey", "api_key", "bearer", "auth"}


@dataclass
class PostmanVariable:
    """Postman variable from collection or environment."""

    key: str
    value: str
    type: str = "default"
    enabled: bool = True


@dataclass
class PostmanAuth:
    """Postman authentication configuration."""

    type: str  # apikey, bearer, basic, oauth2, etc.
    params: Dict[str, Any] = field(default_factory=dict)


@dataclass
class PostmanRequest:
    """Postman request item."""

    name: str
    method: str
    url: str
    headers: Dict[str, str] = field(default_factory=dict)
    body: Optional[Dict[str, Any]] = None
    auth: Optional[PostmanAuth] = None
    folder_path: List[str] = field(default_factory=list)
    description: str = ""


@dataclass
class PostmanFolder:
    """Postman folder/group."""

    name: str
    items: List[Any] = field(default_factory=list)
    auth: Optional[PostmanAuth] = None
    description: str = ""


@dataclass
class ImportedCollection:
    """Result of importing a Postman collection."""

    name: str
    description: str
    requests: List[PostmanRequest]
    variables: List[PostmanVariable]
    auth_config: Optional[PostmanAuth] = None
    folders: List[str] = field(default_factory=list)


class PostmanCollectionImporter:
    """Import Postman Collection v2.1 format."""

    SUPPORTED_VERSIONS = ["v2.1", "v2.1.0"]

    # Mapping of Postman auth types to REST Incantation auth types
    AUTH_TYPE_MAPPING = {
        "apikey": "apiKey",
        "bearer": "bearer",
        "basic": "basic",
        "oauth2": "oauth2",
        "digest": "digest",
        "hawk": "hawk",
        "awsv4": "awsv4",
        "ntlm": "ntlm",
        "noauth": None,
    }

    def __init__(self):
        """Initialize the importer."""
        self.collection_data: Optional[Dict[str, Any]] = None
        self.requests: List[PostmanRequest] = []
        self.variables: List[PostmanVariable] = []
        self.folders: List[str] = []
        self.current_folder_depth = 0

    def load_collection(self, collection_json: str | Dict[str, Any]) -> ImportedCollection:
        """Load and parse a Postman collection.

        Args:
            collection_json: JSON string or dict containing Postman collection

        Returns:
            ImportedCollection with parsed data

        Raises:
            ValueError: If collection format is invalid, unsupported, or exceeds limits
        """
        # Validate input size if string
        if isinstance(collection_json, str):
            if len(collection_json.encode("utf-8")) > MAX_COLLECTION_SIZE_MB * 1024 * 1024:
                raise ValueError(f"Collection exceeds maximum size of {MAX_COLLECTION_SIZE_MB}MB")
            try:
                self.collection_data = json.loads(collection_json)
            except json.JSONDecodeError as exc:
                raise ValueError(f"Invalid JSON: {exc}") from exc
        else:
            self.collection_data = collection_json

        # Validate collection
        self._validate_collection()

        # Extract collection metadata
        name = self.collection_data.get("info", {}).get("name", "Imported Collection")
        description = self.collection_data.get("info", {}).get("description", "")

        # Parse collection-level auth
        collection_auth = self._parse_auth(self.collection_data.get("auth"))

        # Parse variables
        self._parse_variables(self.collection_data.get("variable", []))

        # Parse items (requests and folders)
        items = self.collection_data.get("item", [])
        self.current_folder_depth = 0
        self._parse_items(items, folder_path=[], parent_auth=collection_auth)

        return ImportedCollection(
            name=name,
            description=description,
            requests=self.requests,
            variables=self.variables,
            auth_config=collection_auth,
            folders=self.folders,
        )

    def load_environment(self, environment_json: str | Dict[str, Any]) -> List[PostmanVariable]:
        """Load a Postman environment file.

        Args:
            environment_json: JSON string or dict containing Postman environment

        Returns:
            List of PostmanVariable objects

        Raises:
            ValueError: If environment format is invalid
        """
        # Parse JSON if string
        if isinstance(environment_json, str):
            try:
                env_data = json.loads(environment_json)
            except json.JSONDecodeError as exc:
                raise ValueError(f"Invalid JSON: {exc}") from exc
        else:
            env_data = environment_json

        # Validate environment
        if "values" not in env_data:
            raise ValueError("Invalid Postman environment: missing 'values' field")

        variables = []
        for var_data in env_data.get("values", []):
            if not isinstance(var_data, dict) or "key" not in var_data:
                continue

            variables.append(
                PostmanVariable(
                    key=var_data.get("key", ""),
                    value=var_data.get("value", ""),
                    type=var_data.get("type", "default"),
                    enabled=var_data.get("enabled", True),
                )
            )

        return variables

    def _validate_collection(self) -> None:
        """Validate that the collection is a supported Postman format.

        Raises:
            ValueError: If collection is invalid or unsupported
        """
        if not self.collection_data:
            raise ValueError("No collection data loaded")

        info = self.collection_data.get("info")
        if not info:
            raise ValueError("Invalid Postman collection: missing 'info' field")

        # Check schema version
        schema = info.get("schema", "")
        if not any(version in schema for version in self.SUPPORTED_VERSIONS):
            logger.warning(
                "Collection schema %s may not be fully supported. "
                "Supported versions: %s",
                schema,
                self.SUPPORTED_VERSIONS,
            )

    def _parse_variables(self, variables_data: List[Dict[str, Any]]) -> None:
        """Parse collection variables.

        Args:
            variables_data: List of variable dicts from collection

        Raises:
            ValueError: If too many variables
        """
        if len(variables_data) > MAX_VARIABLES_PER_COLLECTION:
            raise ValueError(f"Collection exceeds maximum variables limit ({MAX_VARIABLES_PER_COLLECTION})")

        for var_data in variables_data:
            if not isinstance(var_data, dict) or "key" not in var_data:
                continue

            self.variables.append(
                PostmanVariable(
                    key=var_data.get("key", ""),
                    value=var_data.get("value", ""),
                    type=var_data.get("type", "default"),
                    enabled=True,  # Collection variables are always enabled
                )
            )

    def _parse_auth(self, auth_data: Optional[Dict[str, Any]]) -> Optional[PostmanAuth]:
        """Parse Postman auth configuration.

        Args:
            auth_data: Auth dict from collection/folder/request

        Returns:
            PostmanAuth object or None
        """
        if not auth_data or not isinstance(auth_data, dict):
            return None

        auth_type = auth_data.get("type", "noauth")
        if auth_type == "noauth" or auth_type not in auth_data:
            return None

        # Extract parameters based on auth type
        params = {}
        auth_params = auth_data.get(auth_type, [])

        if isinstance(auth_params, list):
            # Parameters as list of {key, value} objects
            for param in auth_params:
                if isinstance(param, dict) and "key" in param:
                    params[param["key"]] = param.get("value", "")
        elif isinstance(auth_params, dict):
            # Parameters as direct dict
            params = auth_params

        return PostmanAuth(type=auth_type, params=params)

    def _parse_items(
        self,
        items: List[Dict[str, Any]],
        folder_path: List[str],
        parent_auth: Optional[PostmanAuth] = None,
    ) -> None:
        """Parse collection items (requests and folders) recursively.

        Args:
            items: List of item dicts (requests or folders)
            folder_path: Current folder hierarchy
            parent_auth: Authentication from parent folder/collection

        Raises:
            ValueError: If folder depth exceeds maximum or too many requests
        """
        for item in items:
            if not isinstance(item, dict):
                continue

            # Check if this is a folder
            if "item" in item:
                # Check folder depth limit
                if len(folder_path) >= MAX_FOLDER_DEPTH:
                    logger.warning(
                        "Folder nesting exceeds maximum depth (%d). Skipping folder: %s",
                        MAX_FOLDER_DEPTH,
                        item.get("name", "Unnamed"),
                    )
                    continue

                folder_name = item.get("name", "Unnamed Folder")
                folder_auth = self._parse_auth(item.get("auth")) or parent_auth

                # Add to folders list
                folder_full_path = "/".join(folder_path + [folder_name])
                self.folders.append(folder_full_path)

                # Recursively parse folder items
                self._parse_items(
                    item["item"],
                    folder_path=folder_path + [folder_name],
                    parent_auth=folder_auth,
                )
            # This is a request
            elif "request" in item:
                if len(self.requests) >= MAX_REQUESTS_PER_COLLECTION:
                    logger.warning(
                        "Collection exceeds maximum requests limit (%d). Skipping remaining requests.",
                        MAX_REQUESTS_PER_COLLECTION,
                    )
                    return

                request = self._parse_request(item, folder_path, parent_auth)
                if request:
                    self.requests.append(request)

    def _parse_request(
        self,
        item: Dict[str, Any],
        folder_path: List[str],
        parent_auth: Optional[PostmanAuth] = None,
    ) -> Optional[PostmanRequest]:
        """Parse a single Postman request.

        Args:
            item: Request item dict
            folder_path: Current folder hierarchy
            parent_auth: Authentication from parent folder/collection

        Returns:
            PostmanRequest object or None if parsing fails
        """
        request_data = item.get("request", {})
        if not request_data:
            return None

        # Handle request as string (just URL) or dict
        if isinstance(request_data, str):
            return PostmanRequest(
                name=item.get("name", "Unnamed Request"),
                method="GET",
                url=request_data,
                folder_path=folder_path,
                description=item.get("description", ""),
            )

        # Extract method
        method = request_data.get("method", "GET").upper()

        # Extract URL (can be string or object)
        url_data = request_data.get("url", "")
        if isinstance(url_data, dict):
            url = self._build_url_from_object(url_data)
        else:
            url = str(url_data)

        # Extract headers
        headers = {}
        for header in request_data.get("header", []):
            if isinstance(header, dict) and "key" in header:
                # Only include enabled headers
                if header.get("disabled", False):
                    continue
                headers[header["key"]] = header.get("value", "")

        # Extract body
        body = None
        body_data = request_data.get("body", {})
        if body_data:
            body = self._parse_body(body_data)

        # Extract auth (request-level overrides folder/collection)
        auth = self._parse_auth(request_data.get("auth")) or parent_auth

        return PostmanRequest(
            name=item.get("name", "Unnamed Request"),
            method=method,
            url=url,
            headers=headers,
            body=body,
            auth=auth,
            folder_path=folder_path,
            description=item.get("description", ""),
        )

    def _build_url_from_object(self, url_obj: Dict[str, Any]) -> str:
        """Build URL string from Postman URL object.

        Args:
            url_obj: URL object with raw, protocol, host, path, query, etc.

        Returns:
            Complete URL string
        """
        # Prefer raw URL if available
        if "raw" in url_obj:
            return url_obj["raw"]

        # Build URL from components
        protocol = url_obj.get("protocol", "https")
        host = url_obj.get("host", [])
        if isinstance(host, list):
            host = ".".join(host)
        path = url_obj.get("path", [])
        if isinstance(path, list):
            path = "/".join(path)

        url = f"{protocol}://{host}/{path}".rstrip("/")

        # Add query parameters
        query = url_obj.get("query", [])
        if query:
            query_parts = []
            for q in query:
                if isinstance(q, dict) and "key" in q:
                    if q.get("disabled", False):
                        continue
                    key = q["key"]
                    value = q.get("value", "")
                    query_parts.append(f"{key}={value}")
            if query_parts:
                url += "?" + "&".join(query_parts)

        return url

    def _parse_body(self, body_data: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Parse request body.

        Args:
            body_data: Body dict from request

        Returns:
            Body data dict or None
        """
        mode = body_data.get("mode", "")

        if mode == "raw":
            return {
                "mode": "raw",
                "content": body_data.get("raw", ""),
                "content_type": body_data.get("options", {}).get("raw", {}).get("language", "text"),
            }
        elif mode == "formdata":
            return {"mode": "formdata", "data": body_data.get("formdata", [])}
        elif mode == "urlencoded":
            return {"mode": "urlencoded", "data": body_data.get("urlencoded", [])}
        elif mode == "file":
            return {"mode": "file", "src": body_data.get("file", {}).get("src", "")}
        elif mode == "graphql":
            return {
                "mode": "graphql",
                "query": body_data.get("graphql", {}).get("query", ""),
                "variables": body_data.get("graphql", {}).get("variables", ""),
            }

        return None

    def map_auth_to_rest_incantation(self, postman_auth: PostmanAuth) -> Dict[str, Any]:
        """Map Postman auth to REST Incantation credential format.

        Args:
            postman_auth: PostmanAuth object

        Returns:
            Dict with scheme_type and values for REST Incantation
        """
        scheme_type = self.AUTH_TYPE_MAPPING.get(postman_auth.type.lower())
        if not scheme_type:
            return {"scheme_type": "unknown", "values": postman_auth.params}

        values = {}

        if postman_auth.type == "apikey":
            # API Key auth
            values["api_key"] = postman_auth.params.get("value", "")
            values["key_name"] = postman_auth.params.get("key", "X-API-Key")
            values["location"] = postman_auth.params.get("in", "header")

        elif postman_auth.type == "bearer":
            # Bearer token auth
            values["token"] = postman_auth.params.get("token", "")

        elif postman_auth.type == "basic":
            # Basic auth
            values["username"] = postman_auth.params.get("username", "")
            values["password"] = postman_auth.params.get("password", "")

        elif postman_auth.type == "oauth2":
            # OAuth2 - map various grant types
            values["grant_type"] = postman_auth.params.get("grant_type", "authorization_code")
            values["access_token_url"] = postman_auth.params.get("accessTokenUrl", "")
            values["authorization_url"] = postman_auth.params.get("authUrl", "")
            values["client_id"] = postman_auth.params.get("clientId", "")
            values["client_secret"] = postman_auth.params.get("clientSecret", "")
            values["scope"] = postman_auth.params.get("scope", "")
            values["redirect_uri"] = postman_auth.params.get("redirect_uri", "")

            # Handle access token if already present
            if "accessToken" in postman_auth.params:
                values["access_token"] = postman_auth.params["accessToken"]

        else:
            # For other auth types, pass through params
            values = postman_auth.params

        return {"scheme_type": scheme_type, "values": values}

    def get_import_summary(self, imported: ImportedCollection) -> Dict[str, Any]:
        """Generate a summary of the imported collection.

        Args:
            imported: ImportedCollection object

        Returns:
            Summary dict with counts and details
        """
        auth_types = {}
        for request in imported.requests:
            if request.auth:
                auth_type = request.auth.type
                auth_types[auth_type] = auth_types.get(auth_type, 0) + 1

        return {
            "name": imported.name,
            "description": imported.description,
            "total_requests": len(imported.requests),
            "total_folders": len(imported.folders),
            "total_variables": len(imported.variables),
            "auth_types": auth_types,
            "has_collection_auth": imported.auth_config is not None,
            "folders": imported.folders,
        }
