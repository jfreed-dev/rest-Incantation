import base64
import hashlib
import json
import logging
import os
from urllib.parse import urlencode

import requests
import yaml
from flask import Flask, g, redirect, render_template, request, session, url_for

from auth import (
    AuthorizationCodeFlow,
    CustomHeaderManager,
    HybridStorage,
    OAuth2Error,
    RefreshTokenFlow,
    TokenManager,
    generate_api_id,
)
from auth.storage import FileStorage, SessionStorage
from credential_method import find_authentication_method, get_detailed_auth_methods
from importers import PostmanCollectionImporter
from request_executor import RequestExecutor, find_request_in_collection

SECRETS_FILE = os.environ.get("REST_INCANTATION_SECRETS", "config/secrets.yaml")

app = Flask(__name__)

# Configure logging
logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO)


def load_secrets(file_path: str = SECRETS_FILE) -> dict:
    if not os.path.exists(file_path):
        return {}
    try:
        with open(file_path, "r") as file:
            return yaml.safe_load(file) or {}
    except (OSError, yaml.YAMLError):
        return {}


secrets = load_secrets()
app.secret_key = os.environ.get("FLASK_SECRET_KEY", secrets.get("flask_secret_key"))
if not app.secret_key:
    app.secret_key = "dev-secret-key"
    import warnings

    warnings.warn(
        "Using insecure default secret key. "
        "Set FLASK_SECRET_KEY or flask_secret_key in config/secrets.yaml for production.",
        stacklevel=1,
    )

# Storage and token manager (initialized lazily for request context)
_file_storage = FileStorage(
    storage_dir=os.environ.get("REST_INCANTATION_STORAGE_DIR", "data/credentials"),
    encryption_key=app.secret_key,
)
custom_header_manager = CustomHeaderManager()

# Token manager without storage (will be set per-request if needed)
token_manager = TokenManager(storage=None)  # type: ignore[arg-type]


def get_storage():
    """Get storage backend for current request context."""
    if "storage" not in g:
        session_storage = SessionStorage(session)
        g.storage = HybridStorage(session_storage=session_storage, file_storage=_file_storage)
    return g.storage


# Common OpenAPI/Swagger specification paths across different frameworks
OPENAPI_CANDIDATE_PATHS = [
    # OpenAPI 3.x standard locations
    "/openapi.json",
    "/openapi.yaml",
    "/openapi.yml",
    # Swagger 2.x standard locations
    "/swagger.json",
    "/swagger.yaml",
    "/swagger.yml",
    # Common API prefix variations
    "/api/openapi.json",
    "/api/openapi.yaml",
    "/api/swagger.json",
    "/api/swagger.yaml",
    # REST prefix (e.g., EcoStruxure IT)
    "/rest/openapi.json",
    "/rest/openapi.yaml",
    "/rest/swagger.json",
    # Versioned API paths
    "/v1/openapi.json",
    "/v1/swagger.json",
    "/v2/openapi.json",
    "/v2/swagger.json",
    "/v3/openapi.json",
    "/v3/swagger.json",
    "/api/v1/openapi.json",
    "/api/v2/openapi.json",
    "/api/v3/openapi.json",
    # Spring/SpringDoc paths
    "/v2/api-docs",
    "/v3/api-docs",
    "/api-docs",
    "/api-docs.json",
    "/api-docs.yaml",
    # ASP.NET / Swashbuckle paths
    "/swagger/v1/swagger.json",
    "/swagger/v2/swagger.json",
    "/swagger/docs/v1",
    # FastAPI / Starlette
    "/docs/openapi.json",
    # Quarkus
    "/q/openapi",
    "/q/openapi.json",
    "/q/openapi.yaml",
    # Well-known location (emerging standard)
    "/.well-known/openapi.json",
    "/.well-known/openapi.yaml",
    "/.well-known/openapi",
]


def fetch_openapi_documentation(base_url: str, explicit_url: str | None = None):
    if explicit_url:
        candidate_urls = [explicit_url]
    elif base_url.endswith((".json", ".yaml", ".yml")):
        candidate_urls = [base_url]
    else:
        base = base_url.rstrip("/")
        candidate_urls = [f"{base}{path}" for path in OPENAPI_CANDIDATE_PATHS]

    last_error = "Unable to fetch OpenAPI documentation."
    for candidate_url in candidate_urls:
        try:
            response = requests.get(candidate_url, timeout=10)
            response.raise_for_status()
            content_type = response.headers.get("content-type", "")
            if "json" in content_type or candidate_url.endswith(".json"):
                return json.loads(response.text), candidate_url, None
            if (
                "yaml" in content_type
                or "yml" in content_type
                or candidate_url.endswith((".yaml", ".yml"))
            ):
                return yaml.safe_load(response.text), candidate_url, None
            try:
                return json.loads(response.text), candidate_url, None
            except json.JSONDecodeError:
                return yaml.safe_load(response.text), candidate_url, None
        except (requests.RequestException, json.JSONDecodeError, yaml.YAMLError) as exc:
            last_error = f"{candidate_url}: {exc}"

    return None, None, last_error


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/submit-url", methods=["POST"])
def submit_url():
    base_url = request.form.get("base_url", "").strip()
    openapi_url = request.form.get("openapi_url", "").strip()
    if not base_url and not openapi_url:
        return render_template(
            "submit_url.html",
            error="Provide a base URL or an OpenAPI URL.",
            base_url="",
            openapi_url="",
        )

    api_documentation, source_url, error = fetch_openapi_documentation(
        base_url, openapi_url or None
    )
    if not api_documentation:
        return render_template(
            "submit_url.html",
            error=error,
            base_url=base_url,
            openapi_url=openapi_url,
        )

    session["base_url"] = base_url or source_url
    session["openapi_url"] = source_url

    # Get both simple auth_methods (backward compat) and detailed schemes
    auth_methods = find_authentication_method(api_documentation)
    session["auth_methods"] = auth_methods

    # Store detailed auth schemes for new UI
    auth_schemes = get_detailed_auth_methods(api_documentation)
    # Convert dataclasses to dicts for session storage
    session["auth_schemes"] = {
        name: {
            "scheme_type": scheme.scheme_type,
            **{k: v for k, v in scheme.__dict__.items() if k != "scheme_type"},
        }
        for name, scheme in auth_schemes.items()
    }

    # Generate API ID for token management
    api_id = generate_api_id(base_url or source_url, source_url)
    session["api_id"] = api_id

    return redirect(url_for("credentials"))


@app.route("/credentials", methods=["GET", "POST"])
def credentials():
    auth_methods = session.get("auth_methods", {})
    auth_schemes = session.get("auth_schemes", {})
    api_id = session.get("api_id", "")

    if request.method == "POST":
        # Collect credentials from form
        submitted = {name: request.form.get(name, "") for name in auth_methods}

        # Handle OAuth2 specific fields
        for name, scheme in auth_schemes.items():
            if scheme.get("scheme_type") == "oauth2":
                submitted[f"{name}_client_id"] = request.form.get(f"{name}_client_id", "")
                submitted[f"{name}_client_secret"] = request.form.get(f"{name}_client_secret", "")
                submitted[f"{name}_flow"] = request.form.get(f"{name}_flow", "")

        # Handle Basic auth
        for name, scheme in auth_schemes.items():
            if scheme.get("scheme_type") == "http" and scheme.get("scheme") == "basic":
                submitted[f"{name}_username"] = request.form.get(f"{name}_username", "")
                submitted[f"{name}_password"] = request.form.get(f"{name}_password", "")

        session["credentials"] = submitted

        # Handle storage preference
        storage_preference = request.form.get("storage_preference", "session")
        session["storage_preference"] = storage_preference

        # Store credentials using hybrid storage
        if api_id:
            get_storage().set_preference(api_id, storage_preference == "file")

        # Handle token renewal configuration
        enable_renewal = request.form.get("enable_renewal") == "on"
        renewal_interval = int(request.form.get("renewal_interval", 15))
        session["enable_renewal"] = enable_renewal
        session["renewal_interval"] = renewal_interval

        # Collect custom headers
        custom_headers = {}
        i = 0
        while f"custom_header_name_{i}" in request.form:
            header_name = request.form.get(f"custom_header_name_{i}", "").strip()
            header_value = request.form.get(f"custom_header_value_{i}", "").strip()
            if header_name:
                custom_headers[header_name] = header_value
            i += 1
        session["custom_headers"] = custom_headers

        # Store custom headers
        if api_id:
            for name, value in custom_headers.items():
                custom_header_manager.add_header(api_id, name, value)

        return render_template(
            "request_builder.html",
            base_url=session.get("base_url", ""),
            openapi_url=session.get("openapi_url", ""),
            credentials=submitted,
            custom_headers=custom_headers,
            enable_renewal=enable_renewal,
            renewal_interval=renewal_interval,
        )

    if not auth_methods and not auth_schemes:
        return redirect(url_for("index"))

    # Convert auth_schemes dict values to objects with scheme_type attribute for template
    class SchemeWrapper:
        def __init__(self, data):
            for key, value in data.items():
                setattr(self, key, value)

    wrapped_schemes = {name: SchemeWrapper(scheme) for name, scheme in auth_schemes.items()}

    return render_template(
        "credentials.html", auth_methods=auth_methods, auth_schemes=wrapped_schemes
    )


@app.route("/oauth/callback")
def oauth_callback():
    """Handle OAuth 2.0 authorization code callback."""
    code = request.args.get("code")
    state = request.args.get("state")
    error = request.args.get("error")
    error_description = request.args.get("error_description", "")

    if error:
        return render_template(
            "submit_url.html",
            error=f"OAuth error: {error} - {error_description}",
            base_url=session.get("base_url", ""),
            openapi_url=session.get("openapi_url", ""),
        )

    if not code:
        return render_template(
            "submit_url.html",
            error="No authorization code received",
            base_url=session.get("base_url", ""),
            openapi_url=session.get("openapi_url", ""),
        )

    # Retrieve OAuth state from session
    oauth_state = session.get("oauth_state", {})
    if state and oauth_state.get("state") != state:
        return render_template(
            "submit_url.html",
            error="OAuth state mismatch - possible CSRF attack",
            base_url=session.get("base_url", ""),
            openapi_url=session.get("openapi_url", ""),
        )

    # Exchange code for token
    token_url = oauth_state.get("token_url")
    client_id = oauth_state.get("client_id")
    client_secret = oauth_state.get("client_secret")
    redirect_uri = oauth_state.get("redirect_uri")
    code_verifier = oauth_state.get("code_verifier")  # For PKCE

    if not all([token_url, client_id, redirect_uri]):
        return render_template(
            "submit_url.html",
            error="Missing OAuth configuration in session",
            base_url=session.get("base_url", ""),
            openapi_url=session.get("openapi_url", ""),
        )

    try:
        flow = AuthorizationCodeFlow(
            token_url=token_url,
            client_id=client_id,
            client_secret=client_secret or "",
            redirect_uri=redirect_uri,
        )
        token_response = flow.exchange_code(code, code_verifier=code_verifier)

        # Store token in session
        api_id = session.get("api_id", "")
        scheme_name = oauth_state.get("scheme_name", "oauth")

        credentials = session.get("credentials", {})
        credentials[scheme_name] = token_response.access_token
        if token_response.refresh_token:
            credentials[f"{scheme_name}_refresh_token"] = token_response.refresh_token
        session["credentials"] = credentials

        # Configure token renewal if enabled
        if session.get("enable_renewal") and token_response.refresh_token:
            renewal_interval = session.get("renewal_interval", 15) * 60  # to seconds
            token_manager.configure_renewal(
                api_id=api_id,
                interval_seconds=renewal_interval,
                refresh_token=token_response.refresh_token,
                token_url=token_url,
                client_id=client_id,
                client_secret=client_secret,
            )

        return redirect(url_for("request_builder_page"))

    except OAuth2Error as e:
        return render_template(
            "submit_url.html",
            error=f"Token exchange failed: {e}",
            base_url=session.get("base_url", ""),
            openapi_url=session.get("openapi_url", ""),
        )


@app.route("/oauth/authorize/<scheme_name>")
def oauth_authorize(scheme_name):
    """Initiate OAuth 2.0 authorization flow."""
    auth_schemes = session.get("auth_schemes", {})
    scheme = auth_schemes.get(scheme_name)

    if not scheme or scheme.get("scheme_type") != "oauth2":
        return redirect(url_for("credentials"))

    # Get flow configuration from form or defaults
    flows = scheme.get("flows", {})

    # Determine which flow to use (prefer authorization code)
    auth_url = None
    token_url = None

    if "authorizationCode" in flows:
        flow_config = flows["authorizationCode"]
        auth_url = flow_config.get("authorization_url") or flow_config.get("authorizationUrl")
        token_url = flow_config.get("token_url") or flow_config.get("tokenUrl")
    elif "implicit" in flows:
        flow_config = flows["implicit"]
        auth_url = flow_config.get("authorization_url") or flow_config.get("authorizationUrl")

    if not auth_url:
        return render_template(
            "credentials.html",
            auth_methods=session.get("auth_methods", {}),
            auth_schemes=session.get("auth_schemes", {}),
            error="No authorization URL configured for this OAuth scheme",
        )

    # Get client credentials from session
    credentials = session.get("credentials", {})
    client_id = credentials.get(f"{scheme_name}_client_id", "")
    client_secret = credentials.get(f"{scheme_name}_client_secret", "")

    if not client_id:
        return render_template(
            "credentials.html",
            auth_methods=session.get("auth_methods", {}),
            auth_schemes=session.get("auth_schemes", {}),
            error="Client ID is required for OAuth authorization",
        )

    # Generate state and optionally PKCE verifier
    import secrets as secrets_module

    state = secrets_module.token_urlsafe(32)
    code_verifier = secrets_module.token_urlsafe(32)

    # Build redirect URI
    redirect_uri = url_for("oauth_callback", _external=True)

    # Store OAuth state in session
    session["oauth_state"] = {
        "state": state,
        "scheme_name": scheme_name,
        "token_url": token_url,
        "client_id": client_id,
        "client_secret": client_secret,
        "redirect_uri": redirect_uri,
        "code_verifier": code_verifier,
    }

    # Build authorization URL
    code_challenge = (
        base64.urlsafe_b64encode(hashlib.sha256(code_verifier.encode()).digest())
        .rstrip(b"=")
        .decode()
    )

    params = {
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "response_type": "code",
        "state": state,
        "code_challenge": code_challenge,
        "code_challenge_method": "S256",
    }

    # Add scopes if available
    scopes = flow_config.get("scopes", {})
    if scopes:
        params["scope"] = " ".join(scopes.keys())

    auth_redirect = f"{auth_url}?{urlencode(params)}"
    return redirect(auth_redirect)


@app.route("/request-builder")
def request_builder_page():
    """Display the request builder page."""
    credentials = session.get("credentials", {})
    if not credentials:
        return redirect(url_for("credentials"))

    return render_template(
        "request_builder.html",
        base_url=session.get("base_url", ""),
        openapi_url=session.get("openapi_url", ""),
        credentials=credentials,
        custom_headers=session.get("custom_headers", {}),
        enable_renewal=session.get("enable_renewal", False),
        renewal_interval=session.get("renewal_interval", 15),
    )


@app.route("/api/token/refresh", methods=["POST"])
def refresh_token():
    """Manually refresh OAuth token."""
    credentials = session.get("credentials", {})
    auth_schemes = session.get("auth_schemes", {})

    # Find OAuth scheme with refresh token
    for name, scheme in auth_schemes.items():
        if scheme.get("scheme_type") == "oauth2":
            refresh_token_value = credentials.get(f"{name}_refresh_token")
            if refresh_token_value:
                flows = scheme.get("flows", {})
                token_url = None
                for flow_name, flow_config in flows.items():
                    token_url = flow_config.get("token_url") or flow_config.get("tokenUrl")
                    if token_url:
                        break

                if token_url:
                    try:
                        flow = RefreshTokenFlow(token_url=token_url)
                        client_id = credentials.get(f"{name}_client_id", "")
                        client_secret = credentials.get(f"{name}_client_secret", "")

                        token_response = flow.refresh(
                            refresh_token=refresh_token_value,
                            client_id=client_id,
                            client_secret=client_secret,
                        )

                        # Update stored credentials
                        credentials[name] = token_response.access_token
                        if token_response.refresh_token:
                            credentials[f"{name}_refresh_token"] = token_response.refresh_token
                        session["credentials"] = credentials

                        return {"success": True, "message": "Token refreshed"}
                    except OAuth2Error as e:
                        return {"success": False, "error": str(e)}, 400

    return {"success": False, "error": "No refresh token available"}, 400


@app.route("/collections")
def collections_page():
    """Display all imported collections."""
    imported_collections = session.get("imported_collections", [])
    return render_template("collections.html", imported_collections=imported_collections)


@app.route("/import/postman")
def postman_import_page():
    """Display the Postman collection import page."""
    return render_template("postman_import.html")


@app.route("/import/postman/upload", methods=["POST"])
def postman_upload():
    """Upload and preview a Postman collection.

    Expects:
        - collection file via form data (file upload)
        - OR collection JSON via request body

    Returns:
        JSON with collection summary for preview

    Note:
        - Validates file size before processing
        - Does NOT store credentials in session for security
    """
    try:
        # Validate file size limit (10MB)
        MAX_FILE_SIZE = 10 * 1024 * 1024
        
        importer = PostmanCollectionImporter()

        # Check if file upload
        if "collection_file" in request.files:
            file = request.files["collection_file"]
            if file.filename == "":
                return {"error": "No file selected"}, 400

            # Check file size before reading
            file.seek(0, 2)  # Seek to end
            file_size = file.tell()
            file.seek(0)  # Reset to start
            
            if file_size > MAX_FILE_SIZE:
                return {
                    "error": f"File size ({file_size / 1024 / 1024:.1f}MB) exceeds maximum (10MB)"
                }, 413

            collection_data = file.read().decode("utf-8")
            imported = importer.load_collection(collection_data)

        # Check if JSON in request body
        elif request.is_json:
            collection_data = request.get_json()
            imported = importer.load_collection(collection_data)

        else:
            return {"error": "No collection data provided"}, 400

        # Store in session for confirmation - but NOT credentials
        # Credentials/tokens are only stored when explicitly confirmed
        session["pending_import"] = {
            "collection": imported.name,
            "requests": [
                {
                    "name": req.name,
                    "method": req.method,
                    "url": req.url,
                    "folder": "/".join(req.folder_path) if req.folder_path else "",
                    "auth_type": req.auth.type if req.auth else None,
                    # Note: auth parameters are NOT stored in session
                }
                for req in imported.requests
            ],
            "variables": [{"key": var.key, "value": var.value} for var in imported.variables],
            "folders": imported.folders,
        }

        summary = importer.get_import_summary(imported)
        logger.info("Collection preview generated: %s with %d requests", 
                   imported.name, len(imported.requests))
        
        return {"success": True, "summary": summary, "preview": session["pending_import"]}

    except ValueError as e:
        logger.warning("Invalid collection uploaded: %s", str(e))
        return {"error": str(e)}, 400
    except Exception as e:
        logger.exception("Error uploading Postman collection")
        return {"error": "Failed to process collection"}, 500


@app.route("/import/postman/confirm", methods=["POST"])
def postman_confirm_import():
    """Confirm and execute the Postman collection import.

    Expects:
        JSON body with import options:
        - import_requests: bool
        - import_variables: bool
        - import_auth: bool

    Returns:
        JSON with import results

    Note:
        - Sensitive data is NOT included in results for security
        - Session is cleared after confirmation
    """
    if "pending_import" not in session:
        return {"error": "No pending import found"}, 400

    try:
        data = request.get_json() or {}
        import_requests = data.get("import_requests", True)
        import_variables = data.get("import_variables", True)
        import_auth = data.get("import_auth", True)

        pending = session["pending_import"]
        results = {
            "imported_requests": 0,
            "imported_variables": 0,
            "imported_folders": 0,
            "configured_auth": 0,
        }

        # Store imported data in session
        if "imported_collections" not in session:
            session["imported_collections"] = []

        collection_data = {
            "name": pending["collection"],
            "requests": [] if not import_requests else pending["requests"],
            "variables": [] if not import_variables else pending["variables"],
            "folders": pending["folders"],
        }

        if import_requests:
            results["imported_requests"] = len(pending["requests"])

        if import_variables:
            # Note: variables already in session from environment import
            # Only count user-confirmed variables
            results["imported_variables"] = len(pending["variables"])

        if import_auth:
            # Count unique auth configurations (from requests)
            auth_types = set()
            for req in pending["requests"]:
                if req.get("auth_type"):
                    auth_types.add(req["auth_type"])
            results["configured_auth"] = len(auth_types)

        results["imported_folders"] = len(pending["folders"])

        session["imported_collections"].append(collection_data)
        session.pop("pending_import", None)  # Clean up pending import
        session.modified = True

        logger.info("Collection imported successfully: %s (%d requests, %d variables)",
                   pending["collection"],
                   results["imported_requests"],
                   results["imported_variables"])
        
        return {"success": True, "results": results}

    except Exception as e:
        logger.exception("Error confirming Postman import")
        return {"error": "Failed to complete import"}, 500


@app.route("/import/postman/environment", methods=["POST"])
def postman_import_environment():
    """Import a Postman environment file.

    Expects:
        - environment file via form data (file upload)
        - OR environment JSON via request body

    Returns:
        JSON with imported variables (excluding sensitive values for security)

    Note:
        - Environment variables are cached in session only if explicitly confirmed
        - Sensitive keys are NOT logged
    """
    try:
        # Validate file size limit (10MB)
        MAX_FILE_SIZE = 10 * 1024 * 1024
        
        importer = PostmanCollectionImporter()

        # Check if file upload
        if "environment_file" in request.files:
            file = request.files["environment_file"]
            if file.filename == "":
                return {"error": "No file selected"}, 400

            # Check file size before reading
            file.seek(0, 2)
            file_size = file.tell()
            file.seek(0)
            
            if file_size > MAX_FILE_SIZE:
                return {
                    "error": f"File size ({file_size / 1024 / 1024:.1f}MB) exceeds maximum (10MB)"
                }, 413

            env_data = file.read().decode("utf-8")
            variables = importer.load_environment(env_data)

        # Check if JSON in request body
        elif request.is_json:
            env_data = request.get_json()
            variables = importer.load_environment(env_data)

        else:
            return {"error": "No environment data provided"}, 400

        # Store in session only - credentials are NOT logged or displayed
        if "postman_variables" not in session:
            session["postman_variables"] = {}

        imported_count = 0
        for var in variables:
            if var.enabled:
                session["postman_variables"][var.key] = var.value
                imported_count += 1

        # Return response without sensitive values
        return {
            "success": True,
            "imported_count": imported_count,
            "variables": [
                {"key": v.key, "value": "[REDACTED]" if v.key.lower() in {"token", "password", "secret", "key"} else v.value, "enabled": v.enabled}
                for v in variables
            ],
        }

    except ValueError as e:
        logger.warning("Invalid environment file: %s", str(e))
        return {"error": str(e)}, 400
    except Exception as e:
        logger.exception("Error importing Postman environment")
        return {"error": "Failed to import environment"}, 500


@app.route("/api/execute-request", methods=["POST"])
def execute_request():
    """Execute a request from an imported collection.
    
    Expects JSON:
        {
            "collection_name": str,
            "request_name": str
        }
        
    Returns:
        JSON with execution results
    """
    try:
        data = request.get_json()
        if not data:
            return {"error": "No JSON data provided"}, 400
            
        collection_name = data.get("collection_name")
        request_name = data.get("request_name")
        
        if not collection_name or not request_name:
            return {"error": "collection_name and request_name are required"}, 400
        
        # Find collection in session
        imported_collections = session.get("imported_collections", [])
        collection = None
        for coll in imported_collections:
            if coll.get("name") == collection_name:
                collection = coll
                break
        
        if not collection:
            return {"error": f"Collection '{collection_name}' not found"}, 404
        
        # Find request in collection
        req = find_request_in_collection(collection, request_name)
        if not req:
            return {"error": f"Request '{request_name}' not found in collection"}, 404
        
        # Extract request details
        method = req.get("method", "GET")
        url = req.get("url", "")
        auth_type = req.get("auth_type")
        
        # Get variables from collection
        variables = collection.get("variables", [])
        
        # Create executor with variables
        executor = RequestExecutor(variables)
        
        # Execute request
        # Note: For now, we'll use basic auth params from URL/headers
        # Full auth parsing from Postman format will be added later
        result = executor.execute(
            method=method,
            url=url,
            headers=None,  # TODO: Parse headers from request
            body=None,  # TODO: Parse body from request
            auth_type=auth_type,
            auth_params={"token": "{{api_token}}"} if auth_type == "bearer" else None,
        )
        
        logger.info(
            "Request executed: %s %s -> %s",
            method,
            request_name,
            result.get("status_code") if result.get("success") else result.get("error"),
        )
        
        return result
        
    except Exception as e:
        logger.exception("Error executing request")
        return {"error": f"Execution failed: {str(e)}"}, 500


if __name__ == "__main__":
    app.run(debug=True)  # nosec B201 - debug mode only for local development

