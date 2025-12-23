import json
import os

import requests
import yaml
from flask import Flask, redirect, render_template, request, session, url_for

from credential_method import find_authentication_method

SECRETS_FILE = os.environ.get("REST_INCANTATION_SECRETS", "config/secrets.yaml")

app = Flask(__name__)


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


def fetch_openapi_documentation(base_url: str, explicit_url: str | None = None):
    if explicit_url:
        candidate_urls = [explicit_url]
    elif base_url.endswith((".json", ".yaml", ".yml")):
        candidate_urls = [base_url]
    else:
        candidate_urls = [
            f"{base_url.rstrip('/')}/openapi.json",
            f"{base_url.rstrip('/')}/openapi.yaml",
            f"{base_url.rstrip('/')}/openapi.yml",
        ]

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
    auth_methods = find_authentication_method(api_documentation)
    session["auth_methods"] = auth_methods
    return redirect(url_for("credentials"))


@app.route("/credentials", methods=["GET", "POST"])
def credentials():
    auth_methods = session.get("auth_methods", {})
    if request.method == "POST":
        submitted = {name: request.form.get(name, "") for name in auth_methods}
        session["credentials"] = submitted
        return render_template(
            "request_builder.html",
            base_url=session.get("base_url", ""),
            openapi_url=session.get("openapi_url", ""),
            credentials=submitted,
        )

    if not auth_methods:
        return redirect(url_for("index"))

    return render_template("credentials.html", auth_methods=auth_methods)


if __name__ == "__main__":
    app.run(debug=True)
