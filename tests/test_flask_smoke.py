import importlib
import os
import warnings

from app import app


def test_index_route():
    client = app.test_client()

    response = client.get("/")

    assert response.status_code == 200
    assert b"Enter Base API URL" in response.data


def test_secret_key_warning_when_no_key_configured():
    """Verify a warning is issued when using the default insecure secret key."""
    import app as app_module

    env_backup = os.environ.get("FLASK_SECRET_KEY")
    secrets_backup = os.environ.get("REST_INCANTATION_SECRETS")

    try:
        os.environ.pop("FLASK_SECRET_KEY", None)
        os.environ["REST_INCANTATION_SECRETS"] = "/nonexistent/path/secrets.yaml"

        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")
            importlib.reload(app_module)

            assert len(w) == 1
            assert "insecure default secret key" in str(w[0].message)
    finally:
        if env_backup is not None:
            os.environ["FLASK_SECRET_KEY"] = env_backup
        else:
            os.environ.pop("FLASK_SECRET_KEY", None)
        if secrets_backup is not None:
            os.environ["REST_INCANTATION_SECRETS"] = secrets_backup
        else:
            os.environ.pop("REST_INCANTATION_SECRETS", None)
        importlib.reload(app_module)
