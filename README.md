# REST Incantation

[![Tests](https://github.com/jfreed-dev/REST-Incantation/actions/workflows/tests.yml/badge.svg)](https://github.com/jfreed-dev/REST-Incantation/actions/workflows/tests.yml)
[![Qodana](https://github.com/jfreed-dev/REST-Incantation/actions/workflows/qodana_code_quality.yml/badge.svg)](https://github.com/jfreed-dev/REST-Incantation/actions/workflows/qodana_code_quality.yml)

REST Incantation is a Flask-based tool for exploring REST APIs from their OpenAPI documentation. It supports fetching OpenAPI docs from a base URL, detecting auth schemes, and guiding users through credential entry.

## Features
- OpenAPI parsing for JSON and YAML (`openapi.json`, `openapi.yaml`, `openapi.yml`).
- Authentication scheme detection via OpenAPI security schemes.
- Token helper utilities for client-credential flows.
- Simple web UI for API URL entry and credential collection.

## Quick Start
```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python app.py
```

Open `http://127.0.0.1:5000` in your browser.

## Configuration
Secrets are loaded from `config/secrets.yaml` (ignored by git). Start from the example:
```bash
cp config/secrets.example.yaml config/secrets.yaml
```

Supported keys:
- `flask_secret_key`
- `token_endpoint`
- `client_id`
- `client_secret`

You can also override the Flask secret with `FLASK_SECRET_KEY` or point to a different file with `REST_INCANTATION_SECRETS`.

## Development
- Main entry point: `app.py`
- Templates: `templates/`
- Auth helpers: `credential_method.py`, `bearer_tokens.py`

## Testing
```bash
pytest
```

## Contributing
See `CONTRIBUTING.md` for setup and PR expectations.

## Security
Report vulnerabilities per `SECURITY.md`. Do not commit secrets or `token.json`.

## License
MIT License. See `LICENSE`.
