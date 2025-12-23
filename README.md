# REST Incantation

[![Tests](https://github.com/jfreed-dev/REST-Incantation/actions/workflows/tests.yml/badge.svg)](https://github.com/jfreed-dev/REST-Incantation/actions/workflows/tests.yml)
[![codecov](https://codecov.io/gh/jfreed-dev/rest-Incantation/graph/badge.svg)](https://codecov.io/gh/jfreed-dev/rest-Incantation)

REST Incantation is a Flask-based tool for exploring REST APIs from their OpenAPI documentation. It supports fetching OpenAPI docs from a base URL, detecting auth schemes, and guiding users through credential entry.

## Features
- OpenAPI parsing for JSON and YAML (`openapi.json`, `openapi.yaml`, `openapi.yml`).
- Authentication scheme detection via OpenAPI security schemes.
- Token helper utilities for client-credential flows.
- Simple web UI for API URL entry and credential collection.

## Requirements
- Python 3.x
- A reachable OpenAPI endpoint (or a local JSON/YAML spec file)

## Quick Start
```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python app.py
```

Open `http://127.0.0.1:5000` in your browser.

## Using the App
1) Enter a base API URL (for example `https://api.example.com`), or provide a direct OpenAPI URL.
2) REST Incantation will try, in order:
   - your explicit OpenAPI URL (if provided)
   - `<base_url>/openapi.json`
   - `<base_url>/openapi.yaml`
   - `<base_url>/openapi.yml`
3) Review detected auth schemes and enter credentials as needed.

## Screenshots
![Submit URL flow](docs/screenshots/submit-url.svg)
![Credentials entry](docs/screenshots/credentials.svg)

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

## Token Helper (Client Credentials)
`bearer_tokens.py` can refresh tokens using client credentials from `config/secrets.yaml`:
```python
from bearer_tokens import get_token

token = get_token()
```

## Development
- Main entry point: `app.py`
- Templates: `templates/`
- Auth helpers: `credential_method.py`, `bearer_tokens.py`

## Testing
```bash
pytest
```

## Static Analysis
Without a token, it runs locally in CI and uploads the report artifact.

## Troubleshooting
- OpenAPI fetch fails: confirm the base URL is reachable and that `/openapi.json` or `/openapi.yaml` exists.
- Unexpected format errors: check that the spec is valid JSON/YAML and served without HTML wrappers.
- Auth schemes missing: ensure your OpenAPI spec defines `components.securitySchemes`.
- Token refresh fails: verify `token_endpoint`, `client_id`, and `client_secret` in `config/secrets.yaml`.
- Flask sessions reset: set `FLASK_SECRET_KEY` to a stable value (not the default dev key).

## Contributing
See `CONTRIBUTING.md` for setup and PR expectations.

## Security
Report vulnerabilities per `SECURITY.md`. Do not commit secrets or `token.json`.

## License
MIT License. See `LICENSE`.
