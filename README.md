# REST Incantation

[![Tests](https://github.com/jfreed-dev/rest-Incantation/actions/workflows/tests.yml/badge.svg)](https://github.com/jfreed-dev/rest-Incantation/actions/workflows/tests.yml)
[![codecov](https://codecov.io/gh/jfreed-dev/rest-Incantation/graph/badge.svg)](https://codecov.io/gh/jfreed-dev/rest-Incantation)
[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Code style: ruff](https://img.shields.io/badge/code%20style-ruff-000000.svg)](https://github.com/astral-sh/ruff)
[![Security: bandit](https://img.shields.io/badge/security-bandit-yellow.svg)](https://github.com/PyCQA/bandit)
[![Security: pip-audit](https://img.shields.io/badge/security-pip--audit-purple.svg)](https://github.com/pypa/pip-audit)

REST Incantation is a Flask-based tool for exploring REST APIs from their OpenAPI documentation. It supports fetching OpenAPI docs from a base URL, detecting auth schemes, and guiding users through credential entry.

## Features
- OpenAPI parsing for JSON and YAML (`openapi.json`, `openapi.yaml`, `openapi.yml`).
- Authentication scheme detection via OpenAPI security schemes.
- Token helper utilities for client-credential flows.
- Simple web UI for API URL entry and credential collection.

## Requirements
- Python 3.11+
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

### Project Structure
- Main entry point: `app.py`
- Templates: `templates/`
- Auth helpers: `credential_method.py`, `bearer_tokens.py`

### Setup Pre-commit Hooks
```bash
pip install pre-commit
pre-commit install
```

Hooks run automatically on commit:
- **ruff** - linting and formatting
- **mypy** - type checking

## Testing
```bash
pytest

# With coverage
pytest --cov=. --cov-report=term
```

## Docker

### Prerequisites
- [Docker Engine](https://docs.docker.com/engine/install/) 20.10+ or [Docker Desktop](https://www.docker.com/products/docker-desktop/)
- [Docker Compose](https://docs.docker.com/compose/install/) v2.0+ (included with Docker Desktop)

Verify installation:
```bash
docker --version        # Docker version 20.10+
docker compose version  # Docker Compose version v2.0+
```

### Quick Start with Docker
```bash
# Clone the repository
git clone https://github.com/jfreed-dev/rest-Incantation.git
cd rest-Incantation

# Build and run
cd docker
docker compose up --build
```
Open `http://127.0.0.1:5000` in your browser.

### Run in Background (Detached Mode)
```bash
cd docker
docker compose up -d --build

# View logs
docker compose logs -f

# Stop the application
docker compose down
```

### Run Tests in Docker
```bash
# Using the test script
./docker/docker-test.sh

# Or manually
cd docker
docker compose run --rm test
```

### Build Only
```bash
cd docker
docker compose build
```

### Configuration with Docker
To use custom secrets, create `config/secrets.yaml` before starting:
```bash
cp config/secrets.example.yaml config/secrets.yaml
# Edit config/secrets.yaml with your values
```
The config directory is mounted read-only into the container.

## CI Checks
All checks run automatically on push and pull requests:
- **pytest** - tests with coverage reporting
- **ruff** - linting and formatting
- **mypy** - type checking
- **bandit** - security scanning

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
