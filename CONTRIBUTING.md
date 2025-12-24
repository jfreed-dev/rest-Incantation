# Contributing to REST Incantation

Thank you for your interest in contributing to REST Incantation! This project helps developers explore REST APIs from OpenAPI documentation, with a focus on enterprise IT vendor APIs (Cisco, Palo Alto, Juniper, AWS, Azure, etc.).

## Table of Contents

- [Getting Started](#getting-started)
- [Development Environment](#development-environment)
- [Project Structure](#project-structure)
- [Contributing Vendor Profiles](#contributing-vendor-profiles)
- [Testing](#testing)
- [Pull Request Process](#pull-request-process)
- [Code Style](#code-style)
- [Security](#security)

---

## Getting Started

### Prerequisites

- Python 3.11 or higher
- Git
- (Optional) Docker for containerized development

### Quick Setup

```bash
# Clone the repository
git clone https://github.com/jfreed-dev/rest-Incantation.git
cd rest-Incantation

# Create and activate virtual environment
python -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Install pre-commit hooks (recommended)
pip install pre-commit
pre-commit install

# Run the application
python app.py
```

Open http://127.0.0.1:5000 in your browser.

### Using Docker

```bash
cd docker
docker compose up --build
```

---

## Development Environment

### Required Tools

| Tool | Purpose | Install |
|------|---------|---------|
| **ruff** | Linting and formatting | `pip install ruff` |
| **mypy** | Type checking | `pip install mypy` |
| **pytest** | Testing | `pip install pytest pytest-cov` |
| **bandit** | Security scanning | `pip install bandit` |
| **pre-commit** | Git hooks | `pip install pre-commit` |

### Running Quality Checks

```bash
# Linting
ruff check .

# Formatting
ruff format .

# Type checking
mypy .

# Security scan
bandit -c pyproject.toml -r .

# All tests with coverage
pytest --cov=. --cov-report=term
```

### Pre-commit Hooks

Pre-commit hooks run automatically on each commit:

```bash
# Install hooks (one-time setup)
pre-commit install

# Run manually on all files
pre-commit run --all-files
```

Hooks include:
- **ruff** - Linting and auto-formatting
- **mypy** - Type checking

---

## Project Structure

```
rest-Incantation/
├── app.py                      # Main Flask application
├── auth/                       # Authentication module
│   ├── schemes.py              # Security scheme parsing
│   ├── oauth2_flows.py         # OAuth 2.0 implementations
│   ├── storage.py              # Credential storage backends
│   ├── token_manager.py        # Token renewal scheduler
│   └── header_builder.py       # HTTP header construction
├── templates/                  # Jinja2 templates
│   ├── base.html               # Base template with Tailwind
│   ├── components/             # Auth form components
│   └── partials/               # Reusable UI fragments
├── config/                     # Configuration files
│   └── secrets.example.yaml    # Secrets template
├── docs/                       # Documentation
│   ├── VENDOR_PROFILES.md      # Vendor API specifications
│   └── screenshots/            # UI screenshots
├── tests/                      # Test suite
├── credential_method.py        # OpenAPI auth detection
├── load_openapi_documentation.py  # Local file loader
└── bearer_tokens.py            # Legacy token helper
```

### Key Modules

| Module | Responsibility |
|--------|----------------|
| `app.py` | Flask routes, OpenAPI discovery (37 paths) |
| `auth/schemes.py` | Parse OpenAPI securitySchemes |
| `auth/oauth2_flows.py` | OAuth 2.0 flow implementations |
| `auth/storage.py` | Session and encrypted file storage |
| `auth/token_manager.py` | Background token refresh |

---

## Contributing Vendor Profiles

We're building support for enterprise IT vendor APIs. See [docs/VENDOR_PROFILES.md](docs/VENDOR_PROFILES.md) for detailed specifications.

### Target Vendors

| Category | Vendors |
|----------|---------|
| **Network** | Cisco Meraki, Cisco SD-WAN (Viptela), Juniper Mist |
| **Security** | Palo Alto (Prisma, Panorama), Cisco Umbrella, Juniper Security Director |
| **Cloud** | AWS, Microsoft Azure |
| **DCIM** | Schneider Electric EcoStruxure IT |

### Adding a New Vendor Profile

1. **Research the API**
   - Authentication method (OAuth 2.0, API key, etc.)
   - Base URL and API versioning
   - Rate limits and pagination
   - OpenAPI spec availability

2. **Document in VENDOR_PROFILES.md**
   ```yaml
   ### Vendor Name

   | Property | Value |
   |----------|-------|
   | **Vendor ID** | `vendor_id` |
   | **Base URL** | `https://api.vendor.com` |
   | **Auth Type** | OAuth 2.0 / API Key / etc. |
   | **OpenAPI** | Yes (URL) / No |
   | **Rate Limit** | X requests per Y |
   ```

3. **Include**
   - Authentication configuration (endpoints, headers, flows)
   - Rate limiting details
   - Pagination patterns
   - Common API endpoints
   - Official documentation links

### Vendor Profile Requirements

- [ ] Basic information (ID, name, category, base URL)
- [ ] Complete authentication configuration
- [ ] Rate limit documentation (if available)
- [ ] At least 5 common endpoint examples
- [ ] Link to official API documentation
- [ ] OpenAPI spec source (if available)

---

## Testing

### Running Tests

```bash
# Run all tests
pytest

# Run with coverage report
pytest --cov=. --cov-report=term

# Run specific test file
pytest tests/test_flask_smoke.py

# Run tests by marker
pytest -m smoke       # Basic smoke tests
pytest -m unit        # Fast unit tests
pytest -m integration # Integration tests

# Verbose output
pytest -v
```

### Test Requirements

| Change Type | Test Requirement |
|-------------|------------------|
| Bug fix | Test that reproduces and verifies the fix |
| New feature | Tests covering happy path and edge cases |
| Refactoring | Existing tests should pass; add if coverage gaps |
| Documentation | No tests required |

### Writing Tests

- Place tests in `tests/` directory as `test_*.py`
- Use pytest fixtures for common setup
- Mock external API calls
- Aim for 90%+ coverage on new code

Example test structure:

```python
import pytest
from unittest.mock import patch, Mock

class TestFeatureName:
    """Tests for feature description."""

    def test_happy_path(self, client):
        """Feature should work with valid input."""
        response = client.get("/endpoint")
        assert response.status_code == 200

    def test_error_handling(self, client):
        """Feature should handle errors gracefully."""
        with patch("module.function", side_effect=Exception("Error")):
            response = client.get("/endpoint")
        assert response.status_code == 500
```

---

## Pull Request Process

### Before Submitting

1. **Sync with main branch**
   ```bash
   git fetch origin
   git rebase origin/main
   ```

2. **Run all checks**
   ```bash
   ruff check . && ruff format --check .
   mypy .
   pytest --cov=. --cov-report=term
   bandit -c pyproject.toml -r .
   ```

3. **Update documentation** if needed
   - README.md for user-facing changes
   - VENDOR_PROFILES.md for vendor additions
   - Docstrings for API changes

### PR Requirements Checklist

```markdown
## Summary
<!-- Brief description of changes -->

## Type of Change
- [ ] Bug fix
- [ ] New feature
- [ ] Vendor profile addition
- [ ] Documentation update
- [ ] Refactoring

## Testing
- [ ] Added/updated tests
- [ ] All tests passing (`pytest`)
- [ ] Coverage maintained/improved

## Quality Checks
- [ ] Linting passes (`ruff check .`)
- [ ] Formatting passes (`ruff format --check .`)
- [ ] Type checking passes (`mypy .`)
- [ ] Security scan passes (`bandit -c pyproject.toml -r .`)

## Documentation
- [ ] README updated (if applicable)
- [ ] VENDOR_PROFILES.md updated (if applicable)
- [ ] Docstrings added/updated

## Screenshots
<!-- For UI changes, include before/after screenshots -->
```

### Review Process

1. CI pipeline must pass (lint, typecheck, security, pytest, docker)
2. At least one maintainer approval required
3. All review comments addressed
4. Squash merge preferred for clean history

---

## Code Style

### Python Guidelines

- Follow PEP 8 style guidelines
- Use 4-space indentation
- Maximum line length: 100 characters (enforced by ruff)
- Use type hints for function signatures

```python
def process_auth_scheme(
    scheme_data: Dict[str, Any],
    scheme_name: str,
) -> Optional[SecurityScheme]:
    """Parse an authentication scheme from OpenAPI data.

    Args:
        scheme_data: Raw scheme data from OpenAPI spec
        scheme_name: Name of the security scheme

    Returns:
        Parsed SecurityScheme object, or None if invalid
    """
    pass
```

### Naming Conventions

| Type | Convention | Example |
|------|------------|---------|
| Functions | snake_case | `get_auth_token()` |
| Variables | snake_case | `api_response` |
| Classes | PascalCase | `VendorProfile` |
| Constants | UPPER_SNAKE | `MAX_RETRIES` |
| Files | snake_case | `vendor_profiles.py` |

### Import Order

```python
# Standard library
import json
import logging
from typing import Dict, Optional

# Third-party
import requests
from flask import Flask, request

# Local
from auth.schemes import SecurityScheme
from credential_method import find_authentication_method
```

### Docstrings

Use Google-style docstrings:

```python
def fetch_openapi_spec(base_url: str, timeout: int = 10) -> Dict:
    """Fetch OpenAPI specification from a base URL.

    Tries 37 common OpenAPI endpoint paths to discover the spec.

    Args:
        base_url: The base URL of the API
        timeout: Request timeout in seconds

    Returns:
        Parsed OpenAPI specification as a dictionary

    Raises:
        ConnectionError: If all discovery attempts fail
        ValueError: If the spec is invalid
    """
    pass
```

---

## Security

### Reporting Vulnerabilities

Report security issues according to [SECURITY.md](SECURITY.md). Do not open public issues for security vulnerabilities.

### Security Guidelines

- **Never commit secrets** (API keys, passwords, tokens)
- **Use environment variables** for sensitive configuration
- **Validate all user input** before processing
- **Use parameterized queries** if adding database features
- **Follow OWASP guidelines** for web security

### Files to Never Commit

```
config/secrets.yaml
token.json
*.key
*.pem
.env
```

These are already in `.gitignore`.

---

## Getting Help

- **Questions**: Open a GitHub Discussion
- **Bugs**: Open a GitHub Issue with reproduction steps
- **Security**: See [SECURITY.md](SECURITY.md)

## Code of Conduct

All contributors are expected to follow our [Code of Conduct](CODE_OF_CONDUCT.md).

---

Thank you for contributing to REST Incantation!
