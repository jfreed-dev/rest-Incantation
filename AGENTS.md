# Repository Guidelines

## Project Structure & Module Organization
- `app.py` contains the Flask entry point and route wiring.
- Core helpers live in top-level modules: `load_openapi_documentation.py`, `credential_method.py`, and `bearer_tokens.py`.
- HTML templates are in `templates/` (`index.html`, `submit_url.html`, `credentials.html`, `request_builder.html`).
- Security policy is documented in `SECURITY.md`; static analysis config is in `qodana.yaml`.

## Build, Test, and Development Commands
- `python app.py` starts the Flask app in debug mode for local development.
- `pip install -r requirements.txt` installs dependencies.
- `pytest` runs the test suite.

## Coding Style & Naming Conventions
- Python: 4-space indentation, PEP 8 conventions, `snake_case` for functions/variables, `CapWords` for classes.
- Keep modules focused (one purpose per file) and prefer explicit imports.
- Templates: keep filenames descriptive and route-aligned (e.g., `credentials.html`).

## Testing Guidelines
- Tests live under `tests/` and run with `pytest`.
- If you add tests, keep using `pytest`, place them under `tests/`, and name files `test_*.py`.
- Keep tests small and focused on parsing/auth flows (e.g., `load_openapi_documentation`).

## Commit & Pull Request Guidelines
- Existing commit messages are short, sentence-style descriptions (no Conventional Commits).
- Write imperative, specific commit subjects (e.g., "Add OpenAPI loader error handling").
- PRs: include a concise summary, testing notes (or "not tested"), and screenshots for UI changes.
- Do not add AI CLI tools as contributors in repo metadata or documentation.

## Security & Configuration Tips
- Do not commit tokens or secrets. `bearer_tokens.py` writes `token.json`; keep it local.
- Follow `SECURITY.md` for reporting vulnerabilities.
