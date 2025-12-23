# Best Practices

## Security
- Keep secrets in `config/secrets.yaml` and never commit it. Use `config/secrets.example.yaml` as a template.
- Avoid logging tokens, credentials, or full request payloads.
- Rotate secrets if they are ever exposed.

## Configuration
- Prefer environment variables for overrides (`FLASK_SECRET_KEY`, `REST_INCANTATION_SECRETS`).
- Keep configuration minimal and documented in `README.md`.

## Code Quality
- Follow PEP 8 and keep modules single‑purpose.
- Avoid import‑time side effects; expose functions and wire them in `app.py`.
- Keep Flask routes small; move complex logic into helper modules.
- Keep static analysis config in `qodana.yaml` and prefer CI checks over local overrides.

## Testing
- Add tests for parsing, auth detection, and route behavior.
- Use markers (`unit`, `integration`, `smoke`) to keep test intent clear.
- Keep tests in `tests/` with `test_*.py` naming.

## Git & Releases
- Use clear, imperative commit messages.
- Tag releases (`vX.Y.Z`) after CI is green.

## Documentation
- Keep README steps aligned with actual commands and files.
- Add screenshots for UI changes and store them under `docs/screenshots/`.

## Architecture Notes
- `app.py` is the Flask entry point and wires HTTP routes to helpers.
- `load_openapi_documentation.py` parses OpenAPI JSON/YAML for local files; `app.py` handles remote fetches.
- `credential_method.py` reads OpenAPI security schemes and returns a mapping for UI rendering.
- `bearer_tokens.py` handles token refresh logic and expects secrets from `config/secrets.yaml`.
- Templates live in `templates/` and are kept simple to separate UI from backend logic.
