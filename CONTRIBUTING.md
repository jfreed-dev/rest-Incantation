# Contributing

Thanks for contributing to REST Incantation. This project focuses on a clean Flask UI for exploring OpenAPI-backed REST APIs.

## Getting Started
- Create a virtual environment and install dependencies:
  - `python -m venv .venv`
  - `source .venv/bin/activate`
  - `pip install -r requirements.txt`
- Run the app locally:
  - `python app.py`
- Run tests:
  - `pytest`

## Project Conventions
- Follow PEP 8 style and use 4-space indentation.
- Use `snake_case` for functions and variables.
- Keep modules focused and avoid import-time side effects.

## Testing
- Tests are optional for small changes but encouraged for behavior changes.
- If you add tests, use `pytest` and place files under `tests/` as `test_*.py`.

## Pull Requests
- Include a clear summary and testing notes (or "not tested").
- Add screenshots for UI changes.
- Keep documentation aligned with code changes (README, best practices, or config docs).
- Link related issues if applicable.

## Security
- Report security issues according to `SECURITY.md`.
- Do not commit secrets or `token.json`.

## Code of Conduct
All contributors are expected to follow `CODE_OF_CONDUCT.md`.
