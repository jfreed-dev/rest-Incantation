## Summary
<!-- Brief description of what this PR changes and why -->

## Type of Change
<!-- Select all that apply -->
- [ ] Bug fix (non-breaking change that fixes an issue)
- [ ] New feature (non-breaking change that adds functionality)
- [ ] Vendor profile addition
- [ ] Documentation update
- [ ] Refactoring (no functional changes)
- [ ] Breaking change (fix or feature that would cause existing functionality to change)

## Related Issues
<!-- Link any related issues: Fixes #123, Relates to #456 -->

## Changes Made
<!-- Describe the specific changes in this PR -->
-
-
-

## Testing

### Test Coverage
- [ ] Added new tests for this change
- [ ] Updated existing tests
- [ ] No tests needed (documentation only)

### Manual Testing
<!-- Describe any manual testing performed -->

### Test Commands Run
```bash
# Confirm all pass before submitting
pytest --cov=. --cov-report=term
ruff check .
ruff format --check .
mypy .
bandit -c pyproject.toml -r .
```

## Quality Checks
<!-- All must pass for merge -->
- [ ] `ruff check .` passes (linting)
- [ ] `ruff format --check .` passes (formatting)
- [ ] `mypy .` passes (type checking)
- [ ] `bandit -c pyproject.toml -r .` passes (security)
- [ ] `pytest` passes (all tests green)
- [ ] Coverage maintained or improved

## Documentation
- [ ] README.md updated (if user-facing changes)
- [ ] VENDOR_PROFILES.md updated (if vendor addition)
- [ ] Docstrings added/updated for new functions
- [ ] No documentation needed

## Screenshots
<!-- For UI changes, include before/after screenshots -->

## Vendor Profile Checklist
<!-- Only complete if adding a vendor profile -->
- [ ] Basic information documented (ID, name, category, base URL)
- [ ] Authentication configuration complete
- [ ] Rate limit documentation included
- [ ] At least 5 common endpoint examples
- [ ] Link to official API documentation
- [ ] OpenAPI spec source noted (if available)

## Final Checklist
- [ ] I have read [CONTRIBUTING.md](CONTRIBUTING.md)
- [ ] My code follows the project's code style
- [ ] I have performed a self-review of my code
- [ ] I have commented my code where necessary
- [ ] My changes generate no new warnings
- [ ] I have rebased on the latest `main` branch
