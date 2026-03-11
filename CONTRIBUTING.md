# Contributing to secure-sql-mcp

Thanks for contributing. This project enforces strict security behavior, so changes should be small, reviewed, and fully tested.

## Development Setup

1. Create and activate a virtual environment.
2. Install dev dependencies:
   - `python -m pip install -e ".[dev]"`
3. Install pre-commit:
   - `pre-commit install`

## Required Checks Before Opening a PR

Run locally:

```bash
ruff check .
ty check
python -m pytest -q
```

Security-focused suites:

```bash
python -m pytest -q \
  tests/test_mcp_interface.py \
  tests/test_query_validator_security.py \
  tests/test_mcp_stdio_security.py
```

## Pull Request Guidelines

- Keep PRs focused; avoid mixed refactors and feature changes.
- Include tests for behavior changes, especially security-related paths.
- Keep error messages actionable for MCP agents.
- Never weaken deny-by-default policy semantics.
- Never commit secrets (`.env`, credentials, tokens, policy files with sensitive data).

## Commit and Review Expectations

- Use descriptive commit messages.
- Link relevant issues in the PR description.
- Ensure CI is green before requesting review.
- At least one approval is required before merge.
