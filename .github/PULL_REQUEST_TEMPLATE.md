## Summary

- 

## Security Impact

- [ ] Read-only enforcement unchanged
- [ ] Deny-by-default ACL unchanged
- [ ] Error-message sanitization unchanged
- [ ] Security tests added/updated (if behavior changed)

## Test Plan

- [ ] `ruff check .`
- [ ] `ty check`
- [ ] `python -m pytest -q`
- [ ] Security-focused suites (if relevant)

## Checklist

- [ ] No secrets added (`.env`, credentials, tokens)
- [ ] Documentation updated (README/AGENTS) when behavior changed
- [ ] Backward compatibility considered for MCP tool responses
