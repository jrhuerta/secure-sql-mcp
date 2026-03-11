# Security Policy

## Supported Versions

Security fixes are applied to the `main` branch.

## Reporting a Vulnerability

Please do **not** open public issues for vulnerabilities.

Report privately to: `jrhuerta+secure-sql-mcp@proton.me`

Include:

- A clear description of the issue.
- Reproduction steps or proof of concept.
- Impact assessment (what data or controls are affected).
- Suggested remediation if available.

You can expect:

- Initial acknowledgment within 3 business days.
- Triage and severity assessment after acknowledgment.
- Coordination on disclosure timing after fix availability.

## Security Expectations for Contributions

- Do not weaken read-only enforcement.
- Do not weaken deny-by-default table/column policy checks.
- Keep sensitive runtime details out of user-facing error messages.
- Add regression tests for all security-relevant changes.
