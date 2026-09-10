# Contributing

Thanks for your interest in improving this project.

## Guidelines

- **Authorized use only.** This tooling is for security education on systems you own or are explicitly authorized to test. Do not submit code that facilitates unauthorized access.
- **No secrets.** Never commit credentials, API keys, tokens, or personal information.
- **Tests required.** All changes must include or update deterministic offline tests.
- **Standard library preferred.** Avoid adding third-party dependencies without discussion.
- **Clear commits.** Write concise, descriptive commit messages.

## Reporting Issues

Open an issue with a minimal reproduction. Do not include sensitive target information.

## Pull Requests

1. Fork and create a feature branch.
2. Add or update tests.
3. Ensure `python3 -m pytest -q` passes locally.
4. Submit with a clear description of the change.

## Code of Conduct

Be respectful. This is educational tooling — keep it constructive.
