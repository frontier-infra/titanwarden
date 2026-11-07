# Contributing to Titanwarden

Thanks for helping. Titanwarden guards secrets, so changes are held to a high
bar. Small, focused pull requests with tests are the fastest to review.

## Before you start

- For anything larger than a bug fix, open an issue first and describe the
  change. Changes to the agent protocol, the store format or the threat model
  need agreement before code.
- Never add an agent operation that returns a secret value. Use without
  reveal is the core rule.

## Development

You need Python 3.12 or newer and [uv](https://docs.astral.sh/uv/).

```sh
uv sync --frozen
uv run python -m unittest discover -s tests -v
uv run python -O -m unittest discover -s tests -v
```

Tests use a short temporary `TW_HOME` under `/tmp`. Never point development
commands at a live store, and never put a real secret in a test, fixture,
issue or log. Use obviously fake values such as `TEST-ONLY`.

## Pull requests

- Add or update tests for every behavior change.
- Keep the docs in `docs/` in step with the code.
- Plain words in docs and messages. No Unicode en or em dashes; CI checks.
- By contributing you agree that your contribution is licensed under the
  Apache License 2.0, as in section 5 of the [LICENSE](LICENSE).

## Security issues

Do not open a public issue for a vulnerability. See [SECURITY.md](SECURITY.md).
