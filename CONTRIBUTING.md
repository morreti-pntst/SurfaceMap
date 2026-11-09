# Contributing

Contributions are welcome. Keep changes focused, typed where practical, and consistent with the existing API and UI conventions. Never add real third-party targets or credentials to fixtures.

## Local workflow

1. Install Docker Compose v2, Python 3.12, Node 22, and Git.
2. Follow the [quick start](README.md#quick-start), then use `surfacemap start` to start the stack again.
3. Backend checks: from `backend/`, run `pytest`.
4. Frontend checks: from `frontend/`, run `npm ci && npm run build`.
5. Include the actual command output and any untested areas in the pull request description.

Before contributing a scanner integration, define explicit scope enforcement, safe argument construction, timeout/cancellation behavior, provenance, and parser fixtures. Never shell-interpolate user input.

## Licensing

Only submit work you have the right to contribute under the [project license](LICENSE). Identify the source and license of any third-party material and preserve its notices. See [third-party components](THIRD_PARTY.md).
