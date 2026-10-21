# Contributing to Emfirge

Thanks for your interest. Emfirge is solo-maintained and gladly accepts
contributions.

## Quick start

The MCP package is the most contribution-friendly part of the codebase:

```bash
git clone https://github.com/theanshsonkar/emfirge.git
cd emfirge/mcp
npm install
npm run dev
```

### Backend tests

The backend (`backend/`) runs locally with SQLite. You need Python 3.11 or 3.12.

```bash
cd backend
python -m venv .venv && . .venv/bin/activate
pip install -r requirements.txt -r requirements-dev.txt
DATABASE_URL=sqlite:///:memory: python -m pytest -q -n auto
```

Tests never contact AWS or a hosted API.

### MCP tests

```bash
cd mcp && npm ci && npm run build && npm test
```

### How the engine is tested

New engine behaviour lands as a numbered **law**: a property-style invariant test in
`backend/tests/laws/`, named `test_L<n>...`, together with the code that satisfies it. Locked incident
scenarios live in `backend/tests/incidents/`. CI runs every suite on Python 3.11 and 3.12 and on
Node 20 and 22, then publishes a scorecard of laws, scenarios and escalation paths to the job
summary.

### Deploys

The guarded deploy workflow builds the backend from this repository. It deploys only from `main`
in the canonical repository, and fails unless the post-deploy health check passes.

## What we welcome

- **Bug reports** — open a GitHub issue with reproduction steps
- **New rules** — see `backend/app/rules.py` for the pattern. Each rule has
  a `rule_id`, severity, confidence, and optional graph-aware logic
- **New MCP clients to support** — add them to `mcp/src/installer.ts`
  (path detection follows the existing pattern)
- **Documentation improvements** — typos, clarifications, examples
- **Translations** of the README

## What's out of scope (for now)

- **Multi-cloud support** (GCP, Azure) — AWS first. Adding clouds before
  proving the AWS depth is the wrong order
- **New AI integrations** beyond Gemini + Claude — current set is sufficient
- **Self-hosting tooling** (docker-compose, Helm charts, multi-tenant DB
  migrations) — emfirge.cloud is the canonical deployment
- **A full dashboard rewrite** — the dashboard isn't OSS in v1

## Pull requests

- Keep PRs focused — one feature or fix per PR
- Add tests for new functionality (backend uses pytest and Hypothesis; MCP uses
  `node:test`). Engine behaviour changes should come with a law in `backend/tests/laws/`
- Update relevant docs if behavior changes
- The maintainer reviews on a best-effort basis — usually within 7 days

## Coding style

- **Python**: black + isort defaults, 100-char lines OK
- **TypeScript**: strict mode, no `any` unless justified, ESM imports
- **Commits**: clear summary line; explain the *why* in the body if it's
  not obvious from the diff

## License

By contributing, you agree that contributions to the engine/backend are licensed under
**AGPL-3.0**, while contributions under `mcp/` are licensed under **Apache-2.0**.
See the applicable license files for details.

## Questions?

Open a GitHub Discussion. For private/security topics, see `SECURITY.md`.
