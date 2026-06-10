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

The backend (`backend/`) is runnable locally but requires Postgres + several
environment variables. See the comments in `backend/app/main.py` if you want
to spin it up. Most users won't need to — `emfirge.cloud` is the canonical
deployment.

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
- Add tests for new functionality (backend uses pytest, MCP uses TypeScript
  type-checking as the smoke test)
- Update relevant docs if behavior changes
- The maintainer reviews on a best-effort basis — usually within 7 days

## Coding style

- **Python**: black + isort defaults, 100-char lines OK
- **TypeScript**: strict mode, no `any` unless justified, ESM imports
- **Commits**: clear summary line; explain the *why* in the body if it's
  not obvious from the diff

## License

By contributing, you agree your contributions will be licensed under
**BUSL 1.1** (see `LICENSE`). After the Change Date (2030-06-10) or 4 years
after each release, your contributions auto-convert to Apache 2.0.

## Questions?

Open a GitHub Discussion. For private/security topics, see `SECURITY.md`.
