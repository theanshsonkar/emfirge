# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability in Emfirge, please report it
responsibly. Do **not** open a public GitHub issue.

**Email:** ansh@emfirge.cloud

Please include:
- A description of the vulnerability
- Steps to reproduce
- Potential impact

We aim to acknowledge reports within 48 hours and provide an initial
assessment within 7 days.

## Scope

This policy covers:
- The `backend/` source — the scanner running at emfirge.cloud
- The `mcp/` package — `@emfirge/mcp` on npm
- The `iam-role.yaml` CloudFormation template

## Out of scope

- User-misconfigured deployments (e.g., self-hosting without proper
  secrets management)
- Findings reported by Emfirge against your own AWS account — those are
  the tool working as intended; use the recommendations
- Issues in third-party dependencies — please report those upstream

## Security practices

- All AWS access uses **read-only IAM roles** (no write permissions ever)
- Credentials are never stored — STS temporary tokens only, 1-hour TTL
- Rate limiting on all LLM and mutation endpoints
- HMAC-SHA256 verification on GitHub webhooks
- Presigned URLs expire after 1 hour
- The MCP tokenizes AWS identifiers locally — they never leave the
  user's machine in `strict` mode

## Disclosure timeline

We follow a coordinated disclosure model:

1. You report the issue privately
2. We acknowledge within 48 hours
3. We work on a fix; you can request progress updates
4. Once fixed, we publish a release and credit you in the release notes
   (unless you request anonymity)

We do not currently run a paid bug bounty program.
