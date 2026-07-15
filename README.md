<div align="center">

# 🛡️ Emfirge

## Git branch for your cloud.

**Give your AI a read-only map of AWS. Trace attack paths, test a security fix on a cloned graph, and see the result before touching production.**

[Get started][quickstart] · [Read the docs][docs] · [Open dashboard][dashboard] · [npm][npm]

[![npm](https://img.shields.io/npm/v/@emfirge/mcp?style=flat-square&color=cb3837)](https://www.npmjs.com/package/@emfirge/mcp)
[![CI](https://img.shields.io/github/actions/workflow/status/theanshsonkar/emfirge/ci.yml?branch=main&style=flat-square&label=CI)](https://github.com/theanshsonkar/emfirge/actions/workflows/ci.yml)
[![MCP Registry](https://img.shields.io/badge/MCP_Registry-listed-5b5bd6?style=flat-square)][registry]
[![License](https://img.shields.io/badge/License-BUSL_1.1-2563eb?style=flat-square)][license]

</div>

## Your scanner finds problems. Emfirge tests the fix.

Most cloud tools hand you a list and ask you to trust the recommendation. Emfirge builds a connected graph of your account, forks it in memory, applies the proposed security change, re-runs the rules, and shows what got safer—or riskier.

| 🕸️ See the path | 🎯 Find the chokepoint | 🧪 Rehearse the fix | 💬 Stay in your AI |
|---|---|---|---|
| Internet → compute → IAM → data | Prioritize what breaks the most attack paths | No write access. No production mutation. | Claude, Cursor, Kiro, Cline, Continue, Codex |

<div align="center">

**~20 AWS service types · 58 graph-aware rules · 17 rule families · 7 MCP tools**

</div>

## Start in 30 seconds

```bash
npx @emfirge/mcp install
```

Then ask your assistant:

```text
Scan my AWS account using role
arn:aws:iam::123456789012:role/EmfirgeReadOnly in us-east-1
```

No role yet? Say **“help me set up Emfirge.”** You will get a one-click CloudFormation link for a read-only IAM role.

> **Try it now with no setup:** use demo role `arn:aws:iam::194722410583:role/EmfirgeReadOnly` in `us-east-1`.

**Free:** 5 scans per AWS account per day. No signup. No API key.

## Ask questions your cloud can finally answer

```text
Show me the worst attack path from the internet.
What is the blast radius if this instance is compromised?
Which resource should I fix first?
Will closing SSH remove the path without adding new security findings?
Check this account against CIS AWS Foundations 1.5.
```

## One graph. Seven tools.

| Tool | Answer |
|---|---|
| `emfirge_scan` | What does my AWS risk look like? |
| `emfirge_get_findings` | What is wrong and how do I fix it? |
| `emfirge_attack_paths` | How could an attacker reach my data? |
| `emfirge_verify_fix` | What changes if I apply this security fix? |
| `emfirge_simulate_breach` | What happens after this resource is compromised? |
| `emfirge_check_compliance` | Which CIS AWS 1.5 or SOC 2 controls fail? |
| `emfirge_setup_help` | How do I create the read-only role? |

## Proof, not a prompt

```text
Scan AWS → build graph → fork graph → apply mutation → re-run rules → show delta
```

The score, findings, attack paths, and fix verification come from deterministic graph analysis—not an LLM guessing what might happen. Your AI explains the evidence; Emfirge produces it.

## Built for trust

- **Read-only AWS access** through a role you own and can revoke anytime.
- **One-hour STS credentials** protected by an ExternalId and never stored.
- **Local tokenization** of recognized AWS identifiers before MCP results reach your LLM in strict mode.
- **No production changes** during scans, breach simulations, or fix verification.
- **Source available** for the MCP, scanner engine, rules, scoring, and docs.

> Emfirge proves the simulated **security** delta against your latest scan; it does not yet prove application connectivity. Some graph-derived labels may also remain visible in strict mode. See [How it works][how-it-works] and [Privacy][privacy] for the exact boundaries.

## Go deeper when you are ready

[Quickstart][quickstart] · [How the fork works][how-it-works] · [MCP tools][tools] · [Privacy][privacy] · [Security][security] · [Self-hosting][self-hosting] · [Contributing][contributing]

---

<div align="center">

### Stop guessing in production.

**Fork the graph. Follow the path. Prove the security delta.**

[Install Emfirge][quickstart] · [Star the repo][repo]

</div>

[repo]: https://github.com/theanshsonkar/emfirge
[docs]: https://emfirge.cloud/docs
[quickstart]: https://emfirge.cloud/docs/quickstart
[dashboard]: https://app.emfirge.cloud
[npm]: https://www.npmjs.com/package/@emfirge/mcp
[registry]: https://registry.modelcontextprotocol.io/v0.1/servers?search=io.github.theanshsonkar/emfirge
[license]: https://github.com/theanshsonkar/emfirge/blob/main/LICENSE
[how-it-works]: https://emfirge.cloud/docs/how-it-works
[tools]: https://emfirge.cloud/docs/tools
[privacy]: https://emfirge.cloud/docs/privacy
[security]: https://emfirge.cloud/docs/security
[self-hosting]: https://emfirge.cloud/docs/self-host
[contributing]: https://github.com/theanshsonkar/emfirge/blob/main/CONTRIBUTING.md
