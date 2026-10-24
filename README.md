<div align="center">

# 🛡️ Emfirge

### Give your agent a branch of your cloud.

AI agents are starting to change real infrastructure.<br>
Emfirge is the **harness** that lets them try first, on a **branch** of your live AWS,<br>
judged by **lenses** that show what the change would actually do.

[Get started][quickstart] · [Docs][docs] · [npm][npm]

<sub>Built by <a href="https://github.com/theanshsonkar">Ansh Sonkar</a></sub>

</div>

---

## Your agent wants to "clean up unused databases"

Without Emfirge, it calls `DeleteDBInstance` and you learn from your on-call channel what that database was for.

With Emfirge, the agent does it on a branch first:

```text
you    ▸ Clean up the unused databases in us-east-1.

agent  ▸ I tried it on a branch first. Verdict: BLOCK

         ✗ recently_used
           CloudWatch metrics show a deleted resource was used in the last 90 days
           → orders-db

         ✗ data_store_deleted_no_recovery_point
           Deleted data store has no recovery point
           → orders-db

         Branch #2, deleting only legacy-reports-db, passes.
         Want the exact API call for that one?
```

Nothing touched production. The agent changed its plan, and the hand-back it gives you is bound by hash to the verdict it passed.

<sub>Simplified output. The reason codes and messages are the engine's real ones.</sub>

---

## Three layers

### 🧰 The harness: the product
Where the agent works, what it may see, what it gets back, and what it can't skip.
- **Read-only, always.** Emfirge never writes to your cloud. You or your pipeline apply the approved change.
- **Private by default.** AWS identifiers are tokenized on your machine before the LLM sees them.
- **No silent passes.** A change Emfirge can't model can't `pass`. A missing check is reported, not hidden.

### 🌿 The branch: the engine
A Git-style copy of a model of your live AWS: a base snapshot plus an ordered list of changes.
- **Git-style operations.** Fork, roll back, compare and discard, like you would with code.
- **Many ways in.** Feed it typed changes, a Terraform plan, a CloudFormation change set, AWS API calls or AWS CLI commands. The same change gives the same answer whichever way it comes in.
- **A two-sided diff.** See what was added and removed, what became reachable from the internet, and the cost before and after.

### 🔍 Lenses: what gets measured
Each lens judges the branch from one angle, and together they produce a single `pass` / `warn` / `block`.

| | Lens | Asks |
|---|---|---|
| ✅ | **Security** | Does this expose something, or open a privilege-escalation path? |
| ✅ | **Dependencies** | What breaks if this is removed? Is it still in use? Can it be recovered? |
| ✅ | **Compliance** | Which CIS 1.5 and SOC 2 controls flip? (control lists from Prowler's published data; uncovered controls are never `pass`) |
| 🟡 | **Cost** | What does it cost before and after? (AWS's published Price List, us-east-1 only; no LCUs) |
| 🟡 | **Limits** | Will it hit an AWS quota? (early: AWS default quotas) |
| 🔜 | **Yours** | Bring your own evaluator, run against the same branch contract. |

---

## Try it

```bash
npx @emfirge/mcp install
```

Then tell your assistant:

```text
Help me set up Emfirge, then scan arn:aws:iam::123456789012:role/EmfirgeReadOnly in us-east-1
```

The account ID is a placeholder. Setup gives you a one-click CloudFormation link for a read-only role, and you can delete the stack any time to revoke access.

The installer sets up Claude Desktop, Claude Code, Cursor, Kiro, Cline, Continue and Codex, and you can configure any other MCP client by hand. You can also use the [API](https://emfirge.cloud/docs) or the [branch CLI](backend/BRANCH-CLI.md). See all the tools in the [MCP README][mcp-readme].

---

## Built to be trusted

Every behaviour of the engine is pinned by a numbered **law**, a property test that must always hold. There are 48 so far, for example:

> **L1:** an empty branch scores exactly like the live scan.<br>
> **L7:** the same snapshot and changes always give the same verdict.<br>
> **L9:** your identifiers never appear in free-text output.<br>
> **L12:** evidence can make a verdict stricter, never looser.<br>
> **L21:** a Terraform security-group rule and the equivalent AWS API call get the same verdict.

The checks come from public sources rather than hand-written lists: [pathfinding.cloud](https://pathfinding.cloud) escalation paths, policy_sentry IAM data, AWS schemas, Prowler's compliance data, and the AWS Price List. Checkov runs on each branch verdict as an advisory scanner (it warns, it does not block on its own); Trivy is off. Every CI run publishes a scorecard.

**What Emfirge does not claim:** a branch is a model of your cloud, so a `pass` is evidence, not a guarantee. If any part of the check was skipped, the verdict says so. Today Emfirge is a safe workspace, not a gate that blocks a live apply.

---

<details>
<summary><b>What changes can a branch model today?</b></summary>

| Resource type | Add | Modify | Delete |
|---|:-:|:-:|:-:|
| EC2 instance, security group, RDS instance, S3 bucket, Lambda function, network ACL | ✅ | ✅ | ✅ |
| IAM role (including trust policy) | ✅ | ✅ | ✅ |
| IAM user, NAT gateway | ✅ | | |
| RDS snapshot | ✅ | | ✅ |
| EBS volume | ✅ | | ✅ |
| EBS snapshot | | | ✅ |
| Route table | ✅ | ✅ | |
| IAM role policy | | ✅ | |

The live `GET /branches/capabilities` endpoint is the authoritative list, and `GET /branches/field-catalog` lists every settable field with the AWS API member it stands for. Most resource types also carry `tags`; a tag change replaces the complete user tag set. Anything not modeled degrades the verdict rather than passing.

</details>

<details>
<summary><b>Repository layout and licenses</b></summary>

| Path | What it is | License |
|---|---|---|
| [`backend/`](backend) | The engine: collector, graph, branches, input adapters, lenses, verdict, hand-back | AGPL-3.0 |
| [`mcp/`](mcp) | `@emfirge/mcp`, the MCP server and CLI | Apache-2.0 |
| [`site/`](site) | Docs at [emfirge.cloud/docs][docs] | AGPL-3.0 |
| [`iam-role.yaml`](iam-role.yaml) | The read-only customer role | AGPL-3.0 |

</details>

## Built by

Emfirge is designed and built by **Ansh Sonkar** ([@theanshsonkar](https://github.com/theanshsonkar)): the engine, the branch model, the lenses and the MCP.

Building with AI agents on AWS, or want to talk about Emfirge? Email **[ansh@emfirge.cloud](mailto:ansh@emfirge.cloud)**.

---

[Contributing](CONTRIBUTING.md) · [Security](SECURITY.md) · [Privacy](PRIVACY.md)

[docs]: https://emfirge.cloud/docs
[quickstart]: https://emfirge.cloud/docs/quickstart
[npm]: https://www.npmjs.com/package/@emfirge/mcp
[mcp-readme]: mcp/README.md
