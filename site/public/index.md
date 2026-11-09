# emfirge

emfirge is building the harness for AI agents that work on your cloud.

You set it up once. Your agent does the rest, in its own shell.

## Give emfirge to your agent

People don't use the emfirge CLI; their AI agent does. A person sets it up once (paste the prompt below into the agent, approve the browser sign-in, create the read-only AWS role with one click and give the agent its ARN). The agent does the rest: it opens a branch, tries a change, checks it, fixes its own plan and hands back.

```
Set up emfirge for my AWS account and use it for every AWS change from now on.
emfirge is a CLI. Run it as `npx -y emfirge <command>` (Node.js 20 or later). Run `npx -y emfirge guide` first; the full reference is https://emfirge.cloud/cli.md.

1. Run `login`. It opens my browser so I can sign in with GitHub or Google. If it does not open, show me the address it prints, then wait for me.
2. Run `connect` and show me the link it prints. I will create the read-only role and send you the role ARN. Ask me which AWS region to use.
3. Run `context --refresh --role-arn ARN --region REGION`, then `context inventory`. Keep the role ARN: later steps need it.

Before any AWS change: open a branch (`branch open`), try the change on it (`try`), and read `check`. Never apply a change that did not pass. If it fails, fix your plan and try again on the branch. Ask me before `check --policy` or `check --evidence`: they cost money. When a change passes, apply it with your own access, run `report`, and tell me what changed.
```

For you (the person):

- Site: https://emfirge.cloud
- Set up: https://emfirge.cloud/quickstart.md
- How it works: https://emfirge.cloud/how-it-works.md
- Coverage: https://emfirge.cloud/coverage.md
- Security & privacy: https://emfirge.cloud/security.md
- Pricing: https://emfirge.cloud/pricing.md
- Changelog: https://emfirge.cloud/changelog.md
- FAQ: https://emfirge.cloud/faq.md

For your agent:

- CLI reference: https://emfirge.cloud/cli.md
- All pages as markdown: https://emfirge.cloud/llms.txt
- Source: https://github.com/theanshsonkar/emfirge
- Contact: ansh@emfirge.cloud

Works with: Claude Code, Codex, Cursor, Gemini CLI.

## Mission

The path to agents that run infrastructure isn't a smarter model. It's a true world for them to work in: what exists, what's live, what depends on what, and a safe copy to try a change on before it's real.

Intelligence is no longer the constraint. Trust is.

Agents can already write the Terraform and run the CLI. What they can't do is see what a change will break, and owners can't let them near production without that.

We built the hard parts: a branch engine for your live AWS, six checks that say what a change does to your data, exposure, money, availability, control and the outside world, and a record of what was applied, bound by hash to the verdict it was judged with.

Emfirge supplies the truth. Your agent supplies the intelligence. Emfirge has no AI inside: the same branch always gets the same answer, and it never writes to your cloud.

Figure 1. A change enters emfirge in any format and runs on a branch of your live cloud. Six checks answer with facts, and the verdict reads pass, warn or block. The agent reads them, changes its plan and tries again. The change that is left comes back as a hand-back, bound by hash to its verdict.

## What we do

- **A true model of your cloud.** What exists, what's live, what depends on what, and what each identity can reach, read through a role you can revoke any time.
- **A branch for every change.** Your agent tries AWS CLI commands, Terraform plans and CloudFormation change sets on a copy of live, never on production.
- **Six checks, no AI inside.** Data, exposure, money, availability, control, outside world. Deterministic, and what it cannot check is listed as unknown, never as safe.

Where a public source exists, the checks use it: AWS's own API models and Price List, pathfinding.cloud, Prowler and policy_sentry. The few facts with no public source are written by hand, cite the AWS docs, and are tested.

## In production

Our promise is a world your agent can trust: true facts, unknowns marked honestly, and nothing that ever writes to your cloud.

Numbers, counted from the repository:

| What | Count | How it was counted |
|---|---|---|
| Agents deleting prod (benchmark) | 49 / 49 incident tests pass | Locked answers (block / warn / pass) set before scoring and sha256-pinned: 17 cases drawn from real incidents (a database deleted with its only snapshot, `terraform destroy` on a prod VPC) plus locked scenarios. Run through the real engine on synthetic accounts, not a live AWS account. |
| Engine tests (backend) | 3,274 | `pytest --collect-only` in backend/ |
| MCP + CLI tests | 222 | `npm test` in mcp/ |
| Laws | 89 | distinct law ids in the tests, numbered L1 to L92 (L37 to L39 not used) |
| Modeled resource types | 18 | `SUPPORTED_RESOURCE_TYPES` in backend/app/mutations.py |
| pathfinding.cloud escalation paths | 92 | backend/app/data/pathfinding_paths.json |
| Scanner check reads | 55 | backend/app/data/scanner_check_reads.json |
| Native reason codes | 32 | distinct codes in backend/app/verdict.py |
| Prowler check metadata files | 21 | backend/app/data/third_party/prowler/checks |
| Severity crosswalk entries | 21 | backend/app/data/scanner_severity_crosswalk.json |

Same change, same answer: one rule that opens port 22 to the world gives the same verdict as a typed change, an AWS CLI command, an AWS API call, a Terraform plan or a CloudFormation change set. Law L21 pins Terraform and the AWS API to the same verdict.

> A change Emfirge cannot model can't pass. A missing check is reported, not hidden. (Emfirge README)

## Where it runs

emfirge runs wherever your agent runs. Your agent runs the CLI, a thin client; the engine is hosted. Your cloud only ever sees a read-only role.

1. In your terminal
2. In CI
3. In your agent's sandbox

## Trust

Emfirge is read-only by design. Your account IDs are tokenized on your machine before any model sees them. The engine is open source, so you can read every check.

- Read-only role
- Tokenized IDs
- Open source (AGPL-3.0, Apache-2.0)

Security & privacy: https://emfirge.cloud/security.md
Security policy: https://github.com/theanshsonkar/emfirge/blob/main/SECURITY.md
Privacy: https://github.com/theanshsonkar/emfirge/blob/main/PRIVACY.md

## Writing (coming soon)

- Field notes: an AI agent working on real AWS
- Why a cloud agent needs a harness
- Six questions instead of 15,000 rules

---

## How to use emfirge (for agents)

### Set up (you run the commands; your human approves two things)

```
npx -y emfirge login
npx -y emfirge connect
npx -y emfirge context --refresh --role-arn ARN --region REGION
npx -y emfirge context inventory
```

- `login` opens your human's browser to sign in with GitHub or Google (a page on 127.0.0.1 of the machine you run on; it waits 5 minutes). Your human must approve it; if the browser does not open, show them the address it prints, then wait. It is kept in ~/.emfirge/credentials.json, so you need them again only if it expires.
- `connect` prints a one-click CloudFormation link that creates a read-only IAM role (delete the stack to revoke). Show the link to your human. They create the stack, copy the RoleArn from its Outputs and give it to you. `connect` takes no ARN. Ask which AWS region to use; there is no default. Keep the ARN: `check --evidence` needs it again.
- After that you can do everything yourself. Node.js 20 or later. Human steps: https://emfirge.cloud/quickstart.md

### The verbs

1. `context`: ask what is true (`emfirge context inventory`; 11 questions: inventory, resource, depends_on, dependents, reachable, access, data, cost, live, marks, baseline).
2. `branch`: `open`, `fork`, `list`, `get`, `rollback`, `rollback-to`, `discard`, `compare` a copy of the live cloud model. Live never moves.
3. `try`: put a change on the branch (`--typed`, `--aws-cli`, `--aws-api`, `--terraform`, `--cloudformation`).
4. `check`: six answers with facts, what was checked and what is unknown: data, exposure, money, availability, control, outside world. Plus `changed_settings`. `--verdict` gives pass, warn or block.
5. `request`: ask the owner. Not built yet: it exits 1.
6. `report`: the hand-back of what you applied, bound by hash to the verdict (`--verify` checks the binding).

Every flag: https://emfirge.cloud/cli.md. Run `emfirge guide` for the agent guide. When a change passes, apply it yourself, run `emfirge report BRANCH`, and tell your human what changed.

### Rules

- Emfirge never writes to the cloud. You apply your own change, with your own access.
- Facts, not fixes. Emfirge will not tell you what to do.
- Unknown means not checked. It never means safe. Read every `unknown` entry and every changed setting that is not judged.
- Names and IDs come back as tokens (`S3_001`, `NAME_003`, `TAG_001`). Pass them back as they are.
- Emfirge keeps no plan text, only its SHA-256. Apply your own original plan.
- Never apply a change that did not pass. Emfirge is advisory and stops nothing, so this is on you.
- Run `check --policy` and `check --evidence` (they show an estimate first) only after your human agrees.
- Output is JSON on stdout (`--human` for short text); errors are JSON on stderr. Exit codes: 0 ok, 1 usage or rejected input, 2 not signed in, 3 not found, 4 server error or rate limit, 5 conflict, 6 needs a newer emfirge (run `npx emfirge@latest`). A finding never changes the exit code.
