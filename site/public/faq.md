# FAQ. Questions, fixes and terms.

Short answers, what to do when something fails (your agent usually handles it; this is what it sees), and the words emfirge uses.

Human version: https://emfirge.cloud/faq/

## Questions

**Do I need to learn the CLI?**
No. Your agent uses it. You give your agent the setup prompt once and it runs every `emfirge` command itself. The [Agent reference](https://emfirge.cloud/cli.md) is written for the agent; you never have to read it.

**What do I actually do?**
Set up once: paste the setup prompt into your agent, approve the browser sign-in when your agent shows it, and create the read-only role with one click in AWS, then give your agent the role ARN ([Set up](https://emfirge.cloud/quickstart.md)). After that you ask your agent to change your AWS as usual and read what it hands back. You also say yes before a check that costs money, and you decide what your agent is allowed to apply.

**My agent runs in the cloud or in CI, with no browser. How does it sign in?**
It does not sign in. On your own computer you run `npx emfirge login`, then `npx emfirge key create --name ci`, and set the key it prints as `EMFIRGE_API_KEY` in your agent environment's secret settings. Your agent then uses the key and skips the browser. You still create the read-only role yourself and give your agent the role ARN. Steps are under [Set up](https://emfirge.cloud/quickstart.md#sign-in); the commands are in the [Agent reference](https://emfirge.cloud/cli.md#keys).

**How do I make, list or revoke an API key?**
With the CLI, on a computer where you are signed in: `emfirge key create --name LABEL` shows the key once; `emfirge key list` shows your keys (never the key itself); `emfirge key revoke KEY_ID` stops one at once. There is no web page for keys. A project can hold 10 active keys, and a key cannot make more keys. See [Security & privacy](https://emfirge.cloud/security.md#keys).

**Does emfirge change my AWS?**
No. It is read-only. Your agent applies with its own credentials; emfirge records and verifies.

**Which agents work?**
Any agent that can run a shell command: Claude Code, Codex, Cursor, Gemini CLI and others. An MCP adapter exists for clients that cannot, but the npm version (0.2.3) is behind the repo and an update is coming; the CLI is the supported path today.

**Which clouds?**
AWS today. The core is built to be cloud-neutral, with one adapter per cloud, but only AWS exists.

**Does my data go to an LLM?**
Emfirge has no LLM. Identifiers are tokenized on your machine before your agent's model sees them. See [Security & privacy](https://emfirge.cloud/security.md).

**Is a pass a guarantee?**
No. A branch is a model of your cloud. A pass is evidence, and every verdict says what was checked and what was not.

**What if emfirge cannot model my change?**
It cannot pass. The change is listed as unmodeled and the verdict gets stricter. See [Coverage](https://emfirge.cloud/coverage.md).

**Does a block stop my agent?**
Only if the agent listens. Emfirge is advisory today: it does not stop anyone with their own AWS credentials.

**Is it open source?**
The engine is AGPL-3.0, and the MCP adapter and the CLI are Apache-2.0. [Source on GitHub](https://github.com/theanshsonkar/emfirge).

**What does it cost?**
Nothing while in beta. See [Pricing](https://emfirge.cloud/pricing.md).

## Troubleshooting

**`emfirge` is not found, or Node errors on start**
Your agent needs Node.js 20 or later. `npx emfirge --version` prints the version that runs, and `npx emfirge --help` prints the commands the server offers.

**Access denied or 403 when reading my account**
Check the role ARN, the trusted account and the ExternalId in your stack against the link `emfirge connect` prints; your agent can run it again to print the link. A role made with an older shared ExternalId must be redeployed with your own. A 403 is exit code 2.

**The scan is empty**
Confirm the region: most resources are regional and emfirge needs one. Check that the role has the read permissions in [iam-role.yaml](https://github.com/theanshsonkar/emfirge/blob/main/iam-role.yaml). An empty result does not mean your account has no risks.

**Branch not found**
Your agent should use the exact ID printed by `emfirge branch list`, against the same backend that created it. This is exit code 3.

**A change was rejected**
The branch must be open, the resource type supported, and the target must exist for a modify or delete. Unknown fields are rejected. Check [Coverage](https://emfirge.cloud/coverage.md#resources) and run `emfirge try` again with the exact ID.

**HTTP 409 on a change, rollback, discard or new branch**
Someone else changed the branch: run `emfirge branch get` for the new revision token and pass it with `--revision`. Or 10 branches are already open on one base scan: discard branches you no longer need. This is exit code 5.

**Timeouts or HTTP 429**
A scan can take a while on a large account; the client waits up to 240 seconds. For 429 (exit code 4, `rate_limited`), follow the limit and reset time in the message.

**Exit code 6, "needs a newer emfirge"**
The server's command is newer than the install. Your agent runs `npx emfirge@latest`, then retries.

**Your agent says it is not signed in (exit code 2)**
It runs `emfirge login`; that opens your browser and needs you to sign in with GitHub or Google within 5 minutes. The sign-in page opens on the machine where your agent runs. If your agent runs in the cloud or CI, set `EMFIRGE_API_KEY` instead. A key that was revoked also gives exit code 2: run `emfirge key list` on your computer to check, and make a new one.

**`emfirge key create` says forbidden (exit code 2)**
It was run with a key. Only a browser sign-in can make a key, so a leaked key cannot make more. Run it on your own computer after `emfirge login`, with `EMFIRGE_API_KEY` unset.

**`emfirge request` exits 1**
It is not built yet. It prints a JSON error, `not_built`, and sends nothing.

**The verdict says a scanner was unavailable**
Native results still return. `coverage_warnings` says the result is not full coverage. Do not treat it as complete.

## Glossary

| Term | Meaning |
|---|---|
| Branch | A base snapshot plus an ordered list of changes. An empty branch equals live. |
| Snapshot | What emfirge read from your account at one moment. The base of every branch. |
| Change | One add, modify or delete of a supported resource on a branch. |
| Context | What is true about your cloud: what exists, what is live, what depends on what, and your marks. |
| Verb | One of the six CLI commands your agent runs: context, branch, try, check, request, report. `request` is not built yet. |
| Check | One of six questions about a branch: data, exposure, money, availability, control, outside world. Each answers with facts, what was checked and what is unknown. |
| Unknown | What a check could not look at, and why. Unknown means not checked. It never means safe. |
| Changed setting | A setting that differs between a branch and its base, named without its value: judged by a check, or named as not judged. |
| Verdict | `pass`, `warn` or `block`, with reasons. Advisory evidence, not a guarantee. |
| Reason code | A stable name for one fact in a verdict, such as `recently_used`. |
| Lens | An evaluator that looks at the branch from one angle. Several lenses feed the six checks. |
| Law | A numbered property test the engine must always satisfy, such as L7: the same snapshot and changes give the same verdict. |
| Request | An ask to the owner, raised by an agent. Not built yet. |
| Hand-back | What `emfirge report` returns: the exact calls, bound by hash to the verdict they were judged with. |
| API key | A secret that starts with `emf_`, for an agent that cannot open a browser. You make it with `emfirge key create`; the agent sets it as `EMFIRGE_API_KEY`. |
| Token | A stand-in such as `SG_001` for a real identifier, made on your machine. |
| emfirge.md | A planned plain-English file of your marks and limits. Not built yet. |
| MCP | Model Context Protocol: the interface an agent client uses to call tools. Emfirge offers it as an adapter. |

---

All pages as markdown: https://emfirge.cloud/llms.txt. Source: https://github.com/theanshsonkar/emfirge. Contact: ansh@emfirge.cloud.
