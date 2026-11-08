# A branch of your live cloud. The engine, in one page.

Your agent hands emfirge the change it wants to make. Emfirge puts it on a copy of your live AWS, runs six checks, and answers with facts. The agent reads the facts, fixes its own plan and tries again. No AI runs inside emfirge, and it never writes to your cloud.

Human version: https://emfirge.cloud/how-it-works/

## The loop

**Change in, facts out, until it passes.**

*Figure 1. A change enters emfirge in any format and runs on a branch of your live cloud. Six checks answer with facts; a block goes back to the agent, which changes its plan. Only a passing change reaches your agent's context to apply.*

An agent that changes a codebase has files, a branch, tests and a log. An agent that changes a cloud gets the same five things from emfirge: **context** (what is true), a **workspace** (a branch), **signals** (what a change does), **boundaries** (what needs you) and a **record** (what happened).

The loop is `context → branch → try → check → fix → retry → apply → report`. Only what is left after the agent has corrected itself reaches a person.

## A branch of live

**A branch is a base snapshot plus an ordered list of changes.**

*Figure 2. A branch is a snapshot plus changes. The base never moves; each change is a layer replayed on it in order. A fork copies the whole stack into an independent second branch.*

BASE SNAPSHOT
- us-east-1, read through the read-only role at scan time (immutable)

ORDERED CHANGES
- 1  modify  security_group  SG_001  rules (try)
- 2  delete  rds_instance  DB_001 (try)
- 3  add     ebs_volume  size_gb 100 (try)

The engine rebuilds the hypothetical cloud by replaying the changes in order on the base. Live never moves. A snapshot reflects the moment it was read; it is not a continuously synchronized view of production.

An empty branch is live: it scores exactly like the live scan (law L1). That makes `check` on a branch with no changes your baseline.

### Fork.

Copy a branch, base and full change log, into an independent child. Try a variation without losing the original.

### Roll back.

Undo the last change, or truncate the log to the first N changes. Zero returns the branch to its base.

### Compare.

Put two designs on two branches and compare them. The engine ranks the outcomes safest first.

### Discard.

Mark a branch finished so it takes no more changes. It does not delete anything in your cloud.

Several agents can share a base safely. Every branch carries a revision token (a SHA-256 of its history); pass it to a change, rollback or discard, and a stale view is rejected with HTTP 409 instead of silently building on old state.

[Branch commands](https://emfirge.cloud/cli.md#branch)

## Many ways in

**Hand emfirge the change in the form you already have. Same change, same answer.**

| Input | What you give it | Example |
|---|---|---|
| Typed | A small typed change: operation, resource type, ID, fields | `modify security_group SG_001` |
| AWS CLI | One or more `aws …` commands, written out in full | `aws ec2 authorize-security-group-ingress …` |
| AWS API | The API calls as JSON | `AuthorizeSecurityGroupIngress {…}` |
| Terraform | The JSON from `terraform show -json plan.out` | `--terraform plan.json` |
| CloudFormation | A change set, as JSON | `--cfn changeset.json` |

Every format becomes the same typed change on the branch before anything is judged, so an equivalent change gets the same verdict whichever way it arrives. Law L21 pins a Terraform security-group rule and the equivalent AWS API call to the same verdict. Emfirge never runs your plan.

*Figure 3. Same change, five ways in. Whatever the format, it becomes one typed change on one branch and gets one verdict.*

Same change, same answer (L21): Typed change, AWS CLI, AWS API, Terraform, CloudFormation all produce the same verdict. Law L21 pins Terraform and the AWS API to the same verdict, and L20 pins ::/0 to 0.0.0.0/0.

Shorthand the engine cannot read is refused with a clear error, not guessed. Anything it reads but cannot model is listed and makes the verdict stricter.

## The six checks

**Six questions, asked about what the branch changed, not about the action.**

Emfirge compares the branch with its base and asks the same six questions every time. It does not keep a rule per AWS action (there are about 15,000); questions about the result do not grow.

| Check | The question | What it looks at | Example reason code |
|---|---|---|---|
| Data | Did something that holds data disappear with no recovery point? | Deleted data stores, snapshots, backups | `data_store_deleted_no_recovery_point` |
| Exposure | Is anything newly reachable from the internet or another account? | Security groups, network ACLs, route tables, bucket policies, role trust, 92 known escalation paths | `newly_internet_reachable` |
| Money | Did the monthly cost rise above your setting? | Provisioned cost before and after, from AWS's Price List (us-east-1); usage-based cost is listed as unknown | [TODO Ansh: no cost reason code yet; the engine reports `cost_unknown_notes`] |
| Availability | Did something live traffic depends on break or disappear? | The dependency graph and CloudWatch usage evidence | `recently_used` |
| Control | Was access or logging lost? | Admin roles, KMS key policies, CloudTrail, GuardDuty | [TODO Ansh: no reason code yet; control is a new check] |
| Outside world | Does the action itself leave the cloud? | Support cases, quota requests, email, domains, per service | [TODO Ansh: no reason code yet; decided from the action, not the diff] |

Unknown never passes. A change emfirge cannot model gets `unmodeled_change` or `unseen_change` and a stricter verdict; a check that could not run is reported, not hidden. Each reason carries a stable `code`, a plain message, and the resources it names, so the agent can read it like a failed test.

A `pass` is evidence, not a guarantee. A branch is a model of your cloud, and every verdict says what was checked and what was not.

[What each check is built from](https://emfirge.cloud/coverage.md#sources)

## Tell vs ask

**Not every fact needs a person.**

Each fact gets one of two responses. **Tell** writes a line in the record and nobody waits. **Ask** stops the agent at a `request` until you answer, and the agent carries on with other work meanwhile. Too many asks teach people to approve blindly, so the defaults ask only when the damage cannot easily be undone.

| Check | Default response |
|---|---|
| Data | Ask if there is no confirmed backup |
| Exposure | Ask if something is newly reachable |
| Money | Ask above $5 a month, for any commitment, or when the cost is unknown and you set no limit |
| Availability | Ask only if something live depends on it; otherwise tell |
| Control | Always ask |
| Outside world | Always ask |

Thresholds such as the $5 are settings in your `emfirge.md`, not rules in the engine. For something emfirge cannot model, data, control and outside world still ask; money and availability tell, marked "couldn't fully check".

[The request verb](https://emfirge.cloud/cli.md#request)

## emfirge.md

**Write your intent once. Every agent reads it.**

EMFIRGE.MD
- # my cloud
- - prod-* is production. Never delete without me.
- - The nightly-sync schedule is paused on purpose.
- - Tell me about any support case or quota request.
- - Budget: $30/month.

Plain English, kept in your project. Agents read it as context through `emfirge context`. Emfirge enforces the hard lines (the thresholds and the never-without-me rules) as boundaries on `check` and `request`.

## The record

**After the agent applies a change, it says so, and emfirge checks.**

Your agent applies with its own credentials; emfirge never does. Then it calls `report`: emfirge stores the exact calls, bound by hash to the verdict they passed (the input hash, the base snapshot, the branch revision and the verdict ID), and verifies against CloudTrail that what happened is what was judged.

emfirge report (example):

```
$ emfirge report --branch first-try --calls applied-calls.json --verify
  recorded   2 calls   input_sha256 9c1e…a47f
  verdict    PASS      branch first-try #3
  cloudtrail 2 of 2 calls found, 0 not in the verdict
  record     predicted vs actual: match
```

> Example output. CloudTrail verification needs read access to CloudTrail events: [TODO Ansh: confirm iam-role.yaml needs cloudtrail:LookupEvents added before report --verify ships].

A mismatch is named, not smoothed over: `input_hash_mismatch` (these are not the calls that were judged), `base_snapshot_changed`, `branch_revision_changed` or `verdict_changed`.

[The report verb](https://emfirge.cloud/cli.md#report)

## What emfirge never does

- **It never writes to your cloud.** The role is read-only and the engine has no apply path. Your agent applies.
- **It has no AI inside.** The same snapshot and changes always give the same verdict (law L7), so it cannot be talked into a pass.
- **It never passes silently.** A change it cannot model, or a check that did not run, makes the verdict stricter and says so.
- **It never writes the fix.** It supplies facts. The agent supplies the intelligence.

One honest limit: emfirge is advisory today. It is a safe workspace and a record, not a gate that blocks a live apply. A block stops nothing unless your agent or pipeline listens to it.

---

All pages as markdown: https://emfirge.cloud/llms.txt. Source: https://github.com/theanshsonkar/emfirge. Contact: ansh@emfirge.cloud.
