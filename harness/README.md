# harness: the branch for agents (new, not released)

The new Emfirge core. An agent's own AWS tools talk to Emfirge instead of AWS. Emfirge answers from a **branch**
of the real account, says what the change **affects**, and gives a **go / ask** verdict. It never changes the
real account. Nothing in `backend/`, `cli/`, `mcp/` or `site/` (the paused hosted product) depends on this
folder, and this folder does not import them.

Status: built on a development branch, tested on local fakes only. No real-AWS run yet.

## The flow

```
agent's tools ──AWS calls──▶ server      one local endpoint; the agent needs no change
                               │
                               ▼
                            branch       reads: live from the real account (read-only)
                               │         changes: run on an engine (a fake AWS), the real thing copied in on touch
                               │         cannot tell: refused in the client's own error shape, never guessed
                               ▼
                            graph        what each change affects beyond what it touched
                               ▼
                            lenses       data, public access, money, permissions, and your own tools: only what is new
                               ▼
                            gate         every change undoable and nothing flagged or unknown → go (exit 0)
                                         anything else → ask the owner (exit 3)
```

## Modules and the one dependency rule

```
src/emfirge/
  core/      words and plug boundaries (model.py, ports.py). Pure. Imports nothing of ours.
  branch/    the branch: lifecycle, overlay (resource states), router, copy on touch (touch.py), ids, transplant,
             lists, journal, diff, the read-only door (guard.py), the undo prover's door (proving.py).
             Cloud-neutral.
  graph/     reference index over resource states, and reach (who is affected, by which chain). Cloud-neutral.
  lenses/    Lens contract, the built-in lenses, the runner for outside tools. Cloud-neutral.
  gate/      undo facts, detectors, the verdict and its report. Cloud-neutral.
  session/   one session end to end: run a command (or serve a person) on a branch, judge it, print the report,
             give the exit code. Cloud-neutral; a cloud plug-in gives it a bench (session/ports.py).
  aws/       the only package that knows AWS:
               codec.py             wire <-> calls and plain data, from botocore's models (json, rest-json, rest-xml,
                                    query, ec2; RPC v2 CBOR requests read and refused)
               catalog/             the generic catalog, compiled from AWS's published lists (data/catalog.json.gz)
               layered.py           the branch's catalog and copier: generic first, hand-written where it does not know
               outcomes_generic.py  lists, born ids and deletes in answers, generic
               generic_copy/        a copier with no code per type
               curated/             the hand-written types (experiment 09): naming for 18 types, 3 copiers still used
               accounts.py          an HTTP endpoint as an Account; SDK clients over any Account
               real.py              the owner's real account (reads only, re-signed with their credentials)
               engines/             AWS's emulator and moto as engines
               reader.py, places.py the real account's settings around a change, for the graph
               reversibility.py, undo/   static undo facts, and the undo prover
               session.py           the AWS bench for a session
               data/                per-service data (overrides, runs_code, copier_order): count the lines
  server/    the HTTP endpoint (any handler with `handle`; admin routes for a branch) and the wiring (wiring.py).
  cli/       `emf run / serve / seal`.
```

**Rule:** `core` imports nothing. `branch`, `graph`, `lenses`, `gate` import only `core` (and the standard
library). Only `aws` may import boto3/botocore. `server`, `session` and `cli` wire the parts together. A test
(`tests/test_boundaries.py`) fails the build when an import breaks this.

Another cloud is a second package beside `aws/` that implements `core/ports.py`. Nothing else changes.

## No code per AWS service

AWS has hundreds of services. The paused product hand-wrote what each change does: about 18 resource types in
months. Here:

- **What a call does** (read, list, write, permission change) and **which resource it names** come from the
  catalog, compiled from AWS's published lists (botocore's service models, the Service Authorization Reference,
  CloudFormation's resource schemas). Rerun the compile to pick up new services.
- **What a change does** comes from the engine. Where the catalog or the engine does not know, the answer is
  "I cannot tell", and the gate sends it to the owner.
- **What a change affects** comes from references found in the account's own settings (ids, ARNs, addresses,
  names), not from an edge list per service.
- Per-service knowledge is allowed only as **data** in `aws/data/`, each line with the test that shows the
  generic way fails. Count the lines: that number is the cost of a new service and it must stay near zero.

### What is still hand-written

Measured in experiment 23 (`research-log/experiments/23-generic-copy/README.md`). The numbers may change once more:
see experiment 23 for the current ones.

| | Before | Now (default configuration) |
|---|---|---|
| Copy code per type | 674 lines for 18 types | 196 lines still run as copiers: tables with their items (`dynamodb.py` 65), topics with their subscriptions (`sns.py` 38), VPCs with their groups and rules (`ec2.py` 93). See experiment 23 |
| Data per type | 4 lines (catalog overrides) | 4 + 6 (`runs_code.json`) + 4 (`copier_order.json`). See experiment 23 |
| Naming | the 18 hand-written types | still read first for all 18; only the bucket, parameter, queue and policy reads are needed. See experiment 23 |
| Generic code, no type in it | | 1,138 lines (layered, outcomes, copier). See experiment 23 |

## State machines (explicit, one module each)

**Branch** (`branch/lifecycle.py`)

| State | Meaning | Goes to |
|---|---|---|
| `open` | accepting calls | `sealed`, `discarded` |
| `sealed` | the session ended; nothing more is accepted; the diff is fixed | `judged`, `discarded` |
| `judged` | the gate's verdict is attached | `verified`, `discarded` |
| `verified` | the owner or the agent made the real change and the real account now matches the diff | (end) |
| `discarded` | thrown away | (end) |

**The proof mark** (`Branch.begin_proof`, `branch/proving.py`): a one-way mark, not a state. Only a `sealed` branch
can be proven, and only once. The undo prover puts the changes back on the engine, so after the mark the engine no
longer holds the branch: `changes()`, `states_after()`, `drift()` and `copy()` raise `EngineSpent`. Read the diff
first, then prove.

**A resource on a branch** (`branch/overlay.py`)

| State | Meaning | Reads answered by |
|---|---|---|
| `live` | not touched; the default | the real account, live |
| `copied` | copied into the engine because a call named it | the real account's live answer plus the branch's own change. A read with no answer from copy time: the real account, live, while no call has acted on the resource; after that, refused (unless the real account says "not found" and the engine has it: the branch made it) |
| `absent` | the real account does not have it | the engine |
| `born` | created on the branch | the engine |
| `deleted` | deleted on the branch | the engine (it says "not found") |
| `opaque` | could not be copied | nobody: every call that names it is refused |

**The diff** (`branch/diff.py`): one `Change` per resource. `created` carries the new settings, `deleted` the state at
copy time, `modified` what each read shows changed. A path starts with the read it came from
(`GetFunctionConfiguration.Timeout`). A field no call set (a clock, a hash, a revision) is kept and marked `derived`.
A resource a call only named (a role passed to a schedule) is not a change; neither is a container whose list only
shows a child's new state. `action` is a call that acted on a resource and shows in none of its reads.

**Verdict** (`gate/verdict.py`): `go` or `ask`, nothing else. `go` needs all three: every change is fully
undoable, no lens flagged anything new, and nothing is unknown. Users write no rules.

## The command

```
emf run [options] -- <command ...>   run the command against a fresh branch; print the report; exit 0 go, 3 ask
emf serve [options]                  serve a branch and print the lines to source; Ctrl-C or `emf seal` ends it
emf seal --url URL                   end a served branch and print its report
```

Where the real account is: `--real-endpoint URL` (a local stand-in, as every test uses) or `--real-aws` (your real AWS
account, read with your own credentials). One of the two is required.

| Exit code | Meaning |
|---|---|
| 0 | `go`: the agent may make the real change |
| 3 | `ask`: the owner decides; the report says why |
| 2 | Emfirge itself failed (not a verdict) |
| other | the wrapped command's own failure, passed through as 64 + its code, capped at 125 |

## Tests

`pytest` runs the pure tests. `EMFIRGE_LAB=1 pytest -m lab` also starts local fakes (never real AWS). The
measurements behind the design are in `theanshsonkar/emfirge-notes`, `research-log/experiments/`.
