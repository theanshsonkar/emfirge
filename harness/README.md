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
  branch/    the branch: lifecycle, routing, copy on touch, ids, transplant, journal, diff. Cloud-neutral.
  graph/     reference index over resource states, and reach (who is affected, by which chain). Cloud-neutral.
  lenses/    Lens contract, the built-in lenses, the runner for outside tools. Cloud-neutral.
  gate/      undo facts and the verdict. Cloud-neutral.
  aws/       the only package that knows AWS: codec (botocore models), catalog (compiled from AWS's published
             lists), engines (AWS's emulator, moto), the real account, copiers.
  server/    the HTTP endpoint.
  cli/       `emf run -- <command>`: start a branch, run the command against it, print the report, exit 0 or 3.
```

**Rule:** `core` imports nothing. `branch`, `graph`, `lenses`, `gate` import only `core` (and the standard
library). Only `aws` may import boto3/botocore. `server` and `cli` wire the parts together. A test
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
- Per-service knowledge is allowed only as **data** in `aws/data/overrides.json`, each line with the test that
  shows the generic way fails. Count the lines: that number is the cost of a new service and it must stay near zero.

## State machines (explicit, one module each)

**Branch** (`branch/lifecycle.py`)

| State | Meaning | Goes to |
|---|---|---|
| `open` | accepting calls | `sealed`, `discarded` |
| `sealed` | the session ended; nothing more is accepted; the diff is fixed | `judged`, `discarded` |
| `judged` | the gate's verdict is attached | `verified`, `discarded` |
| `verified` | the owner or the agent made the real change and the real account now matches the diff | (end) |
| `discarded` | thrown away | (end) |

**A resource on a branch** (`branch/overlay.py`)

| State | Meaning | Reads answered by |
|---|---|---|
| `live` | not touched; the default | the real account, live |
| `copied` | copied into the engine because a change named it | the real account's live answer plus the branch's own change |
| `absent` | the real account does not have it | the engine |
| `born` | created on the branch | the engine |
| `deleted` | deleted on the branch | the engine (it says "not found") |
| `opaque` | could not be copied | nobody: every call that names it is refused |

**Verdict** (`gate/verdict.py`): `go` or `ask`, nothing else. `go` needs all three: every change is fully
undoable, no lens flagged anything new, and nothing is unknown. Users write no rules.

## Exit codes of `emf run`

| Code | Meaning |
|---|---|
| 0 | `go`: the agent may make the real change |
| 3 | `ask`: the owner decides; the report says why |
| 2 | Emfirge itself failed (not a verdict) |
| other | the wrapped command's own failure, passed through as 64 + its code, capped at 125 |

## Tests

`pytest` runs the pure tests. `EMFIRGE_LAB=1 pytest -m lab` also starts local fakes (never real AWS). The
measurements behind the design are in `theanshsonkar/emfirge-notes`, `research-log/experiments/`.
