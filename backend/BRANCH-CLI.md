# Branch CLI

`scripts/emfirge-branch.py` is a Python-standard-library client for Emfirge's existing modeled branch API. It makes API requests only; branch changes are simulations in Emfirge and do not write to AWS.

Set the API root explicitly. For the hosted service, this is `https://emfirge.cloud/api`; for a local backend, use its local API root. Set `EMFIRGE_API_KEY` when API-key authentication is enabled.

```sh
export EMFIRGE_BASE_URL="https://emfirge.cloud/api"
export EMFIRGE_API_KEY="..." # optional when authentication is disabled
python backend/scripts/emfirge-branch.py create --analysis-id SCAN_ID --name "private-db"
```

The CLI emits one stable, sorted JSON response to stdout. Errors go to stderr and return exit status 2. `--base-url URL` can override the environment variable for one invocation.

## Commands

```sh
python backend/scripts/emfirge-branch.py apply \
  --branch-id BRANCH_ID --op modify --resource-type security_group \
  --branch-revision REVISION_FROM_SHOW \
  --resource-id SG_ID --expected-count 0 --fields-json '{"rules": []}'

# For larger changes, pass a JSON file or pipe JSON on stdin with --fields-file -.
python backend/scripts/emfirge-branch.py apply \
  --branch-id BRANCH_ID --op modify --resource-type iam_role_policy \
  --resource-id ROLE_ARN --fields-file policy-statements.json

# Replace a collected route table's complete normalized route list.
python backend/scripts/emfirge-branch.py apply \
  --branch-id BRANCH_ID --op modify --resource-type route_table \
  --resource-id RTB_ID --fields-json '{"routes": []}'

python backend/scripts/emfirge-branch.py show --branch-id BRANCH_ID
python backend/scripts/emfirge-branch.py fork --branch-id BRANCH_ID --name CANDIDATE --branch-revision REVISION_FROM_SHOW
python backend/scripts/emfirge-branch.py diff --branch-id BRANCH_ID
python backend/scripts/emfirge-branch.py list --analysis-id SCAN_ID
python backend/scripts/emfirge-branch.py capabilities
python backend/scripts/emfirge-branch.py verdict --branch-id BRANCH_ID
python backend/scripts/emfirge-branch.py rollback --branch-id BRANCH_ID --expected-count 1 --branch-revision REVISION_FROM_SHOW
python backend/scripts/emfirge-branch.py discard --branch-id BRANCH_ID --expected-count 1 --branch-revision REVISION_FROM_SHOW
python backend/scripts/emfirge-branch.py compare BRANCH_ID OTHER_BRANCH_ID
```

`rollback` undoes the most recent modeled change. It does not reset the whole branch. `iam_role_policy` supports `modify` only and requires `access_statements` to replace the complete normalized statement list for an existing collected role. `route_table` supports `modify` only and requires `routes` to replace the complete normalized route list for an existing collected route table; route-table associations remain derived from the collected snapshot. The backend models reachability consequences from the changed snapshot and does not predict whether a real deployment will cause an outage. All other resource and operation support follows the backend's current branch mutation API.

`GET /branches/capabilities` and the `capabilities` CLI command return the machine-readable contract used by backend validation. Resource entries list supported operations and special constraints; for example, `iam_role_policy` replaces the complete normalized `access_statements` list, while `route_table` replaces the complete normalized `routes` list. Treat this endpoint as authoritative when generating changes.

For concurrent agents, `apply`, `rollback`, `discard`, and `fork` may pass `--branch-revision` from `show` to reject any intervening history change, including rollback followed by another append that leaves the change count unchanged. These commands also retain their `--expected-count` support where applicable. A stale token returns HTTP 409. Omitting either option remains supported; `discard` still accepts no body.

The change response includes `modeled_state_unchanged`, comparing the rebuilt branch immediately before and after that proposed change. The `diff` and `verdict` responses expose the same field for the whole branch compared with its base. It is `true` only when the complete normalized infrastructure models are identical; `false` does not guarantee a graph, finding, or verdict change because some modeled fields may not appear in those views. A redundant change remains recorded in the branch history.

`GET /branches/{branch_id}` and `show` return branch metadata and the ordered normalized change log, including status and change count. They intentionally omit the full base infrastructure snapshot.

`POST /branches/{branch_id}/fork` and `fork` create a new open branch from an open parent, copying its immutable base snapshot and complete ordered change log. The child has an independent ID and can be edited without changing the parent. The fork operation is serialized against parent change-log writes and returns the child ID and copied change count.

## Local tests

From `backend/`, run `python -m pytest -q tests/test_branch_cli.py`. Tests use a temporary HTTP server bound to loopback and do not contact a hosted API or AWS.
