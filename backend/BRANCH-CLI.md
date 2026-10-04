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
  --resource-id SG_ID --expected-count 0 --fields-json '{"rules": []}'

# For larger changes, pass a JSON file or pipe JSON on stdin with --fields-file -.
python backend/scripts/emfirge-branch.py apply \
  --branch-id BRANCH_ID --op modify --resource-type iam_role_policy \
  --resource-id ROLE_ARN --fields-file policy-statements.json

python backend/scripts/emfirge-branch.py diff --branch-id BRANCH_ID
python backend/scripts/emfirge-branch.py list --analysis-id SCAN_ID
python backend/scripts/emfirge-branch.py capabilities
python backend/scripts/emfirge-branch.py verdict --branch-id BRANCH_ID
python backend/scripts/emfirge-branch.py rollback --branch-id BRANCH_ID --expected-count 1
python backend/scripts/emfirge-branch.py compare BRANCH_ID OTHER_BRANCH_ID
```

`rollback` undoes the most recent modeled change. It does not reset the whole branch. `iam_role_policy` currently supports `modify` only and requires `access_statements` to replace the complete normalized statement list for an existing collected role. The backend verdict reports IAM modeling limits. All other resource and operation support follows the backend's current branch mutation API.

`GET /branches/capabilities` and the `capabilities` CLI command return the machine-readable contract used by backend validation. Resource entries list supported operations and special constraints; for example, `iam_role_policy` supports only `modify`, replacing the complete normalized `access_statements` list for one existing role identified by role ARN. Treat this endpoint as authoritative when generating changes.

For concurrent agents, pass `--expected-count` on both `apply` and `rollback`, using the most recent branch change response or the `num_changes` field returned by `list`. A stale count returns HTTP 409; reload the branch before retrying. Omitting this option remains supported for single-agent workflows.

The change response includes `modeled_state_unchanged`, comparing the rebuilt branch immediately before and after that proposed change. The `diff` and `verdict` responses expose the same field for the whole branch compared with its base. It is `true` only when the complete normalized infrastructure models are identical; `false` does not guarantee a graph, finding, or verdict change because some modeled fields may not appear in those views. A redundant change remains recorded in the branch history.

## Local tests

From `backend/`, run `python -m pytest -q tests/test_branch_cli.py`. Tests use a temporary HTTP server bound to loopback and do not contact a hosted API or AWS.
