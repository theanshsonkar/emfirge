"""Example: Prowler as an Emfirge lens, with no code of ours for Prowler. Not part of the package; not run by the tests.

Prowler writes its findings to a file in OCSF JSON (one array of records). Experiment 04 ran it unmodified before and
after a risky change on an emulated account and kept the records with status_code FAIL, keyed by the check
(metadata.event_code) and the resource (resources[0].uid): 8 new failures. The same, as an ExternalLens:

    from emfirge.lenses import LensView, run_lenses
    lens = prowler_lens()
    result = run_lenses([lens], LensView(changes, before_endpoint=REAL_READONLY_URL, after_endpoint=BRANCH_URL,
                                         env={'PATH': ..., 'AWS_ACCESS_KEY_ID': ..., 'AWS_SECRET_ACCESS_KEY': ...,
                                              'AWS_DEFAULT_REGION': ...}))

ExternalLens sets AWS_ENDPOINT_URL per run; both runs go in parallel. Prowler exits 3 when it found failures, so 3
counts as 'ran'.
"""
from __future__ import annotations

from emfirge.lenses import ExternalLens, json_records

# Prowler writes to a directory; the shell prints the file so the lens reads it from standard output. Each run gets
# its own directory (both runs are in parallel), named after the endpoint it reads.
_COMMAND = (
    'sh', '-c',
    'd=$(mktemp -d) && prowler aws --services s3 iam awslambda dynamodb --output-formats json-ocsf '
    '--output-directory "$d" --output-filename scan --no-banner --ignore-exit-code-3 >"$d/log" 2>&1; '
    'cat "$d/scan.ocsf.json"',
)


def prowler_lens(timeout: float = 600.0) -> ExternalLens:
    return ExternalLens(
        name='prowler',
        command=_COMMAND,
        parser=json_records(('metadata.event_code', 'resources.0.uid'), message_field='status_detail',
                            where={'status_code': 'FAIL'}),
        timeout=timeout,
        ok_exit_codes=frozenset({0, 3}),
    )
