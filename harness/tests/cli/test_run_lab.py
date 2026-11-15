"""`emf run` end to end on local fakes (lab only; never real AWS): a seeded emulator stands in for the real account,
a fresh engine runs the changes, and the command is a small boto3 script that knows nothing of Emfirge."""
from __future__ import annotations

import json
import sys
from pathlib import Path

import boto3
import botocore.config
import pytest

from emfirge.aws.engines import EmulatorEngine
from emfirge.cli.main import main

pytestmark = pytest.mark.lab
REAL, ENGINE, BRANCH = 9864, 9865, 9866
LOC = {'CreateBucketConfiguration': {'LocationConstraint': 'us-west-2'}}
TRUST = json.dumps({'Version': '2012-10-17', 'Statement': [{'Effect': 'Allow', 'Principal': {'Service': 'ec2.amazonaws.com'},
                                                            'Action': 'sts:AssumeRole'}]})


@pytest.fixture(scope='module')
def real(tmp_path_factory):
    emulator = EmulatorEngine(REAL, Path(tmp_path_factory.mktemp('real')))
    emulator.start()
    try:
        cfg = botocore.config.Config(retries={'max_attempts': 1}, s3={'addressing_style': 'path'})
        c = lambda s: boto3.client(s, endpoint_url=emulator.url, region_name='us-west-2', aws_access_key_id='x',
                                   aws_secret_access_key='x', verify=emulator.ca, config=cfg)
        c('s3').create_bucket(Bucket='run-data', **LOC)
        c('iam').create_role(RoleName='run-reader', AssumeRolePolicyDocument=TRUST)
        c('iam').put_role_policy(RoleName='run-reader', PolicyName='read', PolicyDocument=json.dumps({'Version': '2012-10-17',
            'Statement': [{'Effect': 'Allow', 'Action': 's3:GetObject', 'Resource': 'arn:aws:s3:::run-data/*'}]}))
        yield emulator, c
    finally:
        emulator.stop()


def fingerprint(c) -> dict:
    return {'buckets': sorted(b['Name'] for b in c('s3').list_buckets()['Buckets']),
            'roles': sorted(r['RoleName'] for r in c('iam').list_roles()['Roles']),
            'policy': c('iam').get_role_policy(RoleName='run-reader', PolicyName='read')['PolicyDocument']}


def emf(real, script: str, tmp_path: Path, *extra: str) -> tuple[int, str, dict]:
    emulator, _ = real
    report = tmp_path / 'report.json'
    path = tmp_path / 'script.py'
    path.write_text('import boto3, os, sys\n' + script)
    code = main(['run', '--real-endpoint', emulator.url, '--real-ca', emulator.ca, '--engine-port', str(ENGINE),
                 '--port', str(BRANCH), '--workdir', str(tmp_path / 'work'), '--report', str(report), *extra,
                 '--', sys.executable, str(path)])
    return code, '', json.loads(report.read_text()) if report.exists() else {}


def test_a_script_that_only_reads_is_go(real, tmp_path, capsys):
    before = fingerprint(real[1])
    code, _, report = emf(real, "print(len(boto3.client('s3').list_buckets()['Buckets']))", tmp_path)
    out = capsys.readouterr().out
    assert code == 0, out
    assert 'The agent changed nothing.' in out and 'Your account: 0 changing calls reached it.' in out
    assert report['verdict'] == 'go' and report['changes'] == []
    assert fingerprint(real[1]) == before


def test_deleting_a_bucket_a_role_reads_is_ask_and_names_the_role(real, tmp_path, capsys):
    before = fingerprint(real[1])
    code, _, report = emf(real, "boto3.client('s3').delete_bucket(Bucket='run-data')", tmp_path)
    out = capsys.readouterr().out
    assert code == 3, out
    assert 'iam:role/run-reader' in {a['ref'] for a in report['affected']}
    assert 'bucket run-data' in out and 'Deleted:' in out
    assert fingerprint(real[1]) == before


def test_a_failing_script_still_gets_its_report_and_64_plus_its_code(real, tmp_path, capsys):
    script = ("boto3.client('s3').create_bucket(Bucket='run-new', CreateBucketConfiguration={'LocationConstraint': 'us-west-2'})\n"
              "sys.exit(3)")
    before = fingerprint(real[1])
    code, _, report = emf(real, script, tmp_path)
    out = capsys.readouterr().out
    assert code == 67, out
    assert 'Your command failed (exit 3)' in out and 'bucket run-new' in out
    assert report['command_exit_code'] == 3
    assert fingerprint(real[1]) == before


def test_the_script_cannot_see_the_owners_keys(real, tmp_path, capsys, monkeypatch):
    owner_config = tmp_path / 'owner-config'
    owner_config.write_text('[profile owner]\nregion = us-west-2\n')
    monkeypatch.setenv('AWS_ACCESS_KEY_ID', 'OWNER-KEY')
    monkeypatch.setenv('AWS_PROFILE', 'owner')
    monkeypatch.setenv('AWS_CONFIG_FILE', str(owner_config))
    monkeypatch.setattr(boto3, 'DEFAULT_SESSION', None)   # boto3 keeps one per process; emf would start with a fresh one
    seen = tmp_path / 'env.json'
    script = (f"open({str(seen)!r}, 'w').write(__import__('json').dumps({{k: v for k, v in os.environ.items() "
              "if k.startswith('AWS_')}))")
    code, _, _ = emf(real, script, tmp_path)
    env = json.loads(seen.read_text())
    assert code == 0
    assert env['AWS_ACCESS_KEY_ID'] != 'OWNER-KEY' and 'AWS_PROFILE' not in env
    assert env['AWS_CONFIG_FILE'] != str(owner_config) and Path(env['AWS_CONFIG_FILE']).stat().st_size == 0
    assert env['AWS_ENDPOINT_URL'] == f'http://127.0.0.1:{BRANCH}'


def test_a_setting_put_back_on_the_branch_is_go_with_the_prover(real, tmp_path, capsys):
    """The undo prover runs by default: a tag on a role nothing names is proven undoable, so the verdict is go."""
    _, c = real
    c('iam').create_role(RoleName='run-lonely', AssumeRolePolicyDocument=TRUST)
    before = fingerprint(c)
    code, _, report = emf(real, "boto3.client('iam').tag_role(RoleName='run-lonely', Tags=[{'Key': 'team', 'Value': 'x'}])",
                          tmp_path)
    out = capsys.readouterr().out
    assert [u['undo']['undo'] for u in (x for x in report['changes'])] == ['yes'], out
    assert 'undo_and_proof' in report['seconds']
    assert code == 0, out
    assert fingerprint(c) == before


def test_without_the_prover_a_modified_setting_is_ask(real, tmp_path, capsys):
    code, _, report = emf(real, "boto3.client('iam').tag_role(RoleName='run-lonely', Tags=[{'Key': 'team', 'Value': 'y'}])",
                          tmp_path, '--no-prove-undo')
    assert code == 3
    assert 'undo-unknown' in {r['code'] for r in report['reasons']}
