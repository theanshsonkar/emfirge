"""`emf`: arguments, exit 2 when Emfirge fails, the client environment guard, outside tools from the command line.
Pure: nothing is started here (the lab test runs `emf run` end to end)."""
from __future__ import annotations

import pytest

from emfirge.aws.session import NoRealAccount, Options, client_env, real_account
from emfirge.aws.codec import AwsCodec
from emfirge.cli import main as cli
from emfirge.session.outside import outside_lens, whole_records


def test_a_real_account_must_be_chosen(capsys):
    with pytest.raises(SystemExit) as e:
        cli.main(['run', '--', 'true'])
    assert e.value.code == 2


def test_real_endpoint_and_real_aws_cannot_both_be_given():
    with pytest.raises(SystemExit) as e:
        cli.main(['run', '--real-endpoint', 'https://127.0.0.1:1', '--real-aws', '--', 'true'])
    assert e.value.code == 2


def test_nothing_reaches_aws_by_default(tmp_path):
    with pytest.raises(NoRealAccount):
        real_account(Options(workdir=tmp_path), AwsCodec())


def test_a_failure_of_emfirge_is_exit_2(monkeypatch, capsys):
    def broken(options, admin=()):
        raise RuntimeError('the engine did not start')
    monkeypatch.setattr(cli, 'open_bench', broken)
    assert cli.main(['run', '--real-endpoint', 'https://127.0.0.1:1', '--', 'true']) == 2
    assert 'Emfirge failed: RuntimeError: the engine did not start' in capsys.readouterr().err


def test_no_command_is_exit_2(capsys):
    assert cli.main(['run', '--real-endpoint', 'https://127.0.0.1:1']) == 2


def test_the_options_reach_the_wiring(monkeypatch):
    seen = {}

    def capture(options, admin=()):
        seen['options'] = options
        raise RuntimeError('stop here')
    monkeypatch.setattr(cli, 'open_bench', capture)
    cli.main(['run', '--real-endpoint', 'https://127.0.0.1:1', '--real-ca', '/ca.pem', '--engine', 'moto', '--budget', '50',
              '--lens', 'scan=scanner --json', '--prove-undo', '--', 'true'])
    o = seen['options']
    assert (o.real_endpoint, o.real_ca, o.engine, o.budget, o.real_aws, o.prove_undo) == \
        ('https://127.0.0.1:1', '/ca.pem', 'moto', 50, False, True)
    assert o.outside[0].name == 'scan' and tuple(o.outside[0].command) == ('scanner', '--json')


def test_the_client_can_reach_only_the_branch(tmp_path):
    base = {'PATH': '/bin', 'AWS_PROFILE': 'owner', 'AWS_ACCESS_KEY_ID': 'REAL', 'AWS_SECRET_ACCESS_KEY': 'REAL',
            'AWS_SESSION_TOKEN': 'REAL', 'AWS_SHARED_CREDENTIALS_FILE': '/home/owner/.aws/credentials',
            'AWS_CONFIG_FILE': '/home/owner/.aws/config', 'AWS_ENDPOINT_URL_S3': 'https://s3.example',
            'AWS_CONTAINER_CREDENTIALS_FULL_URI': 'http://169.254.170.2/x', 'AWS_REGION': 'eu-west-1',
            'aws_profile': 'owner', 'NO_PROXY': 'internal'}
    env = client_env(base, 'http://127.0.0.1:9999', 'us-west-2', tmp_path)
    assert env['AWS_ENDPOINT_URL'] == 'http://127.0.0.1:9999'
    assert env['AWS_ACCESS_KEY_ID'] == env['AWS_SECRET_ACCESS_KEY'] != 'REAL'
    assert env['AWS_REGION'] == env['AWS_DEFAULT_REGION'] == 'eu-west-1'
    for k in ('AWS_PROFILE', 'AWS_SESSION_TOKEN', 'AWS_ENDPOINT_URL_S3', 'AWS_CONTAINER_CREDENTIALS_FULL_URI', 'aws_profile'):
        assert k not in env
    for k in ('AWS_SHARED_CREDENTIALS_FILE', 'AWS_CONFIG_FILE'):
        assert (tmp_path / 'aws-empty').samefile(env[k]) and (tmp_path / 'aws-empty').read_text() == ''
    assert env['AWS_EC2_METADATA_DISABLED'] == 'true'
    assert env['NO_PROXY'] == 'internal,127.0.0.1,localhost'
    assert env['PATH'] == '/bin'


def test_an_outside_tool_spec_needs_a_name_and_a_command():
    for bad in ('scanner', '=scanner', 'scan='):
        with pytest.raises(ValueError):
            outside_lens(bad)


def test_outside_records_are_findings_by_their_whole_content():
    out = whole_records('{"id": 1, "message": "bucket is public"}\n{"id": 2}\n')
    assert list(out.values()) == ['bucket is public', '{"id": 2}']
    assert whole_records('[{"a": 1}]') == {'{"a": 1}': '{"a": 1}'}
    with pytest.raises(ValueError):
        whole_records('not json')
