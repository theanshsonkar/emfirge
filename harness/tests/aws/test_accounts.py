"""SDK clients over an Account do not depend on the owner's AWS settings. No network."""
from __future__ import annotations

from emfirge.aws.accounts import sdk_client
from emfirge.core.model import WireRequest, WireResponse


class Answering:
    name = 'fake'

    def __init__(self) -> None:
        self.seen: list[WireRequest] = []

    def send(self, request: WireRequest) -> WireResponse:
        self.seen.append(request)
        return WireResponse(200, {'content-type': 'application/x-amz-json-1.0'}, b'{"TableNames": ["t"]}')


def test_a_missing_profile_and_broken_config_files_change_nothing(monkeypatch, tmp_path):
    bad = tmp_path / 'config'
    bad.write_text('[profile nope\nthis is not ini')
    monkeypatch.setenv('AWS_PROFILE', 'no-such-profile')
    monkeypatch.setenv('AWS_CONFIG_FILE', str(bad))
    monkeypatch.setenv('AWS_SHARED_CREDENTIALS_FILE', str(bad))
    account = Answering()
    assert sdk_client(account, 'dynamodb', 'us-west-2').list_tables()['TableNames'] == ['t']
    assert 'Credential=emfirge/' in account.seen[0].headers['Authorization']
