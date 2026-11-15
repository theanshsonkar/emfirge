"""Both engines behind the same plug: start, answer, stop, and leave no process behind. Lab only (local fakes)."""
from __future__ import annotations

import pytest

from emfirge.aws.accounts import sdk_client
from emfirge.aws.engines import EmulatorEngine, MotoEngine
from emfirge.core.ports import Engine

pytestmark = pytest.mark.lab


@pytest.mark.parametrize('make,port', [(EmulatorEngine, 9570), (MotoEngine, 9571)])
def test_an_engine_starts_answers_and_stops(make, port, tmp_path):
    engine = make(port, tmp_path)
    assert isinstance(engine, Engine)
    engine.start()
    try:
        s3 = sdk_client(engine, 's3', 'us-west-2')
        s3.create_bucket(Bucket='plug-test', CreateBucketConfiguration={'LocationConstraint': 'us-west-2'})
        assert [b['Name'] for b in s3.list_buckets()['Buckets']] == ['plug-test']
        assert sdk_client(engine, 'sts', 'us-west-2').get_caller_identity()['Account'] == '000000000000'
    finally:
        engine.stop()
    assert not engine._proc.running
