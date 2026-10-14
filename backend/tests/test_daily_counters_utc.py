import os
import time

import pytest

from app import database


ACCOUNT_ID = '111111111111'


@pytest.fixture(params=['Asia/Kolkata', 'Pacific/Kiritimati', 'Pacific/Pago_Pago'])
def local_timezone(request):
    previous_tz = os.environ.get('TZ')
    os.environ['TZ'] = request.param
    time.tzset()
    yield request.param
    if previous_tz is None:
        os.environ.pop('TZ', None)
    else:
        os.environ['TZ'] = previous_tz
    time.tzset()


def test_daily_counters_use_utc_date(shared_test_db, local_timezone):
    analysis_id = database.save_analysis({
        'aws_account_id': ACCOUNT_ID,
        'findings_json': {'analysis_id': 'utc-counter-test'},
    })
    database.save_simulation_log(ACCOUNT_ID, str(analysis_id), 'seed simulation')
    database.save_llm_usage(ACCOUNT_ID, 'insight')

    assert database.get_scan_count_today(ACCOUNT_ID) == 1
    assert database.get_simulation_count_today(ACCOUNT_ID) == 1
    assert database.get_llm_usage_count_today(ACCOUNT_ID, 'insight') == 1
