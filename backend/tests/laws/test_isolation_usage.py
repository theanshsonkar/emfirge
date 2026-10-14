from app import database

from .test_tenant_isolation import tenant_client


ACCOUNT_A = '111111111111'


def _seed_usage():
    database.save_analysis({
        'aws_account_id': ACCOUNT_A,
        'findings_json': {'analysis_id': 'usage-law-a'},
    })
    database.save_simulation_log(ACCOUNT_A, 'usage-law-a', 'seed usage')


def test_usage_remaining_hides_other_tenant_usage(tenant_client):
    client, key_a, key_b, _ = tenant_client
    _seed_usage()
    headers_a = {'X-API-Key': key_a}
    headers_b = {'X-API-Key': key_b}

    own = client.get(f'/usage/remaining?account_id={ACCOUNT_A}', headers=headers_a)
    hidden = client.get(f'/usage/remaining?account_id={ACCOUNT_A}', headers=headers_b)
    never_seen = client.get('/usage/remaining?account_id=999999999999', headers=headers_b)

    assert own.status_code == 200
    assert own.json()['scans']['used'] > 0
    assert own.json()['simulations']['used'] > 0
    assert hidden.status_code == never_seen.status_code == 200
    assert hidden.json() == never_seen.json()
    assert hidden.json()['scans']['used'] == 0
    assert hidden.json()['simulations']['used'] == 0


def test_simulate_remaining_hides_other_tenant_usage(tenant_client):
    client, key_a, key_b, _ = tenant_client
    _seed_usage()
    headers_a = {'X-API-Key': key_a}
    headers_b = {'X-API-Key': key_b}

    own = client.get('/simulate/remaining?analysis_id=usage-law-a', headers=headers_a)
    hidden = client.get('/simulate/remaining?analysis_id=usage-law-a', headers=headers_b)
    never_seen = client.get('/simulate/remaining?analysis_id=never-seen', headers=headers_b)

    assert own.status_code == 200
    assert own.json()['used'] > 0
    assert hidden.status_code == never_seen.status_code == 200
    assert hidden.json() == never_seen.json()
    assert hidden.json()['used'] == 0
