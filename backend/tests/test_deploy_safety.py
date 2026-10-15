from pathlib import Path

from fastapi.testclient import TestClient

from app import auth
from app.auth import hash_key
from app.database import APIKey, Project
from app.main import app


client = TestClient(app)


def test_old_key_gets_project_at_startup(shared_test_db, monkeypatch):
    raw_key = 'emf_synthetic_legacy_key'
    session = shared_test_db()
    session.add(APIKey(key_hash=hash_key(raw_key), project_name='legacy-proj'))
    session.commit()
    session.close()

    assert auth.backfill_legacy_key_projects(shared_test_db) == 1

    session = shared_test_db()
    projects = session.query(Project).filter_by(name='legacy-proj').all()
    assert len(projects) == 1
    external_id = projects[0].external_id
    assert external_id
    session.close()

    monkeypatch.setattr(auth, 'AUTH_ENABLED', True)
    response = client.get('/project', headers={'X-API-Key': raw_key})
    assert response.status_code == 200
    assert response.json()['external_id'] == external_id


def test_backfill_is_idempotent_and_keeps_external_id(shared_test_db):
    session = shared_test_db()
    session.add_all([
        APIKey(key_hash=hash_key('emf_first'), project_name='first-project'),
        APIKey(key_hash=hash_key('emf_second'), project_name='second-project'),
        Project(name='existing-project', external_id='existing-external-id'),
        APIKey(key_hash=hash_key('emf_existing'), project_name='existing-project'),
    ])
    session.commit()
    session.close()

    assert auth.backfill_legacy_key_projects(shared_test_db) == 2
    session = shared_test_db()
    count_after_first = session.query(Project).count()
    existing_external_id = session.query(Project).filter_by(name='existing-project').one().external_id
    session.close()

    assert auth.backfill_legacy_key_projects(shared_test_db) == 0
    session = shared_test_db()
    assert session.query(Project).count() == count_after_first
    assert session.query(Project).filter_by(name='existing-project').one().external_id == existing_external_id
    session.close()


def test_backfill_skips_blank_project_names(shared_test_db):
    session = shared_test_db()
    session.add_all([
        APIKey(key_hash=hash_key('emf_blank'), project_name=''),
        APIKey(key_hash=hash_key('emf_whitespace'), project_name='   '),
    ])
    session.commit()
    session.close()

    assert auth.backfill_legacy_key_projects(shared_test_db) == 0


def test_startup_reports_auth_state(shared_test_db, monkeypatch, capsys):
    monkeypatch.setattr('app.main.backfill_legacy_key_projects', lambda: 0)
    for enabled, state in ((True, 'ON'), (False, 'OFF')):
        monkeypatch.setattr(auth, 'AUTH_ENABLED', enabled)
        app_report = __import__('app.main', fromlist=['report_startup'])
        app_report.report_startup()
        output = capsys.readouterr().out
        assert f'emfirge: auth is {state}' in output
        assert 'emfirge: linked 0 legacy API key project(s)' in output
        assert 'hash' not in output.lower()
        assert 'external_id' not in output


def test_deploy_workflow_forces_auth():
    workflow = (Path(__file__).parents[2] / '.github' / 'workflows' / 'deploy.yml').read_text()
    docker_run = workflow[workflow.index('sudo docker run'):]
    env_file = docker_run.index('--env-file /home/ubuntu/.env')
    forced_auth = docker_run.index('-e EMFIRGE_REQUIRE_AUTH=1')
    image = docker_run.index('${{ secrets.DOCKERHUB_USERNAME }}/aws-risk-agent:latest')
    assert env_file < forced_auth < image
