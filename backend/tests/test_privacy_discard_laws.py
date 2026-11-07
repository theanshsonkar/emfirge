"""L71b Discard really deletes: no branch row, plan receipt, evidence or policy check survives."""
import pytest

from app import database
from tests.laws.test_plan_receipt_laws import plan_client, _branch, _plan, _typed  # noqa: F401

BRANCH_TABLES = ("branch_logs", "branch_owners", "plan_logs", "branch_evidence_logs", "branch_policy_check_logs")


def _rows(factory, branch_id):
    D = database
    with factory() as db:
        return {
            "branch_logs": db.query(D.BranchLog).filter_by(branch_id=branch_id).count(),
            "branch_owners": db.query(D.BranchOwner).filter_by(branch_id=branch_id).count(),
            "plan_logs": db.query(D.PlanLog).filter_by(branch_id=branch_id).count(),
            "branch_evidence_logs": db.query(D.BranchEvidenceLog).filter_by(branch_id=branch_id).count(),
            "branch_policy_check_logs": db.query(D.BranchPolicyCheckLog).filter_by(branch_id=branch_id).count(),
        }


def _seed_children(factory, branch_id):
    with factory() as db:
        db.add(database.BranchOwner(branch_id=branch_id, project_id=1))
        db.add(database.BranchEvidenceLog(branch_id=branch_id, estimate_id="e"))
        db.add(database.BranchPolicyCheckLog(branch_id=branch_id, branch_revision="r", estimate_id="e"))
        db.commit()


def test_L71b_discard_deletes_branch_and_every_linked_row(plan_client):
    client, factory = plan_client
    keep = _branch(client, "keep")
    _plan(client, keep)
    _seed_children(factory, keep)
    gone = _branch(client, "gone")
    _plan(client, gone)
    _seed_children(factory, gone)
    assert all(v >= 1 for v in _rows(factory, gone).values())
    response = client.post(f"/branches/{gone}/discard", json={})
    assert response.status_code == 200, response.text
    assert response.json() == {"branch_id": gone, "status": "discarded"}
    assert _rows(factory, gone) == {t: 0 for t in BRANCH_TABLES}
    assert all(v >= 1 for v in _rows(factory, keep).values())
    assert client.get(f"/branches/{gone}").status_code == 404
    assert client.post(f"/branches/{gone}/discard", json={}).status_code == 404


def test_L71b_stale_guard_still_conflicts_and_deletes_nothing(plan_client):
    client, factory = plan_client
    bid = _branch(client)
    _typed(client, bid, 0)
    _seed_children(factory, bid)
    before = _rows(factory, bid)
    response = client.post(f"/branches/{bid}/discard", json={"expected_change_count": 0})
    assert response.status_code == 409
    assert _rows(factory, bid) == before
