import json

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app import branches, database
from app.demo_seed import build_demo_infrastructure
from app.egraph import build_graph
from app.graph_schema import GRAPH_SCHEMA_VERSION
from app.models import AWSInfrastructure


@pytest.fixture
def branch_db(monkeypatch, tmp_path):
    engine = create_engine(f"sqlite:///{tmp_path / 'branches.db'}")
    database.Base.metadata.create_all(engine)
    factory = sessionmaker(bind=engine)
    monkeypatch.setattr(database, "SessionLocal", factory)
    monkeypatch.setattr(branches, "SessionLocal", factory)
    yield factory
    database.Base.metadata.drop_all(engine)
    engine.dispose()


def test_L28a_graph_to_dict_carries_schema_version():
    graph = build_graph(build_demo_infrastructure())

    assert graph.to_dict()["schema_version"] == GRAPH_SCHEMA_VERSION
    assert isinstance(graph.to_dict()["schema_version"], int)


def test_L28b_branch_snapshot_versions_are_written_and_decoded(branch_db):
    branch_id = branches.create_branch(AWSInfrastructure(region="us-east-1"), "versioned")
    with branch_db() as session:
        row = session.query(database.BranchLog).filter_by(branch_id=branch_id).one()
        stored = json.loads(row.base_infra_json)
        assert stored["schema_version"] == GRAPH_SCHEMA_VERSION

        stored.pop("schema_version")
        row.base_infra_json = json.dumps(stored, sort_keys=True, separators=(",", ":"))
        session.commit()

    assert branches.get_branch(branch_id).base.region == "us-east-1"

    with branch_db() as session:
        row = session.query(database.BranchLog).filter_by(branch_id=branch_id).one()
        future = json.loads(row.base_infra_json)
        future["schema_version"] = GRAPH_SCHEMA_VERSION + 1
        row.base_infra_json = json.dumps(future, sort_keys=True, separators=(",", ":"))
        session.commit()

    with pytest.raises(ValueError, match=rf"{GRAPH_SCHEMA_VERSION + 1}.*{GRAPH_SCHEMA_VERSION}"):
        branches.get_branch(branch_id)


def test_L28c_graph_to_dict_only_adds_schema_version():
    graph = build_graph(build_demo_infrastructure())
    output = graph.to_dict()
    without_version = dict(output)
    without_version.pop("schema_version")

    assert set(without_version) == {"nodes", "edges"}
    assert without_version["nodes"] == output["nodes"]
    assert without_version["edges"] == output["edges"]
