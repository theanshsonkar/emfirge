import json
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app import branches, database, main, verdict
from app.aws_cli_ingest import parse_cli_commands
from app.models import AWSInfrastructure, SecurityGroup
from tests.incidents.synthetic_base import load_synthetic_base

@pytest.fixture
def client(monkeypatch, tmp_path):
    engine = create_engine(f"sqlite:///{tmp_path / 'mcp.sqlite'}")
    database.Base.metadata.create_all(engine)
    factory = sessionmaker(bind=engine)
    monkeypatch.setattr(database, "SessionLocal", factory)
    monkeypatch.setattr(branches, "SessionLocal", factory)
    monkeypatch.setattr(main, "get_infrastructure_for_analysis", lambda _id: load_synthetic_base("delete"))
    main._branch_request_log.clear()
    for name in ("run_checkov", "run_trivy", "run_cloudsplaining"):
        monkeypatch.setattr(verdict, name, lambda *_a, **_k: {"available": False, "findings": []})
    main.app.dependency_overrides[main.require_api_key] = lambda: None
    yield TestClient(main.app)
    main.app.dependency_overrides.pop(main.require_api_key, None)
    database.Base.metadata.drop_all(engine)
    engine.dispose()

def branch(client, name="x"):
    r = client.post("/branches", json={"base_analysis_id": "synthetic", "name": name})
    assert r.status_code == 200, r.text
    return r.json()["branch_id"]

def test_target_not_found_names_id(client):
    bid = branch(client)
    r = client.post(f"/branches/{bid}/changes", json={"op":"modify", "resource_type":"security_group", "resource_id":"sg-doesnotexist", "fields":{"name":"x"}})
    assert r.status_code == 422
    assert r.json()["detail"] == "Target not found: security_group"
    assert "sg-doesnotexist" not in r.text

def test_cli_shorthand_matches_json():
    shorthand = parse_cli_commands({"format":"aws-cli/1", "commands":["aws ec2 authorize-security-group-ingress --group-id sg-1 --protocol tcp --port 22 --cidr 0.0.0.0/0"]})
    explicit = parse_cli_commands({"format":"aws-cli/1", "commands":["aws ec2 authorize-security-group-ingress --group-id sg-1 --ip-permissions '[{\"IpProtocol\":\"tcp\",\"FromPort\":22,\"ToPort\":22,\"IpRanges\":[{\"CidrIp\":\"0.0.0.0/0\"}]}]'"]})
    assert shorthand == explicit

@pytest.mark.parametrize("command, message", [
    ("aws ec2 authorize-security-group-ingress --group-id sg-1 --port 22 --cidr 0.0.0.0/0", "--protocol is required"),
    ("aws ec2 authorize-security-group-ingress --group-id sg-1 --protocol tcp --port bad --cidr 0.0.0.0/0", "invalid --port bad"),
    ("aws ec2 authorize-security-group-ingress --group-id sg-1 --protocol tcp --port 22", "give exactly one"),
    ("aws ec2 authorize-security-group-ingress --group-id sg-1 --protocol tcp --cidr 2001:db8::/64", "IPv4 CIDR"),
])
def test_cli_shorthand_errors(command, message):
    with pytest.raises(ValueError, match=message):
        parse_cli_commands({"format":"aws-cli/1", "commands":[command]})

def test_cli_shorthand_ports_and_source_group():
    calls = parse_cli_commands({"format":"aws-cli/1", "commands":["aws ec2 authorize-security-group-ingress --group-id sg-1 --protocol tcp --port 8000-8080 --source-group sg-2"]})["calls"]
    assert calls[0]["parameters"]["IpPermissions"] == [{"IpProtocol":"tcp","FromPort":8000,"ToPort":8080,"UserIdGroupPairs":[{"GroupId":"sg-2"}]}]
    all_ports = parse_cli_commands({"format":"aws-cli/1", "commands":["aws ec2 authorize-security-group-ingress --group-id sg-1 --protocol all --cidr 0.0.0.0/0"]})["calls"][0]["parameters"]["IpPermissions"][0]
    assert all_ports == {"IpProtocol":"-1","IpRanges":[{"CidrIp":"0.0.0.0/0"}]}
    icmp = parse_cli_commands({"format":"aws-cli/1", "commands":["aws ec2 authorize-security-group-ingress --group-id sg-1 --protocol icmp --port -1 --cidr 0.0.0.0/0"]})["calls"][0]["parameters"]["IpPermissions"][0]
    assert icmp["FromPort"] == icmp["ToPort"] == -1

def test_egress_protocol_remains_unknown_option():
    with pytest.raises(ValueError, match="unknown option --protocol"):
        parse_cli_commands({"format":"aws-cli/1", "commands":["aws ec2 authorize-security-group-egress --group-id sg-1 --protocol tcp"]})

def test_branch_cap_and_discarded_status(client, monkeypatch):
    monkeypatch.setattr(branches, "MAX_OPEN_BRANCHES_PER_BASE", 2)
    first, second = branch(client, "a"), branch(client, "b")
    third = client.post("/branches", json={"base_analysis_id":"synthetic","name":"c"})
    assert third.status_code == 429
    assert "Discard branches" in third.json()["detail"]
    assert client.post(f"/branches/{first}/discard").status_code == 200
    for endpoint in ("verdict", "diff"):
        response = client.get(f"/branches/{first}/{endpoint}")
        assert response.status_code == 200
        assert response.json()["status"] == "discarded"
    assert client.get(f"/branches/{second}/verdict").json()["status"] == "open"

def test_rate_limit_headers(client, monkeypatch):
    monkeypatch.setenv("EMFIRGE_BRANCH_RATE_LIMIT", "3")
    main._branch_request_log.clear()
    for _ in range(3):
        assert client.post("/branches", json={"base_analysis_id":"synthetic","name":"rate"}).status_code == 200
    response = client.post("/branches", json={"base_analysis_id":"synthetic","name":"rate"})
    assert response.status_code == 429
    assert 1 <= int(response.headers["Retry-After"]) <= 60
    assert "Retry in" in response.json()["detail"]
