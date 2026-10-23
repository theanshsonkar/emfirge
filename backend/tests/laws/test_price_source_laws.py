"""L59 prices from AWS's published price list: cost.py reads vendored Price List Bulk API data, never hand-typed numbers."""
import ast
import json
from pathlib import Path

import pytest

import app.cost as cost
from app.cost import HOURS_PER_MONTH, estimate_monthly_cost
from app.models import (
    AWSInfrastructure, EBSVolume, EC2Data, EC2Instance, LoadBalancer, VPCData,
)

PRICES = Path(cost.__file__).resolve().parent / "data" / "aws_prices.json"
REGION = "us-east-1"

HAND_TYPED_TYPES = [
    "t3.nano", "t3.micro", "t3.small", "t3.medium", "t3.large", "t3.xlarge", "t3.2xlarge",
    "m5.large", "m5.xlarge", "m5.2xlarge", "m5.4xlarge", "m5.12xlarge", "m5.24xlarge",
    "c5.large", "c5.xlarge", "c5.2xlarge", "c5.4xlarge", "c5.9xlarge", "c5.18xlarge",
]


def data():
    return json.loads(PRICES.read_text())["regions"][REGION]


def infra():
    return AWSInfrastructure(
        region=REGION,
        ec2=EC2Data(
            instances=[EC2Instance(id="i-1", type="m5.large", state="running")],
            ebs_volumes=[EBSVolume(id="vol-1", size_gb=10, volume_type="gp3", state="available")],
            load_balancers=[LoadBalancer(arn="arn:lb", name="lb", type="application")],
        ),
        vpc=VPCData(nat_gateways=["nat-1"]),
    )


def total(estimate):
    keep = {"ec2_instance", "nat_gateway", "load_balancer", "ebs_volume"}
    return {item.resource_type: item.monthly_usd for item in estimate.resources if item.resource_type in keep}


def test_L59a_price_file_names_source_publication_date_and_region():
    doc = json.loads(PRICES.read_text())
    assert doc["generated_at"] and doc["price_list_index"].startswith("https://pricing.")
    region = doc["regions"][REGION]
    for offer in ("AmazonEC2", "AWSELB"):
        src = region["sources"][offer]
        assert src["url"].startswith("https://pricing.us-east-1.amazonaws.com/offers/v1.0/aws/")
        assert REGION in src["url"]
        assert src["publication_date"] and src["version"]
    assert cost.PRICE_TABLE_REGION == REGION
    assert cost.PRICE_TABLE_AS_OF == region["sources"]["AmazonEC2"]["publication_date"][:10]


def test_L59b_every_price_cost_py_uses_comes_from_the_json(monkeypatch):
    # No float literals may remain in cost.py.
    tree = ast.parse(Path(cost.__file__).read_text())
    floats = [n.value for n in ast.walk(tree) if isinstance(n, ast.Constant) and isinstance(n.value, float) and n.value != 0.0]
    assert floats == []
    # Loaded values equal the JSON, and changing the loaded data changes the estimate.
    d = data()
    assert cost.EC2_HOURLY_USD == d["ec2_hourly_usd"]
    assert cost.NAT_GATEWAY_HOURLY_USD == d["nat_gateway_hourly_usd"]
    assert cost.ALB_HOURLY_USD == d["alb_hourly_usd"]
    assert cost.EBS_GB_MONTH_USD == d["ebs_gb_month_usd"]
    base = total(estimate_monthly_cost(infra()))
    assert base["ec2_instance"] == round(d["ec2_hourly_usd"]["m5.large"] * HOURS_PER_MONTH, 2)
    assert base["nat_gateway"] == round(d["nat_gateway_hourly_usd"] * HOURS_PER_MONTH, 2)
    assert base["load_balancer"] == round(d["alb_hourly_usd"] * HOURS_PER_MONTH, 2)
    assert base["ebs_volume"] == round(10 * d["ebs_gb_month_usd"]["gp3"], 2)
    monkeypatch.setattr(cost, "EC2_HOURLY_USD", {"m5.large": 1.0})
    monkeypatch.setattr(cost, "NAT_GATEWAY_HOURLY_USD", 2.0)
    monkeypatch.setattr(cost, "ALB_HOURLY_USD", 3.0)
    monkeypatch.setattr(cost, "EBS_GB_MONTH_USD", {"gp3": 4.0})
    patched = total(estimate_monthly_cost(infra()))
    assert patched == {
        "ec2_instance": round(1.0 * HOURS_PER_MONTH, 2),
        "nat_gateway": round(2.0 * HOURS_PER_MONTH, 2),
        "load_balancer": round(3.0 * HOURS_PER_MONTH, 2),
        "ebs_volume": 40.0,
    }


def test_L59c_all_prices_are_positive_floats():
    d = data()
    values = [d["nat_gateway_hourly_usd"], d["alb_hourly_usd"],
              *d["ec2_hourly_usd"].values(), *d["ebs_gb_month_usd"].values()]
    assert len(d["ec2_hourly_usd"]) > 100
    assert {"gp2", "gp3", "io1", "io2", "st1", "sc1", "standard"} <= set(d["ebs_gb_month_usd"])
    assert all(isinstance(v, float) and v > 0 for v in values)


def test_L59d_previously_hand_typed_instance_types_are_present():
    assert set(HAND_TYPED_TYPES) <= set(data()["ec2_hourly_usd"])


def test_L59e_unknown_instance_type_stays_price_unavailable():
    unknown = AWSInfrastructure(region=REGION, ec2=EC2Data(
        instances=[EC2Instance(id="i-x", type="zz9.nonexistent", state="running")],
        ebs_volumes=[EBSVolume(id="vol-x", size_gb=10, volume_type="nosuchtype", state="available")],
    ))
    estimate = estimate_monthly_cost(unknown)
    assert all(item.monthly_usd is None and item.basis == "price-unavailable" for item in estimate.resources)
    assert estimate.unknown_count == 2
