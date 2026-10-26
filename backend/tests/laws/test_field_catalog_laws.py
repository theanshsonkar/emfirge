"""L54 schema-driven field catalog: every settable field traced to AWS's API model."""
import typing

import botocore
import pytest

from app import field_catalog
from app.field_catalog import CATALOG, IDENTITY_FIELDS, Aws, Derived, resolve, validate_fields
from app.mutations import _MUTATION_CAPABILITIES, Change, apply_change
from tests.incidents.synthetic_base import load_synthetic_base

_MODEL_LESS = {"iam_role": {"trust_policy"}, "iam_role_policy": {"access_statements", "policy_documents"},
               "iam_instance_profile": {"role_arn"}}


def _settable_types():
    return sorted(t for t, cap in _MUTATION_CAPABILITIES.items() if cap["operations"] & {"add", "modify"})


@pytest.mark.parametrize("resource_type", _settable_types())
def test_L54a_every_field_of_every_settable_type_is_catalogued(resource_type):
    model = _MUTATION_CAPABILITIES[resource_type]["model"]
    if model is None:
        fields = _MODEL_LESS[resource_type]
    else:
        fields = set(model.model_fields) - {IDENTITY_FIELDS.get(resource_type, "id")}
    catalogued = set(CATALOG[resource_type])
    assert fields - catalogued == set(), f"add these {resource_type} fields to app/field_catalog.py"
    assert catalogued - fields == set(), f"stale catalog entries for {resource_type}"


_JSON_KIND = {str: "string", int: "integer", bool: "boolean"}


def _python_kind(annotation):
    args = [a for a in typing.get_args(annotation) if a is not type(None)]
    if typing.get_origin(annotation) in (list, typing.List):
        return "list"
    if typing.get_origin(annotation) is typing.Literal:
        return "string" if all(isinstance(value, str) for value in typing.get_args(annotation)) else None
    if args and typing.get_origin(annotation) is typing.Union:
        return _python_kind(args[0])
    return _JSON_KIND.get(annotation)


@pytest.mark.parametrize("resource_type,field,source", [
    (t, f, s) for t, fields in sorted(CATALOG.items()) for f, s in sorted(fields.items()) if isinstance(s, Aws)])
def test_L54b_every_aws_source_exists_in_the_aws_model_with_a_matching_type(resource_type, field, source):
    shape = resolve(source)
    model = _MUTATION_CAPABILITIES[resource_type]["model"]
    if model is not None:
        kind = _python_kind(model.model_fields[field].annotation)
        assert kind == shape.type_name, (resource_type, field, kind, shape.type_name)


def test_L54c_instance_types_are_exactly_the_ones_aws_publishes():
    enum = resolve(CATALOG["ec2_instance"]["type"]).enum
    assert "t3.micro" in enum and len(enum) > 100
    for instance_type in enum:
        validate_fields("ec2_instance", {"type": instance_type})
    base = load_synthetic_base("delete")
    with pytest.raises(ValueError, match="RunInstances InstanceType"):
        apply_change(base, Change(op="modify", resource_type="ec2_instance", resource_id="i-dl-web", fields={"type": "t3.mega"}))


def test_L54c_volume_types_come_from_aws_not_a_hand_table():
    enum = set(resolve(CATALOG["ebs_volume"]["volume_type"]).enum)
    base = load_synthetic_base("delete")
    accepted = set()
    for volume_type in sorted(enum | {"gp9", "GP3"}):
        try:
            apply_change(base, Change(op="add", resource_type="ebs_volume", resource_id=f"vol-{volume_type}",
                                      fields={"availability_zone": "ap-south-1a", "size_gb": 125, "volume_type": volume_type}))
            accepted.add(volume_type)
        except ValueError:
            pass
    assert accepted == enum


@pytest.mark.parametrize("resource_type,ident,fields", [
    ("lambda_function", "dl-worker", {"role_arn": "not-an-arn"}),
    ("lambda_function", "dl-worker", {"role_arn": "arn:aws:iam::000000000000:user/Someone"}),
    ("nat_gateway", "", {"subnet_id": "subnet-dl-pub", "connectivity_type": "Public"}),
    ("ec2_instance", "i-dl-web", {"state": "sleeping"}),
    ("s3_bucket", "dl-data-bucket", {"block_public_policy": "yes"}),
])
def test_L54d_values_aws_would_reject_are_rejected(resource_type, ident, fields):
    op = "add" if resource_type == "nat_gateway" else "modify"
    with pytest.raises(ValueError):
        apply_change(load_synthetic_base("delete"), Change(op=op, resource_type=resource_type, resource_id=ident, fields=fields))


def test_L54d_values_aws_accepts_still_pass():
    base = load_synthetic_base("delete")
    apply_change(base, Change(op="modify", resource_type="lambda_function", resource_id="dl-worker",
                              fields={"role_arn": "arn:aws:iam::000000000000:role/service-role/DlWorkerRole"}))
    apply_change(base, Change(op="modify", resource_type="ec2_instance", resource_id="i-dl-web", fields={"type": "m7i-flex.large"}))


@pytest.mark.parametrize("resource_type,field", [
    (t, f) for t, fields in sorted(CATALOG.items()) for f, s in sorted(fields.items()) if isinstance(s, Derived)])
def test_L54e_derived_fields_cannot_be_set(resource_type, field):
    # Rejected whatever the value.
    with pytest.raises(ValueError, match="derived"):
        validate_fields(resource_type, {field: "x"})


def test_L54f_catalog_is_served_with_its_aws_provenance(monkeypatch):
    from app import main
    from tests.test_branch_api import client

    response = client.get("/branches/field-catalog")
    assert response.status_code == 200, response.text
    document = response.json()
    assert document == field_catalog.catalog_document()
    assert document["botocore_version"] == botocore.__version__
    ec2_type = document["resources"]["ec2_instance"]["type"]
    assert ec2_type["kind"] == "aws" and ec2_type["aws"] == "ec2 RunInstances InstanceType" and "t3.micro" in ec2_type["enum"]
    assert document["resources"]["lambda_function"]["role_arn"]["pattern"]
    assert document["resources"]["s3_bucket"]["policy_public"]["kind"] == "derived"
    assert document["resources"]["security_group"]["rules"]["kind"] == "normalized"
