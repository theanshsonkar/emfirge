import json

import pytest

from app.diffing import diff_infrastructure
from app.graph_schema import NODE_SCHEMAS
from app.models import NetworkACL
from app.mutations import (
    Change,
    _MUTATION_CAPABILITIES,
    _collection,
    _identity,
    apply_change,
    mutation_capabilities,
)
from app.verdict import combined_verdict
from tests.incidents.synthetic_base import load_synthetic_base


def _base():
    base = load_synthetic_base("delete")
    acl = NetworkACL(id="acl-law-base", vpc_id=base.vpc.subnets[0].vpc_id if base.vpc.subnets else "vpc-law")
    instances = [item.model_copy(update={"sg_ids": []}) for item in base.ec2.instances]
    ec2 = base.ec2.model_copy(update={"instances": instances})
    groups = [group.model_copy(update={"rules": [], "egress_rules": []}) for group in ec2.security_groups]
    ec2 = ec2.model_copy(update={"security_groups": groups})
    return base.model_copy(update={"ec2": ec2, "vpc": base.vpc.model_copy(update={"nacls": [acl]})})


def _add_samples(base):
    samples = {}
    samples['iam_role'] = Change(op='add', resource_type='iam_role', resource_id='arn:aws:iam::000000000000:role/law-add', fields={'trust_policy': {'Statement': [{'Effect': 'Allow', 'Principal': {'Service': 'ec2.amazonaws.com'}, 'Action': 'sts:AssumeRole'}]}})
    samples['iam_user'] = Change(op='add', resource_type='iam_user', resource_id='law-user-add', fields={})
    for resource_type, capability in _MUTATION_CAPABILITIES.items():
        if resource_type in {'iam_role', 'iam_user'}:
            continue
        if "add" not in capability["operations"]:
            continue
        collection = _collection(base, resource_type)
        if resource_type == "rds_snapshot":
            samples[resource_type] = Change(op="add", resource_type=resource_type, resource_id="snap-law-add", fields={"db_instance_id": base.rds.rds_instances[0].id})
        elif resource_type == "nat_gateway":
            subnet = base.vpc.subnets[0]
            samples[resource_type] = Change(op="add", resource_type=resource_type, resource_id="nat-law-add", fields={"subnet_id": subnet.id, "allocation_id": "eipalloc-law-add"})
        elif resource_type == "network_acl":
            samples[resource_type] = Change(op="add", resource_type=resource_type, resource_id="acl-law-add", fields={"vpc_id": base.vpc.total_vpcs and base.vpc.subnets[0].vpc_id or "vpc-law"})
        elif collection:
            source = collection[0].model_dump()
            identity = _identity(resource_type, collection[0])
            fields = {key: value for key, value in source.items() if key != ("name" if resource_type in {"s3_bucket", "lambda_function"} else "id") and not (resource_type == "security_group" and key == "attached_to")}
            samples[resource_type] = Change(op="add", resource_type=resource_type, resource_id=f"{identity}-law-add", fields=fields)
    return samples


def _delete_samples(base):
    samples = {}
    for resource_type, capability in _MUTATION_CAPABILITIES.items():
        if "delete" not in capability["operations"]:
            continue
        collection = _collection(base, resource_type)
        if not collection:
            continue
        resource_id = _identity(resource_type, collection[0])
        fields = {}
        if resource_type == "rds_instance":
            fields = {"skip_final_snapshot": True, "delete_automated_backups": True}
        samples[resource_type] = Change(op="delete", resource_type=resource_type, resource_id=resource_id, fields=fields)
    return samples


def test_every_addable_type_appears_in_resources_added():
    base = _base()
    samples = _add_samples(base)
    for capability in mutation_capabilities().resources:
        if "add" not in capability.operations:
            continue
        assert capability.resource_type in samples, f"addable resource type needs a SAMPLES entry: {capability.resource_type}"
        change = samples[capability.resource_type]
        branch = apply_change(base, change)
        result = diff_infrastructure(base, branch)
        expected_id = f"iam-role-{change.resource_id.rsplit('/', 1)[-1]}" if change.resource_type == "iam_role" else change.resource_id
        assert any(item["resource_type"] == change.resource_type and item["id"] == expected_id for item in result.resources_added)
        if change.resource_type == "iam_user":
            assert sum(item['resource_type'] == 'iam_user' and item['id'] == 'law-user-add' for item in result.resources_added) == 1
        assert not any(item["resource_type"] == change.resource_type and item["id"] == change.resource_id for item in result.resources_removed)


def test_every_deletable_type_appears_in_resources_removed():
    base = _base()
    samples = _delete_samples(base)
    for capability in mutation_capabilities().resources:
        if "delete" not in capability.operations:
            continue
        assert capability.resource_type in samples, f"deletable resource type needs a SAMPLES entry: {capability.resource_type}"
        change = samples[capability.resource_type]
        branch = apply_change(base, change)
        result = diff_infrastructure(base, branch)
        expected_id = f"iam-role-{change.resource_id.rsplit('/', 1)[-1]}" if change.resource_type == "iam_role" else change.resource_id
        assert any(item["resource_type"] == change.resource_type and item["id"] == expected_id for item in result.resources_removed)
        assert not any(item["resource_type"] == change.resource_type and item["id"] == change.resource_id for item in result.resources_added)


def test_model_only_types_are_exactly_mutable_types_without_graph_nodes():
    expected = {
        capability.resource_type
        for capability in mutation_capabilities().resources
        if capability.resource_type not in NODE_SCHEMAS and _MUTATION_CAPABILITIES[capability.resource_type]["model"] is not None
    }
    from app.diffing import MODEL_ONLY_TYPES
    assert MODEL_ONLY_TYPES == expected
    assert MODEL_ONLY_TYPES == {"rds_snapshot", "ebs_snapshot", "iam_user"}


def test_rds_snapshot_symmetry():
    base = _base()
    change = _add_samples(base)["rds_snapshot"]
    branch = apply_change(base, change)
    left = diff_infrastructure(base, branch)
    right = diff_infrastructure(branch, base)
    assert left.resources_added == right.resources_removed


def test_model_only_modified_entries_contain_field_names_only():
    base = _base()
    snapshot = base.rds.rds_snapshots[0]
    changed = snapshot.model_copy(update={"db_instance_id": "db-law-changed"})
    branch = base.model_copy(update={"rds": base.rds.model_copy(update={"rds_snapshots": [changed]})})
    result = diff_infrastructure(base, branch)
    entry = next(item for item in result.resources_modified if item["resource_type"] == "rds_snapshot")
    encoded = json.dumps(entry, sort_keys=True)
    assert "db-law-changed" not in encoded
    assert "db_instance_id" in entry["changed"]


def test_combined_verdict_includes_snapshot_added():
    base = _base()
    branch = apply_change(base, _add_samples(base)["rds_snapshot"])
    payload = combined_verdict(base, branch, run_scanners=False).model_dump(mode="json")
    assert any(item["resource_type"] == "rds_snapshot" for item in payload["resources_added"])
