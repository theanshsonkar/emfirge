import copy
import re

import pytest

from app.egraph import build_graph
from app.models import AWSInfrastructure, LambdaFunction, RDSInstance
from app.mutations import Change, apply_change, apply_changes


def test_add_ec2_updates_count_and_is_pure(clean_infra):
    before = clean_infra.model_dump()
    result = apply_change(clean_infra, Change(op="add", resource_type="ec2_instance", resource_id="i-003", fields={"type": "t3.small", "state": "running", "sg_ids": ["sg-001"]}))
    assert clean_infra.model_dump() == before
    assert result.ec2.instance_count == 3
    assert result.ec2.instance_ids[-1] == "i-003"
    assert result.ec2.instances[-1].type == "t3.small"


def test_modify_ec2_preserves_other_fields_and_is_pure(clean_infra):
    before = clean_infra.model_dump()
    result = apply_change(clean_infra, Change(op="modify", resource_type="ec2_instance", resource_id="i-001", fields={"imdsv2_required": False, "state": "stopped"}))
    assert clean_infra.model_dump() == before
    changed = next(item for item in result.ec2.instances if item.id == "i-001")
    original = next(item for item in clean_infra.ec2.instances if item.id == "i-001")
    assert changed.imdsv2_required is False and changed.state == "stopped"
    assert changed.sg_ids == original.sg_ids and changed.type == original.type


def test_delete_ec2_cleans_relationships_and_count(clean_infra):
    result = apply_change(clean_infra, Change(op="delete", resource_type="ec2_instance", resource_id="i-001"))
    assert "i-001" not in result.ec2.instance_ids
    assert all(item.id != "i-001" for item in result.ec2.instances)
    assert all("i-001" not in subnet.resources for subnet in result.vpc.subnets)
    assert all("i-001" not in group.attached_to for group in result.ec2.security_groups)
    assert result.ec2.instance_count == 1


def test_delete_security_group_cleans_instances(clean_infra):
    result = apply_change(clean_infra, Change(op="delete", resource_type="security_group", resource_id="sg-001"))
    assert not result.ec2.security_groups
    assert all("sg-001" not in item.sg_ids for item in result.ec2.instances)


def test_delete_ec2_removes_only_deleted_instance_type_occurrence(clean_infra):
    result = apply_change(clean_infra, Change(op="delete", resource_type="ec2_instance", resource_id="i-001"))
    assert result.ec2.instance_types == ["t3.micro"]


def test_delete_rds_cleans_subnet_resources(clean_infra):
    clean_infra.vpc.subnets[0].resources.extend(["prod-db", "prod-db", "other-resource"])
    result = apply_change(clean_infra, Change(op="delete", resource_type="rds_instance", resource_id="prod-db"))
    assert all("prod-db" not in subnet.resources for subnet in result.vpc.subnets)


def test_delete_lambda_cleans_subnet_resources(clean_infra):
    clean_infra.lambda_data.functions.append(LambdaFunction(name="cleanup-fn"))
    clean_infra.vpc.subnets[0].resources.extend(["cleanup-fn", "cleanup-fn", "other-resource"])
    result = apply_change(clean_infra, Change(op="delete", resource_type="lambda_function", resource_id="cleanup-fn"))
    assert all("cleanup-fn" not in subnet.resources for subnet in result.vpc.subnets)


def test_rds_summary_instances_rebuilt_from_authoritative_collection(clean_infra):
    clean_infra.rds.instances = ["stale-id", "prod-db"]
    clean_infra.rds.rds_instances.extend([RDSInstance(id="db-z"), RDSInstance(id="db-a")])
    result = apply_change(clean_infra, Change(op="modify", resource_type="rds_instance", resource_id="prod-db", fields={"encrypted": False}))
    assert result.rds.instances == ["db-a", "db-z", "prod-db"]


def test_delete_security_group_cleans_rds_instances(clean_infra):
    clean_infra.rds.rds_instances[0].sg_ids = ["sg-001", "sg-other"]
    result = apply_change(clean_infra, Change(op="delete", resource_type="security_group", resource_id="sg-001"))
    assert result.rds.rds_instances[0].sg_ids == ["sg-other"]


def test_add_storage_database_and_lambda_updates_collections(empty_infra):
    result = apply_changes(empty_infra, [
        Change(op="add", resource_type="s3_bucket", resource_id="bucket-new"),
        Change(op="add", resource_type="rds_instance", resource_id="db-new"),
        Change(op="add", resource_type="lambda_function", resource_id="fn-new"),
    ])
    assert result.s3.total_buckets == 1 and result.s3.buckets[0].name == "bucket-new"
    assert result.rds.instances == ["db-new"] and result.rds.rds_instances[0].id == "db-new"
    assert result.lambda_data.function_count == 1 and result.lambda_data.functions[0].name == "fn-new"


def test_stacked_add_modify_delete(empty_infra):
    result = apply_changes(empty_infra, [
        Change(op="add", resource_type="ec2_instance", resource_id="i-new", fields={"type": "t3.micro", "state": "running"}),
        Change(op="modify", resource_type="ec2_instance", resource_id="i-new", fields={"imdsv2_required": True}),
        Change(op="delete", resource_type="ec2_instance", resource_id="i-new"),
    ])
    assert result.ec2.instances == [] and result.ec2.instance_count == 0


def test_graph_rebuild_has_added_node_and_no_deleted_dangling_edges(empty_infra):
    added = apply_change(empty_infra, Change(op="add", resource_type="ec2_instance", resource_id="i-new", fields={"type": "t3.micro", "state": "running"}))
    graph = build_graph(added)
    assert graph.get_node("i-new") is not None
    deleted = apply_change(added, Change(op="delete", resource_type="ec2_instance", resource_id="i-new"))
    graph = build_graph(deleted)
    assert graph.get_node("i-new") is None
    assert all(edge.src != "i-new" and edge.dst != "i-new" for edge in graph.edges)




@pytest.mark.parametrize(
    ("resource_type", "resource_id", "identity_field"),
    [
        ("ec2_instance", "i-001", "id"),
        ("security_group", "sg-001", "id"),
        ("rds_instance", "prod-db", "id"),
        ("s3_bucket", "my-app-data", "name"),
        ("lambda_function", "missing-fn", "name"),
    ],
)
def test_modify_rejects_identity_fields(clean_infra, resource_type, resource_id, identity_field):
    if resource_type == "lambda_function":
        clean_infra.lambda_data.functions.append(LambdaFunction(name=resource_id))

    with pytest.raises(ValueError, match=f"Cannot modify identity field: {identity_field}"):
        apply_change(
            clean_infra,
            Change(
                op="modify",
                resource_type=resource_type,
                resource_id=resource_id,
                fields={identity_field: "replacement"},
            ),
        )


def test_modify_rejects_invalid_model_value(clean_infra):
    with pytest.raises(ValueError):
        apply_change(
            clean_infra,
            Change(
                op="modify",
                resource_type="ec2_instance",
                resource_id="i-001",
                fields={"sg_ids": "not-a-list"},
            ),
        )


@pytest.mark.parametrize(
    ("resource_type", "resource_id", "identity_field"),
    [
        ("ec2_instance", "i-new", "id"),
        ("security_group", "sg-new", "id"),
        ("rds_instance", "db-new", "id"),
        ("s3_bucket", "bucket-new", "name"),
        ("lambda_function", "fn-new", "name"),
    ],
)
def test_add_rejects_identity_fields(empty_infra, resource_type, resource_id, identity_field):
    with pytest.raises(ValueError, match=f"Cannot set identity field: {identity_field}"):
        apply_change(
            empty_infra,
            Change(
                op="add",
                resource_type=resource_type,
                resource_id=resource_id,
                fields={identity_field: "replacement"},
            ),
        )


def test_delete_s3_cleans_summary_lists(clean_infra):
    bucket_name = "my-app-data"
    clean_infra.s3.public_buckets = [bucket_name]
    clean_infra.s3.unencrypted_buckets = [bucket_name]
    clean_infra.s3.buckets_without_versioning = [bucket_name]
    clean_infra.s3.buckets_without_logging = [bucket_name]
    result = apply_change(clean_infra, Change(op="delete", resource_type="s3_bucket", resource_id=bucket_name))
    assert all(bucket_name not in values for values in (
        result.s3.public_buckets,
        result.s3.unencrypted_buckets,
        result.s3.buckets_without_versioning,
        result.s3.buckets_without_logging,
    ))


def test_delete_rds_cleans_summary_lists(clean_infra):
    instance_id = "prod-db"
    clean_infra.rds.publicly_accessible = [instance_id]
    clean_infra.rds.unencrypted_instances = [instance_id]
    clean_infra.rds.instances_without_deletion_protection = [instance_id]
    clean_infra.rds.instances_without_log_exports = [instance_id]
    result = apply_change(clean_infra, Change(op="delete", resource_type="rds_instance", resource_id=instance_id))
    assert all(instance_id not in values for values in (
        result.rds.instances,
        result.rds.publicly_accessible,
        result.rds.unencrypted_instances,
        result.rds.instances_without_deletion_protection,
        result.rds.instances_without_log_exports,
    ))


def test_delete_lambda_cleans_summary_lists(clean_infra):
    function_name = "cleanup-fn"
    clean_infra.lambda_data.functions.append(LambdaFunction(name=function_name))
    clean_infra.lambda_data.functions_with_admin_role = [function_name]
    clean_infra.lambda_data.functions_with_outdated_runtime = [function_name]
    clean_infra.lambda_data.functions_with_no_timeout = [function_name]
    result = apply_change(clean_infra, Change(op="delete", resource_type="lambda_function", resource_id=function_name))
    assert all(function_name not in values for values in (
        result.lambda_data.functions_with_admin_role,
        result.lambda_data.functions_with_outdated_runtime,
        result.lambda_data.functions_with_no_timeout,
    ))
def test_invalid_changes_raise(clean_infra):
    with pytest.raises(ValueError, match="Unsupported operation"):
        apply_change(clean_infra, Change(op="replace", resource_type="ec2_instance"))
    with pytest.raises(ValueError, match="Unsupported resource type"):
        apply_change(clean_infra, Change(op="add", resource_type="vpc"))
    with pytest.raises(ValueError, match="Target not found"):
        apply_change(clean_infra, Change(op="delete", resource_type="ec2_instance", resource_id="missing"))
    with pytest.raises(ValueError, match="Unknown field"):
        apply_change(clean_infra, Change(op="modify", resource_type="ec2_instance", resource_id="i-001", fields={"bogus": 1}))


def test_auto_ids_are_stable_and_formatted(empty_infra):
    change = Change(op="add", resource_type="s3_bucket", fields={"is_public": False})
    first = apply_change(empty_infra, change)
    second = apply_change(empty_infra, change)
    first_id = first.s3.buckets[0].name
    assert re.fullmatch(r"new-s3_bucket-[0-9a-f]{6}", first_id)
    assert first_id == second.s3.buckets[0].name


def test_operations_do_not_mutate_input_byte_for_byte(clean_infra):
    snapshot = copy.deepcopy(clean_infra.model_dump_json())
    for change in (
        Change(op="add", resource_type="s3_bucket", resource_id="new-bucket"),
        Change(op="modify", resource_type="ec2_instance", resource_id="i-001", fields={"imdsv2_required": False}),
        Change(op="delete", resource_type="rds_instance", resource_id="prod-db"),
    ):
        apply_change(clean_infra, change)
        assert clean_infra.model_dump_json() == snapshot


def test_recompute_ssh_open_and_close_updates_derived_state(clean_infra):
    before = clean_infra.model_dump_json()
    opened = apply_change(clean_infra, Change(
        op="modify", resource_type="security_group", resource_id="sg-001",
        fields={"rules": [{"from_port": 20, "to_port": 22, "protocol": "tcp",
                            "ip_ranges": ["0.0.0.0/0"]}]},
    ))
    assert opened.ec2.ssh_open_to_internet is True
    assert opened.ec2.ssh_security_group_id == "sg-001"
    assert clean_infra.model_dump_json() == before

    closed = apply_change(opened, Change(
        op="modify", resource_type="security_group", resource_id="sg-001",
        fields={"rules": []},
    ))
    assert closed.ec2.ssh_open_to_internet is False
    assert closed.ec2.ssh_security_group_id is None
    assert opened.ec2.ssh_open_to_internet is True


def test_recompute_rdp_ipv6_range_and_close_updates_derived_state(clean_infra):
    opened = apply_change(clean_infra, Change(
        op="modify", resource_type="security_group", resource_id="sg-001",
        fields={"rules": [{"from_port": 3388, "to_port": 3390, "protocol": "-1",
                            "ip_ranges": ["::/0"]}]},
    ))
    assert opened.ec2.rdp_open_to_internet is True
    assert opened.ec2.rdp_security_group_id == "sg-001"

    closed = apply_change(opened, Change(
        op="modify", resource_type="security_group", resource_id="sg-001",
        fields={"rules": []},
    ))
    assert closed.ec2.rdp_open_to_internet is False
    assert closed.ec2.rdp_security_group_id is None
