import copy
import re

import pytest

from app.egraph import build_graph
from app.diffing import diff_graphs
from app.models import (
    AccessStatement, AWSInfrastructure, EC2Instance, IAMData,
    LambdaFunction, RDSInstance, RolePolicy, SecurityGroup,
    InternetGatewayAttachment, Route, RouteTable, VPCData, VPCSubnet,
)
from app.mutations import (
    Change, SUPPORTED_OPERATIONS, SUPPORTED_RESOURCE_TYPES, _MUTATION_CAPABILITIES,
    apply_change, apply_changes, mutation_capabilities,
)


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


def test_modify_s3_public_flag_rebuilds_public_bucket_summary(clean_infra):
    clean_infra.s3.public_buckets = ["stale-summary"]
    base = clean_infra.model_dump()

    exposed = apply_change(clean_infra, Change(
        op="modify", resource_type="s3_bucket", resource_id="my-app-data",
        fields={"is_public": True},
    ))
    assert exposed.s3.public_buckets == ["my-app-data"]

    secured = apply_change(exposed, Change(
        op="modify", resource_type="s3_bucket", resource_id="my-app-data",
        fields={"is_public": False},
    ))
    assert secured.s3.public_buckets == []
    assert clean_infra.model_dump() == base


def test_delete_ec2_cleans_relationships_and_count(clean_infra):
    result = apply_change(clean_infra, Change(op="delete", resource_type="ec2_instance", resource_id="i-001"))
    assert "i-001" not in result.ec2.instance_ids
    assert all(item.id != "i-001" for item in result.ec2.instances)
    assert all("i-001" not in subnet.resources for subnet in result.vpc.subnets)
    assert all("i-001" not in group.attached_to for group in result.ec2.security_groups)
    assert result.ec2.instance_count == 1


def test_delete_in_use_security_group_requires_explicit_detach(clean_infra):
    with pytest.raises(ValueError, match="Security group is still in use"):
        apply_change(clean_infra, Change(op="delete", resource_type="security_group", resource_id="sg-001"))
    assert clean_infra.ec2.security_groups

    detached = apply_changes(clean_infra, [
        Change(op="modify", resource_type="ec2_instance", resource_id=instance_id,
               fields={"sg_ids": []})
        for instance_id in ("i-001", "i-002")
    ])
    assert next(group for group in detached.ec2.security_groups if group.id == "sg-001").attached_to == []
    detached_graph = build_graph(detached)
    assert not any(
        edge.relationship.value == "attached_to_instance"
        and edge.src == "sg-001"
        for edge in detached_graph.edges
    )
    result = apply_change(detached, Change(op="delete", resource_type="security_group", resource_id="sg-001"))
    assert not result.ec2.security_groups


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


def test_delete_security_group_rejects_rds_reference(clean_infra):
    clean_infra.rds.rds_instances[0].sg_ids = ["sg-001", "sg-other"]
    with pytest.raises(ValueError, match="Security group is still in use"):
        apply_change(clean_infra, Change(op="delete", resource_type="security_group", resource_id="sg-001"))


def test_delete_security_group_rejects_lambda_and_peer_group_references(empty_infra):
    from app.models import SecurityGroup

    empty_infra.ec2.security_groups = [
        SecurityGroup(id="sg-target", name="target"),
        SecurityGroup(id="sg-peer", name="peer", rules=[{"source_sg_ids": ["sg-target"]}]),
    ]
    empty_infra.lambda_data.functions = [LambdaFunction(name="fn-uses-sg", sg_ids=["sg-target"])]
    with pytest.raises(ValueError, match="Security group is still in use"):
        apply_change(empty_infra, Change(op="delete", resource_type="security_group", resource_id="sg-target"))
    assert any(edge.src == "fn-uses-sg" and edge.dst == "sg-target"
               for edge in build_graph(empty_infra).edges)


def test_add_storage_database_and_lambda_updates_collections(empty_infra):
    result = apply_changes(empty_infra, [
        Change(op="add", resource_type="s3_bucket", resource_id="bucket-new"),
        Change(op="add", resource_type="rds_instance", resource_id="db-new"),
        Change(op="add", resource_type="lambda_function", resource_id="fn-new"),
    ])
    assert result.s3.total_buckets == 1 and result.s3.buckets[0].name == "bucket-new"
    assert result.rds.instances == ["db-new"] and result.rds.rds_instances[0].id == "db-new"
    assert result.lambda_data.function_count == 1 and result.lambda_data.functions[0].name == "fn-new"


def test_add_and_modify_ec2_security_groups_reconcile_both_graph_directions(empty_infra):
    empty_infra.ec2.security_groups = [
        SecurityGroup(id="sg-old", name="old"),
        SecurityGroup(id="sg-new", name="new", attached_to=["stale-instance"]),
    ]
    added = apply_change(empty_infra, Change(
        op="add", resource_type="ec2_instance", resource_id="i-branch",
        fields={"type": "t3.micro", "state": "running", "sg_ids": ["sg-old"]},
    ))
    assert added.ec2.security_groups[0].attached_to == ["i-branch"]
    assert added.ec2.security_groups[1].attached_to == []

    modified = apply_change(added, Change(
        op="modify", resource_type="ec2_instance", resource_id="i-branch",
        fields={"sg_ids": ["sg-new"]},
    ))
    graph_diff = diff_graphs(build_graph(added), build_graph(modified))
    assert modified.ec2.security_groups[0].attached_to == []
    assert modified.ec2.security_groups[1].attached_to == ["i-branch"]
    assert graph_diff["removed_edges"] == [
        {"from": "i-branch", "to": "sg-old", "relationship": "uses_security_group"},
        {"from": "sg-old", "to": "i-branch", "relationship": "attached_to_instance"},
    ]
    assert graph_diff["added_edges"] == [
        {"from": "i-branch", "to": "sg-new", "relationship": "uses_security_group"},
        {"from": "sg-new", "to": "i-branch", "relationship": "attached_to_instance"},
    ]


@pytest.mark.parametrize("consumer_type", ["rds_instance", "lambda_function"])
def test_rds_and_lambda_group_changes_use_forward_edges_and_clear_stale_backrefs(empty_infra, consumer_type):
    consumer_id = "db-branch" if consumer_type == "rds_instance" else "fn-branch"
    empty_infra.ec2.instances = [EC2Instance(
        id="i-stable", type="t3.micro", state="running", sg_ids=["sg-old"],
    )]
    empty_infra.ec2.security_groups = [
        SecurityGroup(id="sg-old", name="old", attached_to=["i-stable", consumer_id]),
        SecurityGroup(id="sg-new", name="new"),
    ]
    if consumer_type == "rds_instance":
        empty_infra.rds.rds_instances = [RDSInstance(id=consumer_id, sg_ids=["sg-old"])]
    else:
        empty_infra.lambda_data.functions = [LambdaFunction(name=consumer_id, sg_ids=["sg-old"])]
    before_graph = build_graph(empty_infra)

    updated = apply_change(empty_infra, Change(
        op="modify", resource_type=consumer_type, resource_id=consumer_id,
        fields={"sg_ids": ["sg-new"]},
    ))
    after_graph = build_graph(updated)
    graph_diff = diff_graphs(before_graph, after_graph)

    assert next(group for group in updated.ec2.security_groups if group.id == "sg-old").attached_to == ["i-stable"]
    assert next(group for group in updated.ec2.security_groups if group.id == "sg-new").attached_to == []
    assert {tuple(edge.values()) for edge in graph_diff["removed_edges"]} >= {
        (consumer_id, "sg-old", "uses_security_group"),
        ("sg-old", consumer_id, "attached_to_instance"),
    }
    assert {tuple(edge.values()) for edge in graph_diff["added_edges"]} >= {
        (consumer_id, "sg-new", "uses_security_group"),
    }
    assert not any(edge.src == "sg-old" and edge.dst == consumer_id for edge in after_graph.edges)


@pytest.mark.parametrize("operation", ["add", "modify", "delete"])
def test_security_group_attachment_back_reference_is_not_directly_mutable(empty_infra, operation):
    with pytest.raises(ValueError, match="derived from EC2 sg_ids"):
        apply_change(empty_infra, Change(
            op=operation, resource_type="security_group", resource_id="sg-001",
            fields={"attached_to": ["i-invented"]},
        ))


def test_unrelated_mutation_preserves_existing_security_group_back_references(empty_infra):
    empty_infra.ec2.security_groups = [
        SecurityGroup(id="sg-db", name="db", attached_to=["db-branch"]),
    ]
    empty_infra.s3.buckets = [{"name": "bucket-branch"}]

    result = apply_change(empty_infra, Change(
        op="modify", resource_type="s3_bucket", resource_id="bucket-branch",
        fields={"is_public": True},
    ))

    assert result.ec2.security_groups[0].attached_to == ["db-branch"]


def test_capability_schema_matches_supported_and_executable_mutations(empty_infra):
    contract = mutation_capabilities().model_dump(mode="json")
    advertised = {item["resource_type"]: set(item["operations"])
                  for item in contract["resources"]}
    assert set(advertised) == SUPPORTED_RESOURCE_TYPES
    assert set(contract["operations"]) == SUPPORTED_OPERATIONS
    security_group_constraint = next(
        item for item in next(entry for entry in contract["resources"]
                              if entry["resource_type"] == "security_group")["constraints"]
        if item["kind"] == "derived_field"
    )
    assert set(security_group_constraint["operations"]) == set(SUPPORTED_OPERATIONS)

    ids = {
        "ec2_instance": ("i-capability", "id", {"type": "t3.micro", "state": "running"}),
        "security_group": ("sg-capability", "id", {"name": "capability"}),
        "rds_instance": ("db-capability", "id", {}),
        "s3_bucket": ("bucket-capability", "name", {}),
        "lambda_function": ("fn-capability", "name", {}),
        "iam_role_policy": (
            "arn:aws:iam::000000000000:role/Capability", "role_arn", {},
        ),
        "route_table": ("rt-capability", "id", {"vpc_id": "vpc-capability"}),
        "network_acl": ("acl-capability", "id", {"vpc_id": "vpc-capability"}),
    }
    collection_names = {
        "ec2_instance": ("ec2", "instances"),
        "security_group": ("ec2", "security_groups"),
        "rds_instance": ("rds", "rds_instances"),
        "s3_bucket": ("s3", "buckets"),
        "lambda_function": ("lambda_data", "functions"),
        "route_table": ("vpc", "route_tables"),
        "network_acl": ("vpc", "nacls"),
    }

    for resource_type, operations in advertised.items():
        if resource_type == "ebs_snapshot":
            assert operations == {"delete"}
            continue
        if resource_type == "ebs_volume":
            assert operations == {"add", "delete"}
            continue
        if resource_type == "iam_role":
            assert operations == {"add", "modify", "delete"}
            continue
        if resource_type == "iam_user":
            assert operations == {"add", "modify"}
            continue
        if resource_type in {"iam_instance_profile", "nat_gateway"}:
            assert operations == {"add"}
            continue
        if resource_type == "rds_snapshot":
            assert operations == {"add", "delete"}
            continue
        resource_id, identity_field, add_fields = ids[resource_type]
        for operation in SUPPORTED_OPERATIONS:
            infra = copy.deepcopy(empty_infra)
            if operation == "add":
                fields = dict(add_fields)
            elif operation == "modify":
                fields = {
                    "ec2_instance": {"state": "running"},
                    "security_group": {"name": "capability-modified"},
                    "rds_instance": {"publicly_accessible": False},
                    "s3_bucket": {"encrypted": True},
                    "lambda_function": {"role_arn": None},
                    "network_acl": {"associated_subnet_ids": []},
                }.get(resource_type, {})
            else:
                fields = {}
            if resource_type == "iam_role_policy" and operation == "modify":
                fields = {"access_statements": []}
            if resource_type == "route_table" and operation == "modify":
                fields = {"routes": []}
            if resource_type == "route_table" and operation == "add":
                # A new table needs a VPC the snapshot knows; every VPC has a main table.
                infra.vpc.route_tables.append(RouteTable(id="rt-capability-main", vpc_id="vpc-capability", is_main=True))
            if operation != "add":
                if resource_type == "iam_role_policy":
                    infra.iam.role_policies.append(RolePolicy(
                        role_name="Capability", role_arn=resource_id,
                    ))
                elif resource_type == "route_table":
                    infra.vpc.route_tables.append(RouteTable(**{
                        identity_field: resource_id, **add_fields,
                    }))
                else:
                    model_type = _MUTATION_CAPABILITIES[resource_type]["model"]
                    target = {identity_field: resource_id, **add_fields}
                    getattr(getattr(infra, collection_names[resource_type][0]),
                            collection_names[resource_type][1]).append(model_type(**target))

            change = Change(op=operation, resource_type=resource_type,
                            resource_id=resource_id, fields=fields)
            if operation in operations:
                apply_change(infra, change)
            else:
                with pytest.raises(ValueError):
                    apply_change(infra, change)


def test_route_table_replaces_complete_routes_and_syncs_public_subnet_summary():
    base = AWSInfrastructure(vpc=VPCData(
        internet_gateways=["igw-route-test"],
        public_subnet_ids=["subnet-route-test"],
        subnets=[VPCSubnet(
            id="subnet-route-test", vpc_id="vpc-route-test", is_public=True,
        )],
        route_tables=[RouteTable(
            id="rt-route-test", vpc_id="vpc-route-test",
            associated_subnet_ids=["subnet-route-test"],
            routes=[Route(destination_cidr="0.0.0.0/0",
                          target_type="internet_gateway", target_id="igw-route-test")],
        )],
    ))

    changed = apply_change(base, Change(
        op="modify", resource_type="route_table", resource_id="rt-route-test",
        fields={"routes": [
            {"destination_cidr": "0.0.0.0/0", "target_type": "nat_gateway", "target_id": "nat-route-test"},
        ]},
    ))

    assert base.vpc.route_tables[0].routes[0].target_type == "internet_gateway"
    assert changed.vpc.route_tables[0].routes[0].target_type == "nat_gateway"
    assert changed.vpc.route_tables[0].associated_subnet_ids == ["subnet-route-test"]
    assert changed.vpc.subnets[0].is_public is False
    assert changed.vpc.public_subnet_ids == []


def test_route_table_change_recomputes_main_table_inherited_public_flags():
    base = AWSInfrastructure(vpc=VPCData(
        internet_gateways=["igw-main-route-test"],
        public_subnet_ids=["subnet-inherited"],
        subnets=[VPCSubnet(
            id="subnet-inherited", vpc_id="vpc-inherited", is_public=True,
        )],
        route_tables=[RouteTable(
            id="rt-main-route-test", vpc_id="vpc-inherited", is_main=True,
            routes=[Route(destination_cidr="0.0.0.0/0",
                          target_type="internet_gateway", target_id="igw-main-route-test")],
        )],
    ))

    changed = apply_change(base, Change(
        op="modify", resource_type="route_table", resource_id="rt-main-route-test",
        fields={"routes": []},
    ))

    assert base.vpc.subnets[0].is_public is True
    assert changed.vpc.subnets[0].is_public is False
    assert changed.vpc.public_subnet_ids == []
    assert changed.vpc.route_tables[0].associated_subnet_ids == []


def test_route_table_rejects_partial_or_association_mutations():
    base = AWSInfrastructure(vpc=VPCData(route_tables=[RouteTable(
        id="rt-guard", vpc_id="vpc-guard",
    )]))

    with pytest.raises(ValueError, match="requires only routes"):
        apply_change(base, Change(
            op="modify", resource_type="route_table", resource_id="rt-guard",
            fields={"routes": [], "associated_subnet_ids": ["subnet-invented"]},
        ))
    with pytest.raises(ValueError, match="complete normalized route set"):
        apply_change(base, Change(
            op="modify", resource_type="route_table", resource_id="rt-guard",
            fields={"routes": {"destination_cidr": "0.0.0.0/0"}},
        ))


def test_route_table_rejects_new_igw_without_attachment_evidence_but_preserves_existing_route():
    base = AWSInfrastructure(
        vpc=VPCData(
            internet_gateways=["igw-region-known"],
            route_tables=[RouteTable(
                id="rt-igw-guard", vpc_id="vpc-igw-guard",
                routes=[Route(destination_cidr="0.0.0.0/0",
                              target_type="internet_gateway", target_id="igw-unobserved")],
            )],
        ),
    )

    preserved = apply_change(base, Change(
        op="modify", resource_type="route_table", resource_id="rt-igw-guard",
        fields={"routes": [{
            "destination_cidr": "0.0.0.0/0",
            "target_type": "internet_gateway",
            "target_id": "igw-unobserved",
        }]},
    ))
    assert preserved.vpc.route_tables[0].routes[0].target_id == "igw-unobserved"

    with pytest.raises(ValueError, match="without complete IGW attachment evidence"):
        apply_change(preserved, Change(
            op="modify", resource_type="route_table", resource_id="rt-igw-guard",
            fields={"routes": [{
                "destination_cidr": "0.0.0.0/0",
                "target_type": "internet_gateway",
                "target_id": "igw-region-known",
            }]},
        ))


def test_route_table_igw_target_must_be_available_and_attached_to_the_same_vpc():
    base = AWSInfrastructure(vpc=VPCData(
        internet_gateways=["igw-known"],
        internet_gateway_attachments=[InternetGatewayAttachment(
            internet_gateway_id="igw-known", vpc_id="vpc-other", state="available",
        )],
        internet_gateway_attachments_complete=True,
        route_tables=[RouteTable(id="rt-same-vpc", vpc_id="vpc-local")],
    ))
    change = Change(
        op="modify", resource_type="route_table", resource_id="rt-same-vpc",
        fields={"routes": [{
            "destination_cidr": "0.0.0.0/0",
            "target_type": "internet_gateway",
            "target_id": "igw-known",
        }]},
    )

    with pytest.raises(ValueError, match="not attached to the route table VPC"):
        apply_change(base, change)

    base.vpc.internet_gateway_attachments[0].vpc_id = "vpc-local"
    changed = apply_change(base, change)
    assert changed.vpc.route_tables[0].routes[0].target_id == "igw-known"


@pytest.mark.parametrize("state", ["detached", "attaching", "attached", "detaching", None])
def test_route_table_igw_attachment_state_must_be_available(state):
    base = AWSInfrastructure(vpc=VPCData(
        internet_gateways=["igw-known"],
        internet_gateway_attachments=[InternetGatewayAttachment(
            internet_gateway_id="igw-known", vpc_id="vpc-local", state=state,
        )],
        internet_gateway_attachments_complete=True,
        route_tables=[RouteTable(id="rt-same-vpc", vpc_id="vpc-local")],
    ))

    with pytest.raises(ValueError, match="not attached to the route table VPC"):
        apply_change(base, Change(
            op="modify", resource_type="route_table", resource_id="rt-same-vpc",
            fields={"routes": [{
                "destination_cidr": "0.0.0.0/0",
                "target_type": "internet_gateway",
                "target_id": "igw-known",
            }]},
        ))


def test_modify_iam_role_policy_replaces_normalized_statements_without_mutating_base():
    role_arn = "arn:aws:iam::000000000000:role/AppRole"
    base = AWSInfrastructure(iam=IAMData(role_policies=[RolePolicy(
        role_name="AppRole",
        role_arn=role_arn,
        has_admin=True,
        accessible_resources=["*"],
        policy_names=["AdministratorAccess"],
        access_statements=[AccessStatement(
            effect="allow", actions=["*"], resources=["*"],
        )],
    )]))

    result = apply_change(base, Change(
        op="modify",
        resource_type="iam_role_policy",
        resource_id=role_arn,
        fields={"access_statements": [
            {"effect": "allow", "actions": ["s3:GetObject"], "resources": ["arn:aws:s3:::reports/*"]},
        ]},
    ))

    assert base.iam.role_policies[0].has_admin is True
    changed = result.iam.role_policies[0]
    assert changed.access_statements[0].actions == ["s3:GetObject"]
    assert changed.has_admin is False
    assert changed.accessible_resources == []
    assert changed.policy_names == []


@pytest.mark.parametrize(
    ("op", "fields", "message"),
    [
        ("add", {"access_statements": []}, "modify only"),
        ("modify", {"has_admin": True}, "requires only access_statements"),
        ("modify", {"access_statements": "not-a-list"}, "must be a list"),
    ],
)
def test_iam_role_policy_rejects_unsupported_or_ambiguous_mutation_shapes(clean_infra, op, fields, message):
    with pytest.raises(ValueError, match=message):
        apply_change(clean_infra, Change(
            op=op,
            resource_type="iam_role_policy",
            resource_id="arn:aws:iam::000000000000:role/AppRole",
            fields=fields,
        ))


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
