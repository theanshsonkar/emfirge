"""AWS adapter for permission facts.

Feeds the neutral expansion in ``permission_facts`` from collected role policies and the graph:

  * statements   RolePolicy.access_statements (the same normalized list the graph builds ``can_access`` from)
  * targets      graph data nodes an Allow statement covers, with the service their actions address
  * resources    egraph's own policy-resource matcher (single truth with the ``can_access`` edges)
  * actions      aws_actions (policy-sentry IAM data, botocore operations)

Read-only: no AWS call, no database access.
"""
from __future__ import annotations

from typing import Any, Mapping, Sequence

from app.aws_actions import ACTION_CATALOG_GAP, actions_for_service
from app.egraph import Graph, _IAM_SERVICE_FOR_NODE_TYPE, _policy_resource_matches
from app.permission_facts import (
    PermissionDiff, Permissions, Statement, Target, diff_permissions, normalize, role_permissions,
)

NOTE_ACTION_CATALOG = ("action_catalog", ACTION_CATALOG_GAP)
NOTE_OTHER_LAYERS = ("other_policy_layers", "this is the identity-policy view only: permission boundaries, service control "
                                             "policies, resource policies and session policies are not collected, so "
                                             "other layers may further allow or deny these actions")
NOTE_NEVER_GRANTED = ("permission_never_granted", "Emfirge cannot see which actions the application code calls, so it "
                                                  "cannot tell whether a permission the code needs was never granted to "
                                                  "this role; compare the code's calls against the allowed actions in "
                                                  "the context question 'access' for this role")
NOTE_TARGET_GRANULARITY = ("permission_targets", "actions are expanded only for resources the graph links to the role "
                                                 "(buckets, databases, tables, queues, secrets, functions); access "
                                                 "below the resource level (objects, indexes) is not distinguished")
NOTE_APP_CODE = ("app_code_actions", "which actions the application code calls is not visible to Emfirge, so whether "
                                     "a removed or added permission matters to it is unknown")
NOTE_MANAGED_NOT_RECORDED = ("managed_policies_not_recorded", "the role's policy breakdown was not recorded in this "
                                                              "snapshot, so attached managed policies may be missing "
                                                              "from its permissions")


def role_node_ids(graph: Graph) -> dict[str, str]:
    return {str(n.base.get("arn")): n.id for n in graph.find_nodes_by_type("iam_role") if n.base.get("arn")}


def role_node_id(role: Any, ids: Mapping[str, str]) -> str:
    return ids.get(role.role_arn) or f"iam-role-{role.role_name}"


def _matcher(*graphs: Graph):
    types = {n.id: n.resource_type for g in graphs for n in g.nodes}

    def match(pattern: str, target_id: str) -> bool:
        return _policy_resource_matches(pattern, {"id": target_id, "type": types.get(target_id, "")})
    return match


def role_targets(graphs: Sequence[Graph], statements: Sequence[Statement]) -> list[Target]:
    """Resources an Allow statement can cover, with the service of their actions.

    Taken from the graph's data nodes (not from the coarse ``can_access`` edges, which drop a whole resource when
    any Deny overlaps an Allow). A node is a target when some Allow statement names it, or negates a resource list.
    """
    types: dict[str, str] = {}
    for graph in graphs:
        types.update({n.id: n.resource_type for n in graph.nodes})
    match = _matcher(*graphs)
    allows = [s for s in statements if s.effect == "allow"]
    found: dict[str, Target] = {}
    for node_id, node_type in types.items():
        service = _IAM_SERVICE_FOR_NODE_TYPE.get(node_type)
        if service and any(s.not_resource or any(match(p, node_id) for p in s.resources) for s in allows):
            found[node_id] = Target(node_id, service)
    return [found[k] for k in sorted(found)]


def role_permission_lines(role: Any, graph: Graph) -> Permissions:
    """The effective action-level allow list of one collected role in one graph."""
    statements = normalize(role.access_statements)
    return role_permissions(statements, role_targets([graph], statements), actions_for_service, _matcher(graph))


def role_permission_diff(before_role: Any, after_role: Any, base_graph: Graph, branch_graph: Graph) -> PermissionDiff:
    """Action-level difference of one role between the base and the branch.

    Targets come from both graphs: a resource that exists on only one side is still compared.
    """
    before, after = normalize(before_role.access_statements), normalize(after_role.access_statements)
    graphs = [base_graph, branch_graph]
    merged = {t.id: t for t in role_targets(graphs, before) + role_targets(graphs, after)}
    return diff_permissions(before, after, [merged[k] for k in sorted(merged)], actions_for_service,
                            _matcher(base_graph, branch_graph))


def statements_differ(before_role: Any, after_role: Any) -> bool:
    def key(role: Any) -> list[Statement]:
        return sorted(normalize(role.access_statements),
                      key=lambda s: (s.effect, s.actions, s.resources, s.not_action, s.not_resource, s.conditional))
    return key(before_role) != key(after_role)


def compute_users(graph: Graph, role_id: str) -> list[str]:
    """Resources that use the role (lambda functions, instance profiles, tasks) in this graph."""
    return sorted({e.src for e in graph.edges if e.dst == role_id and e.relationship.value == "uses_iam_role"})


def users_of(graphs: Sequence[Graph], role_ids: Sequence[str]) -> list[str]:
    return sorted({u for g, rid in zip(graphs, role_ids) for u in compute_users(g, rid)})
