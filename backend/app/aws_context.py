"""AWS adapter for the read-only context query.

Turns an ``AWSInfrastructure`` snapshot into the neutral ``FactsBundle`` that
the cloud-neutral core (``context_query``) answers from. Every AWS-specific
truth is reused from where it already lives, never re-derived:

  * tags                  tags.py (``tagged_collections``, ``user_tags``)
  * recovery points       delete_lens.recovery_point_for (the deletion lens uses it too)
  * role last-used        delete_lens.role_recent_use     (ditto)
  * prices                cost.estimate_monthly_cost / cost.unknown_reason
  * exposures             exposure.compute_exposures (severity is NOT passed on)

Read-only: no AWS call, no database access. Branch evidence is passed in as
already-stored rows; ``in_use_evidence.read_evidence`` is never called.
"""
from __future__ import annotations

import re
from typing import Optional, Sequence

from app.aws_permissions import (
    NOTE_ACTION_CATALOG, NOTE_MANAGED_NOT_RECORDED, NOTE_TARGET_GRANULARITY, role_node_id, role_node_ids,
    role_permission_lines,
)
from app.context_query import (
    ContextResponse, CostLine, DataLine, ExposureLine, FactsBundle, Note, PermissionEntry, PermissionNote,
    SourceInfo, TagLine, UseLine, VIRTUAL_NODE_IDS, answer,
)
from app.cost import estimate_monthly_cost, unknown_reason
from app.delete_lens import DATA_STORE_TYPES, RECENT_USE_DAYS, recovery_point_for, role_recent_use
from app.egraph import Graph, build_graph
from app.evidence_models import EvidenceRecord, parse_iso
from app.exposure import compute_exposures
from app.models import AWSInfrastructure
from app.tags import TAGGED_TYPES, tagged_collections, user_tags

# Collection sources (infra.collection keys) each question depends on.
QUESTION_SOURCES: dict[str, tuple[str, ...]] = {
    "inventory": ("ebs_volumes", "scheduler", "cloudfront"),
    "resource": ("ebs_volumes", "scheduler", "cloudfront"),
    "depends_on": ("ebs_volumes", "scheduler", "cloudfront"),
    "dependents": ("ebs_volumes", "scheduler", "cloudfront"),
    "reachable": ("network_interfaces",),
    "access": (),
    "data": ("ebs_snapshots", "ebs_volumes", "rds_snapshots"),
    "cost": ("ebs_volumes",),
    "live": ("iam_role_last_used",),
    "marks": (),
    "baseline": ("scheduler",),
}
# Which snapshot source must be readable before "no recovery point" can be said.
_SNAPSHOT_SOURCE = {"ebs_volume": "ebs_snapshots", "rds_instance": "rds_snapshots"}


_ERROR_DETAIL = re.compile(r"(unexpected error)\s*[\u2014-].*", re.S)


def _safe_warning(text: str) -> str:
    """A collector warning minus any exception text, which can name users, roles and buckets."""
    return _ERROR_DETAIL.sub(r"\1", str(text))


def _node_id(graph: Graph, resource_type: str, name: str) -> str:
    return graph.node_id_for(resource_type, name) or str(name)


safe_warning = _safe_warning
node_id_for = _node_id


def _tag_lines(infra: AWSInfrastructure, graph: Graph) -> list[TagLine]:
    lines = []
    for resource_type, items in tagged_collections(infra).items():
        for item in items:
            ident = str(getattr(item, "id", None) or getattr(item, "name", ""))
            tags = None if item.tags is None else user_tags(item.tags)
            lines.append(TagLine(_node_id(graph, resource_type, ident), resource_type, tags))
    return lines


def _data_lines(infra: AWSInfrastructure, graph: Graph) -> list[DataLine]:
    rds_snapshots = infra.rds.rds_snapshots
    ebs_snapshots = infra.ec2.ebs_snapshots
    stores = (
        [("s3_bucket", b.name, b) for b in infra.s3.buckets]
        + [("rds_instance", d.id, d) for d in infra.rds.rds_instances]
        + [("ebs_volume", v.id, v) for v in infra.ec2.ebs_volumes]
    )
    lines = []
    for resource_type, rid, item in stores:
        assert resource_type in DATA_STORE_TYPES
        # Existing resource: default delete options, so only a surviving snapshot (or an empty bucket) counts.
        point = recovery_point_for(resource_type, rid, item.model_dump(), {}, rds_snapshots, ebs_snapshots)
        node_id = _node_id(graph, resource_type, rid)
        if point is not None:
            lines.append(DataLine(node_id, resource_type, True,
                                  (point.source_id,) if point.source_id != rid else (), (point.kind,)))
            continue
        needed = _SNAPSHOT_SOURCE.get(resource_type)
        readable = needed is None or infra.collection.get(needed) == "ok"
        lines.append(DataLine(node_id, resource_type, False if readable else None))
    return lines


def _cost_lines(infra: AWSInfrastructure, graph: Graph) -> tuple[list[CostLine], str]:
    estimate = estimate_monthly_cost(infra)
    lines = []
    for record in estimate.resources:
        monthly = record.monthly_usd
        if monthly is None and record.basis == "free":
            monthly = 0.0  # cost.py counts free resources as known, not unknown
        lines.append(CostLine(_node_id(graph, record.resource_type, record.resource_id), record.resource_type,
                              monthly, record.basis, unknown_reason(record) if monthly is None else None))
    return lines, f"AWS {estimate.region_assumed} on-demand list prices as of {estimate.as_of}"


def _role_node_ids(graph: Graph) -> dict[str, str]:
    return {str(node.base.get("arn")): node.id for node in graph.find_nodes_by_type("iam_role") if node.base.get("arn")}


def _role_use_lines(infra: AWSInfrastructure, graph: Graph) -> list[UseLine]:
    reference = parse_iso(infra.collected_at)
    status_ok = infra.collection.get("iam_role_last_used") == "ok"
    by_arn = _role_node_ids(graph)
    lines = []
    for role in infra.iam.role_policies:
        node_id = by_arn.get(role.role_arn) or f"iam-role-{role.role_name}"
        used = role_recent_use(infra, role, reference)
        topic = reason = None
        if status_ok and used is None:
            topic = "last_used"
            reason = ("scan has no collected_at to measure the window from" if reference is None
                      else "last-used timestamp could not be read")
        lines.append(UseLine(node_id, used, role.last_used_at if status_ok else None,
                             RECENT_USE_DAYS, "scan:last_used", topic, reason))
    return lines


role_use_lines = _role_use_lines


def _evidence_use_lines(graph: Graph, evidence: Sequence[EvidenceRecord]) -> list[UseLine]:
    grouped: dict[str, list[EvidenceRecord]] = {}
    for record in evidence:
        grouped.setdefault(_node_id(graph, record.resource_type, record.resource_id), []).append(record)
    lines = []
    for node_id, records in sorted(grouped.items()):
        records = sorted(records, key=lambda r: r.source)
        flags = [r.used for r in records]
        # any recorded use wins; unused is only claimed when no source is unknown
        used = True if any(f is True for f in flags) else None if any(f is None for f in flags) else False
        stamps = [r.last_event_at for r in records if r.last_event_at]
        reasons = [f"{r.source} evidence status is '{r.status}'" for r in records if r.used is None]
        lines.append(UseLine(node_id, used, max(stamps) if stamps else None, max(r.window_days for r in records),
                             "branch:evidence", "evidence" if reasons else None,
                             "; ".join(reasons) if reasons else None))
    return lines


def _exposure_lines(infra: AWSInfrastructure, graph: Graph, base_infra: Optional[AWSInfrastructure]) -> list[ExposureLine]:
    # severity is deliberately dropped: context answers carry facts, not ratings
    return [ExposureLine(e.resource_id, e.resource_type, e.protocol, e.from_port, e.to_port, e.source, e.via_sg, e.state)
            for e in compute_exposures(infra, graph, base_infra)]


def _permission_lines(infra: AWSInfrastructure, graph: Graph) -> tuple[list[PermissionEntry], list[PermissionNote]]:
    """Action-level allows per role: the neutral expansion over collected statements (same function the check uses)."""
    ids = role_node_ids(graph)
    entries: list[PermissionEntry] = []
    notes: list[PermissionNote] = []
    for role in infra.iam.role_policies:
        rid = role_node_id(role, ids)
        result = role_permission_lines(role, graph)
        entries += [PermissionEntry(rid, p.action, p.effect, p.resource_ids) for p in result.allows]
        notes += [PermissionNote(rid, topic, text) for topic, text in result.notes]
        if role.policy_documents is None:
            notes.append(PermissionNote(rid, *NOTE_MANAGED_NOT_RECORDED))
    return entries, notes


def build_bundle(infra: AWSInfrastructure, graph: Graph, *, source: SourceInfo,
                 base_infra: Optional[AWSInfrastructure] = None,
                 evidence: Sequence[EvidenceRecord] = ()) -> FactsBundle:
    """The neutral facts bundle for one snapshot (a scan, or a branch's rebuilt state)."""
    cost_lines, price_note = _cost_lines(infra, graph)
    uses = _role_use_lines(infra, graph) + _evidence_use_lines(graph, evidence)
    untagged_types = sorted({n.resource_type for n in graph.nodes
                             if n.id not in VIRTUAL_NODE_IDS and n.resource_type not in TAGGED_TYPES})
    permissions, permission_notes = _permission_lines(infra, graph)
    unknown = {
        "access": [Note(*NOTE_ACTION_CATALOG), Note(*NOTE_TARGET_GRANULARITY)],
        "data": [Note("data_store_types", "only s3_bucket, rds_instance and ebs_volume are assessed; "
                                          "other data stores (tables, queues, caches, secrets) have no recovery assessment")],
        "marks": ([Note("tags:unmodeled_types", "the snapshot has no tag field for: " + ", ".join(untagged_types))]
                  if untagged_types else []),
    }
    known = {"cost": [Note("price_table", price_note)]}
    if evidence:
        known["live"] = [Note("branch_evidence", f"{len(evidence)} stored evidence records read; no provider call is made")]
    return FactsBundle(
        source=source,
        collection=dict(infra.collection),
        needs=QUESTION_SOURCES,
        warnings=tuple(_safe_warning(w) for w in infra.warnings),
        tags=_tag_lines(infra, graph),
        data=_data_lines(infra, graph),
        costs=cost_lines,
        uses=uses,
        exposures=_exposure_lines(infra, graph, base_infra),
        permissions=permissions,
        permission_notes=permission_notes,
        known=known,
        unknown=unknown,
    )


def answer_for_infra(question: str, infra: AWSInfrastructure, *, analysis_id: Optional[str],
                     branch_id: Optional[str] = None, base_infra: Optional[AWSInfrastructure] = None,
                     evidence: Sequence[EvidenceRecord] = (), resource_id: Optional[str] = None) -> ContextResponse:
    """Answer a context question about one snapshot. Raises ``ResourceNotFound`` for an unknown resource."""
    graph = build_graph(infra)
    source = SourceInfo(kind="branch" if branch_id else "scan", analysis_id=analysis_id, branch_id=branch_id,
                        collected_at=infra.collected_at, region=infra.region or None)
    bundle = build_bundle(infra, graph, source=source, base_infra=base_infra, evidence=evidence)
    return answer(question, graph, bundle, resource_id)
