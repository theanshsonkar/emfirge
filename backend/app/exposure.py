"""Per-port public exposure evidence for infrastructure snapshots."""

from __future__ import annotations

from ipaddress import ip_network
from typing import Any, Mapping

from pydantic import BaseModel, ConfigDict

from app.egraph import get_internet_reachable_set, internet_ingress, nacl_allows_inbound, subnet_has_igw_route
from app.rules import PORT_CLASSES


class Exposure(BaseModel):
    """One security-group ingress rule exposed to an external source."""

    model_config = ConfigDict(frozen=True)

    resource_id: str
    resource_type: str
    protocol: str
    from_port: int
    to_port: int
    source: str
    via_sg: str
    state: str
    severity: str


_PRIVATE_NETWORKS = tuple(ip_network(value) for value in (
    "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10",
    "127.0.0.0/8", "169.254.0.0/16", "::1/128", "fc00::/7", "fe80::/10",
))
_CONSUMER_TYPES = {"ec2_instance", "rds_instance", "lambda_function", "elasticache_cluster"}


def _value(item: Any, name: str, default: Any = None) -> Any:
    if isinstance(item, Mapping):
        return item.get(name, default)
    return getattr(item, name, default)


def _data(node: Any) -> Mapping[str, Any]:
    value = _value(node, "base", None)
    if value is None:
        value = _value(node, "metadata", {})
    return value if isinstance(value, Mapping) else {}


def _external(cidr: Any) -> bool:
    try:
        network = ip_network(str(cidr), strict=False)
    except ValueError:
        return False
    return not any(network.version == private.version and network.subnet_of(private)
                   for private in _PRIVATE_NETWORKS)


def _ports(rule: Any) -> tuple[int, int]:
    protocol = str(_value(rule, "protocol", "-1"))
    if protocol == "-1" or _value(rule, "from_port") is None or _value(rule, "to_port") is None:
        return 0, 65535
    return int(_value(rule, "from_port")), int(_value(rule, "to_port"))


def _modeled_resource_ids(infra: Any) -> set[str]:
    ids = set()
    for owner, field in (("ec2", "instances"), ("rds", "rds_instances"), ("lambda_data", "functions"), ("elasticache", "clusters")):
        for item in (_value(_value(infra, owner, {}), field, []) or []):
            value = _value(item, "id", _value(item, "name", None))
            if value is not None:
                ids.add(str(value))
    return ids


def _eni_proves_unused(sg_id: str, infra: Any, base_infra: Any = None) -> bool:
    collection = _value(infra, "collection", {}) or {}
    if collection.get("network_interfaces") != "ok":
        return False
    interfaces = _value(infra, "network_interfaces", None)
    if interfaces is None:
        return False
    modeled = _modeled_resource_ids(infra)
    base_modeled = _modeled_resource_ids(base_infra) if base_infra is not None else set()
    return not any(sg_id in (_value(interface, "sg_ids", []) or []) and
                   (_value(interface, "attached_resource", None) is None or
                    str(_value(interface, "attached_resource")) in modeled or
                    str(_value(interface, "attached_resource")) not in base_modeled)
                   for interface in interfaces)


def _sg_nodes(infra: Any, graph: Any) -> dict[str, Any]:
    return {str(_value(node, "id")): node for node in graph.find_nodes_by_type("security_group")}


def _sg_consumers(sg_id: str, infra: Any, graph: Any) -> list[Any]:
    consumers = []
    for node in graph.nodes:
        resource_type = str(_value(node, "resource_type", _value(node, "type", "")))
        if resource_type not in _CONSUMER_TYPES:
            continue
        if sg_id in (_value(_data(node), "sg_ids", []) or []):
            consumers.append(node)
    # Security groups referencing this SG are also consumers, matching the
    # in-use deletion guard (source and destination SG references).
    for node in graph.find_nodes_by_type("security_group"):
        if str(_value(node, "id")) == sg_id:
            continue
        if any(sg_id in (_value(rule, field, []) or [])
               for rule in (_value(_data(node), "rules", []) or []) + (_value(_data(node), "egress_rules", []) or [])
               for field in ("source_sg_ids", "dest_sg_ids")):
            consumers.append(node)
    return consumers

def _severity(protocol: str, from_port: int, to_port: int, source: str, state: str) -> str:
    if state == "latent":
        return "Moderate"
    world_open = source in {"0.0.0.0/0", "::/0"}
    if protocol == "-1" and world_open:
        return "Critical"
    classes = {PORT_CLASSES[port] for port in range(from_port, to_port + 1) if port in PORT_CLASSES}
    if world_open and (22 >= from_port and 22 <= to_port or 3389 >= from_port and 3389 <= to_port or classes & {"ADMIN", "DATABASE", "INTERNAL"}):
        return "Critical"
    if classes & {"WEB"} and not (classes & {"ADMIN", "DATABASE", "INTERNAL"}):
        return "Info"
    return "Moderate"


def _rule_exposures(sg_id: str, sg: Any, resource_id: str, resource_type: str,
                    state: str, subnet_id: str | None, graph: Any) -> list[Exposure]:
    result = []
    route = subnet_has_igw_route(subnet_id, graph) if subnet_id else None
    for rule in _value(_data(sg), "rules", []) or []:
        sources = [str(source) for source in (_value(rule, "ip_ranges", []) or []) if _external(source)]
        if not sources:
            continue
        protocol = str(_value(rule, "protocol", "-1"))
        from_port, to_port = _ports(rule)
        if state == "active":
            if route is False:
                continue
            nacl, _ = nacl_allows_inbound(subnet_id, from_port, to_port, protocol, graph) if subnet_id else (True, "assumed")
            if not nacl:
                continue
        for source in sources:
            result.append(Exposure(resource_id=resource_id, resource_type=resource_type,
                                   protocol=protocol, from_port=from_port, to_port=to_port,
                                   source=source, via_sg=sg_id, state=state,
                                   severity=_severity(protocol, from_port, to_port, source, state)))
    return result


def compute_exposures(infra: Any, graph: Any, base_infra: Any = None) -> list[Exposure]:
    """Compute active and latent external ingress exposures deterministically."""
    sg_nodes = _sg_nodes(infra, graph)
    reachable = get_internet_reachable_set(graph)
    exposures: list[Exposure] = []
    for sg_id, sg in sorted(sg_nodes.items()):
        consumers = _sg_consumers(sg_id, infra, graph)
        if not consumers and _eni_proves_unused(sg_id, infra, base_infra):
            exposures.extend(_rule_exposures(sg_id, sg, sg_id, "security_group", "latent", None, graph))
            continue
        if not consumers:
            exposures.extend(_rule_exposures(sg_id, sg, sg_id, "security_group", "active", None, graph))
            continue
        for consumer in sorted(consumers, key=lambda node: str(_value(node, "id"))):
            resource_id = str(_value(consumer, "id"))
            if resource_id not in reachable:
                continue
            data = _data(consumer)
            subnet_id = _value(data, "subnet_id")
            if not subnet_id:
                subnet_ids = _value(data, "subnet_ids", []) or []
                subnet_id = subnet_ids[0] if subnet_ids else None
            exposures.extend(_rule_exposures(
                sg_id, sg, resource_id,
                str(_value(consumer, "resource_type", _value(consumer, "type", ""))),
                "active", subnet_id, graph,
            ))
    return sorted(exposures, key=lambda item: item.model_dump_json())
