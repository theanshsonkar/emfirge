INTERNET_CIDRS = frozenset({"0.0.0.0/0", "::/0"})


def is_internet_cidr(cidr) -> bool:
    return isinstance(cidr, str) and cidr.strip() in INTERNET_CIDRS


_ALL_PROTOCOLS = frozenset({"-1", "all"})
_TCP_PROTOCOLS = frozenset({"tcp", "6"})


def rule_opens_port_to_internet(rule: dict, port: int) -> bool:
    """True when an ingress rule lets the internet reach TCP ``port``.

    Single definition of "SSH/RDP open to the internet": the source must be
    0.0.0.0/0 or ::/0, the protocol tcp or all traffic (-1), and the port
    range (FromPort..ToPort) must contain ``port``. An all-traffic rule
    carries no ports (None) and covers every port.
    """
    if not any(is_internet_cidr(cidr) for cidr in (rule.get("ip_ranges") or [])):
        return False
    protocol = rule.get("protocol")
    protocol = "tcp" if protocol is None else str(protocol).strip().lower()
    if protocol in _ALL_PROTOCOLS:
        return True
    if protocol not in _TCP_PROTOCOLS:
        return False
    try:
        start = int(rule.get("from_port", 0))
        end_value = rule.get("to_port")
        end = start if end_value is None else int(end_value)
    except (TypeError, ValueError):
        return False
    if start < 0 or end < 0:
        return False
    if start > end:
        start, end = end, start
    return start <= port <= end
