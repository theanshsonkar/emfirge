INTERNET_CIDRS = frozenset({"0.0.0.0/0", "::/0"})


def is_internet_cidr(cidr) -> bool:
    return isinstance(cidr, str) and cidr.strip() in INTERNET_CIDRS
