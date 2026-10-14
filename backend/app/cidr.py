INTERNET_CIDRS = frozenset({"0.0.0.0/0", "::/0"})


def is_internet_cidr(cidr) -> bool:
    return str(cidr) in INTERNET_CIDRS
