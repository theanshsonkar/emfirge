"""Customer identifier extraction and stable tokenization for LLM-bound data."""

IDENTIFIER_KEYS = {
    "id", "name", "arn", "role_arn", "role_name", "instance_profile_arn",
    "allocation_id", "public_ip", "attached_to", "target_instances", "resources",
    "policy_arn", "function_name", "bucket", "bucket_name",
}
NOT_IDENTIFIERS = {"*", "local", "0.0.0.0/0", "::/0"}


def _is_identifier_key(key: str) -> bool:
    return (
        key in IDENTIFIER_KEYS
        or key.endswith("_id")
        or key.endswith("_ids")
        or key.endswith("_arn")
        or key.endswith("_arns")
    )


def customer_identifiers(infra, account_id=None) -> list[str]:
    """Collect customer-owned identifiers from an infrastructure model."""
    identifiers = set()

    def add(value):
        if isinstance(value, str) and len(value) >= 3 and value not in NOT_IDENTIFIERS:
            identifiers.add(value)

    def walk(value):
        if isinstance(value, dict):
            for key, child in value.items():
                if _is_identifier_key(key):
                    if isinstance(child, str):
                        add(child)
                    elif isinstance(child, list):
                        for item in child:
                            add(item)
                walk(child)
        elif isinstance(value, list):
            for child in value:
                walk(child)

    walk(infra.model_dump(mode="json"))
    if account_id is not None:
        add(str(account_id))
    return sorted(identifiers, key=lambda value: (-len(value), value))


def tokenize(text: str, identifiers: list[str]) -> str:
    """Replace identifiers with stable, deterministic resource tokens."""
    ordered = sorted(set(identifiers), key=lambda value: (-len(value), value))
    for number, identifier in enumerate(ordered, 1):
        text = text.replace(identifier, f"res-{number}")
    return text


def tokenize_obj(obj, identifiers: list[str]):
    """Recursively tokenize strings in a JSON-compatible object."""
    if isinstance(obj, str):
        return tokenize(obj, identifiers)
    if isinstance(obj, dict):
        return {key: tokenize_obj(value, identifiers) for key, value in obj.items()}
    if isinstance(obj, list):
        return [tokenize_obj(value, identifiers) for value in obj]
    return obj
