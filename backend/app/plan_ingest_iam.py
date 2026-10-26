"""Terraform IAM resources -> normalized role, user and instance-profile changes (AWS adapter).

What Terraform knows only after apply (arns, rendered policy documents) stays unknown: it is
reported in unknown_fields and never replaced by a guess. What AWS derives from known inputs
(a role's arn from account, path and name) is rebuilt here.
"""
from __future__ import annotations

import copy
import json
import re
from typing import Any

from app.models import AccessStatement, PolicyDocumentRecord, merge_policy_statements
from app.mutations import Change

PLACEHOLDER_ACCOUNT = "000000000000"
PLACEHOLDER_REASON = "account id unknown at plan time; placeholder used for identity only"
ADMIN_POLICY_ARN = "arn:aws:iam::aws:policy/AdministratorAccess"
_ACCOUNT_RE = re.compile(r"^\d{12}$")
_INDEX_RE = re.compile(r"\[[^\]]*\]")
_NON_RESOURCE_ROOTS = frozenset({"var", "local", "module", "each", "count", "self", "path", "terraform", "data"})

IAM_POLICY_TYPES = frozenset({
    "aws_iam_role_policy", "aws_iam_user_policy",
    "aws_iam_role_policy_attachment", "aws_iam_user_policy_attachment",
    "aws_iam_policy_attachment", "aws_iam_role_policy_attachments_exclusive",
    "aws_iam_access_key", "aws_iam_user_login_profile", "aws_iam_policy",
})
# aws_iam_policy only registers a document; the principals it reaches carry the change.


def plan_account_id(plan: dict) -> str | None:
    """Account id the plan itself knows: an aws_caller_identity data source in prior_state."""
    def walk(module: Any) -> str | None:
        if not isinstance(module, dict):
            return None
        for resource in module.get("resources") or []:
            if isinstance(resource, dict) and resource.get("type") == "aws_caller_identity":
                account = (resource.get("values") or {}).get("account_id")
                if isinstance(account, str) and _ACCOUNT_RE.match(account):
                    return account
        for child in module.get("child_modules") or []:
            found = walk(child)
            if found:
                return found
        return None
    prior = plan.get("prior_state")
    values = prior.get("values") if isinstance(prior, dict) else None
    return walk((values or {}).get("root_module")) if isinstance(values, dict) else None


def _get(obj: Any, name: str, default: Any = None) -> Any:
    return obj.get(name, default) if isinstance(obj, dict) else getattr(obj, name, default)


def iam_context(plan: dict, iam_roles: Any) -> dict[str, Any]:
    """Which account id Terraform-created IAM identities get, and where it came from."""
    accounts = set()
    for role in iam_roles or []:
        arn = _get(role, "role_arn")
        parts = arn.split(":") if isinstance(arn, str) else []
        if len(parts) > 4 and _ACCOUNT_RE.match(parts[4]):
            accounts.add(parts[4])
    if len(accounts) == 1:
        return {"account": next(iter(accounts)), "source": "base"}
    account = plan_account_id(plan)
    if account:
        return {"account": account, "source": "plan"}
    return {"account": PLACEHOLDER_ACCOUNT, "source": "placeholder"}


def _is_unknown(after_unknown: Any, field: str) -> bool:
    if isinstance(after_unknown, dict):
        return bool(after_unknown.get(field))
    return isinstance(after_unknown, list) and field in after_unknown


def identity_arn(item: dict, iam: dict[str, Any], unknown: list[dict], kind: str) -> str | None:
    """The ARN of a role, policy or instance profile being created.

    AWS builds it from account, path and name; Terraform leaves it unknown until apply, so it is
    rebuilt here. None when the name or path is itself unknown.
    """
    change = item.get("change") or {}
    after, after_unknown = change.get("after") or {}, change.get("after_unknown") or {}
    address = item.get("address", "")
    arn = after.get("arn")
    if isinstance(arn, str) and arn.startswith("arn:") and not _is_unknown(after_unknown, "arn"):
        return arn
    name = after.get("name")
    if _is_unknown(after_unknown, "name") or not isinstance(name, str) or not name:
        unknown.append({"address": address, "field": "name", "reason": "unknown Terraform value"})
        return None
    path = after.get("path", "/")
    if _is_unknown(after_unknown, "path") or not isinstance(path, str) or not path.startswith("/") or not path.endswith("/"):
        unknown.append({"address": address, "field": "path", "reason": "unknown Terraform value"})
        return None
    if iam["source"] == "placeholder":
        unknown.append({"address": address, "field": "arn", "reason": PLACEHOLDER_REASON})
    return f"arn:aws:iam::{iam['account']}:{kind}{path}{name}"


def _unknown_map(change: dict) -> dict:
    value = change.get("after_unknown")
    if isinstance(value, list):
        return {field: True for field in value if isinstance(field, str)}
    return value if isinstance(value, dict) else {}


def _module_key(address: Any) -> str:
    return _INDEX_RE.sub("", address) if isinstance(address, str) else ""


class ConfigIndex:
    """plan.configuration resources, so an attribute Terraform leaves unknown can still be traced
    to the resource it references (policy_arn = aws_iam_policy.x.arn)."""

    def __init__(self, plan: dict):
        self.resources: dict[tuple[str, str], dict] = {}

        def walk(module: Any, prefix: str) -> None:
            if not isinstance(module, dict):
                return
            for resource in module.get("resources") or []:
                if isinstance(resource, dict) and resource.get("mode", "managed") == "managed":
                    self.resources[(prefix, f"{resource.get('type')}.{resource.get('name')}")] = resource
            for name, call in (module.get("module_calls") or {}).items():
                walk((call or {}).get("module"), f"{prefix}.module.{name}" if prefix else f"module.{name}")

        walk((plan.get("configuration") or {}).get("root_module"), "")

    def expression(self, item: dict, attr: str) -> dict:
        config = self.resources.get((_module_key(item.get("module_address")), f"{item.get('type')}.{item.get('name')}")) or {}
        value = (config.get("expressions") or {}).get(attr)
        return value if isinstance(value, dict) else {}

    def bases(self, item: dict, attr: str) -> list[tuple[str, str]]:
        """Distinct (module, 'type.name') resources an attribute's expression references."""
        module = _module_key(item.get("module_address"))
        result: list[tuple[str, str]] = []
        for reference in self.expression(item, attr).get("references") or []:
            if not isinstance(reference, str):
                continue
            tokens = [_INDEX_RE.sub("", part) for part in reference.split(".")]
            if len(tokens) < 2 or tokens[0] in _NON_RESOURCE_ROOTS:
                continue
            key = (module, f"{tokens[0]}.{tokens[1]}")
            if key not in result:
                result.append(key)
        return result


def _normalize_statements(document: Any) -> list[AccessStatement]:
    from app.aws_api_ingest import _policy_statements
    return _policy_statements(document)


def _record_dump(record: PolicyDocumentRecord) -> dict:
    return record.model_dump(mode="json")


def _record_key(record: PolicyDocumentRecord) -> tuple:
    return (record.kind, record.arn if record.kind == "managed" else record.name)


class IamModel:
    """Registry of the IAM resources a plan creates and the permissions flowing to roles and users."""

    def __init__(self, plan: dict, iam: dict[str, Any], base_roles: Any = None, base_users: Any = None,
                 base_profiles: Any = None):
        self.iam = iam
        self.config = ConfigIndex(plan)
        self.base_roles = {}
        self.base_roles_by_name: dict[str, list[str]] = {}
        for role in base_roles or []:
            arn, name = _get(role, "role_arn"), _get(role, "role_name")
            if isinstance(arn, str):
                self.base_roles[arn] = role
                self.base_roles_by_name.setdefault(str(name), []).append(arn)
        self.base_users = {_get(user, "username"): user for user in (base_users or []) if _get(user, "username")}
        self.base_profiles: dict[str, Any] = dict(base_profiles or {})
        self.roles: dict[tuple[str, str], list[dict]] = {}
        self.users: dict[tuple[str, str], list[dict]] = {}
        self.policies: dict[tuple[str, str], list[dict]] = {}
        self.profiles: dict[tuple[str, str], list[dict]] = {}
        self.role_by_name: dict[str, str | None] = {}
        self.policy_by_arn: dict[str, dict] = {}
        self.profile_by_name: dict[str, str | None] = {}
        self.user_names: set[str] = set()
        self.by_address: dict[str, dict] = {}
        self.contribs: list[dict] = []
        for item in plan.get("resource_changes") or []:
            if isinstance(item, dict) and isinstance(item.get("change"), dict):
                self._register(item)

    # ------------------------------------------------------------------ registry
    def _register(self, item: dict) -> None:
        if item.get("mode", "managed") != "managed":
            return
        typ = item.get("type")
        change = item["change"]
        actions = change.get("actions") or []
        if actions == ["delete"] or typ not in {"aws_iam_role", "aws_iam_user", "aws_iam_policy", "aws_iam_instance_profile"}:
            return
        after, after_unknown = change.get("after") or {}, change.get("after_unknown") or {}
        key = (_module_key(item.get("module_address")), f"{typ}.{item.get('name')}")
        created = "create" in actions
        notes: list[dict] = []
        if typ == "aws_iam_user":
            name = after.get("name")
            if isinstance(name, str) and name and not _is_unknown(after_unknown, "name"):
                entry = {"name": name, "created": created, "address": item.get("address")}
                self.users.setdefault(key, []).append(entry)
                self.user_names.add(name)
                self.by_address[item.get("address", "")] = entry
            return
        kind = {"aws_iam_role": "role", "aws_iam_policy": "policy", "aws_iam_instance_profile": "instance-profile"}[typ]
        arn = identity_arn(item, self.iam, notes, kind)
        if arn is None:
            return
        name = after.get("name")
        entry = {"arn": arn, "name": name, "created": created, "address": item.get("address"), "notes": notes, "item": item}
        self.by_address[item.get("address", "")] = entry
        if typ == "aws_iam_role":
            self.roles.setdefault(key, []).append(entry)
            self.role_by_name[name] = arn if name not in self.role_by_name or self.role_by_name[name] == arn else None
        elif typ == "aws_iam_instance_profile":
            self.profiles.setdefault(key, []).append(entry)
            self.profile_by_name[name] = arn if name not in self.profile_by_name or self.profile_by_name[name] == arn else None
        else:
            entry["statements"] = None
            if not _is_unknown(after_unknown, "policy") and after.get("policy") is not None:
                try:
                    entry["statements"] = _normalize_statements(after["policy"])
                except Exception:  # noqa: BLE001 - an unreadable document stays unknown
                    entry["statements"] = None
            self.policies.setdefault(key, []).append(entry)
            self.policy_by_arn[arn] = entry

    # ------------------------------------------------------------------ lookups
    @staticmethod
    def _after_value(item: dict, attr: str) -> tuple[Any, bool]:
        change = item.get("change") or {}
        after = change.get("after") or {}
        if attr not in after or _is_unknown(change.get("after_unknown") or {}, attr):
            return None, False
        return after[attr], True

    def _by_reference(self, item: dict, attr: str, table: dict[tuple[str, str], list[dict]]) -> dict | None:
        found: list[dict] = []
        for base in self.config.bases(item, attr):
            found.extend(table.get(base, []))
        return found[0] if len(found) == 1 else None

    def role_arn(self, item: dict, attr: str) -> str | None:
        """The role an attribute (a role name, or an arn) points to."""
        value, known = self._after_value(item, attr)
        if known and isinstance(value, str) and value:
            if value.startswith("arn:"):
                return value
            planned = self.role_by_name.get(value)
            if planned:
                return planned
            base = self.base_roles_by_name.get(value, [])
            return base[0] if len(base) == 1 else None
        entry = self._by_reference(item, attr, self.roles)
        return entry["arn"] if entry else None

    def user_name(self, item: dict, attr: str) -> str | None:
        value, known = self._after_value(item, attr)
        if known and isinstance(value, str) and value:
            return value
        entry = self._by_reference(item, attr, self.users)
        return entry["name"] if entry else None

    def _principals_from_list(self, item: dict, attr: str, resolve_one) -> tuple[list[str], bool]:
        """(principals, complete) for a list attribute such as aws_iam_policy_attachment.roles."""
        change = item.get("change") or {}
        values = (change.get("after") or {}).get(attr)
        unknown = _unknown_map(change).get(attr)
        if unknown is True or (isinstance(unknown, list) and any(unknown)):
            result = []
            for base in self.config.bases(item, attr):
                for table in (self.roles, self.users):
                    for entry in table.get(base, []):
                        resolved = resolve_one(entry)
                        if resolved:
                            result.append(resolved)
            return result, False
        return [value for value in values or [] if isinstance(value, str)], True

    def managed_record(self, item: dict, attr: str, address: str, unknown: list[dict]) -> tuple[PolicyDocumentRecord | None, dict | None]:
        """(record, plan policy entry) for the policy an attachment points to."""
        value, known = self._after_value(item, attr)
        entry = None
        if known and isinstance(value, str) and value:
            arn = value
            entry = self.policy_by_arn.get(arn)
        else:
            entry = self._by_reference(item, attr, self.policies)
            arn = entry["arn"] if entry else None
        if arn is None:
            unknown.append({"address": address, "field": attr, "reason": "unknown Terraform value"})
            return None, None
        if arn == ADMIN_POLICY_ARN:
            statements = [AccessStatement(effect="allow", actions=["*"], resources=["*"])]
            return PolicyDocumentRecord(name="AdministratorAccess", kind="managed", arn=arn, statements=statements), entry
        if entry is not None:
            if entry["statements"] is None:
                unknown.append({"address": address, "field": "policy", "reason": "unknown Terraform value"})
                return None, entry
            return PolicyDocumentRecord(name=entry["name"] or arn.rsplit("/", 1)[-1], kind="managed", arn=arn,
                                        statements=copy.deepcopy(entry["statements"])), entry
        for role in self.base_roles.values():
            for record in _get(role, "policy_documents") or []:
                if _get(record, "arn") == arn:
                    return PolicyDocumentRecord.model_validate(record.model_dump() if hasattr(record, "model_dump") else record), None
        unknown.append({"address": address, "field": attr,
                        "reason": "managed policy contents are not in the plan or the snapshot"})
        return None, None

    # ------------------------------------------------------------------ resource handlers
    def identity(self, address: str) -> tuple[str | None, list[dict]]:
        entry = self.by_address.get(address)
        return (entry["arn"], entry["notes"]) if entry else (None, [])

    def profile_arn_for_instance(self, item: dict, unknown: list[dict]) -> str | None:
        address = item.get("address", "")
        value, known = self._after_value(item, "iam_instance_profile")
        if known:
            if not isinstance(value, str) or not value:
                return None
            if value.startswith("arn:"):
                return value
            planned = self.profile_by_name.get(value)
            if planned:
                return planned
            matches = sorted(key for key in self.base_profiles if isinstance(key, str) and key.startswith("arn:")
                             and key.rsplit("/", 1)[-1] == value)
            if len(matches) == 1:
                return matches[0]
        else:
            entry = self._by_reference(item, "iam_instance_profile", self.profiles)
            if entry:
                return entry["arn"]
        unknown.append({"address": address, "field": "iam_instance_profile",
                        "reason": "profile arn unknown at plan time" if not known else "profile not found in the plan or the snapshot"})
        return None

    def profile_change(self, item: dict, unknown: list[dict]) -> tuple[list[Change], dict | None]:
        address = item.get("address", "")
        actions = (item.get("change") or {}).get("actions") or []
        arn, notes = self.identity(address)
        if actions != ["create"] or arn is None:
            return [], self._unmodeled(item, "an instance profile can be created here, not changed or removed" if arn else
                                       "the profile name or path is unknown at plan time", unseen=False)
        unknown.extend(notes)
        role_arn = self.role_arn(item, "role")
        fields: dict[str, Any] = {}
        if role_arn:
            fields["role_arn"] = role_arn
        else:
            unknown.append({"address": address, "field": "role", "reason": "role unknown at plan time"})
        return [Change(op="add", resource_type="iam_instance_profile", resource_id=arn, fields=fields)], None

    @staticmethod
    def _unmodeled(item: dict, detail: str, *, unseen: bool = True) -> dict:
        provider = item.get("provider_name")
        result = {"address": item.get("address", ""), "type": item.get("type", ""),
                  "actions": (item.get("change") or {}).get("actions", []),
                  "provider_name": provider if isinstance(provider, str) else None,
                  "outside_view": False, "detail": detail}
        if unseen:
            result["unseen"] = True
        return result

    def handle(self, item: dict, unknown: list[dict], unmodeled: list[dict]) -> None:
        """Record the permission changes one IAM resource makes; changes are built by finalize()."""
        typ = item.get("type")
        change = item.get("change") or {}
        actions = change.get("actions") or []
        if typ == "aws_iam_policy" or actions in (["no-op"], ["read"]):
            return
        address = item.get("address", "")
        before, after = change.get("before") or {}, change.get("after") or {}
        removing = [side for side in (before,) if "delete" in actions or "update" in actions]
        adding = "create" in actions or "update" in actions
        if typ in {"aws_iam_role_policy", "aws_iam_user_policy"}:
            kind, attr = ("role", "role") if typ == "aws_iam_role_policy" else ("user", "user")
            for old in removing:
                principal = self._before_principal(kind, old.get(attr))
                if principal and old.get("name") is not None:
                    self._contribute(item, "remove", principal, ("inline", old["name"]), None)
            if adding:
                principal = self._principal(item, kind, attr)
                if principal is None:
                    unmodeled.append(self._unmodeled(item, f"the {kind} this policy belongs to is unknown at plan time"))
                    return
                self._inline_policy(item, principal, after, unknown)
        elif typ in {"aws_iam_role_policy_attachment", "aws_iam_user_policy_attachment"}:
            kind, attr = ("role", "role") if typ == "aws_iam_role_policy_attachment" else ("user", "user")
            for old in removing:
                principal = self._before_principal(kind, old.get(attr))
                if principal and old.get("policy_arn"):
                    self._contribute(item, "remove", principal, ("managed", old["policy_arn"]), None)
            if adding:
                principal = self._principal(item, kind, attr)
                if principal is None:
                    unmodeled.append(self._unmodeled(item, f"the {kind} this policy is attached to is unknown at plan time"))
                    return
                self._attach(item, principal, "policy_arn", unknown)
        elif typ == "aws_iam_role_policy_attachments_exclusive":
            if adding:
                principal = self._principal(item, "role", "role_name")
                if principal is None:
                    unmodeled.append(self._unmodeled(item, "the role is unknown at plan time"))
                    return
                self._attach_many(item, principal, "policy_arns", unknown)
        elif typ == "aws_iam_policy_attachment":
            if adding:
                roles, roles_complete = self._principals_from_list(item, "roles", lambda e: e.get("arn") if "arn" in e else None)
                users, users_complete = self._principals_from_list(item, "users", lambda e: e.get("name") if "arn" not in e else None)
                resolved = []
                for name in roles:
                    arn = name if name.startswith("arn:") else (self.role_by_name.get(name) or (self.base_roles_by_name.get(name) or [None])[0])
                    if arn:
                        resolved.append(("role", arn))
                    else:
                        unknown.append({"address": address, "field": "roles", "reason": "role not found in the plan or the snapshot"})
                resolved.extend(("user", name) for name in users)
                if not (roles_complete and users_complete):
                    unknown.append({"address": address, "field": "roles/users", "reason": "unknown Terraform value"})
                if (after.get("groups") or _is_unknown(change.get("after_unknown") or {}, "groups")):
                    unknown.append({"address": address, "field": "groups", "reason": "unsupported_attribute"})
                if not resolved:
                    unmodeled.append(self._unmodeled(item, "no role or user this policy is attached to could be resolved"))
                    return
                for principal in resolved:
                    self._attach(item, principal, "policy_arn", unknown)
        elif typ == "aws_iam_access_key":
            if adding:
                name = self.user_name(item, "user")
                if name is None:
                    unmodeled.append(self._unmodeled(item, "the user this key belongs to is unknown at plan time"))
                    return
                self._contribute(item, "flag", ("user", name), "has_access_keys", None)
        elif typ == "aws_iam_user_login_profile":
            if adding:
                name = self.user_name(item, "user")
                if name is None:
                    unmodeled.append(self._unmodeled(item, "the user this login belongs to is unknown at plan time"))
                    return
                self._contribute(item, "flag", ("user", name), "has_console_access", None)

    def role_inline_blocks(self, item: dict, arn: str, unknown: list[dict]) -> None:
        """aws_iam_role's own inline_policy blocks and managed_policy_arns (create only)."""
        change = item.get("change") or {}
        after, after_unknown = change.get("after") or {}, _unknown_map(change)
        address = item.get("address", "")
        blocks = after.get("inline_policy") or []
        unknown_blocks = after_unknown.get("inline_policy")
        if unknown_blocks is True:
            unknown.append({"address": address, "field": "inline_policy", "reason": "unknown Terraform value"})
            blocks = []
        for index, block in enumerate(blocks):
            if not isinstance(block, dict) or not block.get("name"):
                continue
            block_unknown = unknown_blocks[index] if isinstance(unknown_blocks, list) and index < len(unknown_blocks) else {}
            if _is_unknown(block_unknown if isinstance(block_unknown, dict) else {}, "policy") or block.get("policy") is None:
                unknown.append({"address": address, "field": f"inline_policy[{index}].policy", "reason": "unknown Terraform value"})
                continue
            self._inline_policy(item, ("role", arn), {"name": block["name"], "policy": block["policy"]}, unknown)
        arns = after.get("managed_policy_arns")
        if _is_unknown(after_unknown, "managed_policy_arns") and after_unknown.get("managed_policy_arns") is True:
            self._attach_refs(item, ("role", arn), "managed_policy_arns", unknown)
        else:
            for policy_arn in arns or []:
                if isinstance(policy_arn, str):
                    self._attach_known(item, ("role", arn), policy_arn, unknown)

    # ------------------------------------------------------------------ contributions
    def _principal(self, item: dict, kind: str, attr: str) -> tuple[str, str] | None:
        if kind == "role":
            arn = self.role_arn(item, attr)
            return ("role", arn) if arn else None
        name = self.user_name(item, attr)
        return ("user", name) if name else None

    def _before_principal(self, kind: str, value: Any) -> tuple[str, str] | None:
        if not isinstance(value, str) or not value:
            return None
        if kind == "user":
            return ("user", value)
        arn = value if value.startswith("arn:") else self.role_by_name.get(value) or (self.base_roles_by_name.get(value) or [None])[0]
        return ("role", arn) if arn else None

    def _contribute(self, item: dict, op: str, principal: tuple[str, str], key: Any, record: PolicyDocumentRecord | None,
                    policy_entry: dict | None = None) -> None:
        self.contribs.append({"item": item, "op": op, "principal": principal, "key": key, "record": record,
                              "policy_entry": policy_entry})

    def _inline_policy(self, item: dict, principal: tuple[str, str], values: dict, unknown: list[dict]) -> None:
        address = item.get("address", "")
        change = item.get("change") or {}
        policy_unknown = _is_unknown(change.get("after_unknown") or {}, "policy") and item.get("type") != "aws_iam_role"
        name = values.get("name")
        if name is None or _is_unknown(change.get("after_unknown") or {}, "name") and item.get("type") != "aws_iam_role":
            name = f"terraform:{address}"
        if policy_unknown or values.get("policy") is None:
            unknown.append({"address": address, "field": "policy", "reason": "unknown Terraform value"})
            return
        try:
            statements = _normalize_statements(values["policy"])
        except Exception:  # noqa: BLE001
            unknown.append({"address": address, "field": "policy", "reason": "invalid JSON"})
            return
        record = PolicyDocumentRecord(name=str(name), kind="inline", arn=None, statements=statements)
        self._contribute(item, "add", principal, _record_key(record), record)

    def _attach(self, item: dict, principal: tuple[str, str], attr: str, unknown: list[dict]) -> None:
        address = item.get("address", "")
        record, entry = self.managed_record(item, attr, address, unknown)
        if record is not None:
            self._contribute(item, "add", principal, _record_key(record), record, entry)

    def _attach_known(self, item: dict, principal: tuple[str, str], policy_arn: str, unknown: list[dict]) -> None:
        fake = {**item, "change": {"after": {"policy_arn": policy_arn}, "after_unknown": {}}}
        record, entry = self.managed_record(fake, "policy_arn", item.get("address", ""), unknown)
        if record is not None:
            self._contribute(item, "add", principal, _record_key(record), record, entry)

    def _attach_refs(self, item: dict, principal: tuple[str, str], attr: str, unknown: list[dict]) -> None:
        address = item.get("address", "")
        bases = self.config.bases(item, attr)
        if not bases:
            unknown.append({"address": address, "field": attr, "reason": "unknown Terraform value"})
            return
        for base in bases:
            for entry in self.policies.get(base, []):
                fake = {**item, "change": {"after": {"policy_arn": entry["arn"]}, "after_unknown": {}}}
                record, found = self.managed_record(fake, "policy_arn", address, unknown)
                if record is not None:
                    self._contribute(item, "add", principal, _record_key(record), record, found)

    def _attach_many(self, item: dict, principal: tuple[str, str], attr: str, unknown: list[dict]) -> None:
        change = item.get("change") or {}
        after_unknown = _unknown_map(change)
        if after_unknown.get(attr) is True or (isinstance(after_unknown.get(attr), list) and any(after_unknown[attr])):
            self._attach_refs(item, principal, attr, unknown)
            return
        for policy_arn in (change.get("after") or {}).get(attr) or []:
            if isinstance(policy_arn, str):
                self._attach_known(item, principal, policy_arn, unknown)

    # ------------------------------------------------------------------ emission
    def finalize(self, unknown: list[dict], unmodeled: list[dict]) -> list[tuple[Change, str, dict]]:
        """One change per contribution, each carrying the principal's complete permissions so far."""
        out: list[tuple[Change, str, dict]] = []
        states: dict[tuple[str, str], dict | None] = {}
        claimed: set[str] = set()

        for contrib in self.contribs:
            item, principal = contrib["item"], contrib["principal"]
            address = item.get("address", "")
            if contrib["op"] == "flag":
                if not self._user_exists(principal[1]):
                    unmodeled.append(self._unmodeled(item, f"the user {principal[1]} is not in the snapshot or created by this plan"))
                    continue
                change = Change(op="modify", resource_type="iam_user", resource_id=principal[1], fields={contrib["key"]: True})
                out.append((change, address, item))
                continue
            if principal not in states:
                states[principal] = self._initial_state(principal)
            state = states[principal]
            if state is None:
                unmodeled.append(self._unmodeled(
                    item, f"the {principal[0]} {principal[1].rsplit('/', 1)[-1]} is not in the snapshot or created by this plan, "
                    "or its current permissions were not collected"))
                continue
            if contrib["op"] == "add":
                record = contrib["record"]
                if state["mode"] == "docs":
                    state["records"] = [r for r in state["records"] if _record_key(r) != _record_key(record)] + [record]
                else:
                    seen = {json.dumps(s.model_dump(mode="json"), sort_keys=True) for s in state["statements"]}
                    for statement in record.statements:
                        dump = json.dumps(statement.model_dump(mode="json"), sort_keys=True)
                        if dump not in seen:
                            seen.add(dump)
                            state["statements"].append(statement)
            else:
                if state["mode"] != "docs":
                    unmodeled.append(self._unmodeled(item, "a policy cannot be removed from a principal whose policy documents were not recorded"))
                    continue
                before = len(state["records"])
                state["records"] = [r for r in state["records"] if _record_key(r) != tuple(contrib["key"])]
                if len(state["records"]) == before:
                    unknown.append({"address": address, "field": "policy", "reason": "no_matching_policy"})
                    continue
            change = self._change(principal, state)
            out.append((change, address, item))
            entry = contrib["policy_entry"]
            if entry is not None and entry["address"] not in claimed:
                claimed.add(entry["address"])
                out.append((change.model_copy(deep=True), entry["address"], entry["item"]))
        return out

    def _user_exists(self, name: str) -> bool:
        return name in self.base_users or name in self.user_names

    def _initial_state(self, principal: tuple[str, str]) -> dict | None:
        kind, ident = principal
        if kind == "role":
            created = any(e["arn"] == ident and e["created"] for entries in self.roles.values() for e in entries)
            base = self.base_roles.get(ident)
            if created and base is None:
                return {"mode": "docs", "records": [], "flags": {}}
        else:
            created = any(e["name"] == ident and e["created"] for entries in self.users.values() for e in entries)
            base = self.base_users.get(ident)
            if created and base is None:
                return {"mode": "docs", "records": [], "flags": {}}
        if base is None:
            return None
        documents = _get(base, "policy_documents")
        if documents is not None:
            records = [PolicyDocumentRecord.model_validate(d.model_dump() if hasattr(d, "model_dump") else d) for d in documents]
            return {"mode": "docs", "records": records, "flags": {}}
        statements = _get(base, "access_statements")
        if statements is None:
            return None
        return {"mode": "statements", "flags": {},
                "statements": [AccessStatement.model_validate(s.model_dump() if hasattr(s, "model_dump") else s) for s in statements]}

    @staticmethod
    def _change(principal: tuple[str, str], state: dict) -> Change:
        if state["mode"] == "docs":
            records = sorted(state["records"], key=lambda r: (r.kind, r.name, r.arn or ""))
            fields: dict[str, Any] = {"policy_documents": [_record_dump(r) for r in records],
                                      "access_statements": [s.model_dump(mode="json") for s in merge_policy_statements(records)]}
        else:
            fields = {"access_statements": [s.model_dump(mode="json") for s in state["statements"]]}
        if principal[0] == "role":
            return Change(op="modify", resource_type="iam_role_policy", resource_id=principal[1], fields=fields)
        return Change(op="modify", resource_type="iam_user", resource_id=principal[1], fields=fields)
