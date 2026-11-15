"""Build step: compile AWS's published lists into one catalog file. Run by hand when AWS publishes new services.

    python -m emfirge.aws.catalog.compile --svcref DIR --cfn DIR --out src/emfirge/aws/data/catalog.json.gz

Inputs, all published by AWS, none edited:
  --svcref   the Service Authorization Reference, one <prefix>.json per IAM service prefix: what each action is
             (read, list, write, permission, tagging, data plane), which resource types it acts on, their ARN
             formats, and which actions each SDK operation needs.
  --cfn      the CloudFormation resource schemas: which settings are write-only, whether the id is given by the
             service, which actions read / create / update / delete a resource.
  botocore   the SDK's service models (installed): the operations and their request members.

There is no code per service here. Every rule runs the same way for all 400+ services; what cannot be told stays
'unknown' or unbound, and the runtime catalog then says so (complete=False).

Output layout (gzip JSON). The per-service and per-type parts are JSON strings, decoded only when first used:
  {"format": 1, "built_from": {...},
   "services": {"<botocore service>": "<json: {op: entry}>"},
   "types":    {"<prefix>": "<json: {name: info}>"},
   "arn_services": {"<service in ARNs>": ["<prefix>", ...]}}
"""
from __future__ import annotations

import argparse
import collections
import gzip
import html
import json
import os
import re
import sys
from dataclasses import dataclass, field
from typing import Any, Iterable

import botocore
import botocore.session
from botocore import xform_name

from .arns import ArnFormat, compile_format, parent_of
from .names import Member, arn_member, bind_vars, split

KIND_ORDER = ('read', 'list', 'tagging', 'write', 'permission')   # how much a call changes, least first
READ_VERBS = ('Get', 'Describe', 'List')


def kind_of(props: dict[str, Any]) -> str:
    """The reference's annotations -> a core Kind value. Permission and tagging are narrower kinds of write."""
    if props.get('IsPermissionManagement'):
        return 'permission'
    if props.get('IsTaggingOnly'):
        return 'tagging'
    if props.get('IsWrite'):
        return 'write'
    if props.get('IsList'):
        return 'list'
    return 'read'


def shape(arn_format: str) -> str:
    """An ARN format with its variables' names left out: role/${RoleName} and role/${RoleNameWithPath} agree."""
    return re.sub(r'\$\{\w+\}', '${}', arn_format)


def squash(text: str) -> str:
    return re.sub(r'[^a-z0-9]', '', text.lower())


# ------------------------------------------------------------------ inputs
def load_json_dir(path: str) -> Iterable[dict[str, Any]]:
    for name in sorted(os.listdir(path)):
        if name.endswith('.json'):
            with open(os.path.join(path, name)) as f:
                yield json.load(f)


@dataclass
class TypeInfo:
    """One resource type, canonical across the reference (events lists kms:key too; it is kms's type)."""
    id: str
    prefix: str
    name: str
    formats: list[ArnFormat] = field(default_factory=list)
    parent: str | None = None
    data_plane: bool = False
    cfn: dict[str, Any] | None = None


class Reference:
    """The Service Authorization Reference, indexed: actions per prefix, canonical resource types, SDK mapping."""

    def __init__(self, docs: Iterable[dict[str, Any]]):
        self.docs = {d['Name']: d for d in docs}
        self.actions = {p: {a['Name']: a for a in d.get('Actions', [])} for p, d in self.docs.items()}
        self.types: dict[str, TypeInfo] = {}
        self.alias: dict[tuple[str, str], str] = {}
        self.sdk: dict[tuple[str, str], tuple[str, dict[str, Any]]] = {}
        self._build_types()
        self._build_sdk()
        self._mark_data_plane()

    def _build_types(self) -> None:
        """A resource listed by a service that is not its owner (events lists kms's key, ssm lists iam's role as
        role/${RoleName}) is the owner's type: same ARN shape, variables aside, in the service the ARN names."""
        owner: dict[str, str] = {}
        for prefix, doc in self.docs.items():
            for r in doc.get('Resources', []):
                for text in r.get('ARNFormats', []):
                    if text.split(':')[2:3] == [prefix]:
                        owner.setdefault(shape(text), f"{prefix}:{r['Name']}")
        for prefix, doc in self.docs.items():
            for r in doc.get('Resources', []):
                texts = r.get('ARNFormats', [])
                foreign = [t for t in texts if t.split(':')[2:3] != [prefix] and shape(t) in owner]
                tid = owner[shape(foreign[0])] if foreign and len(foreign) == len(texts) else f"{prefix}:{r['Name']}"
                self.alias[(prefix, r['Name'])] = tid
                if tid not in self.types:
                    p, n = tid.split(':', 1)
                    self.types[tid] = TypeInfo(tid, p, n)
                info = self.types[tid]
                if tid.split(':', 1)[0] != prefix:
                    continue          # the owner's own formats describe it
                for t in texts:
                    if t not in [f.text for f in info.formats]:
                        f = compile_format(tid, t)
                        if f:
                            info.formats.append(f)
        all_formats = [f for t in self.types.values() for f in t.formats]
        by_service = collections.defaultdict(list)
        for f in all_formats:
            by_service[f.service].append(f)
        for t in self.types.values():
            if t.formats:
                t.parent = parent_of(t.formats[0], by_service[t.formats[0].service])

    def _build_sdk(self) -> None:
        for prefix, doc in self.docs.items():
            for o in doc.get('Operations', []):
                for s in o.get('SDK', []):
                    if s.get('Package') == 'Boto3':
                        self.sdk.setdefault((s['Name'], s['Method']), (prefix, o))

    def _mark_data_plane(self) -> None:
        for prefix, acts in self.actions.items():
            for a in acts.values():
                if a.get('Annotations', {}).get('Properties', {}).get('IsDataPlane'):
                    for r in a.get('Resources', []):
                        tid = self.alias.get((prefix, r['Name']))
                        if tid:
                            self.types[tid].data_plane = True

    def resources_of(self, prefix: str, action: dict[str, Any]) -> list[str]:
        out = []
        for r in action.get('Resources', []):
            tid = self.alias.get((prefix, r['Name']))
            if tid and tid not in out:
                out.append(tid)
        return out

    def holds_data(self, tid: str) -> bool:
        """The type, or a type inside it in the ARN hierarchy (an object in a bucket), has data-plane actions."""
        return any(self.types[t].data_plane for t in self.types if self._within(t, tid))

    def _within(self, tid: str, ancestor: str) -> bool:
        seen = 0
        while tid and seen < 10:
            if tid == ancestor:
                return True
            tid, seen = self.types[tid].parent, seen + 1
        return False


@dataclass
class MainAction:
    prefix: str
    name: str
    action: dict[str, Any]

    @property
    def props(self) -> dict[str, Any]:
        return self.action.get('Annotations', {}).get('Properties', {})


def main_action(ref: Reference, service: str, op: str, metadata: dict[str, Any]) -> MainAction | None:
    """The action that decides what an operation is. The reference lists every action an operation needs
    (UpdateFunctionConfiguration needs iam:PassRole too); the one named like the operation, in its own service,
    decides; then one named in the same words (DeleteObjects -> DeleteObject). Without one: the most changing action
    of its own service, then of any service, so that a call is never taken for less than it may do."""
    hit = ref.sdk.get((service, xform_name(op)))
    if hit:
        prefix, entry = hit
        authorized = [a for a in entry.get('AuthorizedActions', []) if a['Name'] in ref.actions.get(a['Service'], {})]
        same = [a for a in authorized if a['Service'] == prefix and a['Name'] == op]
        alike = [a for a in authorized if a['Service'] == prefix and split(a['Name']).words == split(op).words]
        own = [a for a in authorized if a['Service'] == prefix]
        for group in (same, alike, own, authorized):
            if group:
                a = max(group, key=lambda a: KIND_ORDER.index(kind_of(_props(ref, a))))
                return MainAction(a['Service'], a['Name'], ref.actions[a['Service']][a['Name']])
    for prefix in (metadata.get('signingName'), metadata.get('endpointPrefix'), service):
        if prefix in ref.actions and op in ref.actions[prefix]:
            return MainAction(prefix, op, ref.actions[prefix][op])
    return None


def _props(ref: Reference, a: dict[str, Any]) -> dict[str, Any]:
    return ref.actions[a['Service']][a['Name']].get('Annotations', {}).get('Properties', {})


# ------------------------------------------------------------------ CloudFormation
class CloudFormation:
    """CloudFormation schemas, each tied to the reference's resource types it describes."""

    def __init__(self, schemas: Iterable[dict[str, Any]], ref: Reference):
        self.by_type: dict[str, dict[str, Any]] = {}
        schemas = list(schemas)
        for exact in (True, False):   # a type named exactly like a schema keeps that schema
            for s in schemas:
                for tid in self._types_for(s, ref, exact):
                    self.by_type.setdefault(tid, s)

    @staticmethod
    def _perms(schema: dict[str, Any], handler: str) -> set[str]:
        return set(schema.get('handlers', {}).get(handler, {}).get('permissions', []))

    def _types_for(self, schema: dict[str, Any], ref: Reference, exact: bool) -> list[str]:
        """exact: the same name in the prefix the create handler mostly calls (AWS::EC2::SecurityGroup <->
        ec2:security-group). Otherwise: the types, with the schema's name in theirs, that the create handler's
        own actions named after it act on (AWS::Events::Rule <-> events:rule-on-default-event-bus)."""
        perms = self._perms(schema, 'create') or self._perms(schema, 'update')
        prefixes = collections.Counter(p.split(':')[0] for p in perms if ':' in p)
        if not prefixes:
            return []
        prefix = prefixes.most_common(1)[0][0]
        name = split(schema['typeName'].split('::')[-1]).joined
        if not name:
            return []
        if exact:
            return [t.id for t in ref.types.values() if t.prefix == prefix and split(t.name).joined == name]
        out: list[str] = []
        for p in sorted(perms):
            pre, _, act = p.partition(':')
            if pre == prefix and name in squash(act) and act in ref.actions.get(prefix, {}):
                out += [t for t in ref.resources_of(prefix, ref.actions[prefix][act])
                        if t not in out and name in split(t.split(':', 1)[1]).joined]
        return out

    def creates(self, tid: str, action: str) -> bool:
        """The action is one that only creating this type uses (not updating or deleting it)."""
        s = self.by_type.get(tid)
        if not s:
            return False
        return action in self._perms(s, 'create') and action not in self._perms(s, 'update') | self._perms(s, 'delete')

    def read_actions(self, tid: str) -> set[str]:
        s = self.by_type.get(tid)
        return self._perms(s, 'read') if s else set()

    def flags(self, tid: str) -> dict[str, Any]:
        s = self.by_type.get(tid)
        if not s:
            return {}
        pid = s.get('primaryIdentifier', [])
        ro = set(s.get('readOnlyProperties', []))
        return {'cfn': s['typeName'], 'cfn_id': [p.rsplit('/', 1)[-1] for p in pid],
                'id_given_by_service': bool(pid) and all(p in ro for p in pid),
                'write_only_settings': sorted(p.replace('/properties/', '', 1) for p in s.get('writeOnlyProperties', []))}


# ------------------------------------------------------------------ operations
def members_of(op_model: Any) -> list[Member]:
    shape = op_model.input_shape
    if shape is None:
        return []
    required = set(shape.required_members)
    out = []
    for name, m in shape.members.items():
        doc = html.unescape(re.sub(r'<[^>]+>', '', m.documentation or '')).strip().lower()
        is_list = m.type_name == 'list'
        if is_list and m.member.type_name != 'string':
            continue   # a list of structures: its strings are found by the mention scan, not bound
        if m.type_name not in ('string', 'list'):
            continue
        out.append(Member(name, is_list, name in required, m.serialization.get('location') == 'uri', doc))
    return out


def named_after(ref: Reference, prefix: str, op: str) -> list[str]:
    """For an action AWS lists no resource for (EC2's Describe* cannot be scoped), the types of its service that
    the operation is named after (DescribeSecurityGroups -> security-group). They are bound like listed types, so
    a read of a resource held on a branch can be routed; 'n' stays unset, so complete is not affected."""
    hits = [t.id for t in ref.types.values() if t.prefix == prefix and is_target(t.id, op)]
    longest = max((len(split(t.split(':', 1)[1]).joined) for t in hits), default=0)
    return [t for t in hits if len(split(t.split(':', 1)[1]).joined) == longest]


def bindings_for(ref: Reference, tid: str, members: list[Member]) -> list[list[Any]]:
    """[[format index, {variable: [member, is_list]}], ...] for each format fully bound, most variables first."""
    info = ref.types[tid]
    alts = []
    for i, f in enumerate(info.formats):
        b = bind_vars(list(f.variables), info.name, members)
        if f.variables and len(b) == len(f.variables):
            alts.append([i, {v: [m.name, int(m.is_list)] for v, m in b.items()}])
    alts.sort(key=lambda a: -len(a[1]))
    return alts


def is_target(tid: str, op: str) -> bool:
    """The operation is named after the type (UpdateFunctionConfiguration -> function)."""
    name = split(tid.split(':', 1)[1]).joined
    return bool(name) and name in squash(op)


def compile_op(ref: Reference, cfn: CloudFormation, op: str, op_model: Any, act: MainAction | None) -> dict[str, Any]:
    if act is None:
        return {'k': 'unknown'}
    entry: dict[str, Any] = {'k': kind_of(act.props), 'a': f'{act.prefix}:{act.name}'}
    listed = ref.resources_of(act.prefix, act.action)
    members = members_of(op_model)
    if listed:
        entry['n'] = len(listed)
    else:
        listed = named_after(ref, act.prefix, op)
    targets = {t for t in listed if is_target(t, op)}
    binds = []
    for tid in listed:
        target = int(not targets or tid in targets)
        alts = bindings_for(ref, tid, members)
        if alts:
            binds.append({'t': tid, 'g': target, 'alts': alts})
            continue
        parent = ref.types[tid].parent
        if parent and parent not in listed:
            palts = bindings_for(ref, parent, members)
            if palts:   # the container is named, the thing inside it is not (DeleteObjects names the bucket)
                binds.append({'t': parent, 'g': target, 'alts': palts, 'via': tid})
    if binds:
        entry['b'] = binds
    whole = arn_member([t.split(':', 1)[1] for t in listed], members)
    if whole:
        entry['arn'] = [whole.name, int(whole.is_list)]
    creates = [t for t in targets if cfn.creates(t, f'{act.prefix}:{act.name}')]
    if creates:
        entry['c'] = creates
    return entry


# ------------------------------------------------------------------ reads per type
@dataclass
class ReadCandidate:
    service: str
    op: str
    action: str
    action_resources: list[str]
    members: list[Member]


def read_template(ref: Reference, tid: str, cand: ReadCandidate) -> dict[str, Any] | None:
    """{member: template} that fills every required member of the read from the type's id, or None.
    Templates are '${Var}' or a whole ARN format ('arn:${Partition}:...'), filled at run time."""
    info = ref.types[tid]
    required = {m.name for m in cand.members if m.required}
    for i, b in bindings_for(ref, tid, cand.members):
        fmt = info.formats[i]
        if not required <= {m for m, _ in b.values()}:
            continue
        tpl: dict[str, Any] = {}
        for var, (mname, is_list) in b.items():
            value = '${' + var + '}'
            if split(mname).designator == 'url':
                tpl = {}
                break         # an id holds the name, not the address (SQS QueueUrl): no generic way to the URL
            if var.endswith('WithoutLeadingSlash'):
                doc = next(m.doc for m in cand.members if m.name == mname)
                if 'arn' not in doc and 'amazon resource name' not in doc:
                    tpl = {}
                    break
                value = fmt.text      # the name may or may not start with '/': only the ARN is certain
            tpl[mname] = [value] if is_list else value
        if tpl:
            return tpl
    whole = arn_member([info.name], cand.members) if tid in cand.action_resources else None
    if whole and required <= {whole.name}:
        fmt = next((f for f in info.formats if not any(v.endswith('WithPath') for v in f.variables)), None)
        if fmt:
            return {whole.name: [fmt.text] if whole.is_list else fmt.text}
    return None


def compile_reads(ref: Reference, cfn: CloudFormation, candidates: dict[str, list[ReadCandidate]]) -> dict[str, list[list[Any]]]:
    """type -> [[service, op, template]]. A read is kept when it is about the type (its action lists the type, or
    CloudFormation's read handler uses it, or it lists no type and is named after this one) and its required
    members can all be filled from the id. Data-plane reads (GetObject, Scan) show content, not state: left out."""
    out: dict[str, list[list[Any]]] = {}
    for tid, info in ref.types.items():
        cfn_reads = cfn.read_actions(tid)
        rows = []
        for cand in candidates.get(info.prefix, []):
            from_cfn = cand.action in cfn_reads
            about = from_cfn or (cand.op.startswith(READ_VERBS) and (
                tid in cand.action_resources or (not cand.action_resources and is_target(tid, cand.op))))
            if not about:
                continue
            tpl = read_template(ref, tid, cand)
            if tpl:
                rank = (0 if cand.action in cfn_reads else 1,
                        next((i for i, v in enumerate(READ_VERBS) if cand.op.startswith(v)), 3), cand.op)
                rows.append((rank, [cand.service, cand.op, tpl]))
        rows = own_service_first(rows, info.prefix)
        if rows:
            out[tid] = [r for _, r in sorted(rows, key=lambda x: x[0])]
    return out


def own_service_first(rows: list[tuple[Any, list[Any]]], prefix: str) -> list[tuple[Any, list[Any]]]:
    """Several SDK services can share one IAM prefix (lambda and lambda-web). When the one named like the prefix
    has reads for the type, the others' reads are left out: they are a different API over the same permission."""
    own = [r for r in rows if r[1][0] == prefix]
    return own or rows


# ------------------------------------------------------------------ the whole build
def compile_all(svcref: str, cfn_dir: str) -> dict[str, Any]:
    ref = Reference(load_json_dir(svcref))
    cfn = CloudFormation(load_json_dir(cfn_dir), ref)
    session = botocore.session.get_session()
    services: dict[str, dict[str, Any]] = {}
    candidates: dict[str, list[ReadCandidate]] = collections.defaultdict(list)
    for service in session.get_available_services():
        model = session.get_service_model(service)
        ops = {}
        for op in model.operation_names:
            om = model.operation_model(op)
            act = main_action(ref, service, op, model.metadata)
            entry = compile_op(ref, cfn, op, om, act)
            ops[op] = entry
            if act and entry['k'] in ('read', 'list') and not act.props.get('IsDataPlane'):
                candidates[act.prefix].append(ReadCandidate(service, op, f'{act.prefix}:{act.name}',
                                                            ref.resources_of(act.prefix, act.action), members_of(om)))
        services[service] = ops
    reads = compile_reads(ref, cfn, candidates)
    types: dict[str, dict[str, Any]] = collections.defaultdict(dict)
    arn_services: dict[str, set[str]] = collections.defaultdict(set)
    parents = {t.parent for t in ref.types.values() if t.parent}
    for tid, info in ref.types.items():
        row: dict[str, Any] = {'f': [f.text for f in info.formats]}
        if info.parent:
            row['p'] = info.parent
        if tid in parents:
            row['k'] = 1      # has types inside it: its last variable stops at '/'
        if ref.holds_data(tid):
            row['d'] = 1
        row.update(cfn.flags(tid))
        if tid in reads:
            row['r'] = reads[tid]
        types[info.prefix][info.name] = row
        for f in info.formats:
            arn_services[f.service].add(info.prefix)
    return {
        'format': 1,
        'built_from': {'svcref_services': len(ref.docs), 'cfn_schemas': _count(cfn_dir),
                       'types_with_cfn': len(cfn.by_type), 'botocore': botocore.__version__},
        'services': {s: json.dumps(o, separators=(',', ':')) for s, o in services.items()},
        'types': {p: json.dumps(t, separators=(',', ':')) for p, t in types.items()},
        'arn_services': {s: sorted(p) for s, p in arn_services.items()},
    }


def _count(path: str) -> int:
    return sum(1 for n in os.listdir(path) if n.endswith('.json'))


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split('\n')[0])
    ap.add_argument('--svcref', required=True)
    ap.add_argument('--cfn', required=True)
    ap.add_argument('--out', required=True)
    args = ap.parse_args(argv)
    catalog = compile_all(os.path.expanduser(args.svcref), os.path.expanduser(args.cfn))
    data = json.dumps(catalog, separators=(',', ':'), sort_keys=True).encode()
    with open(args.out, 'wb') as f:
        f.write(gzip.compress(data, compresslevel=9, mtime=0))   # same inputs, same bytes
    print(f"{len(catalog['services'])} services, {sum(len(json.loads(t)) for t in catalog['types'].values())} resource types"
          f" -> {args.out} ({os.path.getsize(args.out) // 1024} KiB)")
    return 0


if __name__ == '__main__':
    sys.exit(main())
