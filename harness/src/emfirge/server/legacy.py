"""FOR THE OLD EXPERIMENTS ONLY (09 rig/fidelity/collide, 14 fidelity checks): the prototype's /__branch/ routes
(stats, log, diff, hydrate, snapshots) in the prototype's shapes, served from the new branch.

The prototype named types by short words and keyed some types differently; the two tables below translate. Nothing
else in Emfirge uses this module; delete it when those experiments are retired.
"""
from __future__ import annotations

import json
from typing import Any

from emfirge.branch import Branch
from emfirge.branch.overlay import State
from emfirge.core.model import ChangeType, ResourceRef
from emfirge.core.ports import CannotTell

from .http import Admin

PREFIX = '/__branch/'
OLD_TYPES = {'function': 'lambda:function', 'esm': 'lambda:eventSourceMapping', 'role': 'iam:role', 'user': 'iam:user',
             'policy': 'iam:policy', 'bucket': 's3:bucket', 'table': 'dynamodb:table', 'schedule': 'scheduler:schedule',
             'rule': 'events:rule-on-default-event-bus', 'queue': 'sqs:queue', 'topic': 'sns:topic',
             'loggroup': 'logs:log-group', 'parameter': 'ssm:parameter', 'secret': 'secretsmanager:Secret',
             'key': 'kms:key', 'vpc': 'ec2:vpc', 'subnet': 'ec2:subnet', 'sg': 'ec2:security-group'}
NEW_TYPES = {v: k for k, v in OLD_TYPES.items()}
OLD_STATES = {State.COPIED: 'hydrated', State.ABSENT: 'absent', State.BORN: 'created', State.DELETED: 'deleted',
              State.OPAQUE: 'refused'}


def new_ref(old_type: str, key: str) -> ResourceRef:
    """The prototype's (type, key) as a ResourceRef."""
    if old_type == 'rule':
        key = key.split('/', 1)[1] if key.startswith('default/') else key
    elif old_type == 'parameter':
        key = key.lstrip('/')
    elif old_type == 'policy':
        key = key.rsplit('/', 1)[-1]
    return ResourceRef(OLD_TYPES.get(old_type, old_type), key)


def old_key(ref: ResourceRef) -> list[str]:
    t = NEW_TYPES.get(ref.type, ref.type)
    key = '/' + ref.id if t == 'parameter' and '/' in ref.id else ref.id
    return [t, 'default/' + key if t == 'rule' else key]


def legacy_routes(branch: Branch) -> Admin:
    def route(method: str, path: str, body: bytes) -> Any:
        name = path[len(PREFIX):]
        if name == 'hydrate':
            a = json.loads(body or b'{}')
            try:
                state = branch.copy(new_ref(a['type'], a['key']))
                return {'state': OLD_STATES.get(state, state.value)}
            except CannotTell as e:
                return {'refused': str(e)}
        if name == 'snapshots':
            return [{'resource': old_key(ref), 'state': OLD_STATES.get(branch.overlay.state(ref)), 'service': b.call.service,
                     'op': b.call.operation, 'params': dict(b.call.params)}
                    for ref, bs in branch.baselines.all().items() for b in bs]
        if name == 'stats':
            s = branch.stats()
            return dict(s, refusals=s['refusals'], hydrations=s['copies'])
        if name == 'log':
            return [{'n': e.n, 'service': e.call.split('.')[0], 'operation': e.call.split('.', 1)[1], 'params': e.params,
                     'status': e.status, 'born': [':'.join(old_key(r)) for r in e.born]} for e in branch.log()]
        if name == 'diff':
            return _diff(branch)
        return None
    return route


def _diff(branch: Branch) -> dict[str, Any]:
    held = branch.overlay.held()
    changed = [{'resource': ':'.join(old_key(c.ref)), 'path': f.path, 'to': f.after}
               for c in branch.changes() if c.type is ChangeType.MODIFIED for f in c.fields]
    drift = [{'resource': ':'.join(old_key(c.ref)), 'path': f.path} for c in branch.drift() for f in c.fields]
    return {'changed': changed, 'real_drift_since_hydration': drift,
            'created': [':'.join(old_key(r)) for r, s in held.items() if s is State.BORN],
            'deleted': [':'.join(old_key(r)) for r, s in held.items() if s is State.DELETED],
            'hydrated': [':'.join(old_key(r)) for r, s in held.items() if s is State.COPIED]}
