"""The undo prover end to end on a fake engine behind a fake proof door: one made-up SSM-like store, answered from
botocore-encoded calls. Pure: no network. What it shows: a "yes" needs every read equal (versions too), a refusal or
a missing plan is "unknown", a difference is "no", and nothing outside the change may move."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from emfirge.aws.codec import AwsCodec
from emfirge.aws.undo import BranchUndoProver, Timing
from emfirge.branch.baseline import Answer, Baseline
from emfirge.branch.journal import Entry
from emfirge.branch.overlay import State
from emfirge.core.model import Call, Change, ChangeType, FieldChange, Refs, ResourceRef, Undo

CODEC = AwsCodec('us-west-2')
FAST = Timing(limit=1.0, interval=0.0, busy=0.0, calm=1)
NOW = 2_000_000_000.0


def ref(name: str) -> ResourceRef:
    return ResourceRef('ssm:parameter', name.lstrip('/'))


@dataclass
class FakeEngine:
    """Parameters {name: {'Value', 'Version', 'LastModifiedDate'}}. bump: a put raises the version (as AWS does)."""
    params: dict[str, dict[str, Any]]
    bump: bool = True
    refuse: set[str] = field(default_factory=set)
    side_effect: str | None = None      # a parameter every put also changes
    sent: list[str] = field(default_factory=list)

    def answer(self, call: Call) -> Answer:
        self.sent.append(call.operation)
        if call.operation in self.refuse:
            return Answer(400, {'__type': 'ValidationException', 'message': 'no'})
        p = call.params
        if call.operation == 'GetParameter':
            got = self.params.get(p['Name'])
            return Answer(200, {'Parameter': {'Name': p['Name'], **got}}) if got else \
                Answer(400, {'__type': 'ParameterNotFound'})
        if call.operation == 'PutParameter':
            old = self.params.get(p['Name'])
            if old and not p.get('Overwrite'):
                return Answer(400, {'__type': 'ParameterAlreadyExists'})
            version = (old['Version'] + (1 if self.bump else 0)) if old else 1
            self.params[p['Name']] = {'Value': p['Value'], 'Type': p['Type'], 'Version': version,
                                      'LastModifiedDate': NOW + 1}
            if self.side_effect:
                self.params[self.side_effect]['Value'] += '!'
            return Answer(200, {'Version': version})
        if call.operation == 'DeleteParameter':
            return Answer(200, {}) if self.params.pop(p['Name'], None) else Answer(400, {'__type': 'ParameterNotFound'})
        return Answer(400, {'__type': 'Unknown'})


class FakeDoor:
    def __init__(self, engine: FakeEngine, held: dict[ResourceRef, State], entries: list[Entry],
                 e0: dict[str, dict[str, Any]]) -> None:
        self.engine, self._held, self._entries = engine, held, tuple(entries)
        self._base = {r: [Baseline(r, read(r), Answer(200, {'Parameter': {'Name': '/' + r.id, **e0[r.id]}}),
                                   Answer(200, {}))] for r, s in held.items() if s is State.COPIED}

    def held(self): return dict(self._held)
    def entries(self): return self._entries
    def baselines(self, r): return list(self._base.get(r, []))
    def reads(self, r): return [b.call for b in self._base[r]] if r in self._base else [read(r)]
    def refs(self, call): return Refs((ref(call.params['Name']),)) if 'Name' in call.params else Refs()
    def send(self, call): return self.engine.answer(call)
    def focus(self, r, call, body): return body
    def holds(self, r, call, body): return None


def read(r: ResourceRef) -> Call:
    return CODEC.encode('ssm', 'GetParameter', {'Name': '/' + r.id})


def put(n: int, name: str, value: str, overwrite: bool = True) -> Entry:
    params = {'Name': name, 'Value': value, 'Type': 'String', **({'Overwrite': True} if overwrite else {})}
    return Entry(n, 'ssm', 'PutParameter', params, 200, (ref(name),))


def session(bump: bool = True, **engine: Any) -> tuple[FakeDoor, Change]:
    """A copied parameter '/app/url' (value old, version 1) that the session overwrote with 'new'."""
    e0 = {'app/url': {'Value': 'old', 'Type': 'String', 'Version': 1, 'LastModifiedDate': NOW - 100},
          'app/other': {'Value': 'x', 'Type': 'String', 'Version': 1, 'LastModifiedDate': NOW - 100}}
    eng = FakeEngine({'/' + k: dict(v) for k, v in e0.items()}, bump=bump, **engine)
    eng.answer(CODEC.encode('ssm', 'PutParameter', {'Name': '/app/url', 'Value': 'new', 'Type': 'String',
                                                    'Overwrite': True}))
    door = FakeDoor(eng, {ref('/app/url'): State.COPIED, ref('/app/other'): State.COPIED},
                    [put(1, '/app/url', 'new')], e0)
    return door, Change(ref('/app/url'), ChangeType.MODIFIED, (FieldChange('GetParameter.Parameter.Value', 'old', 'new'),),
                        ('ssm.PutParameter',))


def prover(door: FakeDoor, *changes: Change) -> BranchUndoProver:
    return BranchUndoProver(door, changes, CODEC, FAST, sleep=lambda s: None, clock=lambda: NOW)


def test_a_version_that_does_not_come_back_is_no_and_named():
    door, change = session(bump=True)
    fact = prover(door, change).prove(change)
    assert fact.undo is Undo.NO
    assert fact.reasons[0] == ('put back on the branch: everything the session set came back; these values the '
                               'service keeps moved: Version')
    assert 'GetParameter.Parameter.Version: 1 -> 3' in fact.reasons[1]


def test_a_status_that_says_a_change_is_landing_is_waited_for():
    from emfirge.aws.undo.prover import landing
    ok = lambda body: Answer(200, body)
    assert landing({ref('a'): (ok({'Configuration': {'LastUpdateStatus': 'InProgress'}}),)})
    assert landing({ref('a'): (ok({'Table': {'TableStatus': 'UPDATING'}}),)})
    assert not landing({ref('a'): (ok({'Configuration': {'LastUpdateStatus': 'Successful', 'Note': 'pending'}}),)})


def test_every_field_equal_again_is_yes_and_a_moved_clock_is_named_not_counted():
    door, change = session(bump=False)
    fact = prover(door, change).prove(change)
    assert fact.undo is Undo.YES
    assert fact.reasons[0].startswith('put back on the branch and compared: 1 reads, no difference')
    assert 'LastModifiedDate' in fact.reasons[0]
    assert door.engine.params['/app/url']['Value'] == 'old'


def test_a_refused_inverse_is_unknown():
    door, change = session(bump=False)
    door.engine.refuse.add('PutParameter')
    fact = prover(door, change).prove(change)
    assert fact.undo is Undo.UNKNOWN and 'refused PutParameter' in fact.reasons[0]


def test_putting_back_must_not_move_anything_else():
    door, change = session(bump=False, side_effect='/app/other')
    fact = prover(door, change).prove(change)
    assert fact.undo is Undo.NO and 'app/other (not a change of the session' in fact.reasons[0]


def created_session() -> tuple[FakeDoor, Change]:
    """Only a creation: '/app/new' put where nothing was; '/app/url' is copied and untouched."""
    e0 = {'app/url': {'Value': 'old', 'Type': 'String', 'Version': 1, 'LastModifiedDate': NOW - 100}}
    eng = FakeEngine({'/app/url': dict(e0['app/url'])})
    eng.answer(CODEC.encode('ssm', 'PutParameter', {'Name': '/app/new', 'Value': 'v', 'Type': 'String'}))
    door = FakeDoor(eng, {ref('/app/url'): State.COPIED, ref('/app/new'): State.BORN},
                    [put(1, '/app/new', 'v', overwrite=False)], e0)
    return door, Change(ref('/app/new'), ChangeType.CREATED, calls=('ssm.PutParameter',))


def test_a_created_thing_is_yes_once_it_is_gone_and_nothing_else_moved():
    door, created = created_session()
    fact = prover(door, created).prove(created)
    assert fact.undo is Undo.YES and '/app/new' not in door.engine.params
    assert door.engine.sent.count('DeleteParameter') == 1


def test_a_created_thing_whose_delete_is_refused_is_unknown_and_said_to_be_still_there():
    door, created = created_session()
    door.engine.refuse.add('DeleteParameter')
    fact = prover(door, created).prove(created)
    assert fact.undo is Undo.UNKNOWN and 'refused DeleteParameter' in fact.reasons[0]
    assert 'still there' in ' '.join(fact.reasons)


def test_deleted_and_action_changes_are_not_tried_and_a_call_shared_with_a_deletion_blocks():
    door, change = session(bump=False)
    gone = Change(ref('/app/other'), ChangeType.DELETED, calls=('ssm.PutParameter',))
    door._entries = (Entry(1, 'ssm', 'PutParameter', {'Name': '/app/url', 'Value': 'new', 'Type': 'String',
                                                       'Overwrite': True}, 200, (ref('/app/url'), ref('/app/other'))),)
    p = prover(door, change, gone)
    assert p.prove(gone).undo is Undo.UNKNOWN and 'not put back' in p.prove(gone).reasons[0]
    fact = p.prove(change)
    assert fact.undo is Undo.UNKNOWN and 'also deleted ssm:parameter/app/other' in fact.reasons[0]
    assert 'PutParameter' not in door.engine.sent[1:]


def test_the_proof_runs_once_and_a_change_outside_the_diff_is_unknown():
    door, change = session(bump=False)
    p = prover(door, change)
    p.prove(change)
    sent = len(door.engine.sent)
    assert p.prove(change).undo is Undo.YES and len(door.engine.sent) == sent
    other = Change(ref('/app/zzz'), ChangeType.MODIFIED)
    assert p.prove(other).undo is Undo.UNKNOWN


def test_a_side_effect_named_by_no_call_must_come_back_with_the_call_that_made_it():
    door, change = session(bump=False, side_effect='/app/other')
    side = Change(ref('/app/other'), ChangeType.MODIFIED, (FieldChange('GetParameter.Parameter.Value', 'x', 'x!'),))
    p = prover(door, change, side)
    assert p.prove(side).undo is Undo.NO
    fact = p.prove(change)
    assert fact.undo is Undo.NO and 'app/other' in fact.reasons[0]
