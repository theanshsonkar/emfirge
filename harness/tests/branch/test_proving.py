"""The proof door (branch/proving.py): handed out once, only to a sealed branch, after which the branch refuses to
answer for its state; it reaches the engine only, in client ids."""
import pytest
from branch_fakes import THING, make, request

from emfirge.branch import Stage
from emfirge.branch.lifecycle import IllegalMove
from emfirge.branch.overlay import State
from emfirge.branch.proving import EngineSpent
from emfirge.core.model import ResourceRef

A = ResourceRef(THING, 'a')


def _sealed():
    b, real, engine, _ = make({'a': {'size': 1}})
    b.handle(request('put', name='a', set={'size': 2}))
    b.handle(request('create'))
    b.seal()
    return b, real, engine


def test_only_a_sealed_branch_is_handed_to_a_prover():
    b, _, _, _ = make({'a': {}})
    with pytest.raises(IllegalMove):
        b.begin_proof()
    b.move(Stage.DISCARDED)
    with pytest.raises(IllegalMove):
        b.begin_proof()


def test_after_the_door_opens_branch_state_reads_fail_loudly():
    b, _, _ = _sealed()
    assert b.changes()                      # read before proving: fine
    b.begin_proof()
    for read in (b.changes, b.states_after, b.drift, lambda: b.copy(A)):
        with pytest.raises(EngineSpent):
            read()
    with pytest.raises(EngineSpent):
        b.begin_proof()
    assert b.life.stage is Stage.SEALED     # the lifecycle itself is unchanged: judged comes next


def test_the_door_sends_to_the_engine_only():
    b, real, engine = _sealed()
    door = b.begin_proof()
    sent_real = list(real.sent)
    got = door.send(b._codec.encode('cloud', 'put', {'name': 'a', 'set': {'size': 1}}))
    assert got.ok and engine.things['a']['size'] == 1
    assert real.sent == sent_real and real.things['a'] == {'size': 1}


def test_the_door_translates_ids_of_things_born_on_the_branch():
    b, _, engine = _sealed()
    door = b.begin_proof()
    born = next(r for r, s in door.held().items() if s is State.BORN)
    assert born.id not in engine.things           # the client sees an alias
    assert door.send(b._codec.encode('cloud', 'get', {'name': born.id})).ok


def test_the_door_gives_records_and_reads():
    b, _, _ = _sealed()
    door = b.begin_proof()
    assert [e.operation for e in door.entries()] == ['put', 'create']
    assert [x.call.operation for x in door.baselines(A)] == ['get', 'list']
    assert [c.operation for c in door.reads(A)] == ['get', 'list']
    listing = door.send(b._codec.encode('cloud', 'list', {}))
    assert door.holds(A, b._codec.encode('cloud', 'list', {}), listing.body) is True
    assert door.holds(ResourceRef(THING, 'zz'), b._codec.encode('cloud', 'list', {}), listing.body) is False
    assert door.holds(A, b._codec.encode('cloud', 'get', {'name': 'a'}), {'name': 'a'}) is None
