"""The two state machines: every legal move works, every other move raises."""
import itertools

import pytest

from emfirge.branch.lifecycle import MOVES as STAGE_MOVES, IllegalMove, Lifecycle, Stage
from emfirge.branch.overlay import ANSWERED_BY, ENGINE_ANSWERS, MOVES as STATE_MOVES, Overlay, State
from emfirge.core.model import ResourceRef

R = ResourceRef('cloud:thing', 'a')


def _reach(stage: Stage) -> Lifecycle:
    """A lifecycle brought to `stage` by legal moves."""
    path = {Stage.OPEN: [], Stage.SEALED: [Stage.SEALED], Stage.JUDGED: [Stage.SEALED, Stage.JUDGED],
            Stage.VERIFIED: [Stage.SEALED, Stage.JUDGED, Stage.VERIFIED], Stage.DISCARDED: [Stage.DISCARDED]}[stage]
    life = Lifecycle()
    for s in path:
        life.move(s)
    return life


@pytest.mark.parametrize('src,dst', list(itertools.product(Stage, Stage)))
def test_lifecycle_moves(src, dst):
    life = _reach(src)
    if dst in STAGE_MOVES[src]:
        life.move(dst)
        assert life.stage is dst
    else:
        with pytest.raises(IllegalMove):
            life.move(dst)
        assert life.stage is src


def test_lifecycle_table_matches_the_readme():
    assert STAGE_MOVES[Stage.OPEN] == {Stage.SEALED, Stage.DISCARDED}
    assert STAGE_MOVES[Stage.SEALED] == {Stage.JUDGED, Stage.DISCARDED}
    assert STAGE_MOVES[Stage.JUDGED] == {Stage.VERIFIED, Stage.DISCARDED}
    assert not STAGE_MOVES[Stage.VERIFIED] and not STAGE_MOVES[Stage.DISCARDED]


def test_only_an_open_branch_accepts_calls():
    for stage in Stage:
        assert _reach(stage).accepting is (stage is Stage.OPEN)


def _to(state: State) -> Overlay:
    path = {State.LIVE: [], State.COPIED: [State.COPIED], State.ABSENT: [State.ABSENT],
            State.BORN: [State.ABSENT, State.BORN], State.DELETED: [State.COPIED, State.DELETED],
            State.OPAQUE: [State.OPAQUE]}[state]
    o = Overlay()
    for s in path:
        o.move(R, s, 'why')
    return o


@pytest.mark.parametrize('src,dst', list(itertools.product(State, State)))
def test_overlay_moves(src, dst):
    o = _to(src)
    if dst in STATE_MOVES[src]:
        o.move(R, dst)
        assert o.state(R) is dst
    else:
        with pytest.raises(IllegalMove):
            o.move(R, dst)
        assert o.state(R) is src


def test_overlay_facts():
    assert ENGINE_ANSWERS == {State.COPIED, State.ABSENT, State.BORN, State.DELETED}
    assert set(ANSWERED_BY) == set(State)
    o = Overlay()
    assert o.state(R) is State.LIVE and not o.changed_anything()
    o.move(R, State.OPAQUE, 'it is cursed')
    assert o.why_opaque(R) == 'it is cursed' and not o.changed_anything()
    b = ResourceRef('cloud:thing', 'b')
    o.move(b, State.COPIED)
    o.move(b, State.DELETED)
    assert o.from_real() == {b} and o.changed_anything()
    assert o.held_types() == {'cloud:thing'}
