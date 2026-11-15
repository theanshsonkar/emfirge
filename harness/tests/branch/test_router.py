"""The routing decision, as a pure function."""
import pytest

from emfirge.branch.overlay import State
from emfirge.branch.router import Way, route
from emfirge.core.model import Kind, Refs, ResourceRef

A, B = ResourceRef('cloud:thing', 'a'), ResourceRef('cloud:thing', 'b')


def states(**s):
    return lambda r: s.get(r.id, State.LIVE)


def go(kind, refs, st=states(), changed=False, head=False):
    return route(kind, refs, st, changed_anything=changed, head=head)


def test_unknown_kind_is_refused_and_never_sent_anywhere():
    r = go(Kind.UNKNOWN, Refs((A,)))
    assert r.way is Way.REFUSE and 'sent nowhere' in r.reason


@pytest.mark.parametrize('kind', [Kind.READ, Kind.LIST, Kind.WRITE, Kind.PERMISSION, Kind.TAGGING])
def test_anything_naming_an_opaque_resource_is_refused(kind):
    r = go(kind, Refs((A,), (B,)), states(b=State.OPAQUE))
    assert r.way is Way.REFUSE and r.refs == (B,)


def test_reads():
    assert go(Kind.READ, Refs((A,))).way is Way.REAL
    assert go(Kind.LIST, Refs()).way is Way.MERGED_LIST
    assert go(Kind.READ, Refs((A,)), states(a=State.COPIED)).way is Way.TRANSPLANT
    assert go(Kind.READ, Refs((A,)), states(a=State.COPIED), head=True).way is Way.ENGINE
    for s in (State.ABSENT, State.BORN, State.DELETED):
        assert go(Kind.READ, Refs((A,)), states(a=s)).way is Way.ENGINE
    mixed = go(Kind.READ, Refs((A, B)), states(a=State.BORN))
    assert mixed.way is Way.COPY and mixed.refs == (B,)


def test_a_read_that_names_something_unknown():
    assert go(Kind.READ, Refs((), (), complete=False)).way is Way.MERGED_LIST
    assert go(Kind.READ, Refs((), (), complete=False), changed=True).way is Way.REFUSE


@pytest.mark.parametrize('kind', [Kind.WRITE, Kind.PERMISSION, Kind.TAGGING])
def test_changes(kind):
    first = go(kind, Refs((A,), (B,)))
    assert first.way is Way.COPY and first.refs == (A, B)
    assert go(kind, Refs((A,), (B,)), states(a=State.COPIED, b=State.ABSENT)).way is Way.ENGINE
    assert go(kind, Refs((A,)), states(a=State.DELETED)).way is Way.ENGINE
    assert go(kind, Refs()).way is Way.ENGINE   # the catalog says it names nothing that exists (a creation)


@pytest.mark.parametrize('kind', [Kind.WRITE, Kind.PERMISSION, Kind.TAGGING])
def test_a_change_the_branch_cannot_place_is_refused(kind):
    r = go(kind, Refs((A,), (), complete=False), states(a=State.COPIED))
    assert r.way is Way.REFUSE and 'cannot place' in r.reason
