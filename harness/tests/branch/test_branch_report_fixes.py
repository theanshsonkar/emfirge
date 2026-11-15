"""The branch's report after integration: what is a change, what is derived, what the journal keeps, reads with no
copy-time answer, copy notes, copies that are still settling."""
from __future__ import annotations

import json

from branch_fakes import THING, FakeAccount, FakeCatalog, FakeCodec, FakeCopier, FakeOutcomes, answer, make, ok, request

from emfirge.branch import Branch
from emfirge.branch.sides import Sides
from emfirge.branch.ids import IdMap
from emfirge.core.model import ChangeType, ResourceRef

A, B = ResourceRef(THING, 'a'), ResourceRef(THING, 'b')


def refused(r) -> bool:
    return r.status == 400 and r.headers.get('x-refused') == 'true'


def test_a_resource_a_call_only_names_is_no_change():
    b, _, _, _ = make({'a': {'size': 1}, 'b': {'size': 1}})
    b.handle(request('put', name='a', uses='b', set={'size': 2}))
    assert {c.ref for c in b.changes()} == {A}                       # b was copied (named), not changed
    [e] = b.journal.entries()
    assert e.refs == (A, B) and e.primary == (A,)


def test_a_call_that_acts_but_shows_in_no_read_is_an_action():
    b, _, _, _ = make({'a': {'size': 1}})
    b.handle(request('put', name='a', set={}))
    [c] = b.changes()
    assert c.type is ChangeType.ACTION and c.calls == ('cloud.put',)


def test_fields_no_call_set_are_marked_derived():
    b, _, engine, _ = make({'a': {'size': 1, 'revision': 'r1'}})
    b.handle(request('put', name='a', set={'size': 2}))
    engine.things['a']['revision'] = 'r2'                            # the service moved its own counter
    fields = {f.path: f.derived for f in b.changes()[0].fields}
    assert fields == {'get.size': False, 'get.revision': True, 'list.size': False, 'list.revision': True}


def test_a_container_whose_list_shows_a_changed_child_is_not_changed():
    sides = Sides(FakeCodec(), None, None, IdMap(), FakeOutcomes())
    group = ResourceRef(THING, 'group')
    call = FakeCodec().encode('cloud', 'list', {})
    one = {'items': [{'name': 'a', 'size': 1}]}
    two = {'items': [{'name': 'a', 'size': 2}]}
    assert sides.membership(group, call, one) == sides.membership(group, call, two) == {'items': ['cloud:thing/a']}
    assert sides.membership(A, call, two) == {'name': 'a', 'size': 2}   # its own item is still compared whole
    grown = {'items': [{'name': 'a', 'size': 2}, {'name': 'b', 'size': 0}]}
    assert sides.membership(group, call, grown) != sides.membership(group, call, one)   # a child joining is a change


def test_the_journal_keeps_each_answer_as_plain_data():
    b, _, _, _ = make()
    alias = answer(b.handle(request('create')))['id']
    [e] = b.journal.entries()
    assert e.answer == {'id': alias} and e.status == 200


def test_a_read_without_a_copy_time_answer():
    # unchanged on the branch: the real account, live
    b, real, _, _ = make({'a': {'size': 1}, 'lossy-b': {'size': 1}})
    b.handle(request('put', name='a', uses='lossy-b', set={'size': 2}))   # lossy-b is copied (named), not acted on
    real.things['lossy-b']['size'] = 5
    assert answer(b.handle(request('peek', name='lossy-b')))['size'] == 5
    # changed, and the copier checked this read alike: the engine
    b2, _, _, _ = make({'c': {'size': 1}})
    b2.handle(request('put', name='c', set={'size': 2}))
    assert answer(b2.handle(request('peek', name='c')))['size'] == 2
    # changed, and not checked: refused
    b3, _, _, _ = make({'lossy-c': {'size': 1}})
    b3.handle(request('put', name='lossy-c', set={'size': 2}))
    r = b3.handle(request('peek', name='lossy-c'))
    assert refused(r) and 'no answer from the time it was copied' in answer(r)['message']
    assert answer(b3.handle(request('get', name='lossy-c')))['size'] == 2      # a read with a baseline still answers
    # changed, not checked, but the real account says 'not found' and the engine has it: the branch made it
    b4, real4, _, _ = make({'lossy-d': {'size': 1}})
    b4.handle(request('put', name='lossy-d', set={'size': 2}))
    del real4.things['lossy-d']
    assert answer(b4.handle(request('peek', name='lossy-d')))['size'] == 2


def test_what_a_copy_lacks_is_an_unknown_about_it():
    b, _, _, _ = make({'lossy-1': {'size': 1, 'colour': 'red'}})
    b.handle(request('put', name='lossy-1', set={'size': 2}))
    [u] = b.unknowns()
    assert u.ref == ResourceRef(THING, 'lossy-1') and 'its colour' in u.what and u.where == 'branch'


class Settling(FakeAccount):
    """An engine whose copies say 'creating' for their first reads, as a slow service does."""

    def send(self, r):
        d = json.loads(r.body)
        if d['op'] == 'get' and d['params'].get('name') in self.things:
            self.counter += 1
            if self.counter <= 2:
                return ok({'name': d['params']['name'], **self.things[d['params']['name']], 'state': 'creating'})
        return super().send(r)


def test_baselines_wait_until_the_copy_holds_still():
    real = FakeAccount('real', {'a': {'size': 1}})
    branch = Branch(FakeCodec(), FakeCatalog(), FakeCopier(), real, Settling('engine'), FakeOutcomes())
    branch.handle(request('put', name='a', set={'size': 2}))
    [base] = [x for x in branch.baselines.of(A) if x.call.operation == 'get']
    assert 'state' not in base.e0.body
    assert [(f.path, f.after) for f in branch.changes()[0].fields] == [('get.size', 2), ('list.size', 2)]


def test_the_read_only_door_keeps_the_names_of_the_calls_it_stopped():
    import pytest
    from emfirge.branch.guard import NotARead
    b, real, _, _ = make({'a': {}})
    with pytest.raises(NotARead):
        b.real.send(request('put', name='a', set={}))
    assert b.stats()['real_blocked'] == 1 and b.stats()['real_blocked_calls'] == ['cloud.put'] and real.sent == []
