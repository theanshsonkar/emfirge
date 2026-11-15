"""The Branch end to end on an in-memory cloud: routing, copy on touch, honesty, the report, isolation."""
from branch_fakes import THING, answer, make, request

from emfirge.branch import Stage, State
from emfirge.core.model import ChangeType, ResourceRef


def refused(r) -> bool:
    return r.status == 400 and r.headers.get('x-refused') == 'true'


def test_a_read_of_an_untouched_resource_is_answered_live_by_the_real_account():
    b, real, engine, _ = make({'a': {'size': 1}})
    assert answer(b.handle(request('get', name='a'))) == {'name': 'a', 'size': 1}
    assert real.sent == ['get'] and engine.sent == []


def test_a_change_copies_on_touch_runs_on_the_engine_and_never_reaches_the_real_account():
    b, real, engine, copier = make({'a': {'size': 1, 'colour': 'red'}})
    assert answer(b.handle(request('put', name='a', set={'size': 2}))) == {'name': 'a', 'size': 2, 'colour': 'red'}
    assert copier.copied == ['a'] and real.things['a'] == {'size': 1, 'colour': 'red'}
    assert 'put' not in real.sent and b.real.blocked == 0
    assert b.overlay.state(ResourceRef(THING, 'a')) is State.COPIED


def test_later_reads_lay_the_branch_change_over_the_live_real_answer():
    b, real, engine, _ = make({'a': {'size': 1, 'colour': 'red'}})
    b.handle(request('put', name='a', set={'size': 2}))
    real.things['a']['colour'] = 'blue'   # someone changes the real account under the branch
    assert answer(b.handle(request('get', name='a'))) == {'name': 'a', 'size': 2, 'colour': 'blue'}
    assert b.stats()['routes']['transplanted'] == 1
    drift = b.drift()
    assert [(f.path, f.before, f.after) for f in drift[0].fields] == [('get.colour', 'red', 'blue'), ('list.colour', 'red', 'blue')]


def test_lists_merge_the_real_account_and_the_branch():
    b, real, _, _ = make({'a': {'size': 1}, 'b': {'size': 1}})
    b.handle(request('put', name='a', set={'size': 5}))
    b.handle(request('delete', name='b'))
    b.handle(request('put', name='new', set={'size': 0}))
    real.things['z'] = {'size': 7}
    names = {i['name']: i['size'] for i in answer(b.handle(request('list')))['items']}
    assert names == {'a': 5, 'new': 0, 'z': 7}


def test_deleted_and_born_resources_are_answered_by_the_engine():
    b, real, _, _ = make({'a': {'size': 1}})
    b.handle(request('delete', name='a'))
    assert b.handle(request('get', name='a')).status == 404 and 'a' in real.things
    b.handle(request('put', name='a', set={'size': 3}))
    assert b.overlay.state(ResourceRef(THING, 'a')) is State.BORN
    assert answer(b.handle(request('get', name='a')))['size'] == 3


def test_ids_the_engine_gives_out_are_aliased():
    b, _, engine, _ = make()
    got = answer(b.handle(request('create')))['id']
    assert got != 'thing-0001' and got.startswith('thing-')
    assert answer(b.handle(request('get', name=got)))['name'] == got   # the alias works both ways
    assert b.log()[-1].born == (ResourceRef(THING, got),)


def test_unknown_kind_is_refused_and_sent_nowhere():
    b, real, engine, _ = make({'a': {}})
    r = b.handle(request('explode', name='a'))
    assert refused(r) and real.sent == [] and engine.sent == []
    assert 'Emfirge cannot tell' in answer(r)['message'] and 'Nothing was changed' in answer(r)['message']
    assert len(b.unknowns()) == 1 and b.unknowns()[0].where == 'branch'


def test_a_change_the_catalog_cannot_place_is_refused():
    b, real, engine, _ = make({'a': {}})
    assert refused(b.handle(request('put', name='a', mystery=1, set={})))
    assert engine.sent == [] and real.sent == []


def test_a_resource_that_cannot_be_copied_is_refused_the_same_way_every_time():
    b, real, engine, _ = make({'cursed-1': {'size': 1}, 'a': {}})
    first = answer(b.handle(request('put', name='cursed-1', set={})))['message']
    again = answer(b.handle(request('get', name='cursed-1')))['message']
    via = answer(b.handle(request('put', name='a', uses='cursed-1', set={})))['message']
    assert 'cursed things cannot be copied' in first and 'cursed things cannot be copied' in again and 'cursed' in via
    assert b.overlay.state(ResourceRef(THING, 'cursed-1')) is State.OPAQUE
    assert 'put' not in engine.sent and len(b.unknowns()) == 3


def test_a_mentioned_resource_is_copied_first():
    b, _, engine, copier = make({'a': {}, 'helper': {'size': 1}})
    assert b.handle(request('put', name='a', uses='helper', set={})).status == 200
    assert set(copier.copied) == {'a', 'helper'}


def test_a_sealed_branch_refuses_every_call():
    b, real, engine, _ = make({'a': {}})
    b.seal()
    assert refused(b.handle(request('get', name='a'))) and real.sent == []
    assert b.life.stage is Stage.SEALED


def test_the_report_holds_state_level_changes():
    b, _, _, _ = make({'a': {'size': 1}, 'b': {}})
    b.handle(request('put', name='a', set={'size': 2}))
    b.handle(request('delete', name='b'))
    b.handle(request('put', name='c', set={}))
    by = {c.ref.id: c for c in b.changes()}
    assert by['a'].type is ChangeType.MODIFIED and by['a'].calls == ('cloud.put',)
    assert [(f.path, f.before, f.after) for f in by['a'].fields] == [('get.size', 1, 2), ('list.size', 1, 2)]
    assert by['b'].type is ChangeType.DELETED and by['c'].type is ChangeType.CREATED


def test_created_resources_carry_their_settings_and_deleted_ones_their_last_state():
    b, _, _, _ = make({'old': {'size': 4, 'colour': 'red'}})
    b.handle(request('put', name='new', set={'size': 1, 'colour': 'green'}))
    b.handle(request('delete', name='old'))
    by = {c.ref.id: c for c in b.changes()}
    new = {(f.path, f.before, f.after) for f in by['new'].fields}
    old = {(f.path, f.before, f.after) for f in by['old'].fields}
    for read in ('get', 'list'):   # each read the resource shows in reports, named by the read
        assert {(f'{read}.name', None, 'new'), (f'{read}.size', None, 1), (f'{read}.colour', None, 'green')} <= new
        assert {(f'{read}.name', 'old', None), (f'{read}.size', 4, None), (f'{read}.colour', 'red', None)} <= old
    assert len(new) == len(old) == 6


def test_a_resource_created_and_deleted_on_the_branch_is_no_change():
    b, _, _, _ = make()
    b.handle(request('put', name='tmp', set={'size': 1}))
    b.handle(request('delete', name='tmp'))
    assert b.changes() == []
    assert [e.operation for e in b.journal.entries()] == ['put', 'delete']


def test_states_after_hold_every_copied_and_born_resource_as_the_branch_answers_it():
    b, real, _, _ = make({'a': {'size': 1, 'colour': 'red'}})
    b.handle(request('put', name='a', set={'size': 2}))
    b.handle(request('put', name='n', set={'size': 7}))
    real.things['a']['colour'] = 'blue'
    states = b.states_after()
    assert states[ResourceRef(THING, 'a')]['get'] == {'name': 'a', 'size': 2, 'colour': 'blue'}
    assert states[ResourceRef(THING, 'a')]['list'] == {'name': 'a', 'size': 2, 'colour': 'blue'}
    assert states[ResourceRef(THING, 'n')]['get'] == {'name': 'n', 'size': 7}


def test_the_journal_keeps_what_an_undo_needs():
    b, _, _, _ = make({'a': {'size': 1}})
    b.handle(request('put', name='a', uses='a', set={'size': 2}))
    [e] = b.journal.entries()
    assert (e.service, e.operation, e.params, e.status, e.refs) == \
        ('cloud', 'put', {'name': 'a', 'uses': 'a', 'set': {'size': 2}}, 200, (ResourceRef(THING, 'a'),))


def test_two_branches_in_one_process_are_isolated():
    from branch_fakes import FakeAccount, FakeCatalog, FakeCodec, FakeCopier, FakeOutcomes
    from emfirge.branch import Branch
    real = FakeAccount('real', {'a': {'size': 1}})
    one = Branch(FakeCodec(), FakeCatalog(), FakeCopier(), real, FakeAccount('e1'), FakeOutcomes())
    two = Branch(FakeCodec(), FakeCatalog(), FakeCopier(), real, FakeAccount('e2'), FakeOutcomes())
    one.handle(request('put', name='a', set={'size': 9}))
    two.handle(request('delete', name='a'))
    assert answer(one.handle(request('get', name='a')))['size'] == 9
    assert two.handle(request('get', name='a')).status == 404
    assert answer(one.handle(request('list')))['items'] == [{'name': 'a', 'size': 9}]
    assert answer(two.handle(request('list')))['items'] == []
    assert real.things == {'a': {'size': 1}}
    assert one.overlay.held() != two.overlay.held()
