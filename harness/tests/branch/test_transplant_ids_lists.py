"""Pure helpers: structural diff and lay-over, the id map, merged lists, the journal and the diff."""
import pytest

from emfirge.branch import diff, lists, transplant
from emfirge.branch.baseline import Answer, Baseline, Baselines, key_of, noise_between
from emfirge.branch.ids import IdMap, alias_of
from emfirge.branch.journal import Journal
from emfirge.branch.overlay import State
from emfirge.core.model import Call, ChangeType, Kind, Listed, ResourceRef, WireRequest, WireResponse
from emfirge.core.ports import CannotTell

T = 'cloud:thing'


# ---------------------------------------------------------------- transplant
def test_lay_keeps_live_values_and_applies_only_the_branch_change():
    e0 = {'Timeout': 30, 'Env': {'A': '1', 'B': '2'}, 'Lost': None}
    e1 = {'Timeout': 60, 'Env': {'A': '1'}, 'Lost': None}
    real = {'Timeout': 30, 'Env': {'A': '1', 'B': '2'}, 'Lost': 'kept', 'Live': 'now'}
    assert transplant.lay(e0, e1, real) == {'Timeout': 60, 'Env': {'A': '1'}, 'Lost': 'kept', 'Live': 'now'}


def test_lists_are_whole_values_and_missing_room_takes_the_engine_subtree():
    assert transplant.lay({'L': [1, 2]}, {'L': [1]}, {'L': [1, 2, 3]}) == {'L': [1]}
    assert transplant.lay({}, {'New': {'x': 1}}, {}) == {'New': {'x': 1}}
    assert transplant.lay({'S': {'a': 1}}, {'S': {'a': 2}}, {'S': 'scalar'}) == {'S': {'a': 2}}
    assert transplant.lay(1, 2, 3) == 2


def test_leaves():
    assert transplant.leaves({'a': {'b': 1, 'c': [1]}, 'd': {}}) == [('a.b', 1), ('a.c', [1]), ('d', {})]


def test_diff_paths_and_noise():
    assert transplant.changed_paths({'a': {'b': 1}, 'c': 1}, {'a': {'b': 2}}) == [('c', 1, None), ('a.b', 1, 2)]
    assert transplant.without(frozenset({'a'}), [('a.b', 1, 2), ('ab', 1, 2)]) == [('ab', 1, 2)]
    assert noise_between({'RequestId': 'x', 'v': 1}, {'RequestId': 'y', 'v': 1}) == {'RequestId'}
    assert transplant.structured({}, {}) and not transplant.structured({}, []) and not transplant.structured(b'x')


# ---------------------------------------------------------------- ids
def test_id_map_translates_both_ways_in_one_pass():
    m = IdMap()
    m.add('sg-1', 'sg-2')
    m.add('sg-2', 'sg-3')   # a real id equal to another copy's engine id must not chain
    assert m.translate('a sg-1 b sg-2', True) == 'a sg-2 b sg-3'
    assert m.translate(b'sg-3 sg-2', False) == b'sg-2 sg-1'
    assert m.known_engine_id('sg-3') and not m.known_engine_id('sg-1')


def test_id_map_leaves_opaque_payloads_alone():
    m = IdMap()
    m.add('real-1', 'eng-1')
    req = WireRequest('PUT', '/real-1', 'x=real-1', {}, b'real-1')
    assert m.request_to_engine(req, opaque=True).body == b'real-1'
    out = m.request_to_engine(req, opaque=False)
    assert (out.path, out.query, out.body) == ('/eng-1', 'x=eng-1', b'eng-1')
    resp = m.response_to_client(WireResponse(200, {'h': 'eng-1'}, b'eng-1'), opaque=False)
    assert resp.headers['h'] == 'real-1' and resp.body == b'real-1'


@pytest.mark.parametrize('engine_id', ['sg-0000000000000000a', 'vpc-00000001', '12345678-1234-1234-1234-123456789abc'])
def test_aliases_keep_the_format_and_are_stable(engine_id):
    a = alias_of(engine_id)
    assert a != engine_id and len(a) == len(engine_id) and a == alias_of(engine_id)
    assert a.split('-')[0] == engine_id.split('-')[0] or len(engine_id) == 36


# ---------------------------------------------------------------- lists
def _slot(*names, refs=None):
    items = tuple({'name': n, 'v': 0} for n in names)
    return Listed(('items',), items, refs if refs is not None else tuple(ResourceRef(T, n) for n in names), frozenset({T}))


def test_merge_takes_real_items_minus_the_branch_plus_engine_items():
    st = {'b': State.COPIED, 'c': State.DELETED, 'd': State.BORN}
    state_of = lambda r: st.get(r.id, State.LIVE)
    real = {'items': [{'name': n, 'v': 0} for n in 'abc']}
    engine = _slot('b', 'd', 'x')   # x: engine-only, not the branch's (an engine default)
    engine = Listed(engine.path, ({'name': 'b', 'v': 9}, {'name': 'd', 'v': 0}, {'name': 'x', 'v': 0}), engine.refs, engine.types)
    out = lists.merge(real, [_slot('a', 'b', 'c')], [engine], state_of, lambda ref, path: {'name': 'b', 'v': 0})
    assert out == {'items': [{'name': 'a', 'v': 0}, {'name': 'b', 'v': 9}, {'name': 'd', 'v': 0}]}


def test_merge_refuses_items_it_cannot_tell():
    with pytest.raises(CannotTell):
        lists.merge({'items': []}, [_slot('a', refs=(None,))], [], lambda r: State.LIVE, lambda r, p: None)


def test_relevant_and_set_at():
    assert lists.relevant([_slot('a')], frozenset({'other'})) == []
    assert lists.set_at({'a': ''}, ('a', 'b'), [1]) == {'a': {'b': [1]}}


# ---------------------------------------------------------------- journal and diff
def _call(op, **p):
    return Call('cloud', op, p, Kind.READ, WireRequest('POST', '/', '', {}, b''))


def test_journal_and_state_level_diff():
    a, b, c, d = (ResourceRef(T, x) for x in 'abcd')
    j = Journal()
    j.add('cloud', 'put', {'name': 'a'}, 200, (a,))
    j.add('cloud', 'put', {'name': 'a'}, 400, (a,))
    j.add('cloud', 'poke', {'name': 'd'}, 200, (d,))
    j.add('cloud', 'create', {}, 200, (), (b,))
    assert j.calls_on(a) == ('cloud.put',) and [e.n for e in j.entries()] == [1, 2, 3, 4]
    get_a, get_d = _call('get', name='a'), _call('get', name='d')
    bases = Baselines()
    bases.set(a, [Baseline(a, get_a, Answer(200, {'size': 1, 'RequestId': 'r1'}), Answer(200, {'size': 1}),
                           frozenset({'RequestId'}))])
    bases.set(d, [Baseline(d, get_d, Answer(200, {'size': 1}), Answer(200, {'size': 1}))])
    now = {key_of(get_a): Answer(200, {'size': 2, 'RequestId': 'r2'}), key_of(get_d): Answer(200, {'size': 1})}
    held = {a: State.COPIED, b: State.BORN, c: State.DELETED, d: State.COPIED}
    changes = diff.changes(held, frozenset({a, c, d}), bases.all(), lambda base: now[base.key], lambda base, body: body, j,
                           lambda ref: [('get.size', 0)])
    by = {ch.ref.id: ch for ch in changes}
    assert by['a'].type is ChangeType.MODIFIED and [(f.path, f.before, f.after) for f in by['a'].fields] == [('get.size', 1, 2)]
    assert by['b'].type is ChangeType.CREATED and [(f.path, f.before, f.after) for f in by['b'].fields] == [('get.size', None, 0)]
    assert by['c'].type is ChangeType.DELETED and by['c'].fields == ()   # no baseline was kept for it
    assert by['d'].type is ChangeType.ACTION and by['d'].calls == ('cloud.poke',)
    drift = diff.drift(bases.all(), lambda base: Answer(200, {'size': 5}), lambda base, body: body)
    assert {ch.ref.id for ch in drift} == {'a', 'd'}
