"""The reference index: who names whom, and how sure that is."""
from emfirge.graph import ReferenceIndex, Strength, Vocabulary

from acme_cloud import (BADGE, BOX, BOX_GRANT, DNS, EDGE, JOB, JOB_GRANT, STORE, VOCAB, account, b64, policy, ref, urn)


def _index(states):
    return ReferenceIndex.build(states, VOCAB)


def _edge(index, source, target):
    found = [e for e in index.names(source) if e.target == target]
    return max(found, key=lambda e: e.strength) if found else None


def test_exact_address_is_strong():
    e = _edge(_index(account()), JOB, JOB_GRANT)
    assert (e.strength, e.how, e.path) == (Strength.STRONG, 'address', 'grant')   # 'urn:acme:grant/publisher-grant'


def test_id_inside_an_address_is_strong():
    e = _edge(_index(account()), JOB_GRANT, STORE)
    assert (e.strength, e.how) == (Strength.STRONG, 'address')      # 'urn:acme:store/media-files/*'
    assert _edge(_index(account()), EDGE, STORE).how == 'address'    # 'media-files.store.acme.net'


def test_id_as_a_word_in_a_script_is_text():
    e = _edge(_index(account()), BOX, STORE)
    assert (e.strength, e.how, e.path) == (Strength.TEXT, 'text', 'startup<base64>')
    assert 'acme://media-files/latest' in e.snippet


def test_bare_name_equal_to_a_whole_value_is_weak():
    e = _edge(_index(account()), JOB, STORE)
    assert (e.strength, e.how, e.path) == (Strength.WEAK, 'name', 'env.OUTPUT')


def test_whole_token_only():
    states = {STORE: {}, ref('store', 'media-files-backup'): {}, JOB: {'out': 'urn:acme:store/media-files-backup'}}
    assert _edge(_index(states), JOB, STORE) is None


def test_longest_identifier_wins():
    fn, logs = ref('job', 'publisher'), ref('log', 'logs/jobs/publisher')
    states = {fn: {}, logs: {}, JOB_GRANT: {'on': 'urn:acme:log/logs/jobs/publisher:*'}}
    index = _index(states)
    assert _edge(index, JOB_GRANT, logs) is not None
    assert _edge(index, JOB_GRANT, fn) is None


def test_a_plain_word_is_not_matched_inside_text():
    word = ref('bus', 'default')
    states = {word: {}, JOB: {'note': 'use the default settings here'}}
    assert _edge(_index(states), JOB, word) is None


def test_short_names_are_ignored():
    short = ref('store', 'abc')
    states = {short: {}, JOB: {'env': {'X': 'abc'}, 'cmd': 'copy abc now'}}
    assert _index(states).names(JOB) == []


def test_a_name_several_resources_share_is_weak():
    a, b = ref('bus', 'shared-name'), ref('group', 'shared-name')
    states = {a: {}, b: {}, JOB: {'on': 'urn:acme:timer/shared-name/x'}}
    index = _index(states)
    assert {_edge(index, JOB, a).strength, _edge(index, JOB, b).strength} == {Strength.WEAK}


def test_pattern_matches_weakly():
    states = {STORE: {}, JOB: {'on': 'urn:acme:store/media-*'}}
    e = _edge(_index(states), JOB, STORE)
    assert (e.strength, e.how) == (Strength.WEAK, 'pattern')


def test_catch_all_is_scoped_by_its_sibling_patterns():
    states = {STORE: {}, JOB: {}, BOX_GRANT: {'doc': policy({'actions': ['store:*'], 'on': '*'})}}
    index = _index(states)
    assert _edge(index, BOX_GRANT, STORE).how == 'catch-all'
    assert _edge(index, BOX_GRANT, JOB) is None                      # 'store:*' does not cover 'job:job'


def test_catch_all_without_scope_names_nothing():
    states = {STORE: {}, BOX_GRANT: {'on': '*'}}
    assert _index(states).names(BOX_GRANT) == []


def test_owned_host_name_links_a_record_to_the_edge():
    e = _edge(_index(account()), DNS, EDGE)
    assert (e.strength, e.how) == (Strength.STRONG, 'exact')         # 'd1x2y3.edge.acme.net' is the edge's own host


def test_a_value_two_resources_carry_is_nobodys_name():
    a, b = ref('box', 'box-00000000a1'), ref('box', 'box-00000000b2')
    states = {a: {'image': 'img-0123456789'}, b: {'image': 'img-0123456789'}, JOB: {'use': 'img-0123456789'}}
    assert _index(states).names(JOB) == []


def test_alias_of_a_path_shaped_id():
    q = ref('queue', 'https://queue.acme.net/acct/jobs-queue')
    states = {q: {}, JOB_GRANT: {'on': urn('queue', 'jobs-queue')}}
    assert _edge(_index(states), JOB_GRANT, q).strength is Strength.STRONG


def test_ghosts_give_identifiers_and_no_edges():
    states = {JOB: {'out': urn('store', 'media-files')}}
    index = ReferenceIndex.build(states, VOCAB, ghosts={STORE: {'policy': urn('job', 'publisher-job')}})
    assert _edge(index, JOB, STORE) is not None and index.names(STORE) == []


def test_ambient_resource_is_kept_apart():
    region = ref('region', 'north-1')
    states = {region: {}, **{ref('box', f'box-{i:010x}'): {'where': [f'urn:acme:north-1:box/{i}']} for i in range(8)}}
    index = ReferenceIndex.build(states, Vocabulary(VOCAB.address_patterns, VOCAB.opaque_patterns, ambient_min=5))
    assert region in index.ambient and index.named_by(region) == []


def test_badge_names_its_grant_through_a_list():
    assert _edge(_index(account()), BADGE, BOX_GRANT).strength is Strength.STRONG


def test_an_opaque_id_in_a_script_is_strong_a_name_is_text():
    states = {EDGE: {}, STORE: {}, BOX: {'startup': b64('purge edg-0a1b2c3d4e\nfetch urn:acme:store/media-files\n')}}
    index = _index(states)
    assert _edge(index, BOX, EDGE).strength is Strength.STRONG
    assert _edge(index, BOX, STORE).strength is Strength.TEXT        # an address inside a script line is still text
