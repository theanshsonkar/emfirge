"""The rules added after the hold-out test (experiment 21), each on the made-up cloud: own names, typed bare names,
duplicates, pipes, dropped exact links, and the incremental index."""
import copy

from emfirge.core.model import Change, ChangeType
from emfirge.graph import Graph, ReferenceIndex, Relation, Strength, Vocabulary

from acme_cloud import VOCAB, account, ref, urn

LOW_AMBIENT = Vocabulary(VOCAB.address_patterns, VOCAB.opaque_patterns, ambient_min=5)
REGION = ref('region', 'north-1')


def _edge(index, source, target):
    found = [e for e in index.names(source) if e.target == index.canonical(target)]
    return max(found, key=lambda e: e.strength) if found else None


def _boxes(n=8):
    """Resources whose own addresses all carry the region: the region becomes context."""
    return {ref('box', f'box-{i:010x}'): {'Id': f'urn:acme:north-1:box/box-{i:010x}'} for i in range(n)}


# -- own names ----------------------------------------------------------------------------------------------------
def test_region_in_an_own_address_does_not_make_it_someone_elses():
    vault, task = ref('vault', 'db-pass'), ref('task', 'web-task')
    states = {REGION: {}, **_boxes(), vault: {'Id': 'urn:acme:north-1:vault/db-pass'},
              task: {'secrets': [{'from': 'urn:acme:north-1:vault/db-pass'}]}}
    e = _edge(ReferenceIndex.build(states, LOW_AMBIENT), task, vault)
    assert (e.strength, e.how) == (Strength.STRONG, 'exact')


def test_provider_suffix_on_the_id_inside_its_own_address():
    vault, stage, task = ref('vault', 'prod/db-pass'), ref('stage', 'prod'), ref('task', 'web-task')
    address = 'urn:acme:vault/prod/db-pass-x7Y2zQ'      # 'prod' is another resource; the id has a random suffix
    states = {vault: {'Id': address}, stage: {}, task: {'secrets': [{'from': address}]}}
    assert _edge(ReferenceIndex.build(states, VOCAB), task, vault).strength is Strength.STRONG
    states[vault] = {'blob': address}                    # not an identifying field: not claimed as its own
    assert _edge(ReferenceIndex.build(states, VOCAB), task, vault) is None


def test_a_shared_endpoint_is_nobodys_name():
    db, repo, task = ref('db', 'main-db'), ref('repo', 'web-repo'), ref('task', 'web-task')
    states = {db: {'endpoint': 'shared.acme.net'}, repo: {'uri': 'acme://shared.acme.net/web-repo'},
              task: {'image': 'acme://shared.acme.net/web-repo:latest', 'note': ['shared.acme.net']}}
    index = ReferenceIndex.build(states, VOCAB)
    assert _edge(index, task, db) is None and _edge(index, task, repo).strength is Strength.STRONG


# -- bare names ---------------------------------------------------------------------------------------------------
def test_unique_name_with_an_inner_separator_is_strong():
    alias, q = ref('alias', 'alias/data-key'), ref('queue', 'orders-q')
    index = ReferenceIndex.build({alias: {}, q: {'encryption': 'alias/data-key'}}, VOCAB)
    assert _edge(index, q, alias).how == 'typed name' and _edge(index, q, alias).strength is Strength.STRONG


def test_a_label_naming_the_type_makes_a_unique_name_strong():
    q, alarm = ref('queue', 'orders-dlq'), ref('alarm', 'dlq-not-empty')
    states = {q: {}, alarm: {'dimensions': [{'Name': 'QueueName', 'Value': 'orders-dlq'}]}}
    assert _edge(ReferenceIndex.build(states, VOCAB), alarm, q).strength is Strength.STRONG
    states[alarm] = {'dimensions': [{'Name': 'Colour', 'Value': 'orders-dlq'}]}
    assert _edge(ReferenceIndex.build(states, VOCAB), alarm, q).strength is Strength.WEAK


def test_a_typed_name_shared_by_two_resources_stays_weak():
    q, store, fn = ref('queue', 'orders'), ref('store', 'orders'), ref('job', 'job-1')
    index = ReferenceIndex.build({q: {}, store: {}, fn: {'env': {'QUEUE': 'orders'}}}, VOCAB)
    assert _edge(index, fn, q).strength is Strength.WEAK


# -- duplicates ---------------------------------------------------------------------------------------------------
def test_a_pointer_equal_to_another_id_is_not_folded():
    box, net = ref('net', 'net-0a1b2c3d4e'), ref('net', 'net-host-1')
    index = ReferenceIndex.build({box: {}, net: {'NetId': 'net-0a1b2c3d4e'}}, VOCAB)   # net-host-1 points at the net
    assert index.canonical(box) == box and _edge(index, net, box).strength is Strength.STRONG


def test_a_field_labelled_with_the_other_kind_is_a_pointer_even_when_named_back():
    box, card = ref('box', 'box-00aa11bb22'), ref('card', 'card-00cc11dd22')
    states = {box: {'cards': ['card-00cc11dd22']}, card: {'attachment': {'BoxId': 'box-00aa11bb22'}}}
    index = ReferenceIndex.build(states, VOCAB)
    assert index.canonical(box) == box and index.canonical(card) == card


def test_a_resource_listed_again_under_its_internal_id_is_folded():
    grant, dup, job = ref('grant', 'job-grant'), ref('grant', 'grt-0a1b2c3d4e'), ref('job', 'job-1')
    states = {grant: {'GrantId': 'grt-0a1b2c3d4e'}, dup: {'GrantName': 'job-grant'}, job: {'grant': 'grt-0a1b2c3d4e'}}
    index = ReferenceIndex.build(states, VOCAB)
    assert index.canonical(dup) == grant and dup not in index.refs
    assert _edge(index, job, grant).strength is Strength.STRONG


# -- pipes and dropped links --------------------------------------------------------------------------------------
def _topics():
    old, new, sub, q, job = (ref('topic', 'order-events'), ref('topic', 'alerts'), ref('sub', 'sub-0a1b2c3d4e'),
                             ref('queue', 'emails-q'), ref('job', 'consumer-job'))
    states = {old: {}, new: {}, q: {},
              sub: {'topic': urn('topic', 'order-events'), 'endpoint': urn('queue', 'emails-q')},
              job: {'env': {'TOPIC': urn('topic', 'order-events')}}}
    return old, new, sub, q, job, states


def test_a_deleted_topic_reaches_the_queue_behind_its_subscription():
    old, _, sub, q, _, states = _topics()
    c = Graph(VOCAB).affects([Change(old, ChangeType.DELETED)], states).changes[0]
    found = {i.ref: i for i in c.affected}
    assert found[sub].relation is Relation.USES and found[q].relation is Relation.THROUGH and found[q].via == (sub,)


def test_a_repoint_reaches_the_queue_behind_the_old_subscription():
    old, new, sub, q, job, states = _topics()
    after = {job: {'env': {'TOPIC': urn('topic', 'alerts')}}}
    found = {i.ref: i for i in Graph(VOCAB).affects([Change(job, ChangeType.MODIFIED)], states, after).changes[0].affected}
    assert found[sub].relation is Relation.ON_OLD_TARGET and found[q].relation is Relation.THROUGH


def test_a_resource_naming_many_things_is_not_a_pipe():
    old, _, sub, q, _, states = _topics()
    states[sub]['extra'] = [urn('queue', 'emails-q'), urn('topic', 'alerts')]
    found = {i.ref for i in Graph(VOCAB).affects([Change(old, ChangeType.DELETED)], states).changes[0].affected}
    assert q not in found


def test_users_of_what_a_dropped_exact_link_named_are_affected():
    app, lb_wall, lb = ref('wall', 'wal-00000000a1'), ref('wall', 'wal-00000000b2'), ref('balancer', 'web-lb')
    states = {app: {'allow': [{'from': 'wal-00000000b2', 'port': 8080}]}, lb_wall: {}, lb: {'walls': ['wal-00000000b2']}}
    c = Graph(VOCAB).affects([Change(app, ChangeType.MODIFIED)], states, {app: {'allow': []}}).changes[0]
    found = {i.ref: i for i in c.affected}
    assert found[lb_wall].relation is Relation.NO_LONGER_NAMED and found[lb].relation is Relation.BEHIND_LOST_LINK


def test_a_dropped_name_does_not_pull_in_the_users_of_its_target():
    store, other, job = ref('store', 'media-files'), ref('job', 'reader-job'), ref('job', 'writer-job')
    states = {store: {}, other: {'read': urn('store', 'media-files')}, job: {'env': {'STORE': 'media-files'}}}
    c = Graph(VOCAB).affects([Change(job, ChangeType.MODIFIED)], states, {job: {'env': {}}}).changes[0]
    assert other not in {i.ref for i in c.affected}


# -- the incremental index ----------------------------------------------------------------------------------------
def _edge_set(index, refs):
    return {(e.source, e.target, e.path, e.strength) for r in refs for e in index.names(r)}


def test_index_after_changes_equals_a_full_build():
    states = account()
    new = ref('store', 'media-feed')
    changed = {new: {'name': 'media-feed'}, ref('job', 'publisher-job'): {'env': {'OUTPUT': 'media-feed'}}}
    gone = [ref('store', 'scratch-2024')]
    incremental = ReferenceIndex.build(states, VOCAB).with_changes(changed, gone)
    after = {r: s for r, s in {**states, **changed}.items() if r not in gone}
    full = ReferenceIndex.build(after, VOCAB, ghosts={g: states[g] for g in gone})
    refs = set(after)
    assert _edge_set(incremental, refs) == _edge_set(full, refs)


def test_the_account_index_is_built_once_for_the_same_states():
    graph, states = Graph(VOCAB), account()
    assert graph.index(states) is graph.index(copy.deepcopy(states))
    changed = {**states, ref('store', 'scratch-2024'): {'name': 'renamed'}}
    assert graph.index(changed) is not graph.index(states)


def test_a_role_with_two_grants_is_not_a_pipe():
    q, table, role = ref('queue', 'orders-q'), ref('table', 'carts-t'), ref('grant', 'app-grant')
    states = {q: {}, table: {}, role: {'doc': [{'on': urn('queue', 'orders-q')}, {'on': urn('table', 'carts-t')}]}}
    found = {i.ref for i in Graph(VOCAB).affects([Change(q, ChangeType.DELETED)], states).changes[0].affected}
    assert role in found and table not in found


def test_something_that_is_used_is_not_a_pipe():
    old, _, sub, q, _, states = _topics()
    states[ref('job', 'auditor')] = {'watches': urn('sub', 'sub-0a1b2c3d4e')}
    found = {i.ref for i in Graph(VOCAB).affects([Change(old, ChangeType.DELETED)], states).changes[0].affected}
    assert q not in found


def test_a_chain_does_not_continue_across_a_mutual_pair():
    store, grant, shared, other = (ref('store', 'media-files'), ref('grant', 'job-grant'), ref('policy', 'basic-policy'),
                                   ref('grant', 'other-grant'))
    states = {store: {}, grant: {'on': urn('store', 'media-files'), 'attached': urn('policy', 'basic-policy')},
              shared: {'entities': [urn('grant', 'job-grant'), urn('grant', 'other-grant')]},
              other: {'attached': urn('policy', 'basic-policy')}}
    found = {i.ref for i in Graph(VOCAB).affects([Change(store, ChangeType.DELETED)], states).changes[0].affected}
    assert {grant, shared} <= found and other not in found


def test_a_pipe_two_links_away_is_not_followed():
    old, _, sub, q, _, states = _topics()
    hub = ref('hub', 'hub-0a1b2c3d4e')
    states[hub] = {'feeds': urn('topic', 'order-events')}
    states[sub] = {'source': urn('hub', 'hub-0a1b2c3d4e'), 'endpoint': urn('queue', 'emails-q')}
    found = {i.ref for i in Graph(VOCAB).affects([Change(old, ChangeType.DELETED)], states).changes[0].affected}
    assert sub in found and q not in found


def test_a_modify_does_not_reach_through_a_pipe_that_uses_it():
    old, _, sub, q, _, states = _topics()
    found = {i.ref for i in Graph(VOCAB).affects([Change(old, ChangeType.MODIFIED)], states, {old: {'size': 2}}).changes[0].affected}
    assert sub in found and q not in found
