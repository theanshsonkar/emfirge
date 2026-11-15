"""Reach: for a change, who is affected, by which chain, how sure, and what cannot be told."""
from emfirge.core.model import Affected, Change, ChangeType
from emfirge.graph import Graph, Relation, Strength

from acme_cloud import (BADGE, BOX, BOX_GRANT, DNS, EDGE, JOB, JOB_GRANT, OTHER, STORE, TIMER, TIMER_GRANT, VOCAB,
                        account, policy, ref, urn)

DELETED, MODIFIED, CREATED = ChangeType.DELETED, ChangeType.MODIFIED, ChangeType.CREATED


def _run(changes, before=None, after=None, depth=3):
    return Graph(VOCAB, depth).affects(changes, before if before is not None else account(), after)


def _by_ref(report, firm_only=True):
    c = report.changes[0]
    return {i.ref: i for i in (c.affected if firm_only else c.affected + c.maybe)}


def test_deleted_store_reaches_dns_through_the_edge_two_hops():
    found = _by_ref(_run([Change(STORE, DELETED)]))
    assert found[EDGE].relation is Relation.USES and found[EDGE].via == ()
    assert found[DNS].via == (EDGE,) and found[DNS].strength is Strength.STRONG


def test_deleted_store_reaches_the_box_by_its_badge_chain_and_by_its_script():
    found = _by_ref(_run([Change(STORE, DELETED)]))
    assert found[BOX].via == (BOX_GRANT, BADGE) and found[BOX].strength is Strength.STRONG   # box -> badge -> grant -> store
    assert found[JOB].via == (JOB_GRANT,)                                                    # strong chain beats the weak env


def test_deleted_store_reaches_the_timer_at_depth_three_and_not_beyond():
    assert _by_ref(_run([Change(STORE, DELETED)]))[TIMER].via == (JOB_GRANT, JOB)
    assert TIMER not in _by_ref(_run([Change(STORE, DELETED)], depth=2))


def test_deleted_grant_takes_access_from_what_it_named():
    found = _by_ref(_run([Change(BOX_GRANT, DELETED)]))
    assert found[STORE].relation is Relation.REACHED and 'loses a user' in found[STORE].because
    assert found[BOX].relation is Relation.USES and found[BOX].via == (BADGE,)


def test_unused_store_affects_nothing():
    report = _run([Change(OTHER, DELETED)])
    assert report.changes[0].affected == () and report.unknowns() == []


def test_a_setting_change_that_touches_no_reference_reports_its_users_and_nothing_forward():
    after = {JOB: {**account()[JOB], 'memory': 512}}
    report = _run([Change(JOB, MODIFIED)], after=after)
    firm, loose = _by_ref(report), _by_ref(report, firm_only=False)
    assert set(firm) == {TIMER, TIMER_GRANT}                              # who uses the job
    assert loose[STORE].relation is Relation.REACHED and not loose[STORE].firm


def test_an_action_reaches_forward_and_downstream_is_only_maybe():
    report = _run([Change(JOB, ChangeType.ACTION)], after={JOB: account()[JOB]})
    firm, loose = _by_ref(report), _by_ref(report, firm_only=False)
    assert firm[TIMER].relation is Relation.USES
    assert firm[STORE].relation is Relation.REACHED and firm[STORE].via == (JOB_GRANT,)
    assert firm[EDGE].relation is Relation.REACHED          # the store's own policy names the edge
    assert loose[BOX].relation is Relation.DOWNSTREAM and BOX not in firm


def test_a_changed_reference_makes_its_new_target_and_beyond_news():
    after = {JOB: {**account()[JOB], 'grant': urn('grant', 'box-grant')}}
    found = _by_ref(_run([Change(JOB, MODIFIED)], after=after))
    assert found[BOX_GRANT].relation is Relation.NOW_NAMED and found[JOB_GRANT].relation is Relation.NO_LONGER_NAMED
    assert found[STORE].relation is Relation.REACHED and found[STORE].via == (BOX_GRANT,)   # reached through the new reference


def test_timer_run_reaches_the_store_three_links_out():
    found = _by_ref(_run([Change(TIMER, ChangeType.ACTION)], after={TIMER: account()[TIMER]}))
    assert found[STORE].via == (JOB, JOB_GRANT) and found[STORE].relation is Relation.REACHED


def test_repoint_to_a_new_store():
    new = ref('store', 'media-feed')
    after = {new: {'name': 'media-feed'}, JOB: {**account()[JOB], 'env': {'OUTPUT': 'media-feed'}}}
    report = _run([Change(new, CREATED), Change(JOB, MODIFIED)], after=after)
    job = {i.ref: i for i in report.changes[1].affected}
    assert job[JOB_GRANT].relation is Relation.OUT_OF_STEP and 'still names' in job[JOB_GRANT].because
    assert job[STORE].relation is Relation.NO_LONGER_NAMED and job[STORE].strength is Strength.STRONG
    assert job[new].relation is Relation.NOW_NAMED
    assert job[BOX_GRANT].relation is Relation.ON_OLD_TARGET
    assert job[EDGE].relation is Relation.OUT_OF_STEP       # reached through the old store's policy; still on the old store


def test_repoint_to_something_unknown_is_an_unknown():
    after = {JOB: {**account()[JOB], 'env': {'OUTPUT': 'nowhere-at-all'}}}
    report = _run([Change(JOB, MODIFIED)], after=after)
    assert any('names nothing known' in u.what for u in report.unknowns())
    assert _by_ref(report, firm_only=False)[STORE].relation is Relation.NO_LONGER_NAMED


def test_dropped_link_is_no_longer_named():
    after = {JOB: {'env': {'OUTPUT': 'media-files'}}}                 # the grant reference is gone
    found = _by_ref(_run([Change(JOB, MODIFIED)], after=after))
    assert found[JOB_GRANT].relation is Relation.NO_LONGER_NAMED and found[JOB_GRANT].strength is Strength.STRONG


def test_dropped_bare_name_stays_visible_beside_a_firm_finding():
    a, b = ref('node', 'node-alpha'), ref('node', 'node-beta')
    before = {a: {}, b: {'uses': urn('node', 'node-alpha'), 'env': {'OUTPUT': 'node-alpha'}}}
    c = _run([Change(b, ChangeType.MODIFIED)], before=before, after={b: {'uses': urn('node', 'node-alpha'), 'env': {}}}).changes[0]
    assert Relation.NO_LONGER_NAMED not in {i.relation for i in c.maybe if i.ref == a}   # still named exactly: nothing lost
    before[b]['uses'] = 'x'
    c = _run([Change(b, ChangeType.MODIFIED)], before=before, after={b: {'uses': 'x', 'env': {}}}).changes[0]
    assert {i.relation for i in c.maybe if i.ref == a} == {Relation.NO_LONGER_NAMED}     # a weak lost name is shown apart


def test_created_store_with_a_policy_now_names_the_edge_and_only_that():
    new = ref('store', 'media-feed')
    after = {new: {'policy': policy({'allow': 'read', 'who': urn('edge', 'edg-0a1b2c3d4e')})}}
    found = _by_ref(_run([Change(new, CREATED)], after=after))
    assert set(found) == {EDGE} and found[EDGE].relation is Relation.REACHED


def test_created_store_that_shares_a_name_is_only_maybe():
    cache = ref('cache', 'chc-0011223344')
    before = {**account(), cache: {'config': {'name': 'media-feed'}}}
    new = ref('store', 'media-feed')
    report = _run([Change(new, CREATED)], before=before, after={new: {}})
    assert report.changes[0].affected == () and _by_ref(report, firm_only=False)[cache].strength is Strength.WEAK


def test_wildcard_grant_is_only_maybe():
    old = ref('grant', 'old-deploy-grant')
    before = {**account(), old: {'doc': policy({'actions': ['store:*'], 'on': '*'})}}
    report = _run([Change(STORE, DELETED)], before=before)
    assert old not in _by_ref(report) and _by_ref(report, firm_only=False)[old].strength is Strength.WEAK


def test_unknown_states_are_unknowns():
    ghost = ref('store', 'never-seen')
    assert 'no settings are known' in _run([Change(ghost, DELETED)]).unknowns()[0].what
    assert 'new settings are not known' in _run([Change(JOB, MODIFIED)]).unknowns()[0].what


def test_cycles_end():
    a, b, c = ref('node', 'node-aaaa'), ref('node', 'node-bbbb'), ref('node', 'node-cccc')
    states = {a: {'next': urn('node', 'node-bbbb')}, b: {'next': urn('node', 'node-cccc')}, c: {'next': urn('node', 'node-aaaa')}}
    found = _by_ref(_run([Change(a, DELETED)], before=states, depth=10))
    assert set(found) == {b, c}


def test_chain_strength_is_its_weakest_link_and_weak_links_end_chains():
    a, b, c = ref('node', 'node-alpha'), ref('node', 'node-beta'), ref('node', 'node-gamma')
    states = {a: {}, b: {'uses': 'node-alpha'}, c: {'uses': urn('node', 'node-beta')}}
    loose = _by_ref(_run([Change(a, DELETED)], before=states), firm_only=False)
    assert loose[b].strength is Strength.WEAK and c not in loose


def test_text_links_end_chains():
    a, b, c = ref('node', 'node-alpha'), ref('node', 'node-beta'), ref('node', 'node-gamma')
    states = {a: {}, b: {'script': 'copy node-alpha now'}, c: {'uses': urn('node', 'node-beta')}}
    found = _by_ref(_run([Change(a, DELETED)], before=states))
    assert found[b].strength is Strength.TEXT and c not in found


def test_to_affected_carries_the_chain():
    impact = _by_ref(_run([Change(STORE, DELETED)]))[DNS]
    affected = impact.to_affected()
    assert isinstance(affected, Affected) and affected.via == (EDGE,) and affected.strength == 'strong'
    assert 'names' in affected.because
