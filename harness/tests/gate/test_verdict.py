"""The verdict: every reason code, the empty change set, both affected rules, and determinism. Pure.

Resource names are made up (an 'acme' cloud); the gate knows no cloud."""
from __future__ import annotations

import itertools
import random

import pytest

from emfirge.core.model import (Affected, Change, ChangeType, FieldChange, Finding, ResourceRef, Undo, UndoFact,
                                Unknown)
from emfirge.gate import REASONS, AffectedRule, Code, Verdict, decide

JOB = ResourceRef('acme:job', 'publisher')
TIMER = ResourceRef('acme:timer', 'nightly')
STORE = ResourceRef('acme:store', 'media')
GRANT = ResourceRef('acme:grant', 'publisher-grant')

EDIT = Change(JOB, ChangeType.MODIFIED, (FieldChange('Timeout', 30, 60),), ('acme.UpdateJob',))
NEW = Change(STORE, ChangeType.CREATED, calls=('acme.CreateStore',))


def yes(ref: ResourceRef) -> UndoFact:
    return UndoFact(ref, Undo.YES, ('put back on the branch and found equal',))


def codes(decision) -> list[Code]:
    return [r.code for r in decision.reasons]


def test_nothing_changed_is_go_and_says_so():
    d = decide([], [], [], [], [])
    assert d.verdict is Verdict.GO and d.exit_code == 0
    assert codes(d) == [Code.NOTHING_CHANGED]
    assert d.reasons[0].words == 'The agent changed nothing.'


def test_nothing_changed_but_something_unknown_is_ask():
    """A refused call leaves no change but an unknown: the owner must hear that the work was blocked."""
    d = decide([], [], [], [Unknown('acme.RevokeRule: the branch cannot copy this network', 'branch')], [])
    assert d.verdict is Verdict.ASK and d.exit_code == 3
    assert codes(d) == [Code.UNKNOWN]


def test_every_change_undoable_and_nothing_else_is_go():
    d = decide([EDIT, NEW], [yes(JOB), yes(STORE)], [], [], [])
    assert d.verdict is Verdict.GO
    assert codes(d) == [Code.ALL_UNDOABLE]


@pytest.mark.parametrize('undo, code', [(Undo.NO, Code.CANNOT_UNDO), (Undo.UNKNOWN, Code.UNDO_UNKNOWN)])
def test_a_change_that_is_not_undoable_is_ask(undo, code):
    d = decide([EDIT], [UndoFact(JOB, undo, ('first reason', 'second reason'))], [], [], [])
    assert d.verdict is Verdict.ASK
    assert codes(d) == [code]
    assert d.reasons[0].refs == (JOB,)
    assert 'first reason (and 1 more)' in d.reasons[0].words


def test_a_change_without_an_undo_fact_is_unknown():
    d = decide([EDIT], [], [], [], [])
    assert codes(d) == [Code.UNDO_UNKNOWN]
    assert 'no undo fact' in d.reasons[0].words


def test_an_undo_fact_for_something_not_changed_is_ignored():
    d = decide([EDIT], [yes(JOB), UndoFact(STORE, Undo.NO, ('irrelevant',))], [], [], [])
    assert d.verdict is Verdict.GO


def test_a_finding_is_ask():
    f = Finding('public', 'now-public', 'the store can now be read by anyone', (STORE,))
    d = decide([EDIT], [yes(JOB)], [f], [], [])
    assert d.verdict is Verdict.ASK
    assert codes(d) == [Code.FLAGGED]
    assert d.reasons[0].words == 'public flagged: the store can now be read by anyone'
    assert d.reasons[0].refs == (STORE,)


def test_an_unknown_is_ask_and_keeps_its_ref():
    d = decide([EDIT], [yes(JOB)], [], [Unknown('the grant could not be read', 'graph', GRANT)], [])
    assert codes(d) == [Code.UNKNOWN]
    assert d.reasons[0].refs == (GRANT,)


STRONG_TIMER = Affected(TIMER, 'its target names the job')


def test_strict_rule_asks_when_something_outside_is_reached_strongly():
    d = decide([EDIT], [yes(JOB)], [], [], [STRONG_TIMER])
    assert d.rule is AffectedRule.STRICT    # the default
    assert d.verdict is Verdict.ASK
    assert codes(d) == [Code.AFFECTS]
    assert d.reasons[0].refs == (TIMER,)


def test_loose_rule_shows_affected_but_goes():
    d = decide([EDIT], [yes(JOB)], [], [], [STRONG_TIMER], affected_rule=AffectedRule.LOOSE)
    assert d.verdict is Verdict.GO
    assert d.facts.affected == (STRONG_TIMER,)


@pytest.mark.parametrize('strength', ['weak', 'text'])
def test_strict_rule_ignores_weak_and_text_evidence(strength):
    d = decide([EDIT], [yes(JOB)], [], [], [Affected(TIMER, 'a bare name matches', strength=strength)])
    assert d.verdict is Verdict.GO


def test_strict_rule_ignores_what_is_inside_the_change_set():
    timer_edit = Change(TIMER, ChangeType.MODIFIED, (FieldChange('Rate', '1d', '2d'),))
    d = decide([EDIT, timer_edit], [yes(JOB), yes(TIMER)], [], [], [STRONG_TIMER])
    assert d.verdict is Verdict.GO


def test_strict_rule_gives_one_reason_per_affected_thing():
    d = decide([EDIT], [yes(JOB)], [], [], [STRONG_TIMER, Affected(TIMER, 'its role names the job'),
                                             STRONG_TIMER])
    assert codes(d) == [Code.AFFECTS]
    assert 'its role names the job' in d.reasons[0].words and 'its target names the job' in d.reasons[0].words


def test_reasons_are_listed_in_the_table_order():
    d = decide([EDIT, NEW], [UndoFact(JOB, Undo.NO, ('x',))], [Finding('money', 'm', 'costs more')],
               [Unknown('something')], [STRONG_TIMER])
    assert codes(d) == [Code.CANNOT_UNDO, Code.UNDO_UNKNOWN, Code.FLAGGED, Code.UNKNOWN, Code.AFFECTS]


def test_every_code_has_a_verdict_and_words():
    assert set(REASONS) == set(Code)
    for code, (verdict, words) in REASONS.items():
        assert isinstance(verdict, Verdict) and words


def test_same_facts_in_any_order_give_the_same_decision():
    changes = [EDIT, NEW, Change(GRANT, ChangeType.DELETED)]
    facts = [yes(JOB), UndoFact(STORE, Undo.UNKNOWN, ('u',)), UndoFact(GRANT, Undo.NO, ('n',))]
    findings = [Finding('money', 'a', 'one'), Finding('data', 'b', 'two')]
    unknowns = [Unknown('first'), Unknown('second', 'graph')]
    affected = [STRONG_TIMER, Affected(ResourceRef('acme:box', 'b1'), 'it runs the job'),
                Affected(ResourceRef('acme:dns', 'feed'), 'a name', strength='weak')]
    first = decide(changes, facts, findings, unknowns, affected)
    rng = random.Random(7)
    for _ in range(20):
        shuffled = [rng.sample(x, len(x)) for x in (changes, facts, findings, unknowns, affected)]
        assert decide(*shuffled) == first


def test_go_needs_all_conditions_at_once():
    """Each single failing condition, on its own, turns go into ask."""
    spoilers = {
        'undo': dict(undo=[UndoFact(JOB, Undo.UNKNOWN)]),
        'finding': dict(findings=[Finding('data', 'd', 'loses data')]),
        'unknown': dict(unknowns=[Unknown('x')]),
        'affected': dict(affected=[STRONG_TIMER]),
    }
    base = dict(changes=[EDIT], undo=[yes(JOB)], findings=[], unknowns=[], affected=[])
    assert decide(*base.values()).verdict is Verdict.GO
    for n in range(1, len(spoilers) + 1):
        for combo in itertools.combinations(spoilers.values(), n):
            args = {**base}
            for s in combo:
                args.update(s)
            assert decide(*args.values()).verdict is Verdict.ASK
