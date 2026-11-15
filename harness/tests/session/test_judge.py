"""The session pipeline with fake parts: seal -> diff -> reader -> graph -> lenses -> undo -> verdict."""
from __future__ import annotations

from emfirge.branch.lifecycle import Stage
from emfirge.core.model import Change, Undo, UndoFact, Unknown
from emfirge.gate import Code, Verdict
from emfirge.session import judge

from .fakes import (BOX, JOB, STORE, BrokenLens, FakeHeld, FakeReader, FlagLens, created, deleted, modified,
                    parts, ref)


def test_nothing_changed_is_go_and_the_account_is_not_read():
    reader = FakeReader()
    j = judge(FakeHeld(), parts(reader=reader))
    assert j.decision.verdict is Verdict.GO
    assert j.decision.reasons[0].code is Code.NOTHING_CHANGED
    assert reader.asked == [] and j.graph is None


def test_the_branch_is_sealed_then_judged():
    held = FakeHeld()
    judge(held, parts())
    assert held.life.history[-2:] == (Stage.SEALED, Stage.JUDGED)


def test_a_new_thing_that_can_go_again_and_reaches_nothing_is_go():
    new = ref('store', 'fresh-one')
    j = judge(FakeHeld([created(new)], {new: {'name': 'fresh-one'}}), parts())
    assert j.decision.verdict is Verdict.GO
    assert j.decision.exit_code == 0


def test_a_modified_thing_not_proven_is_ask():
    j = judge(FakeHeld([modified(JOB)], {JOB: {'writes': 'urn:acme:store/media', 'size': 2}}), parts())
    assert j.decision.verdict is Verdict.ASK
    assert Code.UNDO_UNKNOWN in {r.code for r in j.decision.reasons}


def test_a_prover_is_made_from_the_diff_after_the_reads_and_can_raise_unknown_to_yes():
    made = []

    class Prover:
        def prove(self, change: Change) -> UndoFact:
            return UndoFact(change.ref, Undo.YES, ('put back and found equal',))

    def factory(changes):
        made.append(tuple(changes))
        return Prover()

    new = ref('store', 'other-one')
    change = modified(new)
    j = judge(FakeHeld([change], {new: {'size': 2}}), parts(prover=factory))
    assert made == [(change,)]
    assert all(u.undo is Undo.YES for u in j.decision.facts.undo)
    assert j.decision.verdict is Verdict.GO


def test_deleting_a_used_thing_is_ask_and_names_what_uses_it():
    j = judge(FakeHeld([deleted(STORE)]), parts())
    assert j.decision.verdict is Verdict.ASK
    affected = {a.ref for a in j.decision.facts.affected}
    assert {JOB, BOX} <= affected
    assert Code.AFFECTS in {r.code for r in j.decision.reasons}


def test_a_failing_lens_becomes_an_unknown_and_stops_go():
    new = ref('store', 'fresh-one')
    j = judge(FakeHeld([created(new)], {new: {'name': 'fresh-one'}}), parts(lenses=(BrokenLens(),)))
    assert j.decision.verdict is Verdict.ASK
    assert any('broken lens failed' in u.what for u in j.decision.facts.unknowns)


def test_a_lens_finding_is_ask():
    new = ref('store', 'fresh-one')
    j = judge(FakeHeld([created(new)], {new: {}}), parts(lenses=(FlagLens(),)))
    assert j.decision.verdict is Verdict.ASK
    assert [f.message for f in j.decision.facts.findings] == ['something new']


def test_the_branchs_own_refusals_are_unknowns():
    j = judge(FakeHeld(refused=[Unknown('svc.Do: cannot tell', 'branch')]), parts())
    assert j.decision.verdict is Verdict.ASK


def test_reader_unknowns_reach_the_gate():
    reader = FakeReader()
    reader.before = lambda changes: __import__('emfirge.session', fromlist=['Reading']).Reading(
        {}, (Unknown('the reader stopped at its budget', 'reader'),), 400)
    new = ref('store', 'fresh-one')
    j = judge(FakeHeld([created(new)], {new: {}}), parts(reader=reader))
    assert any('budget' in u.what for u in j.decision.facts.unknowns)


def test_seconds_and_reads_are_measured():
    j = judge(FakeHeld([deleted(STORE)]), parts())
    assert {'seal_and_diff', 'reader', 'graph', 'lenses', 'gate'} <= set(j.seconds)
    assert j.real == {'reads': 12, 'blocked': 0}
    assert j.reading.reads == 7


def test_outside_lenses_run_before_the_seal_with_both_endpoints():
    seen = []

    class Outside:
        name = 'outside'

        def look(self, view):
            seen.append((view.before_endpoint, view.after_endpoint, held.life.stage))
            from emfirge.lenses import LensResult
            return LensResult()

    held = FakeHeld()
    p = parts()
    p = type(p)(p.reader, p.graph, p.lenses, p.reversibility, outside=(Outside(),))
    judge(held, p, ('http://before', 'http://after'))
    assert seen == [('http://before', 'http://after', Stage.OPEN)]
