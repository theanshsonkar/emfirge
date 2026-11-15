"""How static facts and proofs combine (gate/undo.py). Pure."""
from __future__ import annotations

import pytest

from emfirge.core.model import Change, ChangeType, ResourceRef, Undo, UndoFact
from emfirge.gate import combine, undo_facts

REF = ResourceRef('acme:job', 'j')


def fact(undo: Undo, why: str = '') -> UndoFact:
    return UndoFact(REF, undo, (why,) if why else ())


@pytest.mark.parametrize('static, proof, result', [
    (Undo.NO, None, Undo.NO),
    (Undo.NO, Undo.YES, Undo.NO),            # a static no always wins
    (Undo.NO, Undo.UNKNOWN, Undo.NO),
    (Undo.UNKNOWN, None, Undo.UNKNOWN),
    (Undo.UNKNOWN, Undo.YES, Undo.YES),      # a proof raises unknown to yes
    (Undo.UNKNOWN, Undo.NO, Undo.NO),
    (Undo.UNKNOWN, Undo.UNKNOWN, Undo.UNKNOWN),
    (Undo.YES, None, Undo.YES),
    (Undo.YES, Undo.UNKNOWN, Undo.UNKNOWN),  # an unproven yes is not a yes
    (Undo.YES, Undo.NO, Undo.NO),            # a proof that finds a difference lowers yes
])
def test_combine(static, proof, result):
    got = combine(fact(static, 'static'), fact(proof, 'proof') if proof else None)
    assert got.undo is result and got.ref == REF


@pytest.mark.parametrize('static, proof, reasons', [
    (Undo.NO, Undo.YES, ('static',)),
    (Undo.NO, Undo.UNKNOWN, ('static',)),
    (Undo.UNKNOWN, Undo.YES, ('proof',)),
    (Undo.UNKNOWN, Undo.NO, ('static', 'proof')),
    (Undo.UNKNOWN, Undo.UNKNOWN, ('proof',)),       # the proof's reason, not the generic "not yet proven"
    (Undo.YES, Undo.YES, ('proof',)),
    (Undo.YES, Undo.UNKNOWN, ('proof',)),           # why the proof could not put it back
    (Undo.YES, Undo.NO, ('static', 'proof')),
])
def test_combine_reasons(static, proof, reasons):
    assert combine(fact(static, 'static'), fact(proof, 'proof')).reasons == reasons


def test_an_unknown_proof_without_words_keeps_the_static_reason():
    assert combine(fact(Undo.YES, 'static'), fact(Undo.UNKNOWN)).reasons == ('static',)


def test_a_no_keeps_both_reasons():
    assert combine(fact(Undo.UNKNOWN, 's'), fact(Undo.NO, 'p')).reasons == ('s', 'p')


class Static:
    def __init__(self, answers: dict[ChangeType, Undo]):
        self.answers = answers

    def assess(self, change: Change) -> UndoFact:
        return UndoFact(change.ref, self.answers[change.type], ('static',))


class Prover:
    def __init__(self) -> None:
        self.asked: list[ResourceRef] = []

    def prove(self, change: Change) -> UndoFact:
        self.asked.append(change.ref)
        return UndoFact(change.ref, Undo.YES, ('put back on the branch and found equal',))


def test_the_prover_is_asked_only_where_static_is_not_no():
    changes = [Change(ResourceRef('acme:a', '1'), ChangeType.DELETED),
               Change(ResourceRef('acme:b', '2'), ChangeType.MODIFIED),
               Change(ResourceRef('acme:c', '3'), ChangeType.CREATED)]
    prover = Prover()
    got = undo_facts(changes, Static({ChangeType.DELETED: Undo.NO, ChangeType.MODIFIED: Undo.UNKNOWN,
                                      ChangeType.CREATED: Undo.YES}), prover)
    assert [u.undo for u in got] == [Undo.NO, Undo.YES, Undo.YES]
    assert prover.asked == [ResourceRef('acme:b', '2'), ResourceRef('acme:c', '3')]


def test_without_a_prover_static_facts_stand():
    got = undo_facts([Change(REF, ChangeType.MODIFIED)], Static({ChangeType.MODIFIED: Undo.UNKNOWN}))
    assert got == (UndoFact(REF, Undo.UNKNOWN, ('static',)),)
