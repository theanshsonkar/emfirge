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
    (Undo.YES, Undo.UNKNOWN, Undo.YES),
    (Undo.YES, Undo.NO, Undo.NO),            # a proof that finds a difference lowers yes
])
def test_combine(static, proof, result):
    got = combine(fact(static, 'static'), fact(proof, 'proof') if proof else None)
    assert got.undo is result and got.ref == REF


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
