"""Undo facts for a change set: static facts first, then proofs, combined by one rule.

  static NO      always wins. A proof on a fake cannot see what the provider says is lost (a secret never shown
                 again, a message already sent, what ran while a switch was on).
  static UNKNOWN a proof can raise it to YES (put back on the branch and found equal) or lower it to NO.
  static YES     stays YES unless a proof finds a difference (then NO).

The verdict takes the combined facts only; it never calls a plug-in itself.
"""
from __future__ import annotations

from typing import Iterable

from emfirge.core.model import Change, Undo, UndoFact
from emfirge.core.ports import Reversibility

from .ports import UndoProver


def combine(static: UndoFact, proof: UndoFact | None) -> UndoFact:
    """One fact from a static fact and an optional proof for the same change."""
    if proof is None or static.undo is Undo.NO:
        return static
    if proof.undo is Undo.NO:
        return UndoFact(static.ref, Undo.NO, static.reasons + proof.reasons)
    if proof.undo is Undo.YES:
        return UndoFact(static.ref, Undo.YES, proof.reasons or static.reasons)
    return static


def undo_facts(changes: Iterable[Change], reversibility: Reversibility,
               prover: UndoProver | None = None) -> tuple[UndoFact, ...]:
    """The final undo fact of each change. The prover is asked only where the static fact is not already NO:
    a proof cannot change that answer, and each proof costs a run on the branch."""
    out = []
    for change in changes:
        static = reversibility.assess(change)
        proof = prover.prove(change) if prover is not None and static.undo is not Undo.NO else None
        out.append(combine(static, proof))
    return tuple(out)
