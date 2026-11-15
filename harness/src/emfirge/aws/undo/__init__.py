"""The undo prover: whether a change an agent made on a branch can be put back exactly, established by doing it on
the branch's engine (gate.ports.UndoProver). Generic: driven by botocore's models and a table of verb pairs, with no
code per service. See prover.py for the steps and the order the branch must be used in."""
from .observe import Timing
from .prover import BranchUndoProver, prover_for

__all__ = ['BranchUndoProver', 'Timing', 'prover_for']
