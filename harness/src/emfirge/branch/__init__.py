"""The branch: answers an agent's calls from the real account (read only) and an engine, never changing the real
account. Cloud-neutral: imports only emfirge.core and the standard library (tests/test_boundaries.py checks)."""
from .branch import Branch
from .lifecycle import IllegalMove, Stage
from .overlay import State

__all__ = ['Branch', 'IllegalMove', 'Stage', 'State']
