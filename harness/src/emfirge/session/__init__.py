"""One session on one branch: the command runs against the branch, then the branch is judged and reported.

Cloud-neutral. It imports emfirge.core, branch, graph, lenses and gate only; the cloud parts (the bench: a branch on a
local endpoint; the reader of the account's settings; the vocabulary; the reversibility facts) come in by injection
(Opener, Parts). emfirge.aws.session is the AWS wiring.
"""
from .judge import Judgement, Parts, judge
from .ports import Bench, Held, Reading, StateReader
from .runner import Opener, Output, end_remote, run, serve

__all__ = ['Bench', 'Held', 'Judgement', 'Opener', 'Output', 'Parts', 'Reading', 'StateReader', 'end_remote', 'judge',
           'run', 'serve']
