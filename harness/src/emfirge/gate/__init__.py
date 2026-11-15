"""The gate: undo facts and the verdict (go or ask). Cloud-neutral: imports only emfirge.core."""
from .ports import UndoProver
from .report import as_dict, as_json, as_text
from .undo import combine, undo_facts
from .verdict import REASONS, AffectedRule, Code, Decision, Facts, Reason, Verdict, decide

__all__ = ['AffectedRule', 'Code', 'Decision', 'Facts', 'REASONS', 'Reason', 'UndoProver', 'Verdict', 'as_dict',
           'as_json', 'as_text', 'combine', 'decide', 'undo_facts']
