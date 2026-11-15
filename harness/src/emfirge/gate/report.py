"""A Decision for people (short plain text for a terminal) and for tools (JSON). Pure; stable order.

The order is the Decision's own (Facts.of sorts everything), so two runs on the same facts print the same bytes.
"""
from __future__ import annotations

import json
from typing import Any

from emfirge.core.model import Affected, Change, FieldChange, Finding, UndoFact, Unknown

from .verdict import Decision

_VALUE_WIDTH = 60
_INDENT = '    '


def as_text(decision: Decision) -> str:
    """What would change, what it affects, what was flagged, what is unknown, then the verdict and why."""
    f = decision.facts
    lines = [*_section('What would change', [_change_lines(c, f.undo_of(c.ref)) for c in f.changes]),
             *_section('What it affects', [[_affected_line(a)] for a in f.affected]),
             *_section('What was flagged', [[_finding_line(x)] for x in f.findings]),
             *_section('What Emfirge could not tell', [[_unknown_line(u)] for u in f.unknowns]),
             '',
             f'Verdict: {decision.verdict.value.upper()} (exit {decision.exit_code}, affected rule: {decision.rule.value})',
             'Why:',
             *(f'  - {r.words}' for r in decision.reasons)]
    return '\n'.join(lines) + '\n'


def as_dict(decision: Decision) -> dict[str, Any]:
    f = decision.facts
    return {
        'verdict': decision.verdict.value,
        'exit_code': decision.exit_code,
        'affected_rule': decision.rule.value,
        'reasons': [{'code': r.code.value, 'words': r.words, 'refs': [str(x) for x in r.refs]} for r in decision.reasons],
        'changes': [_change_dict(c, f.undo_of(c.ref)) for c in f.changes],
        'affected': [{'ref': str(a.ref), 'because': a.because, 'via': [str(v) for v in a.via], 'strength': a.strength}
                     for a in f.affected],
        'findings': [{'lens': x.lens, 'code': x.code, 'message': x.message, 'refs': [str(r) for r in x.refs],
                      'detail': _plain(dict(x.detail))} for x in f.findings],
        'unknowns': [{'what': u.what, 'where': u.where, 'ref': str(u.ref) if u.ref else None} for u in f.unknowns],
    }


def as_json(decision: Decision) -> str:
    return json.dumps(as_dict(decision), indent=2, sort_keys=True, ensure_ascii=False)


# ---------------------------------------------------------------------- text
def _section(title: str, items: list[list[str]]) -> list[str]:
    if not items:
        return [f'{title}: nothing']
    return [f'{title} ({len(items)}):', *(line for item in items for line in item)]


def _change_lines(c: Change, undo: UndoFact | None) -> list[str]:
    lines = [f'  {c.type.value:<9} {c.ref}']
    lines += [f'{_INDENT}{_field_line(x)}' for x in c.fields]
    if undo is None:
        lines.append(f'{_INDENT}undo: unknown (no fact given)')
    else:
        lines.append(f'{_INDENT}undo: {undo.undo.value}')
        lines += [f'{_INDENT}  {why}' for why in undo.reasons]
    return lines


def _field_line(x: FieldChange) -> str:
    return f'{x.path}: {_short(x.before)} -> {_short(x.after)}'


def _affected_line(a: Affected) -> str:
    via = f' (via {", ".join(map(str, a.via))})' if a.via else ''
    return f'  {a.ref} [{a.strength}]: {a.because}{via}'


def _finding_line(x: Finding) -> str:
    return f'  {x.lens}/{x.code}: {x.message}'


def _unknown_line(u: Unknown) -> str:
    where = f' [{u.where}]' if u.where else ''
    return f'  {u.what}{where}'


def _short(value: Any) -> str:
    text = '(absent)' if value is None else json.dumps(_plain(value), sort_keys=True, ensure_ascii=False)
    return text if len(text) <= _VALUE_WIDTH else text[:_VALUE_WIDTH - 3] + '...'


# ---------------------------------------------------------------------- json
def _change_dict(c: Change, undo: UndoFact | None) -> dict[str, Any]:
    return {'ref': str(c.ref), 'type': c.type.value, 'calls': list(c.calls),
            'fields': [{'path': x.path, 'before': _plain(x.before), 'after': _plain(x.after)} for x in c.fields],
            'undo': {'undo': undo.undo.value, 'reasons': list(undo.reasons)} if undo else None}


def _plain(value: Any) -> Any:
    """Values as JSON can hold them: mappings and sequences kept, anything else as text."""
    if value is None or isinstance(value, (bool, int, float, str)):
        return value
    if isinstance(value, dict):
        return {str(k): _plain(v) for k, v in value.items()}
    if isinstance(value, (list, tuple, set, frozenset)):
        items = [_plain(v) for v in value]
        return sorted(items, key=repr) if isinstance(value, (set, frozenset)) else items
    return str(value)
