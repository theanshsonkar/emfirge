"""The session's report: short plain text for a person in a hurry or an agent, and JSON for tools.

Text sections, in this order: the verdict and why; what would change (created, modified with each setting
before -> after, deleted, actions); what it affects (the default list, then how many weaker 'maybe' ones, shown with
show_all); flagged by lenses; could not tell; and one line on how the real account was touched.

Plain words: a resource is named the way a person says it ('function tidecast-publisher'), a setting by its own
path without the read that showed it ('Environment.Variables.DRY_RUN'); long lines are wrapped, never cut. Values the
service computed (a clock, a hash, a revision) are counted, not listed. Notes on what the practice copies lack are
counted in one line (listed with show_all and in JSON): they are about the copies, not the change.

Parts are folded: a resource reached only because one reported resource names it (the disks and network cards of
an instance, the rules of a group) is listed under that resource, not on its own line. Folding changes what is
shown, never what is decided: the verdict counts every affected resource.
"""
from __future__ import annotations

import json
import re
import textwrap
from typing import Any, Callable, Iterable, TypeVar

from emfirge.core.model import Change, ChangeType, FieldChange, ResourceRef, Undo
from emfirge.gate import Code, Reason, as_dict
from emfirge.graph import Impact, Relation

from .judge import Judgement

T = TypeVar('T')
WIDTH = 100
REASONS_SHOWN = 6
FIELDS_SHOWN = 8
GROUPS = ((ChangeType.CREATED, 'Created'), (ChangeType.MODIFIED, 'Modified'), (ChangeType.DELETED, 'Deleted'),
          (ChangeType.ACTION, 'Actions'))
VERDICT_WORDS = {'go': 'GO. The agent may make the real change.', 'ask': 'ASK. The owner decides.'}
PHRASES = {
    Relation.USES: 'uses {o}',
    Relation.REACHED: '{o} reaches it',
    Relation.DOWNSTREAM: 'uses something {o} reaches',
    Relation.NO_LONGER_NAMED: '{o} no longer names it',
    Relation.NOW_NAMED: '{o} now names it',
    Relation.OUT_OF_STEP: 'out of step: {o} moved, this still names the old one',
    Relation.ON_OLD_TARGET: 'still uses what {o} moved away from',
}
LOSES_A_USER = 'loses a user: {o} named it'
FOLDABLE = frozenset({Relation.REACHED, Relation.DOWNSTREAM})


def as_text(j: Judgement, show_all: bool = False, command_code: int | None = None) -> str:
    plain = _plain_words(j)
    lines = [*_verdict(j, command_code, plain), '', *_changes(j), '', *_affects(j, show_all), '',
             *_listed('Flagged by lenses', once(f'{f.lens}: {f.message}' for f in j.decision.facts.findings)), '',
             *_listed('Could not tell', once(u.what for u in j.decision.facts.unknowns)), '',
             *_notes(j, show_all), _account(j)]
    return '\n'.join(w for line in lines for w in _wrap(plain(line))) + '\n'


def as_json(j: Judgement, command_code: int | None = None) -> str:
    out: dict[str, Any] = as_dict(j.decision)
    for entry, change in zip(out['changes'], j.decision.facts.changes):
        for field, f in zip(entry['fields'], change.fields):
            field['derived'] = f.derived
    out['maybe'] = [{'ref': str(a.ref), 'because': a.because, 'via': [str(v) for v in a.via], 'strength': a.strength}
                    for a in j.maybe]
    out['copy_notes'] = [{'what': u.what, 'ref': str(u.ref) if u.ref else None} for u in j.copy_notes]
    out['command_exit_code'] = command_code
    out['seconds'] = dict(j.seconds)
    out['real_account'] = {**j.real, 'changing_calls': 0}
    out['reader'] = {'reads': j.reading.reads, **j.reading.counts}
    return json.dumps(out, indent=2, sort_keys=True, ensure_ascii=False)


# ---------------------------------------------------------------------- sections
def _verdict(j: Judgement, command_code: int | None, plain: Callable[[str], str]) -> list[str]:
    d = j.decision
    lines = [f'Verdict: {VERDICT_WORDS[d.verdict.value]} (exit {d.exit_code})']
    if command_code not in (None, 0):
        lines.append(f'Your command failed (exit {command_code}). What it changed before it stopped is below.')
    lines.append('Why:')
    reasons = [_reason(r) for r in once_by(d.reasons, lambda r: r.words)]
    for r in reasons[:REASONS_SHOWN]:
        short = textwrap.shorten(plain(r), width=2 * (WIDTH - 4), placeholder=' (more below)')
        lines += textwrap.wrap(short, WIDTH, initial_indent='  - ', subsequent_indent='    ')
    if len(reasons) > REASONS_SHOWN:
        lines.append(f'  - and {len(reasons) - REASONS_SHOWN} more below')
    return lines


def _reason(r: Reason) -> str:
    """The gate's words; an affected resource's chain is left to 'What it affects'."""
    if r.code is Code.AFFECTS and r.refs:
        return f'{r.refs[0]} is outside the change, and the change reaches it'
    return r.words


def _changes(j: Judgement) -> list[str]:
    changes = j.decision.facts.changes
    if not changes:
        return ['What would change: nothing. The agent changed nothing.']
    lines = [f'What would change ({len(changes)}):']
    for kind, title in GROUPS:
        group = [c for c in changes if c.type is kind]
        if group:
            lines.append(f'  {title}:')
            for c in group:
                lines += _change(c)
                undo = j.decision.facts.undo_of(c.ref)
                if undo is not None and undo.undo is Undo.YES and undo.reasons:
                    lines.append(f'      can be put back: {undo.reasons[0]}')
    return lines


def _change(c: Change) -> list[str]:
    lines = [f'    {c.ref}']
    if c.type is ChangeType.MODIFIED:
        fields = once(_field(x) for x in c.fields if not x.derived)
        lines += [f'      {x}' for x in fields[:FIELDS_SHOWN]]
        if len(fields) > FIELDS_SHOWN:
            lines.append(f'      and {len(fields) - FIELDS_SHOWN} more settings (in the JSON report)')
        computed = list(dict.fromkeys(_tail(x.path) for x in c.fields if x.derived))
        if computed:
            names = ', '.join(computed[:4]) + (', ...' if len(computed) > 4 else '')
            noun = 'value' if len(computed) == 1 else 'values'
            lines.append(f'      and {len(computed)} {noun} the service computed ({names})')
    elif c.type is ChangeType.ACTION and c.calls:
        lines.append(f'      {", ".join(dict.fromkeys(c.calls))}')
    return lines


def _field(x: FieldChange) -> str:
    return f'{x.path}: {_value(x.before)} -> {_value(x.after)}'


def _affects(j: Judgement, show_all: bool) -> list[str]:
    shown, parts = fold(_firm(j)) if not show_all else (_firm(j), {})
    maybe = j.maybe
    if not shown and not maybe:
        return ['What it affects: nothing found in the settings read.']
    more = f'; {len(maybe)} more maybe' + ('' if show_all else ', --all shows them') if maybe else ''
    lines = [f'What it affects ({len(shown)}{more}):']
    deleted = {c.ref for c in j.decision.facts.changes if c.type is ChangeType.DELETED}
    for i in shown:
        lines.append(f'  {i.ref}: {because(i, deleted)}')
        under = parts.get(i.ref, [])
        if under:
            lines.append(f'    and {len(under)} things it names: {", ".join(str(r) for r in under)}')
    if show_all and maybe:
        lines.append('  Maybe (weak evidence, or only next to what changed):')
        lines += [f'    {x}' for x in once(f'{a.ref}: {a.because}' for a in maybe)]
    return lines


def _listed(title: str, items: list[str]) -> list[str]:
    if not items:
        return [f'{title}: nothing']
    return [f'{title} ({len(items)}):', *(f'  {x}' for x in items)]


def _notes(j: Judgement, show_all: bool) -> list[str]:
    notes = j.copy_notes
    if not notes:
        return []
    if not show_all:
        return [f'{len(notes)} notes on what the practice copies lack: in the JSON report (--all lists them).', '']
    return [f'Notes on what the practice copies lack ({len(notes)}):', *(f'  {u.what}' for u in notes), '']


def _account(j: Judgement) -> str:
    blocked = j.real.get('blocked', 0)
    stopped = f' ({blocked} more were stopped at the read-only door)' if blocked else ''
    return f'Your account: 0 changing calls reached it{stopped}. {j.real.get("reads", 0)} reads.'


# ---------------------------------------------------------------------- affected, folded
def _firm(j: Judgement) -> list[Impact]:
    """One line per affected resource: the first (most telling) impact the graph gives for it."""
    if j.graph is None:
        return []
    changed = {c.ref for c in j.decision.facts.changes}
    seen: dict[ResourceRef, Impact] = {}
    for c in j.graph.changes:
        for i in c.affected:
            if i.ref not in changed:
                seen.setdefault(i.ref, i)
    return list(seen.values())


def fold(impacts: Iterable[Impact]) -> tuple[list[Impact], dict[ResourceRef, list[ResourceRef]]]:
    """(shown, parts): an impact reached forward through one link from another shown resource is listed under it."""
    impacts = list(impacts)
    refs = {i.ref for i in impacts}
    parts: dict[ResourceRef, list[ResourceRef]] = {}
    shown = []
    for i in impacts:
        holder = i.chain[-1].source if i.relation in FOLDABLE and len(i.chain) >= 2 else None
        if holder is not None and holder in refs and holder != i.ref:
            parts.setdefault(holder, []).append(i.ref)
        else:
            shown.append(i)
    return shown, parts


def because(i: Impact, deleted: frozenset[ResourceRef] | set[ResourceRef] = frozenset()) -> str:
    """A short reason, in very simple words, with the resources in between."""
    template = LOSES_A_USER if i.relation is Relation.REACHED and i.origin in deleted else PHRASES.get(i.relation, '{r} ({o})')
    words = template.format(o=i.origin, r=i.relation.value.replace('-', ' '))
    via = f' (via {", ".join(str(v) for v in i.via)})' if i.via else ''
    weak = '' if i.strength.label == 'strong' else f' [{i.strength.label}]'
    return words + via + weak


# ---------------------------------------------------------------------- values
DOTTED = re.compile(r'[\w#{}"-]+(?:\.[\w#{}"-]+)+')


def once_by(items: Iterable[T], words: Callable[[T], str]) -> list[T]:
    """Each fact once, by its words (see once)."""
    seen: dict[str, T] = {}
    for item in items:
        seen.setdefault(DOTTED.sub(lambda m: _tail(m.group(0)), words(item)), item)
    return list(seen.values())


def once(lines: Iterable[str]) -> list[str]:
    """Each fact once. A lens or the gate says one fact once per read that shows it ('...(GetFunction.Configuration.
    Environment.Variables.DRY_RUN: true -> false)', and the same from GetFunctionConfiguration): two lines that are
    the same when every dotted path is cut to its last part are one fact. The first is kept."""
    return once_by(lines, lambda line: line)


def _tail(path: str) -> str:
    return path.rsplit('.', 1)[-1]


def _value(value: Any) -> str:
    if value is None:
        return '(none)'
    text = value if isinstance(value, str) else json.dumps(value, sort_keys=True, default=str)
    return text if len(text) <= 40 else text[:37] + '...'


READ_NAME = re.compile(r'\b(?:Get|List|Describe)[A-Z][A-Za-z0-9]*(?:\{[^}]*\})?(?:\[\])?(?:#\d+)?\.(?=[A-Za-z])')


def _plain_words(j: Judgement) -> Callable[[str], str]:
    """Text for a person: every resource of this session by its short name, and read names dropped from paths."""
    f = j.decision.facts
    refs = {c.ref for c in f.changes} | {a.ref for a in f.affected} | {a.ref for a in j.maybe} | \
        {v for a in (*f.affected, *j.maybe) for v in a.via} | {r for x in f.findings for r in x.refs} | \
        {u.ref for u in (*f.unknowns, *j.copy_notes) if u.ref}
    names = sorted(((str(r), short_name(r)) for r in refs), key=lambda p: -len(p[0]))
    pattern = re.compile('|'.join(re.escape(full) for full, _ in names)) if names else None
    table = dict(names)

    def plain(line: str) -> str:
        line = pattern.sub(lambda m: table[m.group(0)], line) if pattern else line
        return READ_NAME.sub('', line)
    return plain


def short_name(ref: ResourceRef) -> str:
    """'lambda:function/tidecast-publisher' -> 'function tidecast-publisher'."""
    kind = ref.type.split(':', 1)[-1].strip('/')
    return f'{kind} {ref.id}'


def _wrap(line: str) -> list[str]:
    """A long line on several lines, indented under its start. Never cut."""
    if len(line) <= WIDTH:
        return [line]
    indent = ' ' * (len(line) - len(line.lstrip()) + 2)
    return textwrap.wrap(line, WIDTH, subsequent_indent=indent, break_on_hyphens=False)
