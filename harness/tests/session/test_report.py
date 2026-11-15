"""The session's text report: section order, short lines, folded parts, each fact once; and its JSON."""
from __future__ import annotations

import json

from emfirge.core.model import FieldChange
from emfirge.session import judge
from emfirge.session.report import as_json, as_text, fold, once

from .fakes import BOX, STORE, FakeHeld, FlagLens, created, deleted, modified, parts, ref

ORDER = ['Verdict:', 'Why:', 'What would change', 'What it affects', 'Flagged by lenses', 'Could not tell', 'Your account:']


def positions(text: str) -> list[int]:
    return [next(i for i, line in enumerate(text.splitlines()) if line.startswith(head)) for head in ORDER]


def test_sections_come_in_order():
    text = as_text(judge(FakeHeld([deleted(STORE)]), parts()))
    p = positions(text)
    assert p == sorted(p)


def test_go_with_nothing_changed_says_so_in_plain_words():
    text = as_text(judge(FakeHeld(), parts()))
    assert text.startswith('Verdict: GO. The agent may make the real change. (exit 0)')
    assert 'The agent changed nothing.' in text
    assert 'Your account: 0 changing calls reached it. 12 reads.' in text


def test_changes_are_grouped_with_settings_before_and_after():
    new = ref('store', 'fresh-one')
    j = judge(FakeHeld([created(new), modified(ref('job', 'publisher'), 'GetJob.Environment.DRY_RUN', 'true', 'false'),
                        deleted(STORE)], {new: {}}), parts())
    text = as_text(j)
    lines = text.splitlines()
    heads = [l.strip() for l in lines if l.strip() in ('Created:', 'Modified:', 'Deleted:', 'Actions:')]
    assert heads == ['Created:', 'Modified:', 'Deleted:']
    assert '      DRY_RUN: true -> false' in lines


def test_the_same_setting_from_two_reads_is_shown_once():
    change = modified(ref('job', 'publisher'))
    change = type(change)(change.ref, change.type, (FieldChange('GetJob.Config.Size', 1, 2), FieldChange('ListJobs.Size', 1, 2)))
    text = as_text(judge(FakeHeld([change], {change.ref: {}}), parts()))
    assert text.count('Size: 1 -> 2') == 1


def test_a_failing_command_is_said_first():
    text = as_text(judge(FakeHeld(), parts()), command_code=5)
    assert 'Your command failed (exit 5).' in text.splitlines()[1]


def test_lines_are_short():
    text = as_text(judge(FakeHeld([deleted(STORE)]), parts(lenses=(FlagLens(message='x' * 400),))))
    assert max(len(l) for l in text.splitlines()) <= 120


def test_flagged_facts_said_once_per_read_are_one_line():
    assert once(['data: off (GetFn.Config.Env.DRY_RUN: true -> false)', 'data: off (GetFnConfig.Env.DRY_RUN: true -> false)',
                 'data: off (other: 1 -> 2)']) == ['data: off (GetFn.Config.Env.DRY_RUN: true -> false)', 'data: off (other: 1 -> 2)']


def test_parts_reached_through_a_shown_resource_are_folded_under_it():
    box = ref('box', 'box-00aa11bb22')
    j = judge(FakeHeld([modified(box, 'reads', 'urn:acme:store/media', 'urn:acme:store/other')],
                       {box: {'reads': 'urn:acme:store/media', 'disk': 'dsk-00aa11bb22', 'size': 9}}), parts())
    impacts = [i for c in j.graph.changes for i in c.affected]
    shown, under = fold(impacts)
    assert {i.ref for i in shown} | {r for rs in under.values() for r in rs} == {i.ref for i in impacts}
    for holder, refs in under.items():
        assert holder in {i.ref for i in shown}


def test_show_all_lists_the_maybe_ones():
    j = judge(FakeHeld([deleted(STORE)]), parts())
    assert as_text(j, show_all=True).count('\n') >= as_text(j).count('\n')


def test_json_has_the_verdict_the_facts_and_the_measurements():
    d = json.loads(as_json(judge(FakeHeld([deleted(STORE)]), parts()), command_code=0))
    assert d['verdict'] == 'ask' and d['exit_code'] == 3
    assert {'changes', 'affected', 'maybe', 'findings', 'unknowns', 'seconds', 'real_account', 'reader'} <= set(d)
    assert d['real_account']['changing_calls'] == 0
    assert {a['ref'] for a in d['affected']} >= {str(BOX)}
