"""The session's text report: section order, short lines, folded parts, each fact once; and its JSON."""
from __future__ import annotations

import json

from emfirge.core.model import Change, ChangeType, FieldChange
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
    assert '      Environment.DRY_RUN: true -> false' in lines


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


def test_resources_are_named_the_way_a_person_says_them_and_json_keeps_full_refs():
    j = judge(FakeHeld([deleted(STORE)]), parts())
    assert 'store media' in as_text(j) and 'store:store/media' not in as_text(j)
    assert json.loads(as_json(j))['changes'][0]['ref'] == 'store:store/media'


def test_reasons_are_wrapped_not_cut_and_at_most_six():
    lenses = tuple(FlagLens(name=f'lens{i}', message=f'finding number {i} ' + 'word ' * 30) for i in range(9))
    text = as_text(judge(FakeHeld([deleted(STORE)]), parts(lenses=lenses)))
    why = text.split('Why:\n', 1)[1].split('\n\n', 1)[0].splitlines()
    assert sum(1 for l in why if l.startswith('  - ')) == 7 and why[-1].startswith('  - and ') and why[-1].endswith('more below')
    assert not any(l.endswith('...') for l in why)
    assert all(len(l) <= 100 for l in text.splitlines())


def test_values_the_service_computed_are_counted_not_listed():
    job = ref('job', 'publisher')
    change = modified(job, 'GetJob.Timeout', 3, 60)
    change = type(change)(job, change.type, change.fields + (FieldChange('GetJob.LastModified', 'a', 'b', derived=True),
                                                            FieldChange('GetJob.RevisionId', 'r1', 'r2', derived=True)))
    j = judge(FakeHeld([change], {job: {}}), parts())
    text = as_text(j)
    assert 'Timeout: 3 -> 60' in text and 'LastModified: a' not in text
    assert 'and 2 values the service computed (LastModified, RevisionId)' in text
    fields = json.loads(as_json(j))['changes'][0]['fields']
    assert [f['derived'] for f in fields] == [False, True, True]


def test_copy_notes_are_one_line_and_never_reach_the_gate():
    from emfirge.core.model import Unknown
    notes = [Unknown(f'the copy of store:store/media lacks: thing {i}', 'copy', STORE) for i in range(13)]
    new = ref('store', 'fresh-one')
    j = judge(FakeHeld([created(new)], {new: {}}, notes=notes), parts())
    assert j.decision.verdict.value == 'go'
    text = as_text(j)
    assert '13 notes on what the practice copies lack: in the JSON report' in text and 'thing 3' not in text
    assert 'thing 3' in as_text(j, show_all=True)
    assert len(json.loads(as_json(j))['copy_notes']) == 13


def test_a_change_that_can_be_put_back_says_how_that_was_established():
    new = ref('store', 'fresh-one')
    text = as_text(judge(FakeHeld([created(new)], {new: {}}), parts()))
    assert '      can be put back: it can be deleted again' in text.splitlines()


def test_a_change_seen_only_in_computed_values_names_its_calls():
    fn = ref('job', 'publisher')
    change = Change(fn, ChangeType.MODIFIED, (FieldChange('GetJob.CodeSha256', 'a', 'b', derived=True),
                                              FieldChange('GetJob.CodeSize', 1, 2, derived=True)), ('job.UpdateJobCode',))
    lines = as_text(judge(FakeHeld([change], {fn: {}}), parts())).splitlines()
    assert '      by: UpdateJobCode' in lines
    assert '      UpdateJobCode changed it; only values the service computed show it: CodeSha256, CodeSize' in lines


def test_every_changed_resource_names_the_calls_that_acted_on_it():
    text = as_text(judge(FakeHeld([deleted(STORE), modified(ref('job', 'publisher'))]), parts()))
    assert text.count('      by: ') == 2 and 'by: Delete' in text and 'by: Update' in text
