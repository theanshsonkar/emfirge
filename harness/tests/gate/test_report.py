"""The report: short plain text and JSON, in a stable order. Pure."""
from __future__ import annotations

import json

from emfirge.core.model import (Affected, Change, ChangeType, FieldChange, Finding, ResourceRef, Undo, UndoFact,
                                Unknown)
from emfirge.gate import as_dict, as_json, as_text, decide

JOB = ResourceRef('acme:job', 'publisher')
TIMER = ResourceRef('acme:timer', 'nightly')
STORE = ResourceRef('acme:store', 'media')


def sample():
    changes = [Change(TIMER, ChangeType.MODIFIED, (FieldChange('State', 'DISABLED', 'ENABLED'),)),
               Change(JOB, ChangeType.MODIFIED, (FieldChange('Env.DRY_RUN', 'true', None),
                                                 FieldChange('Doc', 'x' * 200, {'a': [1, 2]})))]
    undo = [UndoFact(TIMER, Undo.NO, ('it turns something on',)), UndoFact(JOB, Undo.UNKNOWN, ('not yet proven',))]
    findings = [Finding('money', 'runs-more', 'the timer now runs every night', (TIMER,))]
    unknowns = [Unknown('one read was refused', 'branch')]
    affected = [Affected(STORE, 'the job grant names the store', via=(ResourceRef('acme:grant', 'g'),))]
    return decide(changes, undo, findings, unknowns, affected)


def test_text_has_every_section_and_the_verdict_last():
    text = as_text(sample())
    order = ['What would change (2):', 'What it affects (1):', 'What was flagged (1):',
             'What Emfirge could not tell (1):', 'Verdict: ASK (exit 3, affected rule: strict)', 'Why:']
    positions = [text.index(s) for s in order]
    assert positions == sorted(positions)


def test_text_shows_fields_values_and_undo_in_plain_words():
    text = as_text(sample())
    assert 'Env.DRY_RUN: "true" -> (absent)' in text
    assert 'undo: no' in text and 'it turns something on' in text
    assert 'acme:store/media [strong]: the job grant names the store (via acme:grant/g)' in text


def test_text_keeps_long_values_short():
    assert all(len(line) <= 120 for line in as_text(sample()).splitlines() if 'Doc:' in line)


def test_text_of_an_empty_change_set():
    text = as_text(decide([], [], [], [], []))
    assert 'What would change: nothing' in text
    assert 'Verdict: GO (exit 0' in text
    assert 'The agent changed nothing.' in text


def test_json_holds_the_same_facts():
    data = json.loads(as_json(sample()))
    assert data['verdict'] == 'ask' and data['exit_code'] == 3 and data['affected_rule'] == 'strict'
    assert [c['ref'] for c in data['changes']] == ['acme:job/publisher', 'acme:timer/nightly']
    assert data['changes'][1]['undo'] == {'undo': 'no', 'reasons': ['it turns something on']}
    assert [r['code'] for r in data['reasons']] == ['cannot-undo', 'undo-unknown', 'flagged', 'unknown', 'affects']
    assert data['changes'][0]['fields'][1]['after'] == {'a': [1, 2]}


def test_output_is_stable():
    assert as_json(sample()) == as_json(sample())
    assert as_text(sample()) == as_text(sample())
    assert as_dict(sample()) == json.loads(as_json(sample()))
