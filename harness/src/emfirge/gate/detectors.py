"""Generic detectors: facts about a change read from its field paths, values and call names alone.

They are cross-service by design. Clouds name their switches, credentials and outside addresses with the same
few words (State, Enabled, Paused, DryRun, Password, Endpoint, ...), so a short list of words covers every service
of every cloud, with no table per service. Each detector says why a change cannot be put back; none says that it
can. A detector that misses only leaves the change at "not proven", never at "yes".

  turns_on        a switch goes from off (or absent) to on: whatever runs meanwhile (a schedule firing, a job
                  that stops dry-running, a rule that triggers) has happened and cannot be put back.
  outside         a field now holds an e-mail address, a web address or a phone number: something outside the
                  account will be contacted, and a message sent cannot be called back.
  credential      a key, a secret or a password is removed or replaced: its secret part is never shown again,
                  so it cannot be put back, and whatever used it breaks.
  action_verb     a call that runs, sends, empties or asks for something instead of setting a value.
"""
from __future__ import annotations

import re
from typing import Any, Iterable, Iterator, Sequence

from emfirge.core.model import FieldChange

# A switch named for being on: it turns on when its value goes from off to on.
_ON_KEYS = ('enabled', 'state', 'status')
# A switch named for being off: it turns on when its value goes from on to off (DRY_RUN true -> false).
_OFF_KEYS = ('disabled', 'paused', 'suspended', 'dryrun')
_ON_VALUES = frozenset({'true', 'enabled', 'enable', 'on', 'running', 'started', 'yes'})   # not 'active': it means ready
_OFF_VALUES = frozenset({'false', 'disabled', 'disable', 'off', 'inactive', 'paused', 'suspended', 'stopped', 'no', ''})

_OUTSIDE_KEYS = ('endpoint', 'email', 'address', 'webhook', 'phone', 'subscriber', 'recipient')
_EMAIL = re.compile(r'^[^@\s]+@[^@\s]+\.[A-Za-z]{2,}$')
_WEB = re.compile(r'^https?://', re.IGNORECASE)
_PHONE = re.compile(r'^\+\d{7,15}$')

_CREDENTIAL_WORDS = ('accesskey', 'secret', 'password', 'privatekey', 'credential')
_POINTER_ENDINGS = ('arn', 'arns', 'id', 'ids', 'name', 'names')

# Verbs of calls that do something rather than set something. Matched at the start of the operation name.
_ACTION_VERBS = ('Invoke', 'Send', 'Publish', 'Purge', 'Start', 'Run', 'Execute', 'Request', 'Reboot', 'Restart',
                 'Signal', 'Notify')


def field_reasons(fields: Sequence[FieldChange]) -> tuple[str, ...]:
    """Every reason, in plain words, why these field changes cannot be put back. Empty when no detector fires."""
    reasons: list[str] = []
    for leaf in leaves(fields):
        for found in (_turns_on(leaf), _outside(leaf), _credential(leaf)):
            if found and found not in reasons:
                reasons.append(found)
    return tuple(reasons)


def action_reason(calls: Iterable[str]) -> str | None:
    """Why an action (a changing call that set no value) cannot be called back, or None when its verb is not one
    that runs, sends or empties something. Calls are '<service>.<Operation>'."""
    for call in calls:
        operation = call.rsplit('.', 1)[-1]
        verb = next((v for v in _ACTION_VERBS if _starts_with_verb(operation, v)), None)
        if verb:
            return f'{call} does something ({verb.lower()}) rather than set a value: what it did cannot be called back'
    return None


def segments(path: str) -> list[str]:
    """A field path as normalized words: split on '.' and '/', lower case, '_' and '-' dropped, list indexes and
    '*' left out. 'Environment.Variables.DRY_RUN' -> ['environment', 'variables', 'dryrun']."""
    out = []
    for part in re.split(r'[./]', path):
        word = re.sub(r'[\[\]_\-\s]', '', part).lower()
        if word and word != '*' and not word.isdigit():
            out.append(word)
    return out


def leaves(fields: Iterable[FieldChange]) -> Iterator[FieldChange]:
    """Field changes down to plain values: a change of a whole item (a list element that disappeared) is split into
    one change per value inside it, so a detector sees the same thing whatever depth the diff stopped at."""
    for f in fields:
        yield from _split(f.path, f.before, f.after)


def _split(path: str, before: Any, after: Any) -> Iterator[FieldChange]:
    if isinstance(before, dict) or isinstance(after, dict):
        b = before if isinstance(before, dict) else {}
        a = after if isinstance(after, dict) else {}
        for key in sorted(set(b) | set(a), key=str):
            yield from _split(f'{path}.{key}' if path else str(key), b.get(key), a.get(key))
    elif isinstance(before, list) or isinstance(after, list):
        b = before if isinstance(before, list) else []
        a = after if isinstance(after, list) else []
        for i in range(max(len(b), len(a))):
            yield from _split(f'{path}.{i}', b[i] if i < len(b) else None, a[i] if i < len(a) else None)
    elif before != after:
        yield FieldChange(path, before, after)


def _turns_on(f: FieldChange) -> str | None:
    words = segments(f.path)
    if not words:
        return None
    key = words[-1]
    if any(w in key for w in _OFF_KEYS):
        on = _is_on(f.before) and _is_off(f.after)
    elif key.endswith(_ON_KEYS):
        on = _is_off(f.before) and _is_on(f.after)
    else:
        return None
    if not on:
        return None
    return (f'it turns something on ({f.path}: {_show(f.before)} -> {_show(f.after)}): '
            'what runs meanwhile cannot be put back')


def _outside(f: FieldChange) -> str | None:
    words = segments(f.path)
    if not words or not any(k in words[-1] for k in _OUTSIDE_KEYS):
        return None
    if not isinstance(f.after, str) or f.after == f.before:
        return None
    value = f.after.strip()
    if not (_EMAIL.match(value) or _WEB.match(value) or _PHONE.match(value)):
        return None
    return (f'it names an address outside the account ({f.path}): '
            'a message sent there cannot be called back')


def _credential(f: FieldChange) -> str | None:
    words = segments(f.path)
    if f.before is None or not any(c in w for w in words for c in _CREDENTIAL_WORDS):
        return None
    removed = f.after is None
    key = words[-1]
    replaced = any(c in key for c in _CREDENTIAL_WORDS) and not key.endswith(_POINTER_ENDINGS) and f.after != f.before
    if not (removed or replaced):
        return None
    return (f'it {"removes" if removed else "replaces"} a credential ({f.path}): its secret part is never shown again, '
            'so it cannot be put back, and whatever used it breaks')


def _is_on(value: Any) -> bool:
    return value is True or (isinstance(value, str) and value.strip().lower() in _ON_VALUES)


def _is_off(value: Any) -> bool:
    return value is None or value is False or (isinstance(value, str) and value.strip().lower() in _OFF_VALUES)


def _starts_with_verb(operation: str, verb: str) -> bool:
    rest = operation[len(verb):]
    return operation.startswith(verb) and (not rest or rest[0].isupper())


def _show(value: Any) -> str:
    return '(absent)' if value is None else repr(value)
