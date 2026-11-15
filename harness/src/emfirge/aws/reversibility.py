"""AwsReversibility: the Reversibility port for AWS. Static facts only, from the compiled catalog (what AWS publishes
about each resource type) and from the change itself. No code per service, no per-service data.

  ACTION    NO when the call runs, sends, empties or asks for something (its verb says so); else UNKNOWN.
  DELETED   NO, always, with every reason that applies: the type holds data; AWS gives its id (a recreated one
            gets a new id, and what points at the old one breaks); it has settings that can be written but never
            read back; and in every case its history, the ids AWS gave it and what was attached to it are lost.
  CREATED   NO when the new thing is on or contacts an outside address from the start (generic detectors);
            YES when the catalog lists a call that deletes the type; else UNKNOWN.
  MODIFIED  NO when a changed field is a write-only setting, or a generic detector fires (it turns something on,
            names an outside address, removes or replaces a credential). Else UNKNOWN: "yes" for a modified
            resource must be proven by putting it back on the branch (emfirge.gate.ports.UndoProver).
"""
from __future__ import annotations

from typing import Callable, Protocol

from emfirge.core.model import Change, ChangeType, FieldChange, Undo, UndoFact
from emfirge.gate.detectors import action_reason, field_reasons, segments

from .catalog import ResourceTypeInfo

NOT_PROVEN = ('not yet proven on the branch: it is "yes" only after it was put back on the branch '
              'and found equal to before')
LOST_ON_DELETE = ('a deleted thing does not come back as itself: its history, the ids AWS gave it '
                  'and what was attached to it are lost')


class TypeFacts(Protocol):
    """The part of AwsCatalog this module reads."""

    def resource_type(self, type_: str) -> ResourceTypeInfo | None: ...


class AwsReversibility:
    def __init__(self, catalog: TypeFacts):
        self._catalog = catalog
        self._judge: dict[ChangeType, Callable[[Change, ResourceTypeInfo | None], UndoFact]] = {
            ChangeType.ACTION: self._action, ChangeType.DELETED: self._deleted,
            ChangeType.CREATED: self._created, ChangeType.MODIFIED: self._modified}

    def assess(self, change: Change) -> UndoFact:
        return self._judge[change.type](change, self._catalog.resource_type(change.ref.type))

    # ------------------------------------------------------------------ by change type
    @staticmethod
    def _action(change: Change, info: ResourceTypeInfo | None) -> UndoFact:
        why = action_reason(change.calls)
        if why:
            return UndoFact(change.ref, Undo.NO, (why,))
        calls = ', '.join(change.calls) or 'a changing call'
        return UndoFact(change.ref, Undo.UNKNOWN, (f'{calls} changed nothing Emfirge can read back, '
                                                   'so it cannot tell what it did or how to put it back',))

    @staticmethod
    def _deleted(change: Change, info: ResourceTypeInfo | None) -> UndoFact:
        reasons = []
        if info is None:
            reasons.append(f'the catalog does not know the type {change.ref.type}')
        else:
            if info.holds_data:
                reasons.append('it holds data (AWS lists data actions on it or on what it contains): '
                               'deleting it loses that data')
            if info.id_given_by_service:
                reasons.append('AWS gives it its id: a recreated one gets a new id, and what points at the old id breaks')
            settings = _top_level(info.write_only_settings)
            if settings:
                reasons.append(f'some settings can be written but never read back ({", ".join(settings)}): '
                               'a recreated one cannot get them back')
        reasons.append(LOST_ON_DELETE)
        return UndoFact(change.ref, Undo.NO, tuple(reasons))

    @staticmethod
    def _created(change: Change, info: ResourceTypeInfo | None) -> UndoFact:
        reasons = field_reasons(change.fields)
        if reasons:
            return UndoFact(change.ref, Undo.NO, reasons)
        deletes = tuple(getattr(info, 'delete_operations', ()) or ())
        if deletes:
            return UndoFact(change.ref, Undo.YES, (f'it can be deleted again ({", ".join(deletes)})',))
        return UndoFact(change.ref, Undo.UNKNOWN, ('the catalog lists no call that deletes this type, '
                                                  'so a new one may not go away again',))

    @staticmethod
    def _modified(change: Change, info: ResourceTypeInfo | None) -> UndoFact:
        written = _write_only_fields(change.fields, info.write_only_settings if info else ())
        reasons = [f'{path} can be written but never read back: its old value is not known, so it cannot be put back'
                   for path in written]
        reasons += field_reasons(change.fields)
        if reasons:
            return UndoFact(change.ref, Undo.NO, tuple(reasons))
        return UndoFact(change.ref, Undo.UNKNOWN, (NOT_PROVEN,))


def _top_level(settings: tuple[str, ...]) -> list[str]:
    """'Code/ZipFile', 'Code/S3Key', 'SnapStart' -> ['Code', 'SnapStart']: the names a person would recognise."""
    return list(dict.fromkeys(s.split('/', 1)[0] for s in settings))


def _write_only_fields(fields: tuple[FieldChange, ...], settings: tuple[str, ...]) -> list[str]:
    """The paths of the field changes that touch a write-only setting. A setting 'Code/ZipFile' matches the field
    paths 'Code', 'Code.ZipFile' and 'Configuration.Code.ZipFile': its words appear in order in the path, or the
    path's words are the start of the setting's (a whole 'Code' block changed)."""
    wanted = [w for w in (segments(s) for s in settings) if w]
    return list(dict.fromkeys(f.path for f in fields
                              if any(_contains(segments(f.path), w) or _starts(w, segments(f.path)) for w in wanted)))


def _contains(words: list[str], run: list[str]) -> bool:
    n = len(run)
    return any(words[i:i + n] == run for i in range(len(words) - n + 1))


def _starts(words: list[str], prefix: list[str]) -> bool:
    return bool(prefix) and words[:len(prefix)] == prefix
