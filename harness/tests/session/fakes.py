"""Fake parts for the session pipeline: a branch that holds given changes, a reader that returns given states, and
a made-up cloud (identifiers like 'urn:acme:...'), so the pipeline is tested without any cloud."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Mapping, Sequence

from emfirge.branch.lifecycle import Lifecycle, Stage
from emfirge.core.model import Change, ChangeType, FieldChange, Finding, ResourceRef, Undo, UndoFact, Unknown
from emfirge.graph import Graph, Vocabulary
from emfirge.lenses import LensResult, LensView
from emfirge.session import Parts, Reading

VOCAB = Vocabulary.of(addresses=[r'urn:acme:\S+'], opaque=[r'[a-z]{1,6}-[0-9a-f]{8,}'])


def ref(kind: str, ident: str) -> ResourceRef:
    return ResourceRef(f'{kind}:{kind}', ident)


def urn(kind: str, ident: str) -> str:
    return f'urn:acme:{kind}/{ident}'


STORE, JOB, BOX, DISK = ref('store', 'media'), ref('job', 'publisher'), ref('box', 'box-00aa11bb22'), ref('disk', 'dsk-00aa11bb22')
ACCOUNT = {
    STORE: {'name': 'media'},
    JOB: {'writes': urn('store', 'media')},
    BOX: {'reads': urn('store', 'media'), 'disk': 'dsk-00aa11bb22'},
    DISK: {'id': 'dsk-00aa11bb22', 'size': 8},
}


@dataclass
class FakeHeld:
    held: Sequence[Change] = ()
    after: Mapping[ResourceRef, Any] = field(default_factory=dict)
    refused: Sequence[Unknown] = ()
    notes: Sequence[Unknown] = ()
    life: Lifecycle = field(default_factory=Lifecycle)

    def seal(self) -> None:
        self.life.move(Stage.SEALED)

    def move(self, to: Stage) -> None:
        self.life.move(to)

    def changes(self) -> list[Change]:
        return list(self.held)

    def states_after(self) -> dict[ResourceRef, Any]:
        return dict(self.after)

    def unknowns(self) -> tuple[Unknown, ...]:
        return tuple(self.refused)

    def copy_notes(self) -> tuple[Unknown, ...]:
        return tuple(self.notes)

    def stats(self) -> dict[str, Any]:
        return {'real_reads': 12, 'real_blocked': 0}


@dataclass
class FakeReader:
    states: Mapping[ResourceRef, Any] = field(default_factory=lambda: dict(ACCOUNT))
    asked: list = field(default_factory=list)

    def before(self, changes: Sequence[Change]) -> Reading:
        self.asked.append(tuple(changes))
        return Reading(self.states, (), 7, {'resources': len(self.states)})

    def after(self, states: Mapping[ResourceRef, Any]) -> dict[ResourceRef, Any]:
        return dict(states)


@dataclass(frozen=True)
class Undoable:
    """Static facts: a created thing can go again (YES); anything else is unknown."""

    def assess(self, change: Change) -> UndoFact:
        if change.type is ChangeType.CREATED:
            return UndoFact(change.ref, Undo.YES, ('it can be deleted again',))
        if change.type is ChangeType.DELETED:
            return UndoFact(change.ref, Undo.NO, ('it holds data',))
        return UndoFact(change.ref, Undo.UNKNOWN, ('not yet proven',))


@dataclass(frozen=True)
class FlagLens:
    name: str = 'flag'
    message: str = 'something new'

    def look(self, view: LensView) -> LensResult:
        return LensResult((Finding(self.name, 'new', self.message, tuple(c.ref for c in view.changes)),))


@dataclass(frozen=True)
class BrokenLens:
    name: str = 'broken'

    def look(self, view: LensView) -> LensResult:
        raise RuntimeError('the scanner crashed')


@dataclass(frozen=True)
class QuietLens:
    name: str = 'quiet'

    def look(self, view: LensView) -> LensResult:
        return LensResult()


def parts(lenses=(QuietLens(),), reader: FakeReader | None = None, prover=None) -> Parts:
    return Parts(reader or FakeReader(), Graph(VOCAB), lenses, Undoable(), prover=prover)


def created(r: ResourceRef) -> Change:
    return Change(r, ChangeType.CREATED, calls=('svc.Create',))


def modified(r: ResourceRef, path: str = 'Settings.Size', before: Any = 1, after: Any = 2) -> Change:
    return Change(r, ChangeType.MODIFIED, (FieldChange(path, before, after),), ('svc.Update',))


def deleted(r: ResourceRef) -> Change:
    return Change(r, ChangeType.DELETED, calls=('svc.Delete',))
