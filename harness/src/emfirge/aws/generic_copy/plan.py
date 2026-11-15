"""Which operations rebuild a resource type in the engine, chosen from botocore's model by name. Pure: no I/O.

  create     an operation that makes one (Create, Put, Register or Run, then the type's name or its ARN variable's
             words: CreateFunction, PutParameter, RegisterTaskDefinition, RunInstances, CreateDBInstance for rds:db).
  settings   a write that sets what a read shows: the same noun after the verb (PutBucketPolicy <- GetBucketPolicy,
             PutFunctionConcurrency <- GetFunctionConcurrency, PutTargets <- ListTargetsByRule), or the read's noun is
             the write's with the write's verb as a participle in front (AttachRolePolicy <- ListAttachedRolePolicies).
  details    a read that gives one item of a list in full (GetRolePolicy for each name ListRolePolicies gives).
"""
from __future__ import annotations

from dataclasses import dataclass

from botocore.model import ServiceModel

from ..resource_words import noun_of, verb_of

CREATE_VERBS = ('Create', 'Put', 'Register', 'Run')
SETTING_VERBS = ('Put', 'Set', 'Update', 'Create', 'Attach', 'Add', 'Enable', 'Register', 'Associate')
DETAIL_VERBS = ('Get', 'Describe')


@dataclass(frozen=True)
class Setting:
    read: str        # the read whose answer holds the setting
    write: str       # the write that sets it


def creates(model: ServiceModel, words: frozenset[str]) -> list[str]:
    """Operations that create a thing named by `words` (the type's name, its ARN variable's words), closest first."""
    ranked = []
    for op in model.operation_names:
        if verb_of(op) not in CREATE_VERBS:
            continue
        noun = noun_of(op)
        if noun in words:
            ranked.append((0, len(noun), CREATE_VERBS.index(verb_of(op)), op))
        elif any(w and (noun.endswith(w) or noun.startswith(w)) for w in words):
            ranked.append((1, len(noun), CREATE_VERBS.index(verb_of(op)), op))
    return [op for *_, op in sorted(ranked)]


def settings(model: ServiceModel, reads: list[str], create: str) -> list[Setting]:
    """The writes that set what each read shows, in the reads' order."""
    out = []
    for read in reads:
        noun = noun_of(read)
        for op in model.operation_names:
            verb = verb_of(op)
            if op == create or verb not in SETTING_VERBS:
                continue
            if noun_of(op) == noun or (noun == participle(verb) + noun_of(op)):
                out.append(Setting(read, op))
    return out


def details(model: ServiceModel, write: str) -> list[str]:
    """Reads that answer one item of what `write` sets (GetRolePolicy for PutRolePolicy)."""
    noun = noun_of(write)
    return [op for op in model.operation_names if verb_of(op) in DETAIL_VERBS and noun_of(op) == noun]


def participle(verb: str) -> str:
    """'Attach' -> 'attached', 'Enable' -> 'enabled'."""
    v = verb.lower()
    return v + ('d' if v.endswith('e') else 'ed')
