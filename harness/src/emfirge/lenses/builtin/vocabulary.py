"""The words the built-in lenses look for, as data. The shapes are here; the values (one cloud's words) are handed in.

A lens never asks which service a setting belongs to. It looks for words in setting names and values: 'Principal'
in a policy, an address range that means everyone, a key named like a protection switch. Those words differ per
cloud, so they come in through these classes. AWS's are in patterns.py, the one place they are kept.
"""
from __future__ import annotations

import re
from dataclasses import dataclass

Regex = re.Pattern[str]


@dataclass(frozen=True)
class PolicyWords:
    """How a policy statement is written.
    effect_key, allow, deny        the key that says allow or deny, and its two values
    action, not_action ...         the keys of a statement's parts ('Action' / 'NotAction', ...)
    everyone                       principal strings that mean anyone at all (after normalising to 'Type:value')
    principal_classes              (class, regex) in order: what kind of principal a normalised string is
    trust_actions                  actions that let a principal take on an identity (a trust policy grants these)
    limiting_keys, limiting_operators  condition keys and operators that narrow who can call, with a fixed value
    ignored_operator_prefixes      operator prefixes that never narrow (true when the key is absent)
    attached_keys                  setting names that hold a reference to a separately kept policy
    status_words                   read names whose answer status changing is this lens's business
    max_grants                     above this many (principal, action, resource) triples a statement is not compared"""
    effect_key: str
    allow: str
    deny: str
    action: str
    not_action: str
    resource: str
    not_resource: str
    principal: str
    not_principal: str
    condition: str
    everyone: frozenset[str]
    principal_classes: tuple[tuple[str, Regex], ...]
    trust_actions: tuple[str, ...]
    limiting_keys: frozenset[str]
    limiting_operators: frozenset[str]
    any_value_prefix: str
    ignored_operator_prefixes: tuple[str, ...]
    attached_keys: Regex
    status_words: Regex
    max_grants: int = 4096


@dataclass(frozen=True)
class PublicValue:
    """A value that opens something to everyone, under a key of a given name. `why` says where it comes from."""
    key: Regex
    value: Regex
    why: str


@dataclass(frozen=True)
class PublicWords:
    """everyone_ranges   address ranges that mean the whole internet
    context_keys         keys beside an address that say what it opens (ports, protocol)
    outbound             a path or a sibling key saying the rule is about leaving, not reaching in
    deny_values          sibling values saying the rule refuses
    open_flags           switch names that open something when on ('PubliclyAccessible')
    block_flags          switch names that keep things closed when on ('BlockPublicAcls'); off is the news
    values               values that open something to everyone ('AllUsers'): one line per service that uses one
    on, off              how switch values read
    status_words         read names whose answer status changing is this lens's business"""
    everyone_ranges: frozenset[str]
    context_keys: Regex
    outbound: Regex
    deny_values: frozenset[str]
    open_flags: Regex
    block_flags: Regex
    values: tuple[PublicValue, ...]
    on: frozenset[str]
    off: frozenset[str]
    status_words: Regex


@dataclass(frozen=True)
class Protection:
    """One kind of protection, found by the path of a setting.
    kind  'switch'    on means protected; on -> off or removed is the news
          'retention' a number of days or copies kept; smaller is the news
          'expiry'    data is deleted after a number of days; a new or shorter one is the news
          'present'   a protective setting exists; its removal is the news
    unset_is_forever  for 'retention': no value means kept forever, so any value is shorter"""
    name: str
    path: Regex
    kind: str
    unset_is_forever: bool = False


@dataclass(frozen=True)
class DataWords:
    protections: tuple[Protection, ...]
    emptying_operations: Regex
    on: frozenset[str]
    off: frozenset[str]
    status_words: Regex


@dataclass(frozen=True)
class MoneyWords:
    """class_keys      a machine size or class ('InstanceType'); ladder orders the size word at its end
    growth_keys        numbers that cost more when larger; growth_ignore names numbers that do not cost
    plan_keys          how something is billed; any change is a fact
    running_keys       switches whose 'on' means something runs (and is billed by time)
    commitment_operations  calls that commit money or raise a limit
    on, off            running / stopped words"""
    class_keys: Regex
    ladder: tuple[str, ...]
    numbered_size: Regex
    growth_keys: Regex
    growth_ignore: Regex
    plan_keys: Regex
    running_keys: Regex
    commitment_operations: Regex
    on: frozenset[str]
    off: frozenset[str]
