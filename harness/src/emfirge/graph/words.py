"""Words of keys and resource types, to tell whether a field's label names the kind of thing its value names.

'QueueName' holding a queue's name, 'TABLE_NAME' holding a table's name, 'logGroupName' holding a log group's name:
the settings say what the bare name is. The type comes from the resource's own type ('<service>:<kind>'), so the
comparison needs no knowledge of any service: split both into words and look for a shared word that is not generic.
"""
from __future__ import annotations

import re
from typing import Iterable

_CAMEL = re.compile(r'[A-Z]+(?![a-z])|[A-Z]?[a-z]+|\d+')


def words(text: str) -> list[str]:
    """'TargetGroupArn' -> ['target', 'group', 'arn']; 'FEED_BUCKET' -> ['feed', 'bucket']; plural 's' dropped."""
    out = []
    for part in re.split(r'[^A-Za-z0-9]+', text):
        for w in _CAMEL.findall(part):
            w = w.lower()
            out.append(w[:-1] if len(w) > 3 and w.endswith('s') and not w.endswith('ss') else w)
    return out


def type_words(resource_type: str) -> set[str]:
    """Words of '<service>:<kind>': the service, the kind, and the kind's own words ('elbv2:targetgroup')."""
    return {w for part in resource_type.split(':') for w in [part.lower(), *words(part)] if w}


def label_names_type(labels: Iterable[str], resource_type: str, generic: frozenset[str]) -> bool:
    """A label shares a word with the type: a single word ('QueueName' ~ 'sqs:queue') or two neighbouring words
    written together ('TargetGroupArn' ~ 'elbv2:targetgroup'). Generic words ('name', 'id', 'value') never count."""
    kinds = type_words(resource_type) - generic
    for label in labels:
        ws = words(label)
        if any(w in kinds for w in ws if w not in generic) or any(a + b in kinds for a, b in zip(ws, ws[1:])):
            return True
    return False
