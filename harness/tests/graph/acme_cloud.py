"""A made-up cloud for the graph tests. Its identifiers look nothing like AWS's, which is the point: the graph gets
its idea of an address and a generated id only from the Vocabulary."""
from __future__ import annotations

import base64
import json

from emfirge.core.model import ResourceRef
from emfirge.graph import Vocabulary

VOCAB = Vocabulary.of(
    addresses=[r'urn:acme:\S+', r'[a-z][a-z0-9+.-]*://\S+', r'(?i)(?=[a-z0-9.-]*[a-z])[a-z0-9_-]+(\.[a-z0-9_-]+)+\.?(:\d+)?'],
    opaque=[r'[a-z]{1,6}-[0-9a-f]{8,}'])


def ref(kind: str, ident: str) -> ResourceRef:
    """Types are '<service>:<kind>'; in acme every service has one kind of resource."""
    return ResourceRef(f'{kind}:{kind}', ident)


def urn(kind: str, ident: str) -> str:
    return f'urn:acme:{kind}/{ident}'


def policy(*statements: dict) -> str:
    return json.dumps({'statements': list(statements)})


def b64(text: str) -> str:
    return base64.b64encode(text.encode()).decode()


# a small account: a store served by an edge, a name pointing at the edge, two jobs with grants, a box with a badge
STORE, OTHER = ref('store', 'media-files'), ref('store', 'scratch-2024')
EDGE, DNS = ref('edge', 'edg-0a1b2c3d4e'), ref('record', 'feeds.example.org')
JOB, JOB_GRANT = ref('job', 'publisher-job'), ref('grant', 'publisher-grant')
TIMER, TIMER_GRANT = ref('timer', 'weekly-run'), ref('grant', 'timer-grant')
BOX, BADGE, BOX_GRANT = ref('box', 'box-00aa11bb22'), ref('badge', 'box-badge'), ref('grant', 'box-grant')


def account() -> dict[ResourceRef, dict]:
    return {
        STORE: {'name': 'media-files', 'policy': policy({'allow': 'read', 'who': urn('edge', 'edg-0a1b2c3d4e')})},
        OTHER: {'name': 'scratch-2024'},
        EDGE: {'id': 'edg-0a1b2c3d4e', 'host': 'd1x2y3.edge.acme.net', 'origins': [{'host': 'media-files.store.acme.net'}]},
        DNS: {'name': 'feeds.example.org', 'values': [{'value': 'd1x2y3.edge.acme.net'}]},
        JOB: {'grant': urn('grant', 'publisher-grant'), 'env': {'OUT_STORE': 'media-files'}},
        JOB_GRANT: {'doc': policy({'allow': 'write', 'on': urn('store', 'media-files') + '/*'})},
        TIMER: {'target': urn('job', 'publisher-job'), 'grant': urn('grant', 'timer-grant'), 'state': 'off'},
        TIMER_GRANT: {'doc': policy({'allow': 'run', 'on': urn('job', 'publisher-job')})},
        BOX: {'badge': urn('badge', 'box-badge'), 'startup': b64('#!/bin/sh\ncopy acme://media-files/latest /srv\nrun\n')},
        BADGE: {'grants': [{'arn': urn('grant', 'box-grant')}]},
        BOX_GRANT: {'doc': policy({'allow': 'read', 'on': urn('store', 'media-files')})},
    }
