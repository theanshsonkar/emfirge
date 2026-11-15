"""What AWS's identifiers look like, for the graph (moved from experiment 18's states18.py).

The graph finds links by looking for one resource's identifiers in another resource's settings. How sure a match is
depends on the shape of the string: an exact address or a generated id names one thing; a bare short name may name
several. These shapes are the same for every AWS service, so they are data for the whole cloud, not per service.
"""
from __future__ import annotations

from emfirge.graph import Vocabulary

ADDRESSES = (
    r'arn:[a-z0-9-]+:[a-z0-9-]*:[a-z0-9-]*:[0-9a-z-]*:\S+',             # ARN
    r'[a-z][a-z0-9+.-]*://\S+',                                        # URL
    r'(?i)(?=[a-z0-9.-]*[a-z])[a-z0-9_-]+(\.[a-z0-9_-]+)+\.?(:\d+)?',   # host name, optional port
    r'\d{1,3}(\.\d{1,3}){3}(:\d+)?',                                   # IPv4, optional port
)
OPAQUE = (
    r'[a-z]{1,12}-[0-9a-f]{8,}',                                       # i-0abc..., sg-..., vpc-...
    r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}',   # UUID
    r'(?=[A-Z0-9]*[A-Z])(?=[A-Z0-9]*[0-9])[A-Z0-9]{12,}',              # E2ABC..., Z0ABC..., AROA...
)

AWS_VOCABULARY = Vocabulary.of(ADDRESSES, OPAQUE)
