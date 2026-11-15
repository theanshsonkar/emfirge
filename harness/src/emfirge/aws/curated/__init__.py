"""The 18 hand-written resource types of experiment 09, behind the Catalog, Outcomes and Copier ports.

One module per service holds each type's naming knowledge and its copy function (spec.TypeSpec). The kinds rule is
one function (kinds.kind_of), to be dropped when the generic catalog gives kinds.
"""
from __future__ import annotations

from ..codec import AwsCodec
from . import config, dynamodb, ec2, events, iam, lambda_, messaging, s3
from .catalog import CuratedCatalog, CuratedOutcomes
from .copier import CuratedCopier
from .naming import Naming
from .spec import TypeSpec, Where

SPECS: tuple[TypeSpec, ...] = (*lambda_.TYPES, *iam.TYPES, *s3.TYPES, *dynamodb.TYPES, *events.TYPES, *messaging.TYPES,
                               *config.TYPES, *ec2.TYPES)


def curated(codec: AwsCodec, where: Where) -> tuple[CuratedCatalog, CuratedOutcomes, CuratedCopier]:
    """The three ports, sharing one view of the hand-written types."""
    naming = Naming(SPECS)
    return CuratedCatalog(codec, naming, where), CuratedOutcomes(codec, naming), CuratedCopier(naming, where)


__all__ = ['SPECS', 'Where', 'curated']
