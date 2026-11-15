"""The 18 hand-written resource types of experiment 09, behind the Catalog, Outcomes and Copier ports.

One module per service holds each type's naming knowledge and its copy function (spec.TypeSpec). The kinds rule is
one function (kinds.kind_of), to be dropped when the generic catalog gives kinds.
"""
from __future__ import annotations

from ..codec import AwsCodec
from . import dynamodb, ec2, events, iam, kms, lambda_, logs, s3, scheduler, secretsmanager, sns, sqs, ssm
from .catalog import CuratedCatalog, CuratedOutcomes
from .copier import CuratedCopier
from .naming import Naming
from .spec import TypeSpec, Where

SPECS: tuple[TypeSpec, ...] = tuple(t for m in (lambda_, iam, s3, dynamodb, scheduler, events, sqs, sns, logs, ssm,
                                                 secretsmanager, kms, ec2) for t in m.TYPES)


def curated(codec: AwsCodec, where: Where, copy_data: bool = False) -> tuple[CuratedCatalog, CuratedOutcomes, CuratedCopier]:
    """The three ports, sharing one view of the hand-written types. `copy_data`: copies may read the customer's data
    (a table's items, an object's body); off by default."""
    naming = Naming(SPECS)
    return CuratedCatalog(codec, naming, where), CuratedOutcomes(codec, naming), CuratedCopier(naming, where, copy_data)


__all__ = ['SPECS', 'Where', 'curated']
