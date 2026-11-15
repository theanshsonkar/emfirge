"""Put a branch together for AWS: codec, catalog, outcomes and copier, the real account and an engine.

The only place that chooses the parts. By default the branch runs on the generic catalog and outcomes (compiled from
AWS's published lists), with the hand-written (curated) naming only where the generic one does not know, and copies
with the generic and curated copiers in the order experiment 23 measured (aws/data/copier_order.json).

Configurations (keyword options of build):
  catalog='layered' | 'curated'                      what names calls and resources
  copier='layered' | 'curated' | 'generic'           what copies a real resource into the engine
"""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Literal

from emfirge.aws.accounts import HttpAccount, sdk_client
from emfirge.aws.catalog import AwsCatalog
from emfirge.aws.codec import AwsCodec
from emfirge.aws.curated import Where, curated
from emfirge.aws.curated.kinds import kind_of
from emfirge.aws.engines import EmulatorEngine, MotoEngine
from emfirge.aws.generic_copy import GenericCopier
from emfirge.aws.layered import LayeredCatalog, LayeredCopier, copier_order
from emfirge.aws.outcomes_generic import GenericOutcomes
from emfirge.branch import Branch
from emfirge.branch.guard import ReadOnly
from emfirge.core.model import Kind
from emfirge.core.ports import Account, Catalog, Copier, Engine, Outcomes

ENGINES = {'emulator': EmulatorEngine, 'moto': MotoEngine}
CatalogChoice = Literal['layered', 'curated']
CopierChoice = Literal['layered', 'curated', 'generic']


@dataclass(frozen=True)
class Setup:
    real_url: str
    real_ca: str | None
    engine: str              # 'emulator' | 'moto'
    engine_port: int
    workdir: Path
    region: str = 'us-west-2'
    catalog: CatalogChoice = 'layered'
    copier: CopierChoice = 'layered'


class _ReadKinds:
    """Kinds for the one read the wiring itself makes (who the account is)."""

    def kind(self, service: str, operation: str) -> Kind:
        return kind_of(operation)


def account_id(real: Account, codec: AwsCodec, region: str) -> str:
    """Asked of the real account itself, through the read-only door."""
    return sdk_client(ReadOnly(real, codec, _ReadKinds()), 'sts', region).get_caller_identity()['Account']


def make_engine(kind: str, port: int, workdir: Path) -> Engine:
    return ENGINES[kind](port, workdir)


def parts(codec: AwsCodec, where: Where, catalog: CatalogChoice = 'layered',
          copier: CopierChoice = 'layered') -> tuple[Catalog, Outcomes, Copier]:
    """The catalog, outcomes and copier of one configuration."""
    cur_catalog, cur_outcomes, cur_copier = curated(codec, where)
    if catalog == 'curated':
        if copier != 'curated':
            raise ValueError('the curated catalog runs with the curated copier only')
        return cur_catalog, cur_outcomes, cur_copier
    layered = LayeredCatalog(AwsCatalog(account=where.account, region=where.region), codec, cur_catalog)
    generic = GenericCopier(layered, codec, where.region)
    copiers: dict[str, Copier] = {'generic': generic, 'curated': cur_copier}
    if copier != 'layered':
        copiers = {copier: copiers[copier]}
    return layered, GenericOutcomes(codec, layered), LayeredCopier(copiers, copier_order(), codec, layered)


def build(real: Account, engine: Account, region: str = 'us-west-2', codec: AwsCodec | None = None, *,
          catalog: CatalogChoice = 'layered', copier: CopierChoice = 'layered') -> Branch:
    """A branch over `real` with `engine` (already started)."""
    codec = codec or AwsCodec(region)
    cat, outcomes, cop = parts(codec, Where(region, account_id(real, codec, region)), catalog, copier)
    return Branch(codec, cat, cop, real, engine, outcomes)


def build_from(setup: Setup) -> tuple[Branch, Engine]:
    engine = make_engine(setup.engine, setup.engine_port, setup.workdir)
    engine.start()
    try:
        real = HttpAccount('real', setup.real_url, setup.real_ca)
        return build(real, engine, setup.region, catalog=setup.catalog, copier=setup.copier), engine
    except Exception:
        engine.stop()
        raise
