"""Put a branch together for AWS: codec, catalog, outcomes and copier, the real account and an engine.

The only place that chooses the parts. The catalog and copier are injected into the branch, so the curated ones can
be swapped for (or stacked with) the generic catalog without touching the branch.
"""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from emfirge.aws.accounts import HttpAccount, sdk_client
from emfirge.aws.codec import AwsCodec
from emfirge.aws.curated import Where, curated
from emfirge.aws.curated.kinds import kind_of
from emfirge.aws.engines import EmulatorEngine, MotoEngine
from emfirge.branch import Branch
from emfirge.branch.guard import ReadOnly
from emfirge.core.model import Kind
from emfirge.core.ports import Account, Engine

ENGINES = {'emulator': EmulatorEngine, 'moto': MotoEngine}


@dataclass(frozen=True)
class Setup:
    real_url: str
    real_ca: str | None
    engine: str              # 'emulator' | 'moto'
    engine_port: int
    workdir: Path
    region: str = 'us-west-2'


class _ReadKinds:
    """Kinds for the one read the wiring itself makes (who the account is)."""

    def kind(self, service: str, operation: str) -> Kind:
        return kind_of(operation)


def account_id(real: Account, codec: AwsCodec, region: str) -> str:
    """Asked of the real account itself, through the read-only door."""
    return sdk_client(ReadOnly(real, codec, _ReadKinds()), 'sts', region).get_caller_identity()['Account']


def make_engine(kind: str, port: int, workdir: Path) -> Engine:
    return ENGINES[kind](port, workdir)


def build(real: Account, engine: Account, region: str = 'us-west-2', codec: AwsCodec | None = None) -> Branch:
    """A branch over `real` with `engine` (already started) and the curated catalog and copier."""
    codec = codec or AwsCodec(region)
    catalog, outcomes, copier = curated(codec, Where(region, account_id(real, codec, region)))
    return Branch(codec, catalog, copier, real, engine, outcomes)


def build_from(setup: Setup) -> tuple[Branch, Engine]:
    engine = make_engine(setup.engine, setup.engine_port, setup.workdir)
    engine.start()
    try:
        return build(HttpAccount('real', setup.real_url, setup.real_ca), engine, setup.region), engine
    except Exception:
        engine.stop()
        raise
