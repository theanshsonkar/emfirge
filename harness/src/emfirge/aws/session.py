"""The AWS wiring of a session: which parts, in one place.

  real account   a local stand-in (--real-endpoint, used by every test) or the owner's real AWS account through
                 their own credentials (RealAccount; only with an explicit real_aws=True, never by default)
  branch         server.wiring.build over that account, on a fresh engine (AWS's emulator or moto) on a free port
  endpoint       the branch on a free 127.0.0.1 port
  parts          the reader (aws/reader.py), the graph with AWS's vocabulary, the built-in lenses with the catalog's
                 facts, outside tools, AwsReversibility, and the undo prover (aws/undo; on unless turned off)

The client environment is a guard against accidents, not a sandbox: it makes AWS tools that read the usual
variables and files reach only the branch, with dummy keys, so an agent cannot pick up the owner's credentials by
accident. A hostile program can still read files, open sockets and find credentials elsewhere on the machine.
"""
from __future__ import annotations

import socket
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Mapping

from emfirge.aws.accounts import HttpAccount
from emfirge.aws.catalog import AwsCatalog
from emfirge.aws.codec import AwsCodec
from emfirge.aws.reader import AccountReader, ReaderSettings
from emfirge.aws.real import RealAccount
from emfirge.aws.reversibility import AwsReversibility
from emfirge.aws.undo import prover_for
from emfirge.aws.vocabulary import AWS_VOCABULARY
from emfirge.branch import Branch
from emfirge.core.model import Kind, ResourceRef, WireRequest, WireResponse
from emfirge.core.ports import Account, CannotTell
from emfirge.graph import Graph
from emfirge.lenses import ExternalLens, builtin_lenses
from emfirge.server.http import BranchServer
from emfirge.server.wiring import account_id, build, make_engine
from emfirge.session.judge import Parts

DUMMY_KEY = 'emfirge-branch'
LOCAL = '127.0.0.1,localhost'


class NoRealAccount(ValueError):
    """Neither a stand-in nor real AWS was chosen: Emfirge never reaches AWS by default."""


@dataclass(frozen=True)
class Options:
    workdir: Path
    real_endpoint: str | None = None     # a local stand-in for the real account
    real_ca: str | None = None
    real_aws: bool = False               # the owner's real AWS account, with their own credentials
    engine: str = 'emulator'
    engine_port: int | None = None       # default: a free port
    port: int | None = None              # the branch endpoint's port; default: a free port
    region: str = 'us-west-2'
    budget: int = ReaderSettings.budget
    outside: tuple[ExternalLens, ...] = ()
    prove_undo: bool = True              # put changes back on the branch to prove they can be (aws/undo); runs last


@dataclass
class AwsBench:
    """session.ports.Bench for AWS."""
    held: Branch
    url: str
    region: str
    workdir: Path
    codec: AwsCodec
    catalog: AwsCatalog
    _stops: list[Callable[[], None]] = field(default_factory=list)
    _doors: tuple[str, str] | None = None

    def client_env(self, base: Mapping[str, str]) -> dict[str, str]:
        return client_env(base, self.url, self.region, self.workdir)

    def lens_endpoints(self) -> tuple[str, str]:
        """Read-only endpoints for outside tools, started on first use: the real account (behind the branch's own
        read-only door) and the branch (reads only)."""
        if self._doors is None:
            before = ReadsOnly(self.held.real.send, self.codec, self.catalog)
            after = ReadsOnly(self.held.handle, self.codec, self.catalog)
            servers = [BranchServer(door, free_port()).start() for door in (before, after)]   # type: ignore[arg-type]
            self._stops += [s.stop for s in servers]
            self._doors = (servers[0].url, servers[1].url)
        return self._doors

    def close(self) -> None:
        while self._stops:
            try:
                self._stops.pop()()
            except Exception:   # noqa: BLE001 - stop everything else even if one part fails to stop
                pass


class ReadsOnly:
    """An endpoint handler that answers reads with `answer` and refuses everything else in the client's own error
    shape. Served by BranchServer (it only calls `handle`)."""

    def __init__(self, answer: Callable[[WireRequest], WireResponse], codec: AwsCodec, catalog: AwsCatalog) -> None:
        self._answer, self._codec, self._catalog = answer, codec, catalog

    def handle(self, request: WireRequest) -> WireResponse:
        call = self._codec.decode(request)
        if call is None or not self._catalog.kind(call.service, call.operation).reads_only:
            return self._codec.refusal(call, request, 'Emfirge cannot tell: this endpoint answers reads only')
        try:
            return self._answer(request)
        except CannotTell as e:
            return self._codec.refusal(call, request, f'Emfirge cannot tell: {e}')


def open_bench(options: Options, admin: tuple[tuple[str, Any], ...] = ()) -> tuple[AwsBench, Parts]:
    """Start the engine, build the branch over the real account, serve it; and the parts that judge it."""
    codec = AwsCodec(options.region)
    real = real_account(options, codec)
    engine = make_engine(options.engine, options.engine_port or free_port(), options.workdir)
    engine.start()
    stops: list[Callable[[], None]] = [engine.stop]
    try:
        branch = build(real, engine, options.region, codec)
        server = BranchServer(branch, options.port or free_port(), admin).start()
        stops.append(server.stop)
        catalog = AwsCatalog(account=account_id(branch.real, codec, options.region), region=options.region)
        bench = AwsBench(branch, server.url, options.region, options.workdir, codec, catalog, stops)
        return bench, parts(bench, options)
    except BaseException:
        for stop in reversed(stops):
            stop()
        raise


def real_account(options: Options, codec: AwsCodec) -> Account:
    if options.real_endpoint:
        return HttpAccount('real', options.real_endpoint, options.real_ca)
    if options.real_aws:
        return RealAccount(codec, AwsCatalog(), options.region)
    raise NoRealAccount('no real account was given: use --real-endpoint URL for a local stand-in, '
                        'or --real-aws to read your real AWS account with your own credentials')


def parts(bench: AwsBench, options: Options) -> Parts:
    catalog = bench.catalog
    reader = AccountReader(bench.held.real, bench.codec, catalog, options.region, ReaderSettings(budget=options.budget))
    lenses = builtin_lenses(holds_data=_holds_data(catalog), kind_of=_kind_of(catalog))
    prover = (lambda changes: prover_for(bench.held, changes, bench.codec)) if options.prove_undo else None
    return Parts(reader, Graph(AWS_VOCABULARY), lenses, AwsReversibility(catalog), options.outside, prover)


def _holds_data(catalog: AwsCatalog) -> Callable[[ResourceRef], bool | None]:
    def holds(ref: ResourceRef) -> bool | None:
        info = catalog.resource_type(ref.type)
        return info.holds_data if info else None
    return holds


def _kind_of(catalog: AwsCatalog) -> Callable[[str], Kind]:
    def kind(name: str) -> Kind:
        service, _, operation = name.partition('.')
        return catalog.kind(service, operation)
    return kind


def client_env(base: Mapping[str, str], url: str, region: str, workdir: Path) -> dict[str, str]:
    """`base` with every AWS_* variable removed, and AWS tools pointed at the branch only: its endpoint, dummy keys,
    the region kept, the credentials and config files pointed at an empty file, and no instance metadata."""
    region = base.get('AWS_REGION') or base.get('AWS_DEFAULT_REGION') or region
    empty = workdir / 'aws-empty'
    empty.parent.mkdir(parents=True, exist_ok=True)
    empty.write_text('')
    env = {k: v for k, v in base.items() if not k.upper().startswith('AWS_')}
    env.update(AWS_ENDPOINT_URL=url, AWS_ACCESS_KEY_ID=DUMMY_KEY, AWS_SECRET_ACCESS_KEY=DUMMY_KEY,
               AWS_REGION=region, AWS_DEFAULT_REGION=region, AWS_SHARED_CREDENTIALS_FILE=str(empty),
               AWS_CONFIG_FILE=str(empty), AWS_EC2_METADATA_DISABLED='true', AWS_PAGER='')
    for key in ('NO_PROXY', 'no_proxy'):
        env[key] = ','.join(x for x in (base.get(key, ''), LOCAL) if x)
    return env


def free_port() -> int:
    with socket.socket() as s:
        s.bind(('127.0.0.1', 0))
        return s.getsockname()[1]

