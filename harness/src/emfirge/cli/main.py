"""`emf`: run an agent's session on a branch of the account, and get the verdict.

    emf run [options] -- <command ...>   run the command against a fresh branch; print the report; exit 0 go, 3 ask
    emf serve [options]                  serve a branch and print the lines to source; Ctrl-C or `emf seal` ends it
    emf seal --url URL                   end a served branch and print its report

Where the real account is: --real-endpoint URL (a local stand-in, as every test uses) or --real-aws (your real AWS
account, read with your own credentials). One of the two is required: nothing reaches AWS by default or by a typo.

Exit codes: 0 go; 3 ask; 2 Emfirge itself failed; 64 + the command's own code (at most 125) when the command failed.

The environment the command gets is a guard against accidents, not a sandbox against a hostile program: its AWS tools
reach only the branch, with dummy keys, and cannot pick up your credentials from the usual variables and files.
"""
from __future__ import annotations

import argparse
import os
import shutil
import sys
import tempfile
from pathlib import Path
from typing import Sequence

from emfirge.aws.session import Options, open_bench
from emfirge.session import Output, end_remote, run, serve
from emfirge.session.command import FAILED
from emfirge.session.outside import outside_lens


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        return args.do(args)
    except KeyboardInterrupt:
        print('emf: stopped', file=sys.stderr)
        return FAILED
    except Exception as e:   # noqa: BLE001 - any failure of Emfirge itself is exit 2, with plain words
        print(f'emf: Emfirge failed: {type(e).__name__}: {e}', file=sys.stderr)
        return FAILED


def _run(args: argparse.Namespace) -> int:
    command = args.command[1:] if args.command[:1] == ['--'] else args.command
    if not command:
        raise ValueError('no command given: emf run [options] -- <command ...>')
    with _workdir(args.workdir) as workdir:
        options = _options(args, workdir)
        return run(lambda admin: open_bench(options, admin), command, _output(args), dict(os.environ), sys.stdout)


def _serve(args: argparse.Namespace) -> int:
    with _workdir(args.workdir) as workdir:
        options = _options(args, workdir)
        return serve(lambda admin: open_bench(options, admin), _output(args), dict(os.environ), sys.stdout)


def _seal(args: argparse.Namespace) -> int:
    report, code = end_remote(args.url)
    sys.stdout.write(report)
    return code


def _options(args: argparse.Namespace, workdir: Path) -> Options:
    return Options(workdir=workdir, real_endpoint=args.real_endpoint, real_ca=args.real_ca, real_aws=args.real_aws,
                   engine=args.engine, engine_port=args.engine_port, port=args.port, region=args.region, budget=args.budget,
                   outside=tuple(outside_lens(spec) for spec in args.lens), prove_undo=args.prove_undo)


def _output(args: argparse.Namespace) -> Output:
    return Output(show_all=args.all, report_path=Path(args.report) if args.report else None)


class _workdir:
    """The given folder, or a temporary one removed afterwards (engine logs live there)."""

    def __init__(self, given: str | None) -> None:
        self._given = Path(given) if given else None
        self._made: Path | None = None

    def __enter__(self) -> Path:
        if self._given:
            self._given.mkdir(parents=True, exist_ok=True)
            return self._given
        self._made = Path(tempfile.mkdtemp(prefix='emfirge-'))
        return self._made

    def __exit__(self, *_: object) -> None:
        if self._made:
            shutil.rmtree(self._made, ignore_errors=True)


def _parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog='emf', description='The branch for AI agents that work on the cloud.')
    sub = p.add_subparsers(required=True, metavar='command')
    run_p = sub.add_parser('run', help='run a command against a fresh branch, then judge it')
    _branch_options(run_p)
    run_p.add_argument('command', nargs=argparse.REMAINDER, help='-- then the command and its arguments')
    run_p.set_defaults(do=_run)
    serve_p = sub.add_parser('serve', help='serve a branch for your own tools, until Ctrl-C or emf seal')
    _branch_options(serve_p)
    serve_p.set_defaults(do=_serve)
    seal_p = sub.add_parser('seal', help='end a served branch and print its report')
    seal_p.add_argument('--url', required=True, help='the branch endpoint emf serve printed')
    seal_p.set_defaults(do=_seal)
    return p


def _branch_options(p: argparse.ArgumentParser) -> None:
    where = p.add_mutually_exclusive_group(required=True)
    where.add_argument('--real-endpoint', metavar='URL', help='a local stand-in for the real account')
    where.add_argument('--real-aws', action='store_true',
                       help='read your real AWS account with your own credentials (reads only, never writes)')
    p.add_argument('--real-ca', metavar='FILE', help='CA file for --real-endpoint')
    p.add_argument('--engine', choices=('emulator', 'moto'), default='emulator', help='the fake that runs changes')
    p.add_argument('--engine-port', type=int, help='port for the engine (default: a free one)')
    p.add_argument('--port', type=int, help='port for the branch endpoint on 127.0.0.1 (default: a free one)')
    p.add_argument('--region', default=os.environ.get('AWS_REGION') or os.environ.get('AWS_DEFAULT_REGION') or 'us-west-2')
    p.add_argument('--budget', type=int, default=Options.budget, help='reads of the real account for the graph, at most')
    p.add_argument('--lens', action='append', default=[], metavar="'NAME=COMMAND'",
                   help='an outside tool that prints JSON lines; run on the account and on the branch')
    p.add_argument('--prove-undo', action=argparse.BooleanOptionalAction, default=True,
                   help='put each change back on the branch to prove it can be put back (default: on; it runs last)')
    p.add_argument('--report', metavar='FILE.json', help='also write the report as JSON')
    p.add_argument('--all', action='store_true', help='show every affected resource, the maybe ones too')
    p.add_argument('--workdir', metavar='DIR', help='keep engine logs here (default: a temporary folder)')


if __name__ == '__main__':
    sys.exit(main())
