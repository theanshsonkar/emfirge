#!/usr/bin/env python3
"""Real-world evaluation harness (phase A: produce plans and record ingest coverage).

For every vendored target under backend/tests/data/realworld/ (TerraGoat, CloudGoat
scenarios and the clean terraform-aws-modules examples) this script

  1. copies the .tf files into a temporary directory (the vendored files are never edited),
  2. produces a real `terraform show -json` plan WITHOUT AWS credentials,
  3. feeds the plan through Emfirge's real path: plan_ingest.translate_plan on an empty
     AWSInfrastructure, mutations.apply_change per change (as the /plans/terraform route does),
     verdict.combined_verdict(empty_base, branch, ...) and the native rules,
  4. writes one results JSON.

It does NOT compare anything against answer_keys.json (that is phase B).

How plans are produced without credentials
------------------------------------------
Terraform's `mock_provider` only exists for `terraform test`, so it cannot give a
`plan -out` / `show -json`. Instead:

  * the aws provider is configured with fake static keys and skip_credentials_validation,
    skip_requesting_account_id, skip_metadata_api_check, skip_region_validation and
    s3_use_path_style (an override file, or a fresh provider block when the target has none);
  * AWS_ENDPOINT_URL points every service endpoint at a local moto server, so data sources
    (aws_caller_identity, aws_ami, aws_availability_zones, aws_canonical_user_id, ...) are
    answered locally and nothing can reach real AWS. moto is started with a small custom AMI list
    (MOTO_AMIS_PATH) so the name-pattern lookups in the corpus resolve;
  * the real provider binaries (aws, archive, local, null, tls, ...) are downloaded by
    `terraform init`; only `plan` is run, never `apply`, so no provisioner or local-exec executes;
  * files the corpus reads at plan time but that are not vendored (assets, key files, lambda
    payloads) are created as empty stub files inside the temp directory.

Terraform itself is installed into the work dir from releases.hashicorp.com and the zip is
verified against the published SHA256SUMS before use.

Requirements: python3 with the backend deps, `moto[server]` (for `moto_server`), optionally
`checkov` (when found on PATH or via --checkov-bin the scanners run inside combined_verdict).
"""
from __future__ import annotations

import argparse
import hashlib
import io
import json
import os
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import urllib.request
import zipfile
from collections import Counter
from pathlib import Path
from typing import Any

BACKEND = Path(__file__).resolve().parents[1]
CORPUS = BACKEND / "tests" / "data" / "realworld"
sys.path.insert(0, str(BACKEND))

TERRAFORM_VERSION = "1.15.9"
AWS_PROVIDER_PIN = "5.100.0"  # CloudGoat targets the 5.x provider
TERRAGOAT_AWS_PIN = "4.67.0"  # TerraGoat uses aws_db_instance.name (removed in 5.0) and inline s3 acl/versioning blocks
WHITELIST = "203.0.113.10/32"  # RFC 5737 documentation address standing in for "the player's IP"
CGID = "cgidmock0001"

MOCK_AMIS = [
    ("ami-0a1b2c3d4e5f60001", "099720109477", "/dev/sda1", "ubuntu/images/hvm-ssd/ubuntu-jammy-22.04-amd64-server-20240101"),
    ("ami-0a1b2c3d4e5f60002", "099720109477", "/dev/sda1", "ubuntu/images/hvm-ssd-gp3/ubuntu-noble-24.04-amd64-server-20240101"),
    ("ami-0a1b2c3d4e5f60003", "137112412989", "/dev/xvda", "amzn2-ami-hvm-2.0.20240101.0-x86_64-gp2"),
    ("ami-0a1b2c3d4e5f60004", "137112412989", "/dev/xvda", "amzn2-ami-hvm-2.0.20240101.0-x86_64-ebs"),
    ("ami-0a1b2c3d4e5f60005", "137112412989", "/dev/xvda", "al2023-ami-2023.5.20240101.0-kernel-6.1-x86_64"),
]

ENDPOINT_SERVICES = ["ec2", "sts", "iam", "s3", "kms", "rds", "lambda", "secretsmanager", "ssm", "cloudtrail", "cloudwatch",
                     "cloudwatchlogs", "elbv2", "elb", "autoscaling", "sns", "sqs", "dynamodb", "eks", "ecr", "ecs", "route53",
                     "es", "elasticsearch", "neptune", "organizations", "apigateway", "cloudfront", "acm", "wafv2", "efs"]


def endpoints_block(url: str) -> str:
    """Explicit per-service endpoints: provider 4.x ignores AWS_ENDPOINT_URL, so never rely on the env var alone."""
    return "  endpoints {\n" + "".join(f'    {s} = "{url}"\n' for s in ENDPOINT_SERVICES) + "  }\n"


PROVIDER_OVERRIDE = '''provider "aws" {
  profile                     = null
  access_key                  = "AKIAFAKEFAKEFAKEFAKE"
  secret_key                  = "fakefakefakefakefakefakefakefakefakefake"
  skip_credentials_validation = true
  skip_requesting_account_id  = true
  skip_metadata_api_check     = true
  skip_region_validation      = true
  s3_use_path_style           = true
%s}
'''
PROVIDER_FRESH = '''provider "aws" {
  region                      = var.region
  access_key                  = "AKIAFAKEFAKEFAKEFAKE"
  secret_key                  = "fakefakefakefakefakefakefakefakefakefake"
  skip_credentials_validation = true
  skip_requesting_account_id  = true
  skip_metadata_api_check     = true
  skip_region_validation      = true
  s3_use_path_style           = true
%s}
'''
PIN_TEMPLATE = '''terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "%s"
    }
  }
}
'''

CLOUDGOAT = [
    # name, stub files relative to the scenario root (the dir holding terraform/), stubs inside terraform/
    ("cloud_breach_s3", ["cloudgoat.pub", "assets/cardholder_data_primary.csv", "assets/cardholder_data_secondary.csv",
                         "assets/cardholders_corporate.csv", "assets/goat.png", "assets/proxy.com"], []),
    ("ec2_ssrf", ["cloudgoat.pub", "assets/lambda.py", "assets/ssrf_app/app.js"], []),
    ("iam_privesc_by_attachment", [], []),
    ("iam_privesc_by_ec2", [], []),
    ("iam_privesc_by_key_rotation", [], []),
    ("lambda_privesc", [], []),
    ("rds_snapshot", ["cloudgoat.pub", "assets/insert_data.sql"], []),
    ("vulnerable_lambda", [], ["lambda_source_code/policy_applier_lambda1_src/main.py", "lambda_source_code/archives/.keep"]),
    ("vpc_peering_overexposed", [], []),
    ("data_secrets", [], []),
    ("rce_web_app", ["cloudgoat.pub", "cloudgoat", "assets/db.txt", "assets/elasticloadbalancing.log", "assets/rce_app/index.js"], []),
]
CLEAN = [
    ("terraform-aws-vpc", "examples/complete"),
    ("terraform-aws-s3-bucket", "examples/complete"),
    ("terraform-aws-rds", "examples/complete-postgres"),
    ("terraform-aws-ec2-instance", "examples/complete"),
]
# Compatibility patches applied to the temp copy only (recorded in the results).
TERRAGOAT_PATCHES = [("terraform/aws/consts.tf", r'type(\s*)=(\s*)"(string)"', r"type\1=\2\3",
                      "legacy quoted type constraints (Terraform 0.12 era) are rejected by Terraform >= 1.0")]


def log(msg: str) -> None:
    print(msg, file=sys.stderr, flush=True)


# --------------------------------------------------------------------------- tooling
def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def install_terraform(work: Path, version: str) -> Path:
    """Download terraform and verify the zip against the published SHA256SUMS."""
    dest = work / "tfbin" / version
    binary = dest / "terraform"
    if binary.exists():
        return binary
    dest.mkdir(parents=True, exist_ok=True)
    base = f"https://releases.hashicorp.com/terraform/{version}"
    zip_name = f"terraform_{version}_linux_amd64.zip"
    with urllib.request.urlopen(f"{base}/terraform_{version}_SHA256SUMS", timeout=60) as r:
        sums = r.read().decode()
    with urllib.request.urlopen(f"{base}/{zip_name}", timeout=300) as r:
        blob = r.read()
    expected = next(line.split()[0] for line in sums.splitlines() if line.endswith(zip_name))
    actual = hashlib.sha256(blob).hexdigest()
    if actual != expected:
        raise RuntimeError(f"terraform zip sha256 mismatch: {actual} != {expected}")
    with zipfile.ZipFile(io.BytesIO(blob)) as z:
        z.extract("terraform", dest)
    binary.chmod(0o755)
    (dest / "SHA256SUMS.verified").write_text(f"{expected}  {zip_name}\n")
    return binary


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def start_moto(work: Path, moto_bin: str) -> tuple[subprocess.Popen, str]:
    amis = [{
        "ami_id": ami_id, "state": "available", "public": True, "owner_id": owner, "image_location": f"{owner}/{name}",
        "sriov": "simple", "root_device_type": "ebs", "root_device_name": root, "description": "mock image",
        "image_type": "machine", "architecture": "x86_64", "name": name, "virtualization_type": "hvm",
        "hypervisor": "xen", "creation_date": "2024-01-01T00:00:00.000Z",
    } for ami_id, owner, root, name in MOCK_AMIS]
    ami_file = work / "moto_amis.json"
    ami_file.write_text(json.dumps(amis, indent=1))
    port = free_port()
    env = {**os.environ, "MOTO_AMIS_PATH": str(ami_file)}
    proc = subprocess.Popen([moto_bin, "-H", "127.0.0.1", "-p", str(port)], env=env,
                            stdout=open(work / "moto.log", "w"), stderr=subprocess.STDOUT)
    url = f"http://127.0.0.1:{port}"
    for _ in range(60):
        try:
            urllib.request.urlopen(url + "/moto-api/", timeout=1).read()
            return proc, url
        except Exception:  # noqa: BLE001
            time.sleep(0.5)
    proc.terminate()
    raise RuntimeError("moto_server did not start; see " + str(work / "moto.log"))


# --------------------------------------------------------------------------- target preparation
class Target:
    def __init__(self, name: str, project: str, kind: str, cwd_rel: str, copy_from: Path, copy_to_rel: str,
                 stubs: list[str], aws_version: str | None, var_style: str, patches: list | None = None):
        self.name, self.project, self.kind = name, project, kind
        self.cwd_rel = cwd_rel            # terraform working dir, relative to the temp root
        self.copy_from = copy_from        # vendored dir to copy
        self.copy_to_rel = copy_to_rel    # where the copy lands under the temp root
        self.stubs = stubs                # empty files created relative to the temp root
        self.aws_version = aws_version
        self.var_style = var_style        # "cloudgoat" | "terragoat" | "none"
        self.patches = patches or []


def targets() -> list[Target]:
    out = [Target("terragoat", "terragoat", "terragoat", "terraform/aws", CORPUS / "terragoat" / "terraform" / "aws",
                  "terraform/aws", ["terraform/aws/resources/customer-master.xlsx", "terraform/aws/resources/lambda_function_payload.zip"],
                  TERRAGOAT_AWS_PIN, "terragoat", TERRAGOAT_PATCHES)]
    for name, root_stubs, tf_stubs in CLOUDGOAT:
        out.append(Target(f"cloudgoat/{name}", "cloudgoat", "cloudgoat", f"{name}/terraform",
                          CORPUS / "cloudgoat" / name / "terraform", f"{name}/terraform",
                          [f"{name}/{s}" for s in root_stubs] + [f"{name}/terraform/{s}" for s in tf_stubs],
                          AWS_PROVIDER_PIN, "cloudgoat"))
    for name, entry in CLEAN:
        out.append(Target(f"clean/{name}", "clean", "clean", entry, CORPUS / "clean" / name, ".", [], None, "none"))
    return out


def declared_variables(tf_dir: Path) -> dict[str, bool]:
    """name -> has_default, for top-level variable blocks of the working dir."""
    found: dict[str, bool] = {}
    for f in sorted(tf_dir.glob("*.tf")):
        text = f.read_text()
        for m in re.finditer(r'^variable\s+"([^"]+)"\s*\{', text, re.M):
            body = text[m.end(): m.end() + 1500]
            depth, end = 1, 0
            for i, ch in enumerate(body):
                depth += (ch == "{") - (ch == "}")
                if depth == 0:
                    end = i
                    break
            found[m.group(1)] = bool(re.search(r"^\s*default\s*=", body[:end], re.M))
    return found


def has_aws_provider_block(tf_dir: Path) -> bool:
    return any(re.search(r'^\s*provider\s+"aws"\s*\{', f.read_text(), re.M) for f in tf_dir.glob("*.tf"))


def refuse_if_unsafe(root: Path) -> None:
    for f in root.rglob("*.tf"):
        if re.search(r'^\s*data\s+"external"', f.read_text(), re.M):
            raise RuntimeError(f"{f}: data \"external\" would execute a program at plan time; refusing")


def prepare(t: Target, tmp: Path, endpoint: str) -> tuple[Path, list[str], list[dict]]:
    root = tmp / re.sub(r"[^A-Za-z0-9_.-]", "_", t.name)
    root.mkdir(parents=True)
    dst = root / t.copy_to_rel if t.copy_to_rel != "." else root
    shutil.copytree(t.copy_from, dst, dirs_exist_ok=True)
    patches = []
    for rel, pattern, repl, why in t.patches:
        p = root / rel
        new, n = re.subn(pattern, repl, p.read_text())
        if n:
            p.write_text(new)
            patches.append({"file": rel, "pattern": pattern, "replacement": repl, "count": n, "reason": why})
    for stub in t.stubs:
        s = root / stub
        s.parent.mkdir(parents=True, exist_ok=True)
        s.write_text("ssh-rsa AAAAB3NzaC1yc2EAAAAmock mock@example\n" if stub.endswith(".pub") else "")
    refuse_if_unsafe(root)
    cwd = root / t.cwd_rel
    if has_aws_provider_block(cwd):
        (cwd / "zz_override.tf").write_text(PROVIDER_OVERRIDE % endpoints_block(endpoint))
    else:
        (cwd / "zz_provider.tf").write_text(PROVIDER_FRESH % endpoints_block(endpoint))
    if t.aws_version:
        declares_aws = any(re.search(r'required_providers\s*\{[^}]*aws\s*=', f.read_text(), re.S) for f in cwd.glob("*.tf"))
        # an override file replaces the version constraint the scenario declares; with nothing to
        # override, declare the pin in an ordinary file instead
        (cwd / ("zz_pin_override.tf" if declares_aws else "zz_pin.tf")).write_text(PIN_TEMPLATE % t.aws_version)
    return cwd, [str(p.relative_to(root)) for p in cwd.glob("*.tf")], patches


def tf_vars(t: Target, cwd: Path) -> list[str]:
    decl = declared_variables(cwd)
    args: list[str] = []
    if t.var_style == "cloudgoat":
        if "profile" in decl:
            args += ["-var", "profile=mock"]
        if "cgid" in decl:
            args += ["-var", f"cgid={CGID}"]
        if "cg_whitelist" in decl and not decl["cg_whitelist"]:
            args += ["-var", f'cg_whitelist=["{WHITELIST}"]']
    elif t.var_style == "terragoat":
        if "profile" in decl:
            args += ["-var", "profile=mock"]
    return args


def run(cmd: list[str], cwd: Path, env: dict, timeout: int) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, cwd=cwd, env=env, capture_output=True, text=True, timeout=timeout)


def make_plan(t: Target, tmp: Path, tf: Path, env: dict, endpoint: str) -> dict[str, Any]:
    result: dict[str, Any] = {}
    try:
        cwd, files, patches = prepare(t, tmp, endpoint)
    except Exception as exc:  # noqa: BLE001
        return {"status": "prepare_failed", "error": str(exc)[:2000]}
    result["patches_applied"] = patches
    started = time.time()
    for _attempt in range(3):  # provider downloads occasionally drop the connection
        init = run([str(tf), "init", "-input=false", "-no-color"], cwd, env, 900)
        if init.returncode == 0:
            break
        time.sleep(5)
    if init.returncode != 0:
        return {**result, "status": "init_failed", "error": (init.stderr or init.stdout)[-3000:]}
    # plan/show run without any proxy variables, so a call that is not answered by moto cannot leave the machine
    offline = {k: v for k, v in env.items() if k.lower() not in {"https_proxy", "http_proxy", "all_proxy"}}
    plan = run([str(tf), "plan", "-input=false", "-no-color", "-out=tfplan", *tf_vars(t, cwd)], cwd, offline, 1200)
    if plan.returncode != 0:
        return {**result, "status": "plan_failed", "error": (plan.stderr or plan.stdout)[-4000:]}
    show = run([str(tf), "show", "-json", "tfplan"], cwd, offline, 300)
    if show.returncode != 0:
        return {**result, "status": "show_failed", "error": show.stderr[-2000:]}
    plan_json = json.loads(show.stdout)
    lock = cwd / ".terraform.lock.hcl"
    providers = re.findall(r'provider "registry.terraform.io/([^"]+)" \{\s*version\s*=\s*"([^"]+)"', lock.read_text()) if lock.exists() else []
    result.update({"status": "planned", "plan_seconds": round(time.time() - started, 1), "plan_json": plan_json,
                   "terraform_variables": [a for a in tf_vars(t, cwd) if a != "-var"],
                   "providers_resolved": {n: v for n, v in providers}})
    return result


# --------------------------------------------------------------------------- plan statistics
def plan_stats(plan: dict) -> dict[str, Any]:
    managed = [r for r in plan.get("resource_changes", []) if r.get("mode") == "managed" and r["change"]["actions"] != ["no-op"]]
    return {
        "managed_resources": len(managed),
        "by_action": dict(Counter("+".join(r["change"]["actions"]) for r in managed)),
        "by_type": dict(sorted(Counter(r["type"] for r in managed).items())),
        "by_provider": dict(Counter(r.get("provider_name", "?").rsplit("/", 1)[-1] for r in managed)),
        "addresses": sorted({r["address"] for r in managed}),
    }


def dump(obj: Any) -> Any:
    if hasattr(obj, "model_dump"):
        return obj.model_dump()
    if isinstance(obj, dict):
        return {str(k): dump(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple, set)):
        return [dump(v) for v in obj]
    return obj


def infra_counts(infra: Any) -> dict[str, int]:
    counts: dict[str, int] = {}

    def walk(prefix: str, value: Any) -> None:
        if isinstance(value, dict):
            for k, v in value.items():
                if not str(k).startswith("_"):
                    walk(f"{prefix}.{k}" if prefix else str(k), v)
        elif isinstance(value, list) and value:
            counts[prefix] = len(value)

    walk("", infra.model_dump())
    return dict(sorted(counts.items()))


def emfirge_run(plan: dict, run_scanners: bool) -> dict[str, Any]:
    from app.egraph import build_graph, get_internet_reachable_set
    from app.exposure import compute_exposures
    from app.models import AWSInfrastructure
    from app.mutations import _collection, _identity, apply_change
    from app.plan_ingest import translate_plan
    from app.rules import run_all_checks
    from app.verdict import _role_ids_with_privilege_escalation, combined_verdict

    out: dict[str, Any] = {}
    stats = plan_stats(plan)
    t0 = time.time()
    translated = translate_plan(plan)
    out["translate_seconds"] = round(time.time() - t0, 2)
    base = AWSInfrastructure()
    branch = base
    applied: list[str] = []
    rejected: list[dict] = []
    address_to_ids: dict[str, list[str]] = {}
    for change, address in zip(translated["changes"], translated["addresses"]):
        try:
            before_ids = {_identity(change.resource_type, i) for i in _collection(branch, change.resource_type)}
            branch = apply_change(branch, change)
            after_ids = {_identity(change.resource_type, i) for i in _collection(branch, change.resource_type)}
            new_ids = sorted(after_ids - before_ids) or ([change.resource_id] if change.resource_id else [])
            address_to_ids.setdefault(address, []).extend(f"{change.resource_type}:{i}" for i in new_ids)
            applied.append(address)
        except Exception as exc:  # noqa: BLE001 - recorded, same as the route's per-change handling
            rejected.append({"address": address, "op": change.op, "resource_type": change.resource_type,
                             "error": f"{type(exc).__name__}: {str(exc)[:300]}"})
    addr_type = {r["address"]: r["type"] for r in plan.get("resource_changes", [])}
    mapped = sorted(set(applied))
    rejected_addr = sorted({r["address"] for r in rejected} - set(mapped))
    unmodeled = translated["unmodeled"]
    unmodeled_addr = sorted({u["address"] for u in unmodeled})
    accounted = set(mapped) | set(rejected_addr) | set(unmodeled_addr)
    silent = [a for a in stats["addresses"] if a not in accounted]
    by_type_mapped = Counter(addr_type.get(a, "?").split("[")[0] for a in mapped)
    plan_by_type = stats["by_type"]
    out["ingest"] = {
        "plan_managed_resources": stats["managed_resources"],
        "mapped": len(mapped),
        "rejected_by_apply": len(rejected_addr),
        "unmodeled_reported": len(unmodeled_addr),
        "no_change_emitted_not_reported": len(silent),
        "changes_emitted": len(translated["changes"]),
        "mapped_by_type": dict(sorted(by_type_mapped.items())),
        "address_to_emfirge_ids": dict(sorted(address_to_ids.items())),
        "plan_by_type": plan_by_type,
        "unmodeled_types": dict(sorted(Counter(u["type"] for u in unmodeled).items())),
        "rejected": rejected,
        "no_change_emitted_addresses": silent,
        "unmodeled": unmodeled,
        "unknown_fields": translated["unknown_fields"],
        "state_counts": infra_counts(branch),
    }
    graph = build_graph(branch)
    findings = run_all_checks(branch, graph)
    flat = []
    for category, items in findings.items():
        for f in items:
            d = dump(f)
            d["_bucket"] = category
            flat.append(d)
    out["native_findings"] = flat
    try:
        out["exposures"] = [dump(e) for e in compute_exposures(branch, graph)]
    except Exception as exc:  # noqa: BLE001
        out["exposures_error"] = f"{type(exc).__name__}: {exc}"
    try:
        out["internet_reachable"] = sorted(get_internet_reachable_set(graph))
        out["roles_with_privilege_escalation"] = sorted(_role_ids_with_privilege_escalation(graph))
    except Exception as exc:  # noqa: BLE001
        out["reachability_error"] = f"{type(exc).__name__}: {exc}"
    t1 = time.time()
    verdict = combined_verdict(base, branch, run_scanners=run_scanners)
    out["verdict_seconds"] = round(time.time() - t1, 2)
    out["verdict"] = dump(verdict)
    out["scanners_requested"] = run_scanners
    return out


# --------------------------------------------------------------------------- main
def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--work", default=str(Path(tempfile.gettempdir()) / "emfirge-realworld"), help="work dir (terraform, plugin cache, moto)")
    ap.add_argument("--out", default=None, help="results JSON (default <work>/results.json)")
    ap.add_argument("--terraform", default=None, help="terraform binary; default: install --terraform-version into the work dir")
    ap.add_argument("--terraform-version", default=TERRAFORM_VERSION)
    ap.add_argument("--moto-bin", default=shutil.which("moto_server"), help="path to moto_server")
    ap.add_argument("--checkov-bin", default=None, help="directory containing the checkov executable (added to PATH)")
    ap.add_argument("--only", default=None, help="comma list of target names (e.g. terragoat,cloudgoat/ec2_ssrf)")
    ap.add_argument("--no-emfirge", action="store_true", help="stop after producing plans")
    ap.add_argument("--save-plans", action="store_true", help="write each plan JSON next to the results")
    args = ap.parse_args()

    work = Path(args.work).resolve()
    work.mkdir(parents=True, exist_ok=True)
    out_path = Path(args.out) if args.out else work / "results.json"
    tf = Path(args.terraform) if args.terraform else install_terraform(work, args.terraform_version)
    tf_version = subprocess.run([str(tf), "version", "-json"], capture_output=True, text=True).stdout
    try:
        tf_version = json.loads(tf_version).get("terraform_version", tf_version)
    except ValueError:
        pass
    if not args.moto_bin:
        log("moto_server not found; pass --moto-bin (pip install 'moto[server]')")
        return 2
    path = os.environ.get("PATH", "")
    if args.checkov_bin:
        path = f"{args.checkov_bin}{os.pathsep}{path}"
    have_checkov = shutil.which("checkov", path=path) is not None
    os.environ["PATH"] = path  # app.scanners shells out to `checkov` from this process

    moto, endpoint = start_moto(work, args.moto_bin)
    plugin_cache = work / "plugin-cache"
    plugin_cache.mkdir(exist_ok=True)
    env = {
        "PATH": path, "HOME": os.environ.get("HOME", "/tmp"), "TF_IN_AUTOMATION": "1", "TF_INPUT": "0",
        "CHECKPOINT_DISABLE": "1", "TF_PLUGIN_CACHE_DIR": str(plugin_cache),
        "AWS_ENDPOINT_URL": endpoint, "AWS_ACCESS_KEY_ID": "AKIAFAKEFAKEFAKEFAKE",
        "AWS_SECRET_ACCESS_KEY": "fakefakefakefakefakefakefakefakefakefake", "AWS_DEFAULT_REGION": "us-east-1",
        "AWS_EC2_METADATA_DISABLED": "true", "AWS_SHARED_CREDENTIALS_FILE": os.devnull, "AWS_CONFIG_FILE": os.devnull,
    }
    for k in ("HTTPS_PROXY", "HTTP_PROXY", "NO_PROXY", "https_proxy", "http_proxy", "no_proxy", "SSL_CERT_FILE", "SSL_CERT_DIR", "CURL_CA_BUNDLE"):
        if k in os.environ:
            env[k] = os.environ[k]
    env["NO_PROXY"] = (env.get("NO_PROXY", "") + ",127.0.0.1,localhost").strip(",")

    wanted = set(args.only.split(",")) if args.only else None
    results: dict[str, Any] = {
        "terraform_version": tf_version, "terraform_sha256_verified": True, "aws_provider_pin": AWS_PROVIDER_PIN,
        "whitelist_used_where_no_default": WHITELIST, "cgid": CGID, "moto_endpoint": endpoint,
        "checkov_available": have_checkov, "scenarios": {},
    }
    try:
        with tempfile.TemporaryDirectory(prefix="emfirge-rw-", dir=work) as tmpname:
            tmp = Path(tmpname)
            for t in targets():
                if wanted and t.name not in wanted:
                    continue
                log(f"== {t.name}")
                entry: dict[str, Any] = {"project": t.project, "name": t.name}
                planned = make_plan(t, tmp, tf, env, endpoint)
                plan_json = planned.pop("plan_json", None)
                entry.update(planned)
                if plan_json is not None:
                    entry["plan"] = {k: v for k, v in plan_stats(plan_json).items() if k != "addresses"}
                    if args.save_plans:
                        (work / "plans").mkdir(exist_ok=True)
                        (work / "plans" / (re.sub(r"[^A-Za-z0-9_.-]", "_", t.name) + ".json")).write_text(json.dumps(plan_json))
                    if not args.no_emfirge:
                        try:
                            entry["emfirge"] = emfirge_run(plan_json, run_scanners=have_checkov)
                        except Exception as exc:  # noqa: BLE001
                            import traceback
                            entry["emfirge_error"] = traceback.format_exc()[-3000:]
                else:
                    log(f"   skipped: {entry.get('status')}")
                results["scenarios"][t.name] = entry
                out_path.write_text(json.dumps(results, indent=2, default=str))
    finally:
        moto.terminate()
    out_path.write_text(json.dumps(results, indent=2, default=str))

    print(f"\nterraform {tf_version}; scanners {'on' if have_checkov else 'off'}; results -> {out_path}")
    print(f"{'target':44} {'status':14} {'plan':>5} {'mapped':>6} {'rej':>4} {'unmod':>5} {'silent':>6} {'native':>6}")
    for name, e in results["scenarios"].items():
        ing = (e.get("emfirge") or {}).get("ingest") or {}
        print(f"{name:44} {e.get('status', '?'):14} {ing.get('plan_managed_resources', e.get('plan', {}).get('managed_resources', '-')):>5} "
              f"{ing.get('mapped', '-'):>6} {ing.get('rejected_by_apply', '-'):>4} {ing.get('unmodeled_reported', '-'):>5} "
              f"{ing.get('no_change_emitted_not_reported', '-'):>6} {len((e.get('emfirge') or {}).get('native_findings', [])) if e.get('emfirge') else '-':>6}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
