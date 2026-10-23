#!/usr/bin/env python3
"""Generate backend/app/data/aws_prices.json from AWS's public Price List Bulk API.

Cloud facts come from the provider's published sources, never hand-typed. This
script downloads the per-region bulk offer files (no credentials needed; the
pricing:GetProducts Query API would need them) into a temp dir OUTSIDE the repo,
streams them (the EC2 file is ~480 MB), filters to exactly what app/cost.py
prices, and writes only the small filtered JSON.

Usage (from backend/):
    python scripts/generate_prices.py [--region us-east-1 ...] [--out PATH] [--tmpdir DIR]

Sources (bulk files, per region):
    https://pricing.us-east-1.amazonaws.com/offers/v1.0/aws/index.json
    <base>/offers/v1.0/aws/AmazonEC2/current/<region>/index.json
    <base>/offers/v1.0/aws/AWSELB/current/<region>/index.json

Exact filters (product attributes of the offer files, all prices are the first
OnDemand price dimension, beginRange "0", currency USD):

  EC2 on-demand instance (AmazonEC2):
      productFamily in {"Compute Instance", "Compute Instance (bare metal)"}
      attributes: locationType == "AWS Region", regionCode == <region>,
                  operatingSystem == "Linux", tenancy == "Shared",
                  preInstalledSw == "NA", capacitystatus == "Used",
                  operation == "RunInstances"      (plain Linux, no licence/SQL/etc.)
      key: attributes.instanceType
  NAT gateway hourly (AmazonEC2):
      productFamily == "NAT Gateway", attributes.usagetype == "NatGateway-Hours"
      (the zonal NAT gateway; "Regional NAT Gateway" SKUs are different usagetypes)
  EBS storage GB-month (AmazonEC2):
      productFamily == "Storage", attributes.volumeApiName in
      {gp2, gp3, io1, io2, st1, sc1, standard}, usagetype startswith "EBS:VolumeUsage"
      (the volume-GB-month SKU; IOPS/throughput add-ons have other usagetypes/families)
  Application Load Balancer hourly (AWSELB):
      productFamily == "Load Balancer-Application",
      attributes: locationType == "AWS Region", usagetype == "LoadBalancerUsage",
                  operation == "LoadBalancing:Application"
      (the fixed hourly portion; excludes LCU, Outposts and TS usage types)
"""

import argparse
import datetime
import json
import shutil
import sys
import tempfile
import time
import urllib.request
from pathlib import Path

BASE = "https://pricing.us-east-1.amazonaws.com"
EC2_URL = BASE + "/offers/v1.0/aws/AmazonEC2/current/{region}/index.json"
ELB_URL = BASE + "/offers/v1.0/aws/AWSELB/current/{region}/index.json"
EBS_TYPES = ("gp2", "gp3", "io1", "io2", "st1", "sc1", "standard")
DEFAULT_OUT = Path(__file__).resolve().parent.parent / "app" / "data" / "aws_prices.json"


def download(url: str, dest: Path, attempts: int = 4) -> None:
    for attempt in range(1, attempts + 1):
        try:
            with urllib.request.urlopen(url, timeout=120) as resp, open(dest, "wb") as out:
                shutil.copyfileobj(resp, out, 1 << 20)
            return
        except Exception as exc:  # network flake: retry with backoff
            print(f"download failed ({exc}); attempt {attempt}/{attempts}", file=sys.stderr)
            if attempt == attempts:
                raise
            time.sleep(2 * attempt)


def _stream_entries(path: Path, section: tuple, entry_indent: int):
    """Yield (key, parsed_object) for each entry of a pretty-printed offer-file section.

    Offer files are pretty-printed with 2-space indentation, so each entry opens
    on a line `<indent>"KEY" : {` and closes on `<indent>}` or `<indent>},`.
    Only one entry is held in memory at a time. ``section`` is the key path to
    the object whose children are yielded, e.g. ("products",) or ("terms", "OnDemand").
    """
    stack = []  # (indent, key) of currently open objects shallower than entry_indent
    buf = None
    key = None
    close = " " * entry_indent
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            if buf is not None:
                buf.append(line)
                if line.startswith(close) and line[entry_indent:].rstrip("\n") in ("}", "},"):
                    text = "".join(buf).rstrip().rstrip(",")
                    yield key, json.loads(text)
                    buf = None
                continue
            stripped = line.lstrip(" ")
            indent = len(line) - len(stripped)
            if indent > entry_indent:
                continue
            if stripped.rstrip("\n") in ("}", "},"):
                while stack and stack[-1][0] >= indent:
                    stack.pop()
                continue
            if not stripped.endswith(" : {\n"):
                continue
            name = json.loads(stripped[: stripped.index(" : {")])
            while stack and stack[-1][0] >= indent:
                stack.pop()
            if indent == entry_indent and tuple(k for _, k in stack) == section:
                key = name
                buf = ["{\n"]
            else:
                stack.append((indent, name))


def _header(path: Path) -> dict:
    """Read the offer file header (everything before "products"), cheaply."""
    head = {}
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            if line.lstrip().startswith('"products"'):
                break
            s = line.strip().rstrip(",")
            if s.startswith('"') and " : " in s and not s.endswith("{"):
                k, v = s.split(" : ", 1)
                head[json.loads(k)] = json.loads(v)
    return head


def _first_usd(term_group: dict) -> float:
    for term in term_group.values():
        for dim in term["priceDimensions"].values():
            if dim.get("beginRange", "0") == "0":
                return float(dim["pricePerUnit"]["USD"])
    raise ValueError("no priced dimension")


def _match(prod: dict, region: str):
    """Classify a product against the filters; return (kind, key) or None."""
    fam = prod.get("productFamily")
    a = prod.get("attributes", {})
    if a.get("regionCode", region) != region and "regionCode" in a:
        return None
    if a.get("locationType") != "AWS Region":
        return None
    if fam in ("Compute Instance", "Compute Instance (bare metal)"):
        if (a.get("operatingSystem") == "Linux" and a.get("tenancy") == "Shared"
                and a.get("preInstalledSw") == "NA" and a.get("capacitystatus") == "Used"
                and a.get("operation") == "RunInstances" and a.get("instanceType")):
            return "ec2", a["instanceType"]
    elif fam == "NAT Gateway":
        if a.get("usagetype") == "NatGateway-Hours":
            return "nat", "nat_gateway_hourly_usd"
    elif fam == "Storage":
        if a.get("volumeApiName") in EBS_TYPES and str(a.get("usagetype", "")).startswith("EBS:VolumeUsage"):
            return "ebs", a["volumeApiName"]
    elif fam == "Load Balancer-Application":
        if a.get("usagetype") == "LoadBalancerUsage" and a.get("operation") == "LoadBalancing:Application":
            return "alb", "alb_hourly_usd"
    return None


def extract(path: Path, region: str) -> dict:
    """Filter one downloaded offer file into {kind: {key: usd}}."""
    wanted = {}  # sku -> (kind, key)
    for sku, prod in _stream_entries(path, ("products",), 4):
        hit = _match(prod, region)
        if hit:
            wanted[sku] = hit
    found = {"ec2": {}, "nat": {}, "ebs": {}, "alb": {}}
    for sku, terms in _stream_entries(path, ("terms", "OnDemand"), 6):
        hit = wanted.get(sku)
        if not hit:
            continue
        kind, key = hit
        price = _first_usd(terms)
        if key in found[kind] and found[kind][key] != price:
            raise ValueError(f"ambiguous price for {kind}/{key}: {found[kind][key]} vs {price}")
        found[kind][key] = price
    return found


def build_region(region: str, tmp: Path) -> dict:
    sources = {}
    merged = {"ec2": {}, "nat": {}, "ebs": {}, "alb": {}}
    for name, template in (("AmazonEC2", EC2_URL), ("AWSELB", ELB_URL)):
        url = template.format(region=region)
        dest = tmp / f"{name}-{region}.json"
        t0 = time.time()
        download(url, dest)
        size = dest.stat().st_size
        head = _header(dest)
        print(f"{name} {region}: {size/1e6:.1f} MB in {time.time()-t0:.0f}s", file=sys.stderr)
        sources[name] = {
            "url": url,
            "version": head.get("version"),
            "publication_date": head.get("publicationDate"),
        }
        found = extract(dest, region)
        for kind, values in found.items():
            merged[kind].update(values)
        dest.unlink()
    missing = [k for k in ("nat", "alb") if not merged[k]]
    if missing or not merged["ec2"] or not merged["ebs"]:
        raise SystemExit(f"{region}: filters matched nothing for {missing or 'ec2/ebs'}")
    return {
        "sources": sources,
        "ec2_hourly_usd": dict(sorted(merged["ec2"].items())),
        "nat_gateway_hourly_usd": merged["nat"]["nat_gateway_hourly_usd"],
        "alb_hourly_usd": merged["alb"]["alb_hourly_usd"],
        "ebs_gb_month_usd": dict(sorted(merged["ebs"].items())),
    }


def render(doc: dict) -> str:
    """Sorted keys; one line per price so diffs stay readable."""
    out = json.dumps(doc, indent=1, sort_keys=True)
    return out + "\n"


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--region", action="append", help="repeatable; default us-east-1")
    ap.add_argument("--out", type=Path, default=DEFAULT_OUT)
    ap.add_argument("--tmpdir", type=Path, default=None, help="download dir (must be outside the repo)")
    args = ap.parse_args(argv)
    regions = args.region or ["us-east-1"]
    tmp = Path(tempfile.mkdtemp(prefix="aws-prices-", dir=args.tmpdir))
    try:
        doc = {
            "generated_at": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d"),
            "generator": "backend/scripts/generate_prices.py",
            "price_list_index": BASE + "/offers/v1.0/aws/index.json",
            "regions": {r: build_region(r, tmp) for r in regions},
        }
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(render(doc), encoding="utf-8")
    print(f"wrote {args.out} ({args.out.stat().st_size} bytes)", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
