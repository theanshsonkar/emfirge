"""L91: context answers say only what is true about where things live, when they were used and what they cost.

Found on a real account (2026-11-08, AGENT-TESTS.md bugs 4-9):
L91a  The streaming scan (what `emfirge context --refresh` calls) runs the one shared collector, so it reads
      every service the shared scan reads (DynamoDB, Scheduler, CloudFront...) and records collection status
      and collected_at. It used to carry its own copy that skipped six collectors and recorded neither.
L91b  Global AWS resources (IAM, CloudFront) are in region "global", never the scan's region.
L91c  `live` counts only resources that really have a last-used, not every resource it listed.
L91d  When the price table's region is not the snapshot's region, cost says so as an unknown.
"""
import ast
import inspect

from app import main
from app.aws_context import GLOBAL_TYPES, answer_for_infra
from app.demo_seed import build_demo_infrastructure


def _ask(question, infra):
    return answer_for_infra(question, infra, analysis_id="a1")


def test_L91a_streaming_scan_uses_the_shared_collector():
    src = inspect.getsource(main.analyze_stream)
    assert "collect_infrastructure(" in src
    tree = ast.parse(src.lstrip() if not src.startswith(" ") else "if True:\n" + src)
    names = {n.id for n in ast.walk(tree) if isinstance(n, ast.Name)} | {
        a.name for n in ast.walk(tree) if isinstance(n, ast.ImportFrom) for a in n.names}
    for private_copy in ("collect_ec2", "collect_s3", "collect_iam", "collect_lambda"):
        assert private_copy not in names, f"analyze_stream calls {private_copy} itself instead of the shared scan"


def test_L91b_global_types_have_no_region():
    infra = build_demo_infrastructure()
    infra = infra.model_copy(update={"region": "ap-south-1"})
    answer = _ask("inventory", infra)
    facts = answer.facts if hasattr(answer, "facts") else answer["facts"]
    regions = {(f.resource_type if hasattr(f, "resource_type") else f["resource_type"]):
               (f.region if hasattr(f, "region") else f["region"]) for f in facts}
    assert "iam_role" in GLOBAL_TYPES and "cloudfront_distribution" in GLOBAL_TYPES
    for typ, region in regions.items():
        if typ in GLOBAL_TYPES:
            assert region == "global", typ
        else:
            assert region == "ap-south-1", typ


def _known(answer, topic):
    known = answer.known if hasattr(answer, "known") else answer["known"]
    return [k.detail if hasattr(k, "detail") else k["detail"] for k in known
            if (k.topic if hasattr(k, "topic") else k["topic"]) == topic]


def _unknown_topics(answer):
    unknown = answer.unknown if hasattr(answer, "unknown") else answer["unknown"]
    return {u.topic if hasattr(u, "topic") else u["topic"] for u in unknown}


def test_L91c_live_counts_only_recorded_last_used():
    infra = build_demo_infrastructure()
    answer = _ask("live", infra)
    facts = answer.facts if hasattr(answer, "facts") else answer["facts"]
    recorded = sum(1 for f in facts if (f.last_used_at if hasattr(f, "last_used_at") else f["last_used_at"]) is not None
                   or (f.used if hasattr(f, "used") else f["used"]) is not None)
    (line,) = _known(answer, "recent_use")
    assert line.startswith(f"{recorded} of {len(facts)} ")


def test_L91d_price_region_mismatch_is_an_unknown():
    infra = build_demo_infrastructure().model_copy(update={"region": "ap-south-1"})
    assert "price_region" in _unknown_topics(_ask("cost", infra))
    same = build_demo_infrastructure().model_copy(update={"region": "us-east-1"})
    assert "price_region" not in _unknown_topics(_ask("cost", same))


def test_L91e_a_denied_read_says_the_role_may_be_old():
    infra = build_demo_infrastructure().model_copy(update={"collection": {"scheduler": "denied"}})
    answer = _ask("inventory", infra)
    unknown = answer.unknown if hasattr(answer, "unknown") else answer["unknown"]
    texts = [(u.reason if hasattr(u, "reason") else u["reason"]) for u in unknown
             if (u.topic if hasattr(u, "topic") else u["topic"]) == "scheduler"]
    assert texts and "update the role stack" in texts[0] and "emfirge connect" in texts[0]
