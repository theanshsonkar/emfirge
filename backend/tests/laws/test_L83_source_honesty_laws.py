"""L83: every hand-written cloud fact is true and sourced; where no source exists, the text says so.

L83a  outside_world is decided per ACTION: a read (Get / List / Describe) of a table service is not an outside-world fact
L83b  actions of services added to the table are classified only where AWS documents the effect; the rest stay unclassified
L83c  every service name in the table is a botocore name (or a documented alias), never an IAM prefix
L83d  source URLs: the scheduler page is managing-schedule-state; no table entry cites the dead Support page
L83e  the check no longer claims typed changes "stay inside the account"
L83f  the inventory lists the hand-written facts touched here with their source status
"""
from __future__ import annotations

import re
from pathlib import Path

import pytest

from app.aws_outside_world import OUTSIDE_WORLD_SERVICES, SCHEDULER_ENTRY, classify_action

from .test_check_facts_laws import _branch_with_calls, _check, _delete_base, _outside, _plan, _unmodeled_item
from tests.test_plan_ingest import plan_client  # noqa: F401  (fixture)

REPO = Path(__file__).resolve().parents[3]
DOC = re.compile(r"https://docs\.aws\.amazon\.com/\S+")


# ── L83a ──────────────────────────────────────────────────────────

@pytest.mark.parametrize("action", [
    "ses.GetAccount", "sesv2.ListEmailIdentities", "support.DescribeCases", "service-quotas.ListServiceQuotas",
    "servicequotas.GetServiceQuota", "savingsplans.DescribeSavingsPlans", "marketplace-catalog.ListEntities",
])
def test_L83a_a_read_of_a_table_service_is_not_an_outside_world_fact(action):
    entry = classify_action(action)
    assert entry is not None and entry.outside is False, action


@pytest.mark.parametrize("action", [
    "ses.SendEmail", "sesv2.SendEmail", "support.CreateCase", "service-quotas.RequestServiceQuotaIncrease",
    "route53domains.RegisterDomain", "savingsplans.CreateSavingsPlan",
])
def test_L83a_a_change_of_a_table_service_stays_an_outside_world_fact(action):
    entry = classify_action(action)
    assert entry is not None and entry.outside is True and DOC.fullmatch(entry.source_url), action


def test_L83a_a_read_makes_no_fact_and_no_unclassified_doubt():
    base = _delete_base()
    items = [_unmodeled_item("support.DescribeCases", "calls[0]"), _unmodeled_item("ses.GetAccount", "calls[1]"),
             _unmodeled_item("support.CreateCase", "calls[2]")]
    result = _check(base, plans=[_plan(*items)]).model_dump()
    outside = {a["damage"]: a for a in result["answers"]}["outside_world"]
    assert [f["action"] for f in outside["facts"]] == ["support.CreateCase"]
    assert not [u for u in outside["unknown"] if u["topic"] == "unclassified_action"]
    assert any(c["topic"] == "read_only_actions" for c in outside["checked"])


# ── L83b ──────────────────────────────────────────────────────────

@pytest.mark.parametrize("action,service", [
    ("sns.Publish", "sns"), ("sns.PublishBatch", "sns"),
    ("organizations.InviteAccountToOrganization", "organizations"),
    ("ram.CreateResourceShare", "ram"),
    ("meteringmarketplace.MeterUsage", "meteringmarketplace"),
])
def test_L83b_documented_actions_of_added_services_are_outside_world_facts(action, service):
    entry = classify_action(action)
    assert entry is not None and entry.outside is True and entry.service == service
    assert DOC.fullmatch(entry.source_url) and entry.reason.strip()


@pytest.mark.parametrize("action", [
    "sns.CreateTopic", "sns.SetTopicAttributes", "organizations.CreateOrganizationalUnit", "ram.DeleteResourceShare",
    "pinpoint.SendMessages", "connect.StartOutboundVoiceContact", "events.CreateApiDestination",
    "marketplace-agreement.SearchAgreements", "aws-marketplace.Subscribe",
])
def test_L83b_what_is_not_sourced_stays_unclassified(action):
    assert classify_action(action) is None, action


# ── L83c ──────────────────────────────────────────────────────────

def test_L83c_service_names_are_botocore_names_not_iam_prefixes():
    import botocore.session
    names = set(botocore.session.get_session().get_available_services())
    # "servicequotas" is the IAM / endpoint prefix; aws_api_ingest.canonical_service maps it to "service-quotas".
    aliases = {"servicequotas"}
    for entry in OUTSIDE_WORLD_SERVICES:
        for service in entry.services:
            assert service in names or service in aliases, service
    assert "aws-marketplace" not in {s for e in OUTSIDE_WORLD_SERVICES for s in e.services}


# ── L83d ──────────────────────────────────────────────────────────

def test_L83d_scheduler_entry_cites_the_live_state_page():
    assert SCHEDULER_ENTRY.source_url == "https://docs.aws.amazon.com/scheduler/latest/UserGuide/managing-schedule-state.html"


def test_L83d_no_table_entry_cites_the_dead_support_page():
    for entry in OUTSIDE_WORLD_SERVICES:
        assert "about-support" not in entry.source_url
    support = classify_action("support.CreateCase")
    assert support.source_url == "https://docs.aws.amazon.com/awssupport/latest/user/case-management.html"


def test_L83d_no_source_still_points_to_a_known_dead_page():
    dead = ("managing-schedule-enable-disable", "about-support.html")
    for path in (REPO / "backend").rglob("*.py"):
        if ".venv" in path.parts or path.name == Path(__file__).name:
            continue
        text = path.read_text(errors="ignore")
        for needle in dead:
            assert needle not in text, f"{path}: {needle}"


# ── L83e ──────────────────────────────────────────────────────────

def test_L83e_the_check_does_not_claim_typed_changes_stay_inside_the_account(plan_client):  # noqa: F811
    branch = _branch_with_calls(plan_client, [
        {"service": "s3", "operation": "DeleteBucket", "parameters": {"Bucket": "dl-data-bucket"}}])
    outside = _outside(plan_client, branch)
    text = " ".join(c["detail"] for c in outside["checked"]).lower()
    assert "stay inside" not in text and "inside the account" not in text and "do not leave" not in text
    assert any(c["topic"] == "typed_changes" for c in outside["checked"])


# ── L83f ──────────────────────────────────────────────────────────

def test_L83f_the_inventory_lists_the_touched_facts_with_a_status():
    text = (REPO / "HAND-WRITTEN-FACTS-INVENTORY.md").read_text()
    for needle in ("UpdateSchedule", "RetryPolicy", "Host", "DeleteTable", "typed_changes", "aws_outside_world",
                   "managing-schedule-state"):
        assert needle in text, needle
    assert "unsourced" in text.lower() and "about-support" not in text
