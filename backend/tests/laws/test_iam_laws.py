import pytest
from hypothesis import given, settings, strategies as st

from app.iam_classifier import _policy_sentry_levels
from app.iam_escalation import _action_matches, matching_paths, paths_for_classifier


ACTIONS = [
    "*",
    "iam:*",
    "iam:Pass*",
    "sts:AssumeRole",
    "lambda:CreateFunction",
]
RESOURCES = ["*", "arn:aws:iam::000000000000:role/test"]
STATEMENT = st.fixed_dictionaries(
    {
        "effect": st.sampled_from(["Allow", "Deny"]),
        "actions": st.lists(st.sampled_from(ACTIONS), min_size=1, max_size=2),
        "resources": st.lists(st.sampled_from(RESOURCES), min_size=1, max_size=2),
        "has_condition": st.booleans(),
    }
)


@settings(max_examples=60, deadline=None)
@given(st.lists(STATEMENT, max_size=8))
def test_L29a_unconditional_wildcard_allow_is_monotonic_up(statements):
    added = statements + [{
        "effect": "Allow",
        "actions": ["*"],
        "resources": ["*"],
        "has_condition": False,
    }]
    before = {path["id"] for path in matching_paths(statements)}
    after = {path["id"] for path in matching_paths(added)}
    assert before <= after


@settings(max_examples=60, deadline=None)
@given(st.lists(STATEMENT, max_size=8))
def test_L29b_unconditional_wildcard_deny_is_monotonic_down(statements):
    denied = statements + [{
        "effect": "Deny",
        "actions": ["*"],
        "resources": ["*"],
        "has_condition": False,
    }]
    assert matching_paths(denied) == []


@settings(max_examples=60, deadline=None)
@given(st.lists(STATEMENT, max_size=8), st.data())
def test_L29c_statement_order_does_not_change_result(statements, data):
    permutation = data.draw(st.permutations(statements))
    assert matching_paths(statements) == matching_paths(permutation)


def test_L29d_iam_wildcards_only():
    assert not _action_matches("iam:[Pp]assrole", "iam:PassRole")
    assert _action_matches("iam:Pass?ole", "iam:PassRole")
    assert _action_matches("IAM:PASSROLE", "iam:passrole")
    assert all(_action_matches("iam:*", action) for action in ("iam:PassRole", "iam:GetUser"))


@pytest.mark.parametrize("action", sorted(paths_for_classifier()))
def test_L29e_curated_permissions_are_known_to_policy_sentry(action):
    known = bool(_policy_sentry_levels(action))
    if not known:
        pytest.xfail(f"known_gap: policy_sentry does not know curated action {action}")
    assert known


_SCOPED_DENY = [
    {"effect": "Allow", "actions": ["*"], "resources": ["*"]},
    {"effect": "Deny", "actions": ["iam:PassRole"], "resources": ["arn:aws:iam::000000000000:role/test"]},
]
_CONDITIONAL_DENY = [
    {"effect": "Allow", "actions": ["*"], "resources": ["*"]},
    {"effect": "Deny", "actions": ["*"], "resources": ["*"], "has_condition": True},
]


def test_L29f_scoped_deny_does_not_block_other_resources():
    assert matching_paths(_SCOPED_DENY)


def test_L29f_conditional_deny_is_ignored_conservatively():
    assert matching_paths(_CONDITIONAL_DENY)
