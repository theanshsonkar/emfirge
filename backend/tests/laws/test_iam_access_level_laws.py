from app import iam_classifier
from app.egraph import build_graph
from app.models import AccessStatement, AWSInfrastructure, IAMData, RolePolicy, S3Bucket, S3Data
from app.verdict import combined_verdict
from policy_sentry.querying import actions as policy_actions


def _infra(action="s3:GetObject", resource="*"):
    return AWSInfrastructure(
        region="us-east-1",
        s3=S3Data(buckets=[S3Bucket(name="synthetic-law36-bucket")]),
        iam=IAMData(role_policies=[RolePolicy(
            role_name="SyntheticLaw36Role",
            role_arn="arn:aws:iam::123456789012:role/SyntheticLaw36Role",
            access_statements=[AccessStatement(
                effect="Allow", actions=[action], resources=[resource],
            )],
        )]),
    )


def _clear_classifier_caches():
    iam_classifier._policy_sentry_service_map.cache_clear()
    iam_classifier._classify_cached.cache_clear()


def _policy_sentry_levels(service, action_names):
    levels = set()
    for qualified_name in action_names:
        action_name = qualified_name.split(":", 1)[1]
        rows = policy_actions.get_action_data(service, action_name).get(service, [])
        levels.update(row["access_level"] for row in rows if "access_level" in row)
    return levels


def _access_edge(graph):
    return next(edge for edge in graph.edges if edge.relationship.value == "can_access")


def test_L36a():
    assert iam_classifier.classify_action("s3:PutObjectAcl") == {"Permissions management"}
    assert iam_classifier.classify_action("iam:PassRole") == {"Permissions management"}
    assert iam_classifier.classify_action("s3:GetObject") == {"Read"}
    assert iam_classifier.classify_action("S3:getobject") == {"Read"}


def test_L36b():
    s3_actions = policy_actions.get_actions_for_service("s3")
    expected_s3_get = _policy_sentry_levels(
        "s3", [name for name in s3_actions if name.split(":", 1)[1].lower().startswith("get")]
    )
    ec2_actions = policy_actions.get_actions_for_service("ec2")
    expected_ec2_describe = _policy_sentry_levels(
        "ec2", [name for name in ec2_actions if name.split(":", 1)[1].lower().startswith("describe")]
    )
    assert iam_classifier.classify_action("s3:Get*") == expected_s3_get
    assert iam_classifier.classify_action("ec2:Describe*") == expected_ec2_describe

    all_s3_levels = _policy_sentry_levels("s3", s3_actions)
    assert iam_classifier.classify_action("s3:*") == all_s3_levels
    assert "Write" in iam_classifier.classify_action("s3:Put?bject")


def test_L36c():
    assert iam_classifier.classify_action("foo:bar") == {"Unknown"}
    assert iam_classifier.classify_action("s3:NoSuchAction") == {"Unknown"}
    graph = build_graph(_infra("s3:NoSuchAction"))
    assert not any(warning.get("kind") == "iam_access_levels_unavailable" for warning in graph.warnings)


def test_L36d(monkeypatch):
    original_get_action_data = policy_actions.get_action_data

    def unavailable(*_args, **_kwargs):
        raise RuntimeError("synthetic policy-sentry outage")

    monkeypatch.setattr(policy_actions, "get_action_data", unavailable)
    _clear_classifier_caches()
    try:
        assert iam_classifier.classify_action("s3:GetObject") == {"Unknown"}
        graph = build_graph(_infra("s3:GetObject"))
        assert any(warning.get("kind") == "iam_access_levels_unavailable" for warning in graph.warnings)

        result = combined_verdict(_infra("s3:GetObject"), _infra("s3:GetObject"), run_scanners=False)
        assert "graph_iam_access_levels_unavailable" in result.collection_warnings
        assert "DEGRADED" in result.summary

        monkeypatch.setattr(policy_actions, "get_action_data", original_get_action_data)
        _clear_classifier_caches()
        fresh_graph = build_graph(_infra("s3:GetObject"))
        assert not any(warning.get("kind") == "iam_access_levels_unavailable" for warning in fresh_graph.warnings)
    finally:
        monkeypatch.setattr(policy_actions, "get_action_data", original_get_action_data)
        _clear_classifier_caches()


def test_L36e():
    graph = build_graph(_infra("s3:Get*", "arn:aws:s3:::synthetic-law36-bucket/*"))
    edge = _access_edge(graph)
    assert edge.attrs["access_level"] != "Unknown"
