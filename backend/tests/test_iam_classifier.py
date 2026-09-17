from app import iam_classifier
from app.egraph import build_graph
from app.models import AWSInfrastructure, IAMData, RolePolicy, S3Data, S3Bucket, AccessStatement


def _infra(action):
    actions = action if isinstance(action, list) else [action]
    return AWSInfrastructure(
        region="us-east-1",
        s3=S3Data(buckets=[S3Bucket(name="bucket-x")]),
        iam=IAMData(role_policies=[RolePolicy(
            role_name="Role", role_arn="arn:aws:iam::123:role/Role",
            access_statements=[AccessStatement(
                effect="allow", actions=actions, resources=["*"]
            )],
        )]),
    )


def _edge(graph):
    return next(edge for edge in graph.edges if edge.relationship.value == "can_access")


def test_offline_access_levels_and_escalation():
    assert iam_classifier.classify_action("s3:GetObject") == {"Read"}
    assert iam_classifier.classify_action("s3:PutObject") == {"Write"}
    assert iam_classifier.classify_action("*") == {
        "Permissions management", "Write", "Tagging", "List", "Read"
    }
    assert iam_classifier.is_privilege_escalation("iam:PassRole") is True


def test_graph_access_annotations_and_role_flag():
    read = _edge(build_graph(_infra("s3:GetObject")))
    assert read.attrs["access_level"] == "Read"
    assert read.attrs["privilege_escalation"] is False

    write = _edge(build_graph(_infra("s3:PutObject")))
    assert write.attrs["access_level"] == "Write"

    escalation_graph = build_graph(_infra(["s3:GetObject", "iam:PassRole"]))
    escalation = _edge(escalation_graph)
    assert escalation.attrs["privilege_escalation"] is True
    assert escalation_graph.get_node("iam-role-Role").base["has_privilege_escalation"] is True

    wildcard = _edge(build_graph(_infra("*")))
    assert wildcard.attrs["access_level"] == "Permissions management"
    assert wildcard.attrs["privilege_escalation"] is True




def test_policy_sentry_api_failure_returns_unknown_and_keeps_edge(monkeypatch):
    from policy_sentry.querying import actions as policy_actions

    def unavailable(*_args, **_kwargs):
        raise RuntimeError("policy-sentry API unavailable")

    monkeypatch.setattr(policy_actions, "get_action_data", unavailable)
    iam_classifier._classify_cached.cache_clear()

    assert iam_classifier.classify_action("s3:GetObject") == {"Unknown"}
    graph = build_graph(_infra("s3:GetObject"))
    access_edges = [
        edge for edge in graph.edges if edge.relationship.value == "can_access"
    ]
    assert len(access_edges) == 1
    assert access_edges[0].attrs["access_level"] == "Unknown"
def test_classifier_failure_keeps_edge_and_unknown(monkeypatch):
    def unavailable(_action):
        raise RuntimeError("classifier unavailable")

    monkeypatch.setattr(iam_classifier, "classify_action", unavailable)
    graph = build_graph(_infra("s3:GetObject"))
    edge = _edge(graph)
    assert edge.attrs["access_level"] == "Unknown"
    assert edge.attrs["privilege_escalation"] is False
    assert graph.get_node("iam-role-Role").base["has_privilege_escalation"] is False


def test_graph_annotations_are_deterministic():
    infra = _infra("s3:PutObject")
    first = [(e.src, e.dst, e.attrs) for e in build_graph(infra).edges]
    second = [(e.src, e.dst, e.attrs) for e in build_graph(infra).edges]
    assert first == second
