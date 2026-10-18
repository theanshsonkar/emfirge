import copy
import json
import random

import pytest
from hypothesis import HealthCheck, given, settings, strategies as st
from pydantic import BaseModel

from app.demo_seed import build_demo_infrastructure
from app.egraph import (
    build_graph,
    get_attack_path_to,
    get_internet_reachable_set,
)


def permuted(infra, rnd):
    """Copy an infrastructure snapshot and shuffle each model-owned list field."""
    result = copy.deepcopy(infra)
    for service in result.__class__.model_fields:
        value = getattr(result, service, None)
        if not isinstance(value, BaseModel):
            continue
        for field in value.__class__.model_fields:
            items = getattr(value, field, None)
            if isinstance(items, list):
                rnd.shuffle(items)
    return result


def canonical_graph(graph):
    return json.dumps(graph.to_dict(), sort_keys=True, separators=(",", ":"))


@pytest.mark.parametrize("snapshot", ["demo", "nightmare", "clean"])
@settings(max_examples=30, deadline=None, suppress_health_check=[HealthCheck.function_scoped_fixture])
@given(seed=st.integers())
def test_L26_graph_rebuild_is_order_independent(snapshot, seed, nightmare_infra, clean_infra):
    base = {
        "demo": build_demo_infrastructure(),
        "nightmare": nightmare_infra,
        "clean": clean_infra,
    }[snapshot]
    assert canonical_graph(build_graph(base)) == canonical_graph(
        build_graph(permuted(base, random.Random(seed)))
    )


@pytest.mark.parametrize("snapshot", ["demo", "nightmare"])
@settings(max_examples=30, deadline=None, suppress_health_check=[HealthCheck.function_scoped_fixture])
@given(seed=st.integers())
def test_L26_attack_paths_are_order_independent(snapshot, seed, nightmare_infra):
    base = build_demo_infrastructure() if snapshot == "demo" else nightmare_infra
    other = permuted(base, random.Random(seed))
    base_graph = build_graph(base)
    other_graph = build_graph(other)
    assert get_internet_reachable_set(base_graph) == get_internet_reachable_set(other_graph)
    for node_id in base_graph._node_index:
        assert get_attack_path_to(base_graph, node_id) == get_attack_path_to(other_graph, node_id)


@pytest.mark.parametrize("snapshot", ["demo", "nightmare", "clean"])
def test_L26_rebuild_twice_is_identical(snapshot, nightmare_infra, clean_infra):
    base = {
        "demo": build_demo_infrastructure(),
        "nightmare": nightmare_infra,
        "clean": clean_infra,
    }[snapshot]
    assert canonical_graph(build_graph(base)) == canonical_graph(build_graph(base))
