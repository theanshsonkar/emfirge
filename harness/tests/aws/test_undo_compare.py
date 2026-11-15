"""The comparison after an undo (aws/undo/compare.py): every field counts, noise and clocks are told from the
answers themselves. Pure."""
from datetime import datetime, timezone

import pytest

from emfirge.aws.undo.compare import Window, compare, time_of
from emfirge.branch.baseline import Answer

T0 = 1_900_000_000.0
WINDOW = Window(T0 + 100, T0 + 110)


def ok(body):
    return Answer(200, body)


def run(e0, e1, now, noise=frozenset(), set_names=frozenset()):
    return compare('Get', ok(e0), ok(e1), ok(now), lambda b: b, noise, set_names, WINDOW)


@pytest.mark.parametrize('value,expected', [
    ('2030-03-17T17:46:40.000+0000', 1900000000.0), ('2030-03-17T17:46:40Z', 1900000000.0),
    (1900000000, 1900000000.0), ('1900000000', 1900000000.0), (1900000000123, 1900000000.123),
    (datetime(2030, 3, 17, 17, 46, 40, tzinfo=timezone.utc), 1900000000.0),
    ('Sun, 17 Mar 2030 17:46:40 GMT', 1900000000.0),
    (42, None), ('abc', None), (True, None), ('2', None),
])
def test_time_of(value, expected):
    assert time_of(value) == (pytest.approx(expected) if expected else None)


def test_ids_versions_and_lists_all_count():
    out = run({'Id': 'a', 'Version': 1, 'Items': [1, 2]}, {}, {'Id': 'b', 'Version': 3, 'Items': [2, 1]})
    assert {d.path for d in out.differences} == {'Id', 'Version', 'Items'}


def test_noise_is_left_out():
    out = run({'RequestId': 'a', 'X': 1}, {}, {'RequestId': 'b', 'X': 1}, noise=frozenset({'RequestId'}))
    assert not out.differences


@pytest.mark.parametrize('during', [T0 + 50, T0])     # a one-second clock may not have moved yet in the session
def test_a_clock_that_moves_to_the_moment_of_the_undo_is_set_aside(during):
    out = run({'LastModified': T0}, {'LastModified': during}, {'LastModified': T0 + 105})
    assert not out.differences and [c.path for c in out.clocks] == ['LastModified']


@pytest.mark.parametrize('e1,now,set_names', [
    ({'LastModified': T0 - 5}, {'LastModified': T0 + 105}, frozenset()),          # went backwards in the session
    ({}, {'LastModified': T0 + 105}, frozenset()),                                 # not a time at the end of the session
    ({'LastModified': T0 + 50}, {'LastModified': T0 + 50}, frozenset()),          # equal: no difference at all
    ({'LastModified': T0 + 50}, {'LastModified': T0 + 500}, frozenset()),         # not the moment of the undo
    ({'LastModified': T0 + 50}, {'LastModified': T0 + 105}, frozenset({'LastModified'})),  # the agent set it
])
def test_anything_else_about_a_time_is_a_difference(e1, now, set_names):
    out = run({'LastModified': T0}, e1, now, set_names=set_names)
    assert not out.clocks
    assert bool(out.differences) is (now != {'LastModified': T0})


def test_status_counts_and_two_errors_alike_are_equal():
    assert compare('Get', Answer(404, {}), None, Answer(200, {}), lambda b: b, frozenset(), frozenset(),
                   WINDOW).differences[0].path == '(status)'
    assert not compare('Get', Answer(404, {'m': 1}), None, Answer(404, {'m': 2}), lambda b: b, frozenset(),
                       frozenset(), WINDOW).differences
