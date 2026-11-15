"""Strings that hide other strings: the graph must open them, and must leave hashes and keys alone."""
import json
import urllib.parse

from emfirge.graph.unpack import leaves, open_packed

from acme_cloud import b64


def _texts(state):
    return {leaf.path: leaf.text for leaf in leaves(state, lambda s: '*' in s)}


def test_json_in_a_string_is_opened():
    found = _texts({'policy': json.dumps({'on': ['urn:acme:store/a']})})
    assert found == {'policy<json>.on[0]': 'urn:acme:store/a'}


def test_url_encoded_json_is_opened():
    found = _texts({'doc': urllib.parse.quote(json.dumps({'on': 'urn:acme:store/a'}))})
    assert found == {'doc<url>.on': 'urn:acme:store/a'}


def test_base64_script_is_opened_as_text():
    found = _texts({'startup': b64('#!/bin/sh\ncopy acme://media-files/x /srv\n')})
    assert found == {'startup<base64>': '#!/bin/sh\ncopy acme://media-files/x /srv\n'}


def test_base64_json_inside_json_is_opened_all_the_way():
    inner = b64(json.dumps({'on': 'urn:acme:store/a'}))
    found = _texts({'outer': json.dumps({'packed': inner})})
    assert found == {'outer<json>.packed<base64>.on': 'urn:acme:store/a'}


def test_a_hash_is_not_opened():
    assert open_packed('1dDJ5+CyjNd+gsytgpyULAbfj5ctnuLtEhlDjrXVJUk=') is None
    assert open_packed('plainname') is None


def test_own_marks_plain_fields_only():
    marks = {leaf.path: leaf.own for leaf in leaves({'host': 'a.b.net', 'list': ['x.y.net'], 'deep': {'k': 'c.d.net'}}, lambda s: False)}
    assert marks == {'host': True, 'list[0]': False, 'deep.k': True}


def test_scope_holds_the_sibling_patterns():
    [*_, star] = leaves({'actions': ['store:*', 'job:run'], 'on': '*'}, lambda s: '*' in s)
    assert star.text == '*' and star.scope == ('store:*', '*')
