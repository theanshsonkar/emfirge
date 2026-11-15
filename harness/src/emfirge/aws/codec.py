"""AWS wire traffic <-> Calls and plain nested data, from botocore's own service models (no per-service code).

Five protocols: json, rest-json, rest-xml, query, ec2. A request is placed by its signing scope (or its JSON target)
and then matched against the operations of that service. Answers are decoded without shapes into plain data (JSON as
is; XML as nested dicts keyed by tag, repeated tags as lists) so that a branch can diff and lay answers over each
other and render them back in the same format. smithy-rpc-v2-cbor (CloudWatch's newest SDKs) is not decoded yet:
such a request is refused, in a shape the client can read.
"""
from __future__ import annotations

import json
import re
import urllib.parse
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from typing import Any, Iterator
from xml.sax.saxutils import escape

import botocore.serialize
import botocore.session
from botocore.model import OperationModel, ServiceModel, Shape

from emfirge.core.model import Call, Kind, WireRequest, WireResponse

ERROR_CODE = 'EmfirgeCannotTell'
REFUSAL_HEADER = 'x-emfirge-cannot-tell'
_SCOPE = re.compile(r'Credential=[^/]+/\d+/[^/]+/([^/]+)/aws4_request')
_QUERY_SCOPE = re.compile(r'X-Amz-Credential=[^&/]+(?:/|%2F)\d+(?:/|%2F)[^&/%]+(?:/|%2F)([^&/%]+)(?:/|%2F)aws4_request', re.I)
_PAGE = re.compile(r'^(Next|LastEvaluated|NextMarker$|Marker$|IsTruncated$)', re.I)


@dataclass(frozen=True)
class ListPath:
    """Where a list member of an answer sits in the plain data, and what its items are."""
    member: str
    path: tuple[str, ...]
    item: Shape


class AwsCodec:
    """core.ports.Codec for AWS."""

    def __init__(self, region: str = 'us-west-2') -> None:
        self.region = region
        self._session = botocore.session.get_session()
        self._models: dict[str, ServiceModel] = {}
        self._routes: dict[str, list[tuple]] = {}
        self._by_scope: dict[str, list[str]] | None = None
        self._services = frozenset(self._session.get_available_services())

    # ------------------------------------------------------------------ models
    def model(self, service: str) -> ServiceModel:
        if service not in self._models:
            self._models[service] = self._session.get_service_model(service)
        return self._models[service]

    def operation(self, call: Call) -> OperationModel:
        return self.model(call.service).operation_model(call.operation)

    def _protocols(self, service: str) -> list[str]:
        md = self.model(service).metadata
        return list(md.get('protocols') or [md['protocol']])

    def wire_protocol(self, call: Call) -> str:
        """The protocol this request was actually sent in (a service may accept several)."""
        return _sniff(call.wire) if _sniff(call.wire) in self._protocols(call.service) else self._protocols(call.service)[0]

    def _candidates(self, scope: str) -> list[str]:
        """Services whose requests are signed with this scope. The service of the same name comes first."""
        if self._by_scope is None:
            self._by_scope = {}
            for name in sorted(self._services):
                md = self._session.get_service_data(name)['metadata']
                key = md.get('signingName') or md.get('endpointPrefix')
                self._by_scope.setdefault(key, []).append(name)
        found = self._by_scope.get(scope, [])
        return sorted(found, key=lambda n: n != scope)

    # ------------------------------------------------------------------ decode
    def decode(self, request: WireRequest) -> Call | None:
        headers = {k.lower(): v for k, v in request.headers.items()}
        scope = _scope(headers, request.query)
        if not scope:
            return None
        services = [scope] if self._known(scope) else []
        services += [s for s in self._candidates(scope) if s not in services]
        if 'x-amz-credential=' in request.query.lower() and request.method in ('GET', 'HEAD'):
            services.append('s3')   # a presigned download (a code bundle, an export) is an S3 object read
        for service in services:
            found = self._decode_as(service, request, headers)
            if found:
                return Call(service, found[0], found[1], Kind.UNKNOWN, request)
        return None

    def _known(self, service: str) -> bool:
        return service in self._services

    def _decode_as(self, service: str, request: WireRequest, headers: dict[str, str]) -> tuple[str, dict] | None:
        model = self.model(service)
        protocols = self._protocols(service)
        target = headers.get('x-amz-target', '')
        if target:
            prefix, _, op = target.rpartition('.')
            if 'json' not in protocols or prefix != model.metadata.get('targetPrefix') or op not in model.operation_names:
                return None
            try:
                return op, json.loads(request.body or b'{}')
            except ValueError:
                return None
        form = dict(urllib.parse.parse_qsl((request.body or b'').decode(errors='replace') or request.query,
                                           keep_blank_values=True))
        proto = next((p for p in protocols if p in ('query', 'ec2')), None)
        if proto and 'Action' in form:
            op = form.pop('Action')
            if op not in model.operation_names:
                return None
            opm = model.operation_model(op)
            return op, (_decode_form(opm.input_shape, form, proto) if opm.input_shape else {})
        if any(p in ('rest-json', 'rest-xml') for p in protocols):
            return self._decode_rest(service, request, headers)
        return None

    def _decode_rest(self, service: str, request: WireRequest, headers: dict[str, str]) -> tuple[str, dict] | None:
        have = dict(urllib.parse.parse_qsl(request.query, keep_blank_values=True))
        path = urllib.parse.unquote(request.path)
        for method, rx, name, need in self._rest_routes(service):
            m = rx.match(path) if method == request.method else None
            if not m or not all(k in have and (v == '' or have[k] == v) for k, v in need.items()):
                continue
            opm = self.model(service).operation_model(name)
            params: dict[str, Any] = {}
            for member, shape in (opm.input_shape.members.items() if opm.input_shape else ()):
                loc, wire = shape.serialization.get('location'), shape.serialization.get('name', member)
                if loc == 'uri' and m.groupdict().get(_group(wire)) is not None:
                    params[member] = m.group(_group(wire))
                elif loc == 'querystring' and wire in have:
                    params[member] = have[wire]
                elif loc == 'header' and wire.lower() in headers:
                    params[member] = headers[wire.lower()]
            if request.body[:1] == b'{' and 'rest-json' in self._protocols(service):
                try:
                    params.update(json.loads(request.body))
                except ValueError:
                    pass
            return name, params
        return None

    def _rest_routes(self, service: str) -> list[tuple]:
        """(method, path regex, operation, required query keys), most specific first."""
        if service not in self._routes:
            out = []
            model = self.model(service)
            for name in model.operation_names:
                http = model.operation_model(name).http
                uri, _, q = http.get('requestUri', '/').partition('?')
                rx = re.escape(uri).replace(r'\{', '{').replace(r'\}', '}').replace(r'\+', '+')
                rx = re.sub(r'\{([\w-]+)\+\}', lambda m: f'(?P<{_group(m.group(1))}>.+)', rx)
                rx = re.sub(r'\{([\w-]+)\}', lambda m: f'(?P<{_group(m.group(1))}>[^/]+)', rx)
                need = dict(urllib.parse.parse_qsl(q, keep_blank_values=True))
                out.append((http.get('method', 'POST'), re.compile('^' + rx + '/?$'), name, need, uri.count('{'), len(uri)))
            out.sort(key=lambda r: (r[4], -len(r[3]), -r[5]))
            self._routes[service] = [r[:4] for r in out]
        return self._routes[service]

    # ------------------------------------------------------------------ encode
    def encode(self, service: str, operation: str, params: dict[str, Any]) -> Call:
        """A call as the SDK would send it (botocore's own serializer), decoded back so params look like a client's."""
        model = self.model(service)
        opm = model.operation_model(operation)
        proto = self._protocols(service)
        proto = next((p for p in proto if p in ('json', 'rest-json', 'rest-xml', 'query', 'ec2')), proto[0])
        r = botocore.serialize.create_serializer(proto, include_validation=False).serialize_to_request(params, opm)
        path, _, q = r['url_path'].partition('?')
        qs = r['query_string'] if isinstance(r['query_string'], str) else urllib.parse.urlencode(r['query_string'], doseq=True)
        body = r['body'] if isinstance(r['body'], (bytes, str)) else urllib.parse.urlencode(r['body'])
        scope = model.metadata.get('signingName') or model.metadata['endpointPrefix']
        headers = dict(r['headers'], Authorization=f'AWS4-HMAC-SHA256 Credential=emfirge/20260101/{self.region}/{scope}'
                                                   f'/aws4_request, SignedHeaders=host, Signature=0')
        wire = WireRequest(r['method'], path, '&'.join(x for x in (q, qs) if x), headers,
                           body.encode() if isinstance(body, str) else body)
        decoded = self.decode(wire)
        return decoded if decoded else Call(service, operation, params, Kind.UNKNOWN, wire)

    # ------------------------------------------------------------------ answers
    def body(self, call: Call, response: WireResponse) -> Any:
        if self.blob_payload(call, 'output_shape') or call.wire.method == 'HEAD':
            return response.body
        return decode_body(response.body)

    def render(self, call: Call, response: WireResponse, body: Any) -> WireResponse:
        data = encode_body(body) if isinstance(body, (dict, list)) else body
        headers = {k: v for k, v in response.headers.items() if k.lower() != 'content-length'}
        headers['Content-Length'] = str(len(data))
        return WireResponse(response.status, headers, data)

    def blob_payload(self, call: Call, which: str) -> bool:
        """The request's (input_shape) or answer's (output_shape) payload is raw bytes: customer data."""
        shape = getattr(self.operation(call), which)
        payload = shape.serialization.get('payload') if shape is not None else None
        return bool(payload and shape.members[payload].type_name == 'blob')

    # ------------------------------------------------------------------ refusals
    def refusal(self, call: Call | None, request: WireRequest, message: str) -> WireResponse:
        proto, service = self._refusal_protocol(call, request)
        text = escape(message)
        head = {REFUSAL_HEADER: 'true'}
        if proto in ('json', 'rest-json'):
            version = self.model(service).metadata.get('jsonVersion', '1.1') if service else '1.1'
            ctype = f'application/x-amz-json-{version}' if proto == 'json' else 'application/json'
            body = json.dumps({'__type': ERROR_CODE, 'message': message}).encode()
            return WireResponse(400, dict(head, **{'Content-Type': ctype, 'x-amzn-ErrorType': ERROR_CODE}), body)
        error = f'<Code>{ERROR_CODE}</Code><Message>{text}</Message>'
        if proto == 'ec2':
            xml = f'<Response><Errors><Error>{error}</Error></Errors><RequestID>emfirge</RequestID></Response>'
        elif proto == 'rest-xml' and service == 's3':
            xml = f'<Error>{error}<RequestId>emfirge</RequestId></Error>'
        else:
            xml = f'<ErrorResponse><Error><Type>Sender</Type>{error}</Error><RequestId>emfirge</RequestId></ErrorResponse>'
        body = b'' if request.method == 'HEAD' else ('<?xml version="1.0" encoding="UTF-8"?>' + xml).encode()
        return WireResponse(400, dict(head, **{'Content-Type': 'text/xml'}), body)

    def _refusal_protocol(self, call: Call | None, request: WireRequest) -> tuple[str, str | None]:
        if call is not None:
            return self.wire_protocol(call), call.service
        headers = {k.lower(): v for k, v in request.headers.items()}
        scope = _scope(headers, request.query)
        service = scope if scope and self._known(scope) else next(iter(self._candidates(scope or '')), None)
        sniffed = _sniff(request)
        if service and sniffed not in self._protocols(service):
            sniffed = self._protocols(service)[0]
        return sniffed, service

    # ------------------------------------------------------------------ lists in answers
    def list_paths(self, call: Call, body: Any) -> list[ListPath]:
        """The top-level list members of an answer, located in this codec's plain data."""
        shape = self.operation(call).output_shape
        if shape is None or not isinstance(body, dict):
            return []
        if not _is_xml(body):
            return [ListPath(n, (n,), m.member) for n, m in shape.members.items() if m.type_name == 'list']
        root = next(iter(body))
        wrap = (shape.serialization['resultWrapper'],) if 'resultWrapper' in shape.serialization else ()
        ec2 = self.wire_protocol(call) == 'ec2'
        out = []
        for n, m in shape.members.items():
            if m.type_name != 'list':
                continue
            tag = m.serialization.get('name', n)
            if m.serialization.get('flattened'):
                out.append(ListPath(n, (root, *wrap, tag), m.member))
            else:
                item = m.member.serialization.get('name', 'item' if ec2 else 'member')
                out.append(ListPath(n, (root, *wrap, tag, item), m.member))
        return out

    def field(self, item_shape: Shape, field: str, body: Any) -> str:
        """The name a structure's field has in this codec's plain data (its wire name, for XML)."""
        if not _is_xml(body) or item_shape.type_name != 'structure' or field not in item_shape.members:
            return field
        return item_shape.members[field].serialization.get('name', field)

    def truncated(self, call: Call, body: Any) -> bool:
        """The answer is one page of several."""
        shape = self.operation(call).output_shape
        if shape is None or not isinstance(body, dict):
            return False
        top = body
        if _is_xml(body):
            top = next(iter(body.values()))
            if 'resultWrapper' in shape.serialization and isinstance(top, dict):
                top = top.get(shape.serialization['resultWrapper'], {})
        if not isinstance(top, dict):
            return False
        for n, m in shape.members.items():
            key = m.serialization.get('name', n) if _is_xml(body) else n
            if _PAGE.search(n) and top.get(key) not in (None, '', 'false', False):
                return True
        return False


# ---------------------------------------------------------------------- helpers
def _scope(headers: dict[str, str], query: str) -> str | None:
    m = _SCOPE.search(headers.get('authorization', '')) or _QUERY_SCOPE.search(query)
    return m.group(1) if m else None


def _sniff(request: WireRequest) -> str:
    headers = {k.lower(): v for k, v in request.headers.items()}
    if 'x-amz-target' in headers:
        return 'json'
    if 'smithy-protocol' in headers:
        return 'smithy-rpc-v2-cbor'
    if 'Action=' in (request.body[:200].decode(errors='replace') if request.body else '') or 'Action=' in request.query:
        return 'query'
    return 'rest-json' if 'json' in headers.get('content-type', '') else 'rest-xml'


def _group(name: str) -> str:
    return re.sub(r'\W', '_', name)


def _wire_name(shape: Shape, name: str, proto: str) -> str:
    if proto == 'ec2':
        return shape.serialization.get('queryName') or _cap(shape.serialization.get('name') or name)
    return shape.serialization.get('name', name)


def _cap(s: str) -> str:
    return s[:1].upper() + s[1:]


def _decode_form(shape: Shape, flat: dict[str, str], proto: str, prefix: str = '') -> dict[str, Any]:
    """Form parameters (query and ec2 protocols) back into the operation's input structure. Values stay strings."""
    out = {}
    for name, member in shape.members.items():
        v = _decode_form_value(member, flat, proto, prefix + _wire_name(member, name, proto))
        if v is not None:
            out[name] = v
    return out


def _decode_form_value(m: Shape, flat: dict[str, str], proto: str, key: str) -> Any:
    if m.type_name == 'structure':
        return _decode_form(m, flat, proto, key + '.') or None
    if m.type_name == 'list':
        if proto == 'ec2' or m.serialization.get('flattened'):
            base = key + '.'
        else:
            base = key + '.' + m.member.serialization.get('name', 'member') + '.'
        items: list[Any] = []
        while (v := _decode_form_value(m.member, flat, proto, base + str(len(items) + 1))) is not None:
            items.append(v)
        return items or ([] if key in flat else None)
    if m.type_name == 'map':
        base = key + '.' if m.serialization.get('flattened') else key + '.entry.'
        kname, vname = m.key.serialization.get('name', 'key'), m.value.serialization.get('name', 'value')
        out, i = {}, 1
        while f'{base}{i}.{kname}' in flat:
            out[flat[f'{base}{i}.{kname}']] = _decode_form_value(m.value, flat, proto, f'{base}{i}.{vname}')
            i += 1
        return out or None
    return flat.get(key)


def _is_xml(body: Any) -> bool:
    return isinstance(body, dict) and len(body) == 1 and next(iter(body)).startswith(_XML_ROOT)


_XML_ROOT = '<'
"""XML answers decode to {'<' + root tag: content}: the marker keeps them apart from JSON answers."""


def decode_body(data: bytes) -> Any:
    """Plain nested data from an answer body: JSON as is, XML as nested dicts, anything else as bytes."""
    lead = (data or b'').lstrip()[:1]
    try:
        if lead in (b'{', b'['):
            return json.loads(data)
        if lead == b'<':
            root = ET.fromstring(data)
            return {_XML_ROOT + root.tag: _x2d(root)}
    except (ValueError, ET.ParseError):
        pass
    return data


def encode_body(body: Any) -> bytes:
    if not _is_xml(body):
        return json.dumps(body).encode()
    tag, content = next(iter(body.items()))
    tag = tag[len(_XML_ROOT):]
    ns, _, local = tag[1:].partition('}') if tag.startswith('{') else ('', '', tag)
    root = ET.Element(local)
    if ns:
        root.set('xmlns', ns)
    _d2x(root, content)
    return b'<?xml version="1.0" encoding="UTF-8"?>' + ET.tostring(root)


def _strip_ns(tag: str) -> str:
    return tag.split('}', 1)[-1]


def _x2d(el: ET.Element) -> Any:
    kids = list(el)
    if not kids:
        return el.text or ''
    out: dict[str, Any] = {}
    for k in kids:
        tag, value = _strip_ns(k.tag), _x2d(k)
        if tag not in out:
            out[tag] = value
        elif isinstance(out[tag], _Repeated):
            out[tag].append(value)
        else:
            out[tag] = _Repeated([out[tag], value])
    return {k: list(v) if isinstance(v, _Repeated) else v for k, v in out.items()}


class _Repeated(list):
    """Repeated XML elements of one tag, while decoding."""


def _d2x(el: ET.Element, value: Any) -> None:
    if isinstance(value, dict):
        for k, v in value.items():
            for item in _each(v):
                _d2x(ET.SubElement(el, k), item)
    else:
        el.text = '' if value is None else str(value)


def _each(v: Any) -> Iterator[Any]:
    return iter(v) if isinstance(v, list) else iter([v])


def items_at(body: Any, path: tuple[str, ...]) -> tuple[Any, ...]:
    """The items of the list at `path`: a single XML element is one item, an empty or missing one is none."""
    cur = body
    for k in path:
        if not isinstance(cur, dict) or k not in cur:
            return ()
        cur = cur[k]
    if isinstance(cur, list):
        return tuple(cur)
    return () if cur in ('', None) else (cur,)
