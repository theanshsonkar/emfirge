"""The AWS codec: requests of the five protocols as the SDK sends them, answers as plain data and back, refusals
that the SDK's own parsers read as a normal error. No network."""
from __future__ import annotations

import json
import zlib

import botocore.parsers
import botocore.session
import pytest

from emfirge.aws.codec import ERROR_CODE, REFUSAL_HEADER, AwsCodec, decode_body, encode_body, items_at
from emfirge.core.model import WireRequest, WireResponse

CODEC = AwsCodec('us-west-2')
SESSION = botocore.session.get_session()

ROUND_TRIPS = [   # (service, operation, params): one or more per protocol
    ('dynamodb', 'DescribeTable', {'TableName': 'episodes'}),                                  # json
    ('sqs', 'GetQueueAttributes', {'QueueUrl': 'https://sqs.us-west-2.amazonaws.com/000000000000/jobs',
                                   'AttributeNames': ['All']}),                                 # json
    ('lambda', 'GetFunctionConfiguration', {'FunctionName': 'publisher'}),                     # rest-json
    ('lambda', 'ListTags', {'Resource': 'arn:aws:lambda:us-west-2:000000000000:function:publisher'}),
    ('scheduler', 'GetSchedule', {'Name': 'daily', 'GroupName': 'g1'}),                        # rest-json, query string
    ('s3', 'GetBucketPolicy', {'Bucket': 'media'}),                                            # rest-xml
    ('s3', 'HeadObject', {'Bucket': 'media', 'Key': 'ep/1.mp3'}),
    ('route53', 'ListResourceRecordSets', {'HostedZoneId': 'Z123'}),
    ('iam', 'GetRole', {'RoleName': 'app-role'}),                                              # query
    ('iam', 'ListRoles', {}),
    ('sns', 'GetTopicAttributes', {'TopicArn': 'arn:aws:sns:us-west-2:000000000000:alerts'}),
    ('ec2', 'DescribeVpcs', {'VpcIds': ['vpc-0000000000000008c']}),                           # ec2
    ('ec2', 'DescribeSecurityGroups', {'Filters': [{'Name': 'vpc-id', 'Values': ['vpc-1']}]}),
]


@pytest.mark.parametrize('service,op,params', ROUND_TRIPS)
def test_encode_then_decode_gives_the_same_call(service, op, params):
    call = CODEC.encode(service, op, params)
    again = CODEC.decode(call.wire)
    assert (again.service, again.operation) == (service, op)
    assert json.loads(json.dumps(again.params)) == params


def test_header_members_are_decoded():
    call = CODEC.encode('s3', 'CopyObject', {'Bucket': 'new', 'Key': 'k', 'CopySource': 'media/feed.xml'})
    assert CODEC.decode(call.wire).params['CopySource'] == 'media/feed.xml'


def test_requests_it_cannot_read_are_none():
    assert CODEC.decode(WireRequest('GET', '/', '', {}, b'')) is None   # not signed: not an AWS call
    cbor = WireRequest('POST', '/service/GraniteServiceVersion20100801/operation/GetMetricData', '',
                       {'Authorization': 'AWS4-HMAC-SHA256 Credential=a/20260101/us-west-2/monitoring/aws4_request',
                        'Smithy-Protocol': 'rpc-v2-cbor'}, b'\xa0')
    assert CODEC.decode(cbor) is None


def test_a_presigned_download_is_read_as_an_object_read():
    q = 'X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=X%2F20261115%2Fus-west-2%2Flambda%2Faws4_request&X-Amz-Signature=0'
    call = CODEC.decode(WireRequest('GET', '/awslambda-us-west-2-tasks/snapshots/000000000000/f-1', q, {}, b''))
    assert (call.service, call.operation) == ('s3', 'GetObject')


XML = (b'<?xml version="1.0" encoding="UTF-8"?><ListRolesResponse xmlns="https://iam.amazonaws.com/doc/2010-05-08/">'
       b'<ListRolesResult><Roles><member><RoleName>a</RoleName></member><member><RoleName>b</RoleName></member></Roles>'
       b'<IsTruncated>false</IsTruncated></ListRolesResult></ListRolesResponse>')


def test_xml_answers_round_trip_through_plain_data():
    body = decode_body(XML)
    root = next(iter(body))
    assert body[root]['ListRolesResult']['Roles']['member'] == [{'RoleName': 'a'}, {'RoleName': 'b'}]
    assert decode_body(encode_body(body)) == body
    call = CODEC.encode('iam', 'ListRoles', {})
    [lp] = CODEC.list_paths(call, body)
    assert [i['RoleName'] for i in items_at(body, lp.path)] == ['a', 'b'] and not CODEC.truncated(call, body)
    parsed = botocore.parsers.create_parser('query').parse(
        {'status_code': 200, 'headers': {}, 'body': encode_body(body)}, SESSION.get_service_model('iam').operation_model('ListRoles').output_shape)
    assert [r['RoleName'] for r in parsed['Roles']] == ['a', 'b']


def test_json_answers_and_render_keep_length_and_checksum_true():
    call = CODEC.encode('dynamodb', 'DescribeTable', {'TableName': 't'})
    r = WireResponse(200, {'x-amz-crc32': '1', 'Content-Length': '2'}, b'{}')
    out = CODEC.render(call, r, {'Table': {'TableName': 't'}})
    assert out.headers['x-amz-crc32'] == str(zlib.crc32(out.body)) and out.headers['Content-Length'] == str(len(out.body))
    assert CODEC.body(call, out) == {'Table': {'TableName': 't'}}


def test_object_payloads_stay_bytes():
    call = CODEC.encode('s3', 'GetObject', {'Bucket': 'b', 'Key': 'k.json'})
    assert CODEC.body(call, WireResponse(200, {}, b'{"a": 1}')) == b'{"a": 1}'
    assert CODEC.blob_payload(call, 'output_shape')


REFUSALS = [('dynamodb', 'DescribeTable', {'TableName': 't'}), ('lambda', 'GetFunction', {'FunctionName': 'f'}),
            ('s3', 'GetBucketPolicy', {'Bucket': 'b'}), ('route53', 'GetHostedZone', {'Id': 'Z1'}),
            ('iam', 'GetRole', {'RoleName': 'r'}), ('ec2', 'DescribeVpcs', {}), ('elbv2', 'DescribeLoadBalancers', {})]


@pytest.mark.parametrize('service,op,params', REFUSALS)
def test_refusals_parse_as_a_normal_error_with_our_code(service, op, params):
    call = CODEC.encode(service, op, params)
    r = CODEC.refusal(call, call.wire, 'Emfirge cannot tell: x & <y>.')
    assert r.status == 400 and r.headers[REFUSAL_HEADER] == 'true'
    model = SESSION.get_service_model(service)
    parser = botocore.parsers.create_parser(CODEC.wire_protocol(call))
    parsed = parser.parse({'status_code': r.status, 'headers': r.headers, 'body': r.body},
                          model.operation_model(op).output_shape)
    assert parsed['Error']['Code'] == ERROR_CODE
    assert parsed['Error']['Message'] == 'Emfirge cannot tell: x & <y>.'


def test_a_refusal_for_a_request_that_could_not_be_decoded_is_still_in_its_protocol():
    wire = WireRequest('POST', '/', '', {'Authorization': 'AWS4-HMAC-SHA256 Credential=a/1/us-west-2/ec2/aws4_request',
                                         'Content-Type': 'application/x-www-form-urlencoded'}, b'Action=NoSuchThing')
    assert CODEC.refusal(None, wire, 'm').body.startswith(b'<?xml')
