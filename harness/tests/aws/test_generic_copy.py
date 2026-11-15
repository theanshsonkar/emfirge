"""The generic copier's pure parts: filling an input from answers by names and shapes, choosing operations, comparing
the two sides. No network."""
from __future__ import annotations

from emfirge.aws.codec import AwsCodec
from emfirge.aws.generic_copy import compare, plan
from emfirge.aws.generic_copy.fill import Fetch, fill, unwrap
from emfirge.aws.generic_copy.sdk import refused_value

CODEC = AwsCodec('us-west-2')


def shape(service, op):
    return CODEC.model(service).operation_model(op).input_shape


def test_a_function_create_is_filled_from_its_read_and_its_code_is_a_download():
    answer = {'Configuration': {'FunctionName': 'f', 'Runtime': 'python3.12', 'Role': 'arn:aws:iam::000000000000:role/r',
                                'Handler': 'h.h', 'Timeout': 30, 'State': 'Active', 'VpcConfig': {'SubnetIds': []}},
              'Code': {'RepositoryType': 'S3', 'Location': 'https://example.invalid/code.zip?sig=1'},
              'Tags': {'team': 'media'}}
    got = fill(shape('lambda', 'CreateFunction'), [answer])
    assert not got.missing
    assert got.params['Code'] == {'ZipFile': Fetch('https://example.invalid/code.zip?sig=1')}
    assert got.params['Timeout'] == 30 and got.params['Tags'] == {'team': 'media'}
    assert 'State' not in got.params and 'VpcConfig' not in got.params     # read-only, and empty


def test_a_wrapper_the_answer_lacks_is_filled_from_its_top_level():
    got = fill(shape('s3', 'CreateBucket'), [{'Bucket': 'b'}, {'LocationConstraint': 'us-west-2'}])
    assert got.params == {'Bucket': 'b', 'CreateBucketConfiguration': {'LocationConstraint': 'us-west-2'}}
    got = fill(shape('s3', 'PutBucketVersioning'), [{'Bucket': 'b'}, {'Status': 'Enabled'}])
    assert got.params['VersioningConfiguration'] == {'Status': 'Enabled'}


def test_a_decoded_document_becomes_text_and_an_arn_stands_for_a_name_but_not_the_other_way():
    got = fill(shape('iam', 'CreateRole'), [unwrap({'Role': {'RoleName': 'r', 'AssumeRolePolicyDocument': {'Version': '2012-10-17'},
                                                              'PermissionsBoundary': {'PermissionsBoundaryType': 'Policy',
                                                                                      'PermissionsBoundaryArn': 'arn:aws:iam::000000000000:policy/b'}}}, 'iam:role')])
    assert got.params['AssumeRolePolicyDocument'] == '{"Version": "2012-10-17"}'
    assert got.params['PermissionsBoundary'] == 'arn:aws:iam::000000000000:policy/b'
    got = fill(shape('lambda', 'CreateEventSourceMapping'), [{'FunctionArn': 'arn:aws:lambda:us-west-2:000000000000:function:f'}])
    assert got.params['FunctionName'].endswith(':function:f')
    assert 'PolicyArn' not in fill(shape('iam', 'AttachRolePolicy'), [{'RoleName': 'r', 'PolicyName': 'p'}]).params


def test_what_no_answer_fills_is_reported_not_invented():
    got = fill(shape('iam', 'CreatePolicy'), [{'PolicyName': 'p'}])
    assert got.missing == ['PolicyDocument']


def test_unwrap_goes_into_the_record_named_after_the_type_or_the_only_one():
    assert unwrap({'Table': {'TableName': 't'}}, 'dynamodb:table') == {'TableName': 't'}
    assert unwrap({'Vpcs': [{'VpcId': 'vpc-1'}]}, 'ec2:vpc') == {'VpcId': 'vpc-1'}
    assert unwrap({'Configuration': {}, 'Code': {}}, 'lambda:function') == {'Configuration': {}, 'Code': {}}


def test_the_create_and_the_settings_are_chosen_by_name():
    lam, iam = CODEC.model('lambda'), CODEC.model('iam')
    assert plan.creates(lam, frozenset({'function'}))[0] == 'CreateFunction'
    assert plan.creates(CODEC.model('rds'), frozenset({'db', 'dbinstance'})) == ['CreateDBInstance']
    pairs = {(s.read, s.write) for s in plan.settings(lam, ['GetFunctionConcurrency', 'GetPolicy'], 'CreateFunction')}
    assert ('GetFunctionConcurrency', 'PutFunctionConcurrency') in pairs
    pairs = {(s.read, s.write, s.item) for s in plan.settings(iam, ['ListAttachedRolePolicies', 'ListRolePolicies',
                                                                     'GetInstanceProfile'], 'CreateRole')}
    assert ('ListAttachedRolePolicies', 'AttachRolePolicy', '') in pairs and ('ListRolePolicies', 'PutRolePolicy', '') in pairs
    assert ('GetInstanceProfile', 'AddRoleToInstanceProfile', 'role') in pairs
    assert plan.details(iam, 'PutRolePolicy') == ['GetRolePolicy']


def test_ids_the_engine_gave_out_are_paired_with_the_real_ones():
    real = {'RoleName': 'r', 'RoleId': 'AROAREAL00000001', 'Tags': [{'Key': 'k', 'Value': 'v'}]}
    engine = {'RoleName': 'r', 'RoleId': 'AROAENGINE000001', 'Tags': [{'Key': 'k', 'Value': 'v'}]}
    assert compare.new_ids(real, engine, 'role') == [('AROAREAL00000001', 'AROAENGINE000001')]
    assert compare.generated({'DomainName': 'd111.cloudfront.net', 'Comment': 'x'},
                             {'DomainName': 'd222.cloudfront.net', 'Comment': 'y'}, frozenset()) == \
        [('d111.cloudfront.net', 'd222.cloudfront.net')]
    assert compare.new_ids({'Groups': [{'GroupId': 'sg-00000001'}]}, {'Groups': [{'GroupId': 'sg-00000009'}]}, 'x') == []


def test_differences_and_missing_items():
    assert compare.differences({'Timeout': 30, 'LastModified': 'a'}, {'Timeout': 60, 'LastModified': 'b'}, str) == ['Timeout']
    assert compare.fewer_items({'Subscriptions': [1, 2]}, {'Subscriptions': [1]}) == ['Subscriptions: 2 real, 1 copied']
    assert compare.same_item({'PolicyName': 'p', 'Doc': 'x'}, {'PolicyName': 'p'}, str)


def test_the_value_an_engine_refuses_is_found_in_its_message():
    params = {'QueueName': 'q', 'Attributes': {'QueueArn': 'a', 'VisibilityTimeout': '30'}}
    assert refused_value('Unknown Attribute QueueArn.', params, frozenset({'QueueName'})) == ('Attributes', 'QueueArn')
    assert refused_value('The Revision Id provided does not match', {'RevisionId': 'x', 'FunctionName': 'f'},
                         frozenset({'FunctionName'})) == ('RevisionId',)
    assert refused_value('something else', params, frozenset({'QueueName'})) is None


# ------------------------------------------------------------------ contents, located reads, made-up values
from emfirge.aws.catalog import AwsCatalog                      # noqa: E402
from emfirge.aws.generic_copy import contents, locate           # noqa: E402
from emfirge.aws.layered import LayeredCatalog                  # noqa: E402
from emfirge.core.model import ResourceRef                      # noqa: E402

CATALOG = LayeredCatalog(AwsCatalog(account='000000000000', region='us-west-2'), CODEC)


def _refs(service, op, params):
    return CATALOG.refs(CODEC.encode(service, op, params))


def test_the_contents_of_a_bucket_and_a_table_are_the_reads_the_catalog_leaves_out():
    bucket = ResourceRef('s3:bucket', 'b1')
    known = {op for _, op, _ in CATALOG.reads_of(bucket)}
    found = [op for op, _ in contents.contents_reads(CODEC.model('s3'), 's3', bucket, {'Bucket': 'b1'}, known,
                                                     CATALOG.kind, _refs)]
    assert 'ListObjectsV2' in found
    table = ResourceRef('dynamodb:table', 't')
    known = {op for _, op, _ in CATALOG.reads_of(table)}
    found = [op for op, _ in contents.contents_reads(CODEC.model('dynamodb'), 'dynamodb', table, {'TableName': 't'},
                                                     known, CATALOG.kind, _refs)]
    assert 'Scan' in found
    assert 'GetItem' in contents.data_reads(CODEC.model('dynamodb'), 'dynamodb', table, {'TableName': 't'}, known,
                                            CATALOG.kind, _refs)


def test_contents_are_written_back_by_the_write_named_after_the_read_or_its_items():
    assert contents.item_write(CODEC.model('s3'), 'ListObjectsV2', 'Contents') == 'PutObject'
    assert contents.item_write(CODEC.model('dynamodb'), 'Scan', 'Items') == 'PutItem'
    assert contents.more_pages({'Items': [1], 'LastEvaluatedKey': {'pk': 'x'}})
    assert not contents.more_pages({'Contents': [1], 'IsTruncated': False})


def test_a_policy_is_read_by_the_arn_its_list_gives():
    ref = ResourceRef('iam:policy', 'p')
    pages = iter([{'Policies': [{'PolicyName': 'p', 'Arn': 'arn:aws:iam::000000000000:policy/team/p'}]}])
    arn = locate.arn_of(pages, ref, CATALOG.parse_arn)
    assert arn == 'arn:aws:iam::000000000000:policy/team/p'
    assert ('GetPolicy', {'PolicyArn': arn}) in locate.reads_by_arn(CODEC.model('iam'), 'iam:policy', arn)


def test_a_number_the_engine_made_up_is_found_but_a_count_at_the_top_is_not():
    real = {'Endpoint': {'Address': 'a', 'Port': 5432}, 'AttachmentCount': 1}
    engine = {'Endpoint': {'Address': 'b', 'Port': 41234}, 'AttachmentCount': 0}
    assert compare.invented_numbers(real, engine, frozenset()) == ['Endpoint.Port']
    assert compare.invented_numbers(real, engine, frozenset({'Endpoint'})) == []
