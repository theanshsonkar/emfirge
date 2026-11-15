"""S3: buckets, with their objects (small buckets only) and bucket settings."""
from __future__ import annotations

import urllib.parse
from typing import Any, Mapping

from emfirge.core.ports import CannotTell

from .context import CopyContext
from .spec import TypeSpec, pick

BUCKET = 's3:bucket'
MAX_OBJECTS, MAX_BYTES = 200, 1 << 20
NOT_COPIED = ('get_bucket_notification_configuration', 'get_bucket_replication', 'get_bucket_website')
SETTINGS = (('get_bucket_lifecycle_configuration', 'put_bucket_lifecycle_configuration', 'Rules', 'LifecycleConfiguration'),
            ('get_bucket_cors', 'put_bucket_cors', 'CORSRules', 'CORSConfiguration'))


def bucket_of(value: str, params: Mapping[str, Any]) -> str | None:
    """A bucket name, also from a copy source ('bucket/key', '/bucket/key?versionId=...'), which names the
    bucket a copy reads from."""
    v = urllib.parse.unquote(value.split('?', 1)[0]).lstrip('/')
    return v.split('/', 1)[0] or None


def copy_bucket(x: CopyContext, b: str) -> bool:
    s3, e = x.real('s3'), x.engine('s3')
    loc = x.find(s3.get_bucket_location, Bucket=b)
    if loc is None:
        return False
    for getter in NOT_COPIED:
        r = x.find(getattr(s3, getter), Bucket=b)
        if r and any(k != 'ResponseMetadata' for k in r):
            raise CannotTell(f'{getter[4:]} is not copied yet')
    objs = s3.list_objects_v2(Bucket=b)
    if objs.get('IsTruncated') or objs.get('KeyCount', 0) > MAX_OBJECTS or \
            any(o['Size'] > MAX_BYTES for o in objs.get('Contents', [])):
        raise CannotTell('the bucket is too big to copy')
    where = loc.get('LocationConstraint')
    e.create_bucket(Bucket=b, **({'CreateBucketConfiguration': {'LocationConstraint': where}} if where else {}))
    for o in objs.get('Contents', []):
        g = s3.get_object(Bucket=b, Key=o['Key'])
        e.put_object(Bucket=b, Key=o['Key'], Body=g['Body'].read(), **pick(g, 'ContentType', 'Metadata', 'CacheControl', 'ContentEncoding'))
    pol = x.find(s3.get_bucket_policy, Bucket=b)
    if pol:
        e.put_bucket_policy(Bucket=b, Policy=pol['Policy'])
    pab = x.find(s3.get_public_access_block, Bucket=b)
    if pab:
        e.put_public_access_block(Bucket=b, PublicAccessBlockConfiguration=pab['PublicAccessBlockConfiguration'])
    ver = s3.get_bucket_versioning(Bucket=b)
    if ver.get('Status'):
        e.put_bucket_versioning(Bucket=b, VersioningConfiguration={'Status': ver['Status']})
    enc = x.find(s3.get_bucket_encryption, Bucket=b)
    if enc:
        e.put_bucket_encryption(Bucket=b, ServerSideEncryptionConfiguration=enc['ServerSideEncryptionConfiguration'])
    tags = x.find(s3.get_bucket_tagging, Bucket=b)
    if tags and tags.get('TagSet'):
        e.put_bucket_tagging(Bucket=b, Tagging={'TagSet': tags['TagSet']})
    for getter, putter, key, arg in SETTINGS:
        r = x.find(getattr(s3, getter), Bucket=b)
        if r and r.get(key):
            getattr(e, putter)(Bucket=b, **{arg: {key: r[key]}})
    return True


TYPES = [
    TypeSpec(BUCKET, 's3', params=('Bucket', 'CopySource'), arn=r'([^/]+)(?:/.*)?',
             lists=(('ListBuckets', 'Buckets', 'Name'),), removed_by=('DeleteBucket',), canon=bucket_of,
             reads=lambda w, b: [('GetBucketLocation', {'Bucket': b}), ('GetBucketPolicy', {'Bucket': b}),
                                 ('GetPublicAccessBlock', {'Bucket': b}), ('GetBucketVersioning', {'Bucket': b}),
                                 ('GetBucketEncryption', {'Bucket': b}), ('GetBucketTagging', {'Bucket': b}),
                                 ('ListObjectsV2', {'Bucket': b})],
             copy=copy_bucket),
]
