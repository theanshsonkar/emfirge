"""SQS: queues (messages are not copied: reading them changes the real queue)."""
from __future__ import annotations

import json
import re
from typing import Any, Mapping

from .context import CopyContext
from .spec import TypeSpec, Where

QUEUE = 'sqs:queue'
QUEUE_URL = r'https?://[^/]+/\d{12}/([^/?]+)'
QUEUE_SETTABLE = ('DelaySeconds', 'MaximumMessageSize', 'MessageRetentionPeriod', 'Policy', 'ReceiveMessageWaitTimeSeconds',
                  'RedrivePolicy', 'VisibilityTimeout', 'KmsMasterKeyId', 'KmsDataKeyReusePeriodSeconds',
                  'SqsManagedSseEnabled', 'FifoQueue', 'ContentBasedDeduplication', 'DeduplicationScope',
                  'FifoThroughputLimit', 'RedriveAllowPolicy')
def queue_name(v: str, p: Mapping[str, Any]) -> str:
    m = re.fullmatch(QUEUE_URL, v)
    return m.group(1) if m else v


def queue_url(w: Where, n: str) -> str:
    return f'https://sqs.{w.region}.amazonaws.com/{w.account}/{n}'


def copy_queue(x: CopyContext, n: str) -> bool:
    sqs = x.real('sqs')
    u = x.find(sqs.get_queue_url, QueueName=n)
    if u is None:
        return False
    u = u['QueueUrl']
    attrs = sqs.get_queue_attributes(QueueUrl=u, AttributeNames=['All'])['Attributes']
    a = {k: v for k, v in attrs.items() if k in QUEUE_SETTABLE}
    if 'RedrivePolicy' in a:
        rp = json.loads(a['RedrivePolicy'])
        rp['deadLetterTargetArn'] = x.ref(rp['deadLetterTargetArn'])
        a['RedrivePolicy'] = json.dumps(rp)
    tags = sqs.list_queue_tags(QueueUrl=u).get('Tags')
    eu = x.engine('sqs').create_queue(QueueName=n, Attributes=a, **({'tags': tags} if tags else {}))['QueueUrl']
    x.same(u, eu)
    return True


TYPES = [
    TypeSpec(QUEUE, 'sqs', params=('QueueUrl', 'QueueName'), arn=r'([^:]+)', url=QUEUE_URL,
             lists=(('ListQueues', 'QueueUrls', None),), removed_by=('DeleteQueue',), canon=queue_name,
             reads=lambda w, n: [('GetQueueAttributes', {'QueueUrl': queue_url(w, n), 'AttributeNames': ['All']}),
                                 ('ListQueueTags', {'QueueUrl': queue_url(w, n)})],
             copy=copy_queue),
]
