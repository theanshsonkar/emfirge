"""SQS queues and SNS topics (with their subscriptions). Messages are not copied: reading them changes the queue."""
from __future__ import annotations

import json
import re
from typing import Any, Mapping

from .context import CopyContext
from .spec import TypeSpec, Where

QUEUE, TOPIC = 'sqs:queue', 'sns:topic'
QUEUE_URL = r'https?://[^/]+/\d{12}/([^/?]+)'
QUEUE_SETTABLE = ('DelaySeconds', 'MaximumMessageSize', 'MessageRetentionPeriod', 'Policy', 'ReceiveMessageWaitTimeSeconds',
                  'RedrivePolicy', 'VisibilityTimeout', 'KmsMasterKeyId', 'KmsDataKeyReusePeriodSeconds',
                  'SqsManagedSseEnabled', 'FifoQueue', 'ContentBasedDeduplication', 'DeduplicationScope',
                  'FifoThroughputLimit', 'RedriveAllowPolicy')
TOPIC_SETTABLE = ('DisplayName', 'Policy', 'DeliveryPolicy', 'KmsMasterKeyId', 'FifoTopic', 'ContentBasedDeduplication',
                  'TracingConfig', 'SignatureVersion')
SUBSCRIPTION_SETTABLE = ('RawMessageDelivery', 'FilterPolicy', 'FilterPolicyScope', 'RedrivePolicy', 'DeliveryPolicy')


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


def topic_arn(w: Where, n: str) -> str:
    return f'arn:aws:sns:{w.region}:{w.account}:{n}'


def copy_topic(x: CopyContext, n: str) -> bool:
    sns, e = x.real('sns'), x.engine('sns')
    arn = topic_arn(x.where, n)
    a = x.find(sns.get_topic_attributes, TopicArn=arn)
    if a is None:
        return False
    tags = sns.list_tags_for_resource(ResourceArn=arn).get('Tags')
    e.create_topic(Name=n, Attributes={k: v for k, v in a['Attributes'].items() if k in TOPIC_SETTABLE},
                   **({'Tags': tags} if tags else {}))
    for s in sns.list_subscriptions_by_topic(TopicArn=arn)['Subscriptions']:
        confirmed = s['SubscriptionArn'].startswith('arn:')
        attrs = {}
        if confirmed:
            got = sns.get_subscription_attributes(SubscriptionArn=s['SubscriptionArn'])['Attributes']
            attrs = {k: v for k, v in got.items() if k in SUBSCRIPTION_SETTABLE}
        es = e.subscribe(TopicArn=arn, Protocol=s['Protocol'], Endpoint=x.tr(s['Endpoint']), Attributes=attrs,
                         ReturnSubscriptionArn=True)['SubscriptionArn']
        if confirmed and es.startswith('arn:'):
            x.same(s['SubscriptionArn'].rsplit(':', 1)[1], es.rsplit(':', 1)[1])
    return True


TYPES = [
    TypeSpec(QUEUE, 'sqs', params=('QueueUrl', 'QueueName'), arn=r'([^:]+)', url=QUEUE_URL,
             lists=(('ListQueues', 'QueueUrls', None),), removed_by=('DeleteQueue',), canon=queue_name,
             reads=lambda w, n: [('GetQueueAttributes', {'QueueUrl': queue_url(w, n), 'AttributeNames': ['All']}),
                                 ('ListQueueTags', {'QueueUrl': queue_url(w, n)})],
             copy=copy_queue),
    TypeSpec(TOPIC, 'sns', params=('TopicArn', 'SubscriptionArn'), arn=r'([^:]+)(?::.+)?',
             lists=(('ListTopics', 'Topics', 'TopicArn'), ('ListSubscriptions', 'Subscriptions', 'TopicArn')),
             removed_by=('DeleteTopic',),
             reads=lambda w, n: [('GetTopicAttributes', {'TopicArn': topic_arn(w, n)}),
                                 ('ListSubscriptionsByTopic', {'TopicArn': topic_arn(w, n)}),
                                 ('ListTagsForResource', {'ResourceArn': topic_arn(w, n)})],
             copy=copy_topic),
]
