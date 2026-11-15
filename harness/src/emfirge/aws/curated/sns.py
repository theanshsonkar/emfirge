"""SNS: topics, with their subscriptions."""
from __future__ import annotations

from .context import CopyContext
from .spec import TypeSpec, Where

TOPIC = 'sns:topic'
TOPIC_SETTABLE = ('DisplayName', 'Policy', 'DeliveryPolicy', 'KmsMasterKeyId', 'FifoTopic', 'ContentBasedDeduplication',
                  'TracingConfig', 'SignatureVersion')
SUBSCRIPTION_SETTABLE = ('RawMessageDelivery', 'FilterPolicy', 'FilterPolicyScope', 'RedrivePolicy', 'DeliveryPolicy')


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
    TypeSpec(TOPIC, 'sns', params=('TopicArn', 'SubscriptionArn'), arn=r'([^:]+)(?::.+)?',
             lists=(('ListTopics', 'Topics', 'TopicArn'), ('ListSubscriptions', 'Subscriptions', 'TopicArn')),
             removed_by=('DeleteTopic',),
             reads=lambda w, n: [('GetTopicAttributes', {'TopicArn': topic_arn(w, n)}),
                                 ('ListSubscriptionsByTopic', {'TopicArn': topic_arn(w, n)}),
                                 ('ListTagsForResource', {'ResourceArn': topic_arn(w, n)})],
             copy=copy_topic),
]
