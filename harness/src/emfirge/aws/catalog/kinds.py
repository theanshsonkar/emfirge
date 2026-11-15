"""The two-key read rule: a call is a read only when AWS's list says so AND its name starts with a plain read verb.

AWS's list calls some calls reads that change something or cost money on the account: sqs.ReceiveMessage hides
messages, logs.StartQuery runs a billed query, iam.GenerateCredentialReport makes a report. The real account is
only ever read, so a read must be certain. The verbs below were kept only where every operation that starts with
them, across all services, is a plain read (experiment 16 lists the evidence). Anything else that AWS calls a read
becomes UNKNOWN: the branch refuses it, and why() says so in plain words.

One generic rule for all services; no per-service data.
"""
from __future__ import annotations

import re

from emfirge.core.model import Kind

# Left out on evidence: Validate (some validators contact outside systems), Check and Simulate (billed policy
# checks), Verify (ds.VerifyTrust), Export (acm.ExportCertificate is billed and exports a key), Preview, Detect,
# Invoke, Start, Stop, Generate, Create, Receive, Admin, Transact.
READ_VERB = re.compile(r'^(Get|List|Describe|BatchGet|BatchDescribe|BatchList|Search|Head|Lookup|Query|Scan|Select|'
                       r'Count|View|Download|Estimate|Filter)(?![a-z])')
FIRST_WORD = re.compile(r'^[A-Z][a-z]*')


def two_key(published: Kind, operation: str) -> Kind:
    """AWS's kind, unless it is a read whose name does not start with a plain read verb."""
    if published.reads_only and not READ_VERB.match(operation):
        return Kind.UNKNOWN
    return published


def why(published: Kind | None, operation: str, action: str = '') -> str:
    """Plain words for the kind, for a refusal message."""
    if published is None or published is Kind.UNKNOWN:
        return "AWS's list does not say what this call does, so Emfirge cannot tell whether it changes anything."
    if two_key(published, operation) is Kind.UNKNOWN:
        verb = FIRST_WORD.match(operation).group(0) if FIRST_WORD.match(operation) else operation
        return (f"AWS's list calls this a {published.value}, but its name ({verb}...) says it may change something "
                f"or cost money, so Emfirge does not treat it as a read.")
    return f"AWS's list calls this a {published.value}" + (f' (action {action}).' if action else '.')
