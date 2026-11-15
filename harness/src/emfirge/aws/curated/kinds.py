"""What a call does, by the operation's name: experiment 09's rule, kept in one function so it can be dropped when
the generic catalog gives kinds from AWS's own list of actions."""
from __future__ import annotations

import re

from emfirge.core.model import Kind

_READ = re.compile(r'^(Get|Describe|Head|BatchGet|Lookup|Search)[A-Z]|^(Query|Scan)$')
_LIST = re.compile(r'^List[A-Z]')
_PERMISSION = re.compile(r'Polic(y|ies)|Permission|^(Add|Remove)(Role|User)|Grant|AccessBlock|Acl$')
_TAGGING = re.compile(r'^(Tag|Untag)[A-Z]|^(Add|Remove)Tags|^(Put|Delete)\w*Tagging$|^(Create|Delete)Tags$')


def kind_of(operation: str) -> Kind:
    """READ / LIST by name; every other operation changes something. An Invoke runs the customer's own code, whose
    effects on the account cannot be told from the call: UNKNOWN (refused), never a read."""
    if 'Invoke' in operation:
        return Kind.UNKNOWN
    if _LIST.match(operation):
        return Kind.LIST
    if _READ.match(operation):
        return Kind.READ
    if _TAGGING.search(operation):
        return Kind.TAGGING
    if _PERMISSION.search(operation):
        return Kind.PERMISSION
    return Kind.WRITE
