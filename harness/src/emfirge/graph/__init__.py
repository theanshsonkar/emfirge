"""The graph: what a change affects beyond what it touched, found in the account's own settings.

Cloud-neutral. It imports only emfirge.core and the standard library. What identifiers look like in a cloud
(addresses, generated ids) comes in as data through Vocabulary; there is no code per service or resource type.

    graph = Graph(vocabulary)
    report = graph.affects(changes, before_states, after_states)
    report.affected()   # list[Affected]: the default report
    report.unknowns()   # list[Unknown]
"""
from .index import Edge, ReferenceIndex, Strength
from .reach import ChangeReport, Graph, GraphReport, Impact, Relation
from .vocabulary import Vocabulary

__all__ = ['ChangeReport', 'Edge', 'Graph', 'GraphReport', 'Impact', 'ReferenceIndex', 'Relation', 'Strength', 'Vocabulary']
