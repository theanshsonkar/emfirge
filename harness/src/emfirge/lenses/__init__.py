"""Lenses: facts about what a branch holds, one concern each, only what the change makes new. Cloud-neutral: this
package imports only emfirge.core and the standard library; one cloud's words come in as data (builtin/patterns.py)."""
from .api import Lens, LensResult, LensView, run_lenses
from .builtin import DataLens, MoneyLens, PermissionsLens, PublicLens, builtin_lenses
from .external import ExternalLens, json_records, text_lines

__all__ = ['DataLens', 'ExternalLens', 'Lens', 'LensResult', 'LensView', 'MoneyLens', 'PermissionsLens', 'PublicLens',
           'builtin_lenses', 'json_records', 'run_lenses', 'text_lines']
