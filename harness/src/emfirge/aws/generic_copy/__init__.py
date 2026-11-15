"""A Copier with no code per resource type: reads from the catalog, operations and member names from botocore's
models (see copier.py for the steps, fill.py for the name matching, plan.py for choosing the operations)."""
from .copier import Copied, GenericCopier

__all__ = ['Copied', 'GenericCopier']
