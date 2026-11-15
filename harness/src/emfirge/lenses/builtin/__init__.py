"""The four built-in lenses. Each works on any service: generic detectors on the state diff, words as data."""
from __future__ import annotations

from typing import Callable

from emfirge.core.model import Kind

from .data import DataLens, HoldsData
from .money import MoneyLens, Price
from .permissions import PermissionsLens
from .public import PublicLens


def builtin_lenses(holds_data: HoldsData | None = None, price: Price | None = None,
                   kind_of: Callable[[str], Kind] | None = None) -> tuple[DataLens, PublicLens, MoneyLens, PermissionsLens]:
    """The built-in lenses with AWS's words. Everything passed in is optional: without it a lens says what it could
    not tell instead of guessing."""
    return DataLens(holds_data), PublicLens(), MoneyLens(price), PermissionsLens(kind_of=kind_of)


__all__ = ['DataLens', 'MoneyLens', 'PermissionsLens', 'PublicLens', 'builtin_lenses']
