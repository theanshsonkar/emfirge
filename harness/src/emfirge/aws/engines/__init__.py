"""Engines: local fakes of AWS that answer a branch's changes, started and stopped as subprocesses. Each one is a
core.ports.Engine; nothing above this package may know which one runs."""
from .emulator import EmulatorEngine
from .moto import MotoEngine

__all__ = ['EmulatorEngine', 'MotoEngine']
