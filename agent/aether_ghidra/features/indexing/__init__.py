"""Persistent whole-program function indexing for AETHER."""

from .model import FunctionEntry, FunctionIndex
from .manager import FunctionIndexManager

__all__ = ["FunctionEntry", "FunctionIndex", "FunctionIndexManager"]
