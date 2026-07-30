"""Argus — autonomous correlation recon engine.

Importing the package registers all built-in modules and exposes the
pivot engine. Add modules in modules.py (or a new file imported here) and
they auto-register into core.MODULES.
"""
from . import core, modules  # noqa: F401  (import registers the modules)
from .pivot import pivot, dossier, Budget, Graph, classify  # noqa: F401
from .core import Finding, run_module, run_all, MODULES  # noqa: F401

__version__ = "0.1.0"
