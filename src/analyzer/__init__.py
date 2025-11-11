# This file makes 'scanner' a Python package and controls what is exposed when
# other files (like app/app.py) use 'from scanner import ...'

# Expose essential data models from scanner/models.py
# We use try/except blocks here because models.py (and others) don't exist yet,
# but this structure is prepared for when they do.

try:
    from .models import Severity, Finding, VulnerabilityReport
except ImportError:
    pass

# Expose the core scanning functions from scanner/core.py
try:
    from .core import scan_file, scan_directory
except ImportError:
    pass

# Expose the base rule classes from scanner/rules.py
try:
    from .rules import BaseRule
except ImportError:
    pass

# Define modules to be loaded
__all__ = [
    "Severity",
    "Finding",
    "VulnerabilityReport",
    "scan_file",
    "scan_directory",
    "BaseRule",
]
