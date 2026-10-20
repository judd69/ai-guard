"""AIGuard — a fast, offline static analyzer that audits AI-generated code.

Scans Python source for hallucinated imports, dangerous calls, leaked
secrets, weak error handling, unsafe network usage, AI "tells", and
risky dependencies. Pure standard library, zero third-party deps.
"""

__version__ = "0.1.0"

from .checks import Severity, scan_file, scan_path
from .report import Finding, render_text, render_json

__all__ = [
    "__version__",
    "Severity",
    "scan_file",
    "scan_path",
    "Finding",
    "render_text",
    "render_json",
]
