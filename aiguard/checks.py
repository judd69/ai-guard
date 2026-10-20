"""Static analyzers for AI-generated Python code.

Each check walks the AST (or the raw source for secrets) and yields
:class:`~aiguard.report.Finding` objects. Everything here is pure
standard library.
"""

from __future__ import annotations

import ast
import difflib  # noqa: F401  (kept out of the hot path; see _edit_distance_le2)
import importlib.util
import io
import re
import tokenize
from pathlib import Path
from typing import Iterator, List, Optional, Sequence

from .report import Finding, Severity

# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------

_LINE_SNIPPET_MAX = 120


def _snippet(lines: Sequence[str], lineno: int) -> str:
    if 1 <= lineno <= len(lines):
        text = lines[lineno - 1].strip()
        if len(text) > _LINE_SNIPPET_MAX:
            text = text[: _LINE_SNIPPET_MAX - 1] + "\u2026"
        return text
    return ""


def _parse(source: str) -> Optional[ast.Module]:
    try:
        return ast.parse(source)
    except (SyntaxError, ValueError):
        return None


def _dotted_name(node: ast.AST) -> Optional[str]:
    """Rebuild a dotted name like ``os.path`` / ``subprocess.run``."""
    parts: List[str] = []
    cur: Optional[ast.AST] = node
    while isinstance(cur, ast.Attribute):
        parts.append(cur.attr)
        cur = cur.value
    if isinstance(cur, ast.Name):
        parts.append(cur.id)
        return ".".join(reversed(parts))
    return None


# ---------------------------------------------------------------------------
# 1. hallucinated-imports (high)
# ---------------------------------------------------------------------------

def check_hallucinated_imports(
    tree: ast.Module, relpath: str, lines: Sequence[str]
) -> Iterator[Finding]:
    """Flag absolute imports that cannot be resolved by the interpreter.

    AI models frequently invent plausible-sounding packages
    (``import fastjson`` instead of ``ujson``). ``importlib.util.find_spec``
    resolves stdlib, installed third-party, and local modules; anything
    else is almost certainly hallucinated.
    """
    seen: set = set()
    for node in ast.walk(tree):
        name: Optional[str] = None
        if isinstance(node, ast.Import):
            for alias in node.names:
                name = alias.name.split(".")[0]
                if name not in seen:
                    seen.add(name)
                    yield from _check_import_name(name, node.lineno, relpath, lines)
        elif isinstance(node, ast.ImportFrom):
            # Skip relative imports (level > 0) — they resolve inside the package.
            if node.level and node.level > 0:
                continue
            if node.module:
                name = node.module.split(".")[0]
                if name not in seen:
                    seen.add(name)
                    yield from _check_import_name(name, node.lineno, relpath, lines)


def _check_import_name(
    name: str, lineno: int, relpath: str, lines: Sequence[str]
) -> Iterator[Finding]:
    try:
        spec = importlib.util.find_spec(name)
    except (ImportError, ValueError, AttributeError):
        spec = None
    if spec is None:
        yield Finding(
            check_id="hallucinated-imports",
            severity=Severity.HIGH,
            file=relpath,
            line=lineno,
            message=(
                f"import '{name}' cannot be resolved — it may be a "
                f"hallucinated package. Run `pip install {name}` if it is "
                f"real, otherwise remove or replace the import."
            ),
            snippet=_snippet(lines, lineno),
        )


# ---------------------------------------------------------------------------
# 2. dangerous-calls (high / critical)
# ---------------------------------------------------------------------------

_CRITICAL_CALLS = {
    "eval",
    "exec",
    "pickle.loads",
    "pickle.load",
    "marshal.loads",
    "marshal.load",
}
_HIGH_CALLS = {
    "compile",
    "os.system",
    "popen",  # os.popen
    "os.popen",
}


def check_dangerous_calls(
    tree: ast.Module, relpath: str, lines: Sequence[str]
) -> Iterator[Finding]:
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        dotted = _dotted_name(node.func)
        if dotted is None:
            continue
        base = dotted.split(".")[-1] if "." not in dotted else dotted

        # eval / exec / compile with non-literal arguments -> code injection risk
        if dotted in ("eval", "exec", "compile"):
            first = node.args[0] if node.args else None
            if first is not None and not isinstance(first, ast.Constant):
                severity = Severity.CRITICAL if dotted in ("eval", "exec") else Severity.HIGH
                yield Finding(
                    check_id="dangerous-calls",
                    severity=severity,
                    file=relpath,
                    line=node.lineno,
                    message=(
                        f"{dotted}() called with a non-literal argument — "
                        f"classic code-injection vector in AI-written code."
                    ),
                    snippet=_snippet(lines, node.lineno),
                )
            continue

        # os.system / os.popen
        if dotted in ("os.system", "os.popen"):
            yield Finding(
                check_id="dangerous-calls",
                severity=Severity.HIGH,
                file=relpath,
                line=node.lineno,
                message=(
                    f"{dotted}() invokes a shell — prefer subprocess.run() "
                    f"with a list of arguments and no shell."
                ),
                snippet=_snippet(lines, node.lineno),
            )
            continue

        # subprocess.* with shell=True
        if dotted.startswith("subprocess."):
            for kw in node.keywords:
                if kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value is True:
                    yield Finding(
                        check_id="dangerous-calls",
                        severity=Severity.HIGH,
                        file=relpath,
                        line=node.lineno,
                        message=(
                            f"{dotted}() with shell=True — shell injection "
                            f"risk if any argument is influenced by input."
                        ),
                        snippet=_snippet(lines, node.lineno),
                    )
                    break
            continue

        # pickle / marshal deserialization
        if dotted in ("pickle.loads", "pickle.load", "marshal.loads", "marshal.load"):
            yield Finding(
                check_id="dangerous-calls",
                severity=Severity.CRITICAL,
                file=relpath,
                line=node.lineno,
                message=(
                    f"{dotted}() deserializes untrusted data — arbitrary code "
                    f"execution risk. Use a safe format (e.g. JSON) instead."
                ),
                snippet=_snippet(lines, node.lineno),
            )
            continue

        # yaml.load without an explicit Loader
        if dotted in ("yaml.load", "yaml.unsafe_load"):
            has_loader = any(kw.arg == "Loader" for kw in node.keywords)
            if not has_loader:
                yield Finding(
                    check_id="dangerous-calls",
                    severity=Severity.HIGH,
                    file=relpath,
                    line=node.lineno,
                    message=(
                        "yaml.load() without Loader=yaml.SafeLoader can "
                        "construct arbitrary Python objects."
                    ),
                    snippet=_snippet(lines, node.lineno),
                )
            continue


# ---------------------------------------------------------------------------
# 3. secrets (critical) — regex over raw source
# ---------------------------------------------------------------------------

_PLACEHOLDER_RE = re.compile(
    r"(xxx+|example|test|changeme|placeholder|dummy|fake|sample|todo|your[_-]?key|none|null)",
    re.IGNORECASE,
)

_SECRET_PATTERNS = [
    ("AWS access key", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("GitHub token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b")),
    ("OpenAI-style API key", re.compile(r"\bsk-[A-Za-z0-9_\-]{20,}\b")),
    (
        "hardcoded credential",
        re.compile(
            r"(?i)\b(api[_-]?key|secret[_-]?key|client[_-]?secret|password|passwd|"
            r"auth[_-]?token|access[_-]?token)\b\s*[:=]\s*['\"]([^'\"]{8,})['\"]"
        ),
    ),
]


def _looks_like_placeholder(value: str) -> bool:
    return bool(_PLACEHOLDER_RE.search(value))


def check_secrets(
    source: str, relpath: str, lines: Sequence[str]
) -> Iterator[Finding]:
    flagged_lines: set = set()  # one finding per line: patterns can overlap
    for label, pattern in _SECRET_PATTERNS:
        for match in pattern.finditer(source):
            lineno = source.count("\n", 0, match.start()) + 1
            if lineno in flagged_lines:
                continue
            matched = match.group(0)
            # For the generic pattern, group(2) is the credential value.
            value = match.group(2) if match.lastindex == 2 else matched
            if _looks_like_placeholder(value):
                continue
            flagged_lines.add(lineno)
            yield Finding(
                check_id="secrets",
                severity=Severity.CRITICAL,
                file=relpath,
                line=lineno,
                message=(
                    f"possible {label} committed in source — rotate it and "
                    f"move it to an environment variable or secret store."
                ),
                snippet=_redact(_snippet(lines, lineno)),
            )


def _redact(snippet: str) -> str:
    """Mask the secret-looking tail of a snippet so reports stay safe."""
    return re.sub(r"(['\"])[^'\"]{6,}(['\"])", r"\1***redacted***\2", snippet)


# ---------------------------------------------------------------------------
# 4. weak-error-handling (medium)
# ---------------------------------------------------------------------------

def check_weak_error_handling(
    tree: ast.Module, relpath: str, lines: Sequence[str]
) -> Iterator[Finding]:
    for node in ast.walk(tree):
        if not isinstance(node, ast.ExceptHandler):
            continue
        if node.type is None:
            yield Finding(
                check_id="weak-error-handling",
                severity=Severity.MEDIUM,
                file=relpath,
                line=node.lineno,
                message="bare `except:` swallows everything, including "
                "KeyboardInterrupt — catch a specific exception instead.",
                snippet=_snippet(lines, node.lineno),
            )
            continue
        type_name = _dotted_name(node.type)
        if type_name == "Exception" and len(node.body) == 1 and isinstance(
            node.body[0], (ast.Pass, ast.Continue)
        ):
            verb = "pass" if isinstance(node.body[0], ast.Pass) else "continue"
            yield Finding(
                check_id="weak-error-handling",
                severity=Severity.MEDIUM,
                file=relpath,
                line=node.lineno,
                message=f"`except Exception: {verb}` silently discards errors — "
                "log the exception or handle it explicitly.",
                snippet=_snippet(lines, node.lineno),
            )


# ---------------------------------------------------------------------------
# 5. network-safety (medium)
# ---------------------------------------------------------------------------

_REQUESTS_METHODS = {
    "get", "post", "put", "delete", "patch", "head", "options", "request",
}


def _has_kw(call: ast.Call, name: str) -> bool:
    return any(kw.arg == name for kw in call.keywords)


def check_network_safety(
    tree: ast.Module, relpath: str, lines: Sequence[str]
) -> Iterator[Finding]:
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        dotted = _dotted_name(node.func)
        if dotted is None:
            continue

        # requests.<method>(...) without timeout=
        if dotted.startswith("requests."):
            method = dotted.split(".", 1)[1]
            if method in _REQUESTS_METHODS and not _has_kw(node, "timeout"):
                yield Finding(
                    check_id="network-safety",
                    severity=Severity.MEDIUM,
                    file=relpath,
                    line=node.lineno,
                    message=f"requests.{method}() without timeout= can hang "
                    "forever — pass an explicit timeout.",
                    snippet=_snippet(lines, node.lineno),
                )

        # urllib without timeout
        if dotted in ("urllib.request.urlopen", "urlopen") and not _has_kw(node, "timeout"):
            yield Finding(
                check_id="network-safety",
                severity=Severity.MEDIUM,
                file=relpath,
                line=node.lineno,
                message="urlopen() without timeout= can hang forever — pass "
                "an explicit timeout.",
                snippet=_snippet(lines, node.lineno),
            )

        # disabled TLS verification
        if dotted == "ssl._create_unverified_context":
            yield Finding(
                check_id="network-safety",
                severity=Severity.MEDIUM,
                file=relpath,
                line=node.lineno,
                message="ssl._create_unverified_context() disables TLS "
                "certificate verification — vulnerable to MITM attacks.",
                snippet=_snippet(lines, node.lineno),
            )

        # verify=False anywhere
        for kw in node.keywords:
            if kw.arg == "verify" and isinstance(kw.value, ast.Constant) and kw.value.value is False:
                yield Finding(
                    check_id="network-safety",
                    severity=Severity.MEDIUM,
                    file=relpath,
                    line=node.lineno,
                    message="verify=False disables TLS verification — "
                    "vulnerable to MITM attacks.",
                    snippet=_snippet(lines, node.lineno),
                )
                break


# ---------------------------------------------------------------------------
# 6. ai-tells (low)
# ---------------------------------------------------------------------------

_AI_TELL_RE = re.compile(
    r"(?i)\b(todo|fixme|xxx|hack|lorem ipsum)\b|rest of the code|"
    r"implement (this|the rest)|code goes here|your code here|"
    r"placeholder",
)


def check_ai_tells(
    source: str, relpath: str, lines: Sequence[str]
) -> Iterator[Finding]:
    # Leftover placeholder comments via the tokenizer (accurate, no false
    # positives inside string literals).
    try:
        tokens = tokenize.generate_tokens(io.StringIO(source).readline)
        for tok in tokens:
            if tok.type == tokenize.COMMENT and _AI_TELL_RE.search(tok.string):
                yield Finding(
                    check_id="ai-tells",
                    severity=Severity.LOW,
                    file=relpath,
                    line=tok.start[0],
                    message="leftover AI placeholder comment — finish or "
                    "remove it before shipping.",
                    snippet=_snippet(lines, tok.start[0]),
                )
    except (tokenize.TokenError, IndentationError, SyntaxError):
        pass

    # Suspiciously long lines are typical of pasted AI output.
    for lineno, line in enumerate(lines, start=1):
        if len(line.rstrip("\n")) > 140:
            yield Finding(
                check_id="ai-tells",
                severity=Severity.LOW,
                file=relpath,
                line=lineno,
                message=f"line is {len(line.rstrip())} chars (>140) — "
                "typical of pasted AI output; consider wrapping it.",
                snippet=_snippet(lines, lineno),
            )


# ---------------------------------------------------------------------------
# 7. risky-deps (medium / low)
# ---------------------------------------------------------------------------

# ~40 of the most-downloaded PyPI packages; a near-miss against one of
# these is very likely a typosquat.
_POPULAR_PACKAGES = [
    "requests", "urllib3", "numpy", "pandas", "flask", "django", "fastapi",
    "sqlalchemy", "pytest", "boto3", "click", "redis", "celery", "pillow",
    "matplotlib", "scipy", "scikit-learn", "tensorflow", "torch",
    "transformers", "langchain", "openai", "anthropic", "pydantic",
    "uvicorn", "gunicorn", "aiohttp", "httpx", "beautifulsoup4", "lxml",
    "pyyaml", "python-dotenv", "tqdm", "rich", "typer", "jinja2",
    "werkzeug", "psycopg2-binary", "pymongo", "cryptography", "packaging",
]

_REQ_LINE_RE = re.compile(r"^\s*([A-Za-z0-9_.\-]+)\s*(.*)$")


def _normalize(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def _edit_distance_le2(a: str, b: str) -> bool:
    """True if Levenshtein(a, b) <= 2, with an early-exit banded DP."""
    if a == b:
        return True
    if abs(len(a) - len(b)) > 2:
        return False
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i] + [0] * len(b)
        row_min = cur[0]
        for j, cb in enumerate(b, 1):
            cost = 0 if ca == cb else 1
            cur[j] = min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + cost)
            row_min = min(row_min, cur[j])
        if row_min > 2:
            return False
        prev = cur
    return prev[-1] <= 2


def _parse_requirement_line(line: str) -> Optional[tuple]:
    """Return (name, pinned: bool) or None for comments/blank lines."""
    line = line.strip()
    if not line or line.startswith(("#", "-")):
        return None
    line = line.split(";", 1)[0].strip()  # drop environment markers
    match = _REQ_LINE_RE.match(line)
    if not match:
        return None
    name, rest = match.group(1), match.group(2).strip()
    rest = re.sub(r"\[.*?\]", "", rest).strip()  # drop extras
    pinned = bool(rest)  # any version specifier counts as pinned
    return name, pinned


def _deps_from_requirements(path: Path) -> List[tuple]:
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []
    deps = []
    for line in text.splitlines():
        parsed = _parse_requirement_line(line)
        if parsed:
            deps.append(parsed)
    return deps


def _deps_from_pyproject(path: Path) -> List[tuple]:
    """Minimal hand-rolled parse of [project] dependencies (no tomllib on 3.9)."""
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []
    in_project = False
    in_deps: Optional[int] = None  # bracket depth while inside dependencies list
    deps: List[tuple] = []
    for raw in text.splitlines():
        line = raw.strip()
        if line.startswith("["):
            in_project = line == "[project]"
            in_deps = None
            continue
        if not in_project:
            continue
        if in_deps is None:
            m = re.match(r"dependencies\s*=\s*\[(.*)$", line)
            if m:
                in_deps = 1 + m.group(1).count("[") - m.group(1).count("]")
                for s in re.findall(r"""['"]([^'"]+)['"]""", m.group(1)):
                    parsed = _parse_requirement_line(s)
                    if parsed:
                        deps.append(parsed)
                if in_deps <= 0:
                    in_deps = None
        else:
            in_deps += line.count("[") - line.count("]")
            for s in re.findall(r"""['"]([^'"]+)['"]""", line):
                parsed = _parse_requirement_line(s)
                if parsed:
                    deps.append(parsed)
            if in_deps <= 0:
                in_deps = None
    return deps


def check_risky_deps(root: Path, relpath: str = "") -> Iterator[Finding]:
    """Scan requirements*.txt / pyproject.toml found directly in *root*."""
    dep_files: List[tuple] = []  # (display_name, deps)
    for req in sorted(root.glob("requirements*.txt")):
        dep_files.append((req.name, _deps_from_requirements(req)))
    pyproject = root / "pyproject.toml"
    if pyproject.is_file():
        dep_files.append(("pyproject.toml", _deps_from_pyproject(pyproject)))

    popular = {_normalize(p): p for p in _POPULAR_PACKAGES}
    for display, deps in dep_files:
        for name, pinned in deps:
            norm = _normalize(name)
            if norm in popular:
                if not pinned:
                    yield Finding(
                        check_id="risky-deps",
                        severity=Severity.LOW,
                        file=str(Path(display)),
                        line=0,
                        message=f"dependency '{name}' is unpinned — pin it "
                        "to a known-good version for reproducible builds.",
                        snippet="",
                    )
                continue
            for pop_norm, pop_name in popular.items():
                if _edit_distance_le2(norm, pop_norm):
                    yield Finding(
                        check_id="risky-deps",
                        severity=Severity.MEDIUM,
                        file=str(Path(display)),
                        line=0,
                        message=f"dependency '{name}' looks like a typosquat "
                        f"of '{pop_name}' (edit distance ≤ 2) — verify it "
                        "is the package you intended.",
                        snippet="",
                    )
                    break
            else:
                if not pinned:
                    yield Finding(
                        check_id="risky-deps",
                        severity=Severity.LOW,
                        file=str(Path(display)),
                        line=0,
                        message=f"dependency '{name}' is unpinned — pin it "
                        "to a known-good version for reproducible builds.",
                        snippet="",
                    )


# ---------------------------------------------------------------------------
# orchestration
# ---------------------------------------------------------------------------

def scan_file(path: Path, root: Path) -> List[Finding]:
    """Run all per-file checks on one Python file."""
    try:
        source = path.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        return [
            Finding(
                check_id="read-error",
                severity=Severity.LOW,
                file=str(path.relative_to(root)),
                line=0,
                message=f"could not read file: {exc}",
                snippet="",
            )
        ]
    relpath = str(path.relative_to(root))
    lines = source.splitlines()
    findings: List[Finding] = []
    findings.extend(check_secrets(source, relpath, lines))
    findings.extend(check_ai_tells(source, relpath, lines))
    tree = _parse(source)
    if tree is not None:
        findings.extend(check_hallucinated_imports(tree, relpath, lines))
        findings.extend(check_dangerous_calls(tree, relpath, lines))
        findings.extend(check_weak_error_handling(tree, relpath, lines))
        findings.extend(check_network_safety(tree, relpath, lines))
    findings.sort(key=lambda f: (f.line, f.check_id))
    return findings


def scan_path(target: Path, exclude: Sequence[str] = ()) -> List[Finding]:
    """Scan a file or a directory (recursively) for ``.py`` files."""
    target = target.resolve()
    root = target if target.is_dir() else target.parent
    findings: List[Finding] = []
    if target.is_file():
        findings.extend(scan_file(target, root))
    else:
        for py in sorted(target.rglob("*.py")):
            rel = str(py.relative_to(target))
            if any(py.match(pat) or Path(rel).match(pat) for pat in exclude):
                continue
            findings.extend(scan_file(py, target))
        findings.extend(check_risky_deps(target))
    findings.sort(key=lambda f: (str(f.file), f.line, f.check_id))
    return findings
