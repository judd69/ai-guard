# AIGuard 🛡️

**A fast, offline static analyzer that audits AI-generated Python code — so you can ship AI-written code you actually understand.**

AI coding assistants are everywhere, and teams routinely merge code they never fully read. A recent Hacker News discussion ("how to deal with shipping AI-written code you don't understand") captured the anxiety perfectly: the code *looks* right, passes a skim review, and then `eval(user_input)` goes to production. AIGuard is a five-second sanity check that runs before the PR does — no network, no dependencies, no excuses.

## What it does

Point AIGuard at a file or directory and it runs 7 AST/regex-based checks over your `.py` files:

| Check | Severity | What it catches |
|---|---|---|
| `hallucinated-imports` | high | Imports the interpreter can't resolve (e.g. `import fastjson`) — the classic AI confabulation, with a `pip install` hint |
| `dangerous-calls` | high / critical | `eval`/`exec` with non-literal args, `os.system`, `subprocess(..., shell=True)`, `pickle`/`marshal` deserialization, `yaml.load()` without a `Loader` |
| `secrets` | critical | AWS keys, GitHub tokens, OpenAI-style keys, hardcoded `api_key`/`password` assignments (placeholder values like `xxx`/`changeme` are skipped; findings are redacted in output) |
| `weak-error-handling` | medium | Bare `except:`, `except Exception: pass` / `continue` |
| `network-safety` | medium | `requests.*` / `urlopen` without `timeout=`, `verify=False`, `ssl._create_unverified_context()` |
| `ai-tells` | low | Leftover `TODO`/`FIXME`/"rest of the code" placeholder comments, >140-char pasted lines |
| `risky-deps` | medium / low | Typosquatted packages in `requirements*.txt` / `pyproject.toml` (edit distance ≤ 2 against ~40 popular PyPI packages, e.g. `requets` → `requests`) and unpinned dependencies |

## Install

Requires Python 3.9+, zero third-party dependencies.

```bash
pip install .
# or, isolated:
pipx install .
```

## Usage

```bash
# Scan a directory (recursive) — human-readable report
aiguard scan ./src

# Scan a single file, machine-readable JSON
aiguard scan app.py --json

# Only show medium and above; fail CI on high+
aiguard scan ./src --min-severity medium --fail-on high

# Skip generated code
aiguard scan ./src --exclude 'migrations/*' --exclude 'vendor/*'
```

Exit codes: `0` = pass, `2` = findings at/above `--fail-on` (default `high`), `1` = usage/runtime error.

### Example output

Running `aiguard scan tests/fixtures` on the bundled fixtures produces (real output, exit code 2):

```
AIGuard scan: tests/fixtures
============================================================

--- bad_code.py ---
[high]     hallucinated-imports  bad_code.py:3
           import 'fastjson' cannot be resolved — it may be a hallucinated package. Run `pip install fastjson` if it is real, otherwise remove or replace the import.
           > import fastjson  # hallucinated: not a real package
[critical] secrets  bad_code.py:8
           possible OpenAI-style API key committed in source — rotate it and move it to an environment variable or secret store.
           > API_KEY = "***redacted***"  # leaked secret
[critical] secrets  bad_code.py:10
           possible AWS access key committed in source — rotate it and move it to an environment variable or secret store.
           > REAL_AWS = "***redacted***"  # leaked secret
[critical] dangerous-calls  bad_code.py:15
           eval() called with a non-literal argument — classic code-injection vector in AI-written code.
           > return eval(query)  # dangerous: non-literal eval
[critical] dangerous-calls  bad_code.py:19
           pickle.loads() deserializes untrusted data — arbitrary code execution risk. Use a safe format (e.g. JSON) instead.
           > return pickle.loads(blob)  # dangerous: pickle deserialization
[medium]   network-safety  bad_code.py:23
           requests.get() without timeout= can hang forever — pass an explicit timeout.
           > return requests.get(url)  # network: missing timeout
[medium]   network-safety  bad_code.py:27
           verify=False disables TLS verification — vulnerable to MITM attacks.
           > return requests.get(url, verify=False, timeout=5)  # network: verify=False
[high]     dangerous-calls  bad_code.py:31
           os.system() invokes a shell — prefer subprocess.run() with a list of arguments and no shell.
           > os.system(cmd)  # dangerous: shell
[medium]   weak-error-handling  bad_code.py:37
           bare `except:` swallows everything, including KeyboardInterrupt — catch a specific exception instead.
           > except:  # weak: bare except
[medium]   weak-error-handling  bad_code.py:45
           `except Exception: continue` silently discards errors — log the exception or handle it explicitly.
           > except Exception:  # weak: swallowed exception
[low]      ai-tells  bad_code.py:49
           leftover AI placeholder comment — finish or remove it before shipping.
           > # TODO: rest of the code goes here, implement this later  (ai-tell comment)
[low]      ai-tells  bad_code.py:51
           line is 173 chars (>140) — typical of pasted AI output; consider wrapping it.
           > x = "this is a very long line that goes on and on and on and on and on and on and on and on and on and on and on and on…

--- requirements.txt ---
[medium]   risky-deps  requirements.txt
           dependency 'requets' looks like a typosquat of 'requests' (edit distance ≤ 2) — verify it is the package you intended.
[low]      risky-deps  requirements.txt
           dependency 'numpy' is unpinned — pin it to a known-good version for reproducible builds.
[medium]   risky-deps  requirements.txt
           dependency 'djang' looks like a typosquat of 'django' (edit distance ≤ 2) — verify it is the package you intended.
[low]      risky-deps  requirements.txt
           dependency 'flask' is unpinned — pin it to a known-good version for reproducible builds.

Summary
------------------------------------------------------------
16 finding(s): low=4, medium=6, high=2, critical=4
```

## Use in CI

Drop this into `.github/workflows/aiguard.yml` to audit every PR:

```yaml
name: AIGuard
on: [push, pull_request]
jobs:
  audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: "3.12"
      - run: pip install .
      - run: aiguard scan . --fail-on high
```

## Limitations

- Python only (for now) — it parses Python AST, so other languages are out of scope.
- Heuristic, not a proof: secret regexes can miss exotic formats, and the typosquat list covers ~40 popular packages.
- `hallucinated-imports` resolves against *your* environment — run it in the project's venv for accurate results.
- It won't catch logic bugs. It catches the *shape* of careless AI output: the dangerous calls, the leaked keys, the imports that don't exist.

## License

MIT — see [LICENSE](LICENSE).

---

Built by **Jude (judd69)** · Day 1 of shipping one project every day.
