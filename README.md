
# Controlled Execution Sandbox

A security-focused Python code execution sandbox that safely runs untrusted user input inside a controlled environment. Built with Flask, AST analysis, and multi-layer security controls.

---

## What It Does

This system accepts Python code as input, analyzes it for dangerous patterns, and either executes it safely inside a restricted environment or blocks it with a detailed violation report. All execution attempts are logged with severity levels and displayed in a real-time web UI.

---

## Features

- Multi-layer security: Regex filtering, AST analysis, and restricted builtins
- Real-time web UI with dark terminal theme
- Violation logging with severity levels (LOW / MEDIUM / HIGH / CRITICAL)
- Execution timeout watchdog (5 second limit)
- Output size limit (10KB cap)
- Live stats dashboard (total runs, allowed, blocked, timeouts)
- REST API for programmatic access
- Comprehensive safe and unsafe test suites

---

## Security Layers

### Layer 1 — Regex Pattern Matching
Scans raw input for known dangerous patterns before any parsing occurs.

Blocked patterns include:
- `__import__()` calls
- `exec()` and `eval()` calls
- `open()` file access
- `os.system`, `os.popen`
- `subprocess.*`
- `socket.*`
- `compile()`, `getattr()`, `setattr()`
- `globals()`, `locals()`, `vars()`, `dir()`
- Shell commands like `rm -rf`

### Layer 2 — AST (Abstract Syntax Tree) Analysis
Parses the code into a syntax tree and inspects every node for forbidden structures.

Blocked AST nodes:
- `ast.Import` and `ast.ImportFrom` — blocks all import statements
- `ast.Global` and `ast.Nonlocal` — blocks scope escaping
- `ast.AsyncFunctionDef`, `ast.AsyncFor`, `ast.AsyncWith`, `ast.Await` — blocks async operations
- Dunder attribute access (`__class__`, `__bases__`, `__subclasses__`, etc.)

### Layer 3 — Restricted Builtins
Code executes with a custom `__builtins__` whitelist. Only safe functions are available.

Allowed builtins:
```
print, len, range, sum, sorted, reversed, list, dict, set, tuple,
str, int, float, bool, abs, max, min, round, pow, divmod,
enumerate, zip, map, filter, type, isinstance, repr,
any, all, chr, ord, hex, oct, bin, format
```

Everything else (os, sys, open, exec, eval, etc.) is completely unavailable.

### Layer 4 — Execution Watchdog
Each execution runs in a daemon thread with a 5-second timeout. If execution does not complete in time, the thread is abandoned and a timeout response is returned.

---

## Project Structure
```
sandbox-project/
├── sandbox_core.py       # Security engine (analysis + execution)
├── server.py             # Flask REST API server
├── static/
│   └── index.html        # Web UI
├── tests/
│   ├── safe_tests.py     # Tests that should pass
│   └── unsafe_tests.py   # Tests that should be blocked
├── logs/
│   └── violations.log    # Audit trail of all violations
└── README.md
```

---

## Requirements

- Python 3.10+
- Kali Linux / Ubuntu / Debian
- pip packages: flask, flask-cors, psutil, requests

---

## Installation

### Step 1 — Clone the repository
```bash
git clone https://github.com/YOUR_USERNAME/sandbox-project.git
cd sandbox-project
```

### Step 2 — Create virtual environment
```bash
python3 -m venv ~/sandbox-env
source ~/sandbox-env/bin/activate
```

### Step 3 — Install dependencies
```bash
pip install flask flask-cors psutil requests
```

### Step 4 — Run the server
```bash
python server.py
```

### Step 5 — Open the web UI
```
http://127.0.0.1:5000
```

---

## API Reference

### POST /execute
Submit Python code for sandboxed execution.

**Request:**
```json
{
  "code": "print(sum(range(10)))"
}
```

**Response (allowed):**
```json
{
  "status": "ok",
  "output": "45\n",
  "error": null,
  "time_ms": 2
}
```

**Response (blocked):**
```json
{
  "status": "blocked",
  "violation": "AST_BLOCK",
  "severity": "HIGH",
  "message": "Forbidden AST node: Import"
}
```

**Response (timeout):**
```json
{
  "status": "timeout",
  "output": "",
  "error": "Execution exceeded time limit (5 seconds)",
  "time_ms": 5001
}
```

### GET /stats
Returns execution statistics.
```json
{
  "total": 10,
  "allowed": 6,
  "blocked": 3,
  "timeout": 1,
  "errors": 0
}
```

### GET /health
Returns server health status.
```json
{
  "status": "running",
  "sandbox": "active"
}
```

---

## Running Tests
```bash
source ~/sandbox-env/bin/activate

# Test safe inputs (should all pass)
python tests/safe_tests.py

# Test unsafe inputs (should all be blocked)
python tests/unsafe_tests.py
```

### Safe test cases
| Test | Code | Expected |
|------|------|----------|
| Basic print | `print('Hello')` | ok |
| Arithmetic | `print(2 + 2 * 10)` | ok |
| Sum of range | `print(sum(range(10)))` | ok |
| For loop | `for i in range(5): print(i)` | ok |
| Functions | `def add(a,b): return a+b` | ok |
| List sorting | `sorted([5,3,1,8])` | ok |
| Fibonacci | `a,b=0,1 ...` | ok |

### Unsafe test cases
| Attack | Code | Expected |
|--------|------|----------|
| Read passwd | `open('/etc/passwd').read()` | BLOCKED |
| Import OS | `import os` | BLOCKED |
| OS command | `os.system('whoami')` | BLOCKED |
| Subprocess | `import subprocess` | BLOCKED |
| Network socket | `import socket` | BLOCKED |
| __import__ bypass | `__import__('os')` | BLOCKED |
| Eval injection | `eval('...')` | BLOCKED |
| Exec injection | `exec('...')` | BLOCKED |
| Dunder escape | `''.__class__.__bases__` | BLOCKED |
| Infinite loop | `while True: pass` | TIMEOUT |
| Memory bomb | `x = [0] * 999999999` | BLOCKED |
| Fork bomb | `import os; os.fork()` | BLOCKED |
| Read shadow | `open('/etc/shadow')` | BLOCKED |
| Globals escape | `globals()` | BLOCKED |

---

## How Violations Are Handled

| Severity | Meaning | Example |
|----------|---------|---------|
| CRITICAL | Immediate system threat | `os.system`, `__import__`, dunder access |
| HIGH | Dangerous code structure | `import` statements, `exec`, `eval` |
| MEDIUM | Resource abuse | Output limit exceeded, large allocations |
| LOW | Syntax or parse error | Invalid Python syntax |

All violations are:
1. Returned to the user with rule name, severity, and detail
2. Logged to `logs/violations.log` with timestamp and input
3. Counted in the stats dashboard

---

## Screenshots

> Web UI showing safe execution:
> - Green `[OK]` status
> - Output displayed in blue
> - Execution time shown in milliseconds

> Web UI showing blocked execution:
> - Red `[BLOCKED]` status
> - Violation rule and severity displayed
> - Entry added to violation log panel

---

## Limitations

- Timeout uses `threading.Thread.join()` — daemon threads cannot be forcibly killed in Python, so a truly infinite loop thread will linger until the server restarts
- No containerization (Docker would add a stronger OS-level isolation layer)
- No persistent storage for violation logs across server restarts (logs are written to file but stats reset on restart)

---

## Future Improvements

- Docker container isolation for true OS-level sandboxing
- Persistent stats database using SQLite
- Rate limiting per IP address
- Support for multiple languages (JavaScript, Bash)
- WebSocket support for real-time streaming output
- Admin dashboard for violation analysis

---

## License

MIT License — free to use, modify, and distribute.

---

## Author

Built as part of a Controlled Execution Sandbox security project.
Tested on Kali Linux inside VirtualBox.
