import ast
import re
import time
import threading
from io import StringIO

SHELL_PATTERNS = [
    r"__import__\s*\(",
    r"\bexec\s*\(",
    r"\beval\s*\(",
    r"\bopen\s*\(",
    r"__builtins__",
    r"__class__\s*\.\s*__bases__",
    r"__subclasses__\s*\(",
    r"__globals__",
    r"__code__",
    r"__reduce__",
    r"rm\s+-rf",
    r"os\.system",
    r"os\.popen",
    r"subprocess\.",
    r"socket\.",
    r"\bcompile\s*\(",
    r"\bgetattr\s*\(",
    r"\bsetattr\s*\(",
    r"\bdelattr\s*\(",
    r"\bvars\s*\(",
    r"\bdir\s*\(",
    r"\bglobals\s*\(",
    r"\blocals\s*\(",
]

BLOCKED_AST_NODES = (
    ast.Import,
    ast.ImportFrom,
    ast.Global,
    ast.Nonlocal,
    ast.AsyncFunctionDef,
    ast.AsyncFor,
    ast.AsyncWith,
    ast.Await,
)


class SecurityViolation(Exception):
    def __init__(self, rule, severity, detail):
        self.rule = rule
        self.severity = severity
        self.detail = detail
        super().__init__(f"[{severity}] {rule}: {detail}")


def static_analyze(code: str):
    for pattern in SHELL_PATTERNS:
        if re.search(pattern, code, re.IGNORECASE):
            raise SecurityViolation(
                "REGEX_BLOCK", "CRITICAL",
                f"Dangerous pattern detected: {pattern}"
            )
    try:
        tree = ast.parse(code)
    except SyntaxError as e:
        raise SecurityViolation("SYNTAX_ERROR", "LOW", str(e))

    for node in ast.walk(tree):
        if isinstance(node, BLOCKED_AST_NODES):
            raise SecurityViolation(
                "AST_BLOCK", "HIGH",
                f"Forbidden AST node: {type(node).__name__}"
            )
        if isinstance(node, ast.Attribute):
            if node.attr.startswith("__") and node.attr.endswith("__"):
                raise SecurityViolation(
                    "DUNDER_ACCESS", "CRITICAL",
                    f"Access to dunder attribute blocked: {node.attr}"
                )


def execute_safe(code: str, timeout_sec: int = 5) -> dict:
    static_analyze(code)

    result = {
        "output": "",
        "error": None,
        "status": "ok",
        "time_ms": 0,
    }

    captured_output = StringIO()
    exec_exception = [None]
    exec_done = [False]

    def safe_print(*args, **kwargs):
        kwargs.pop("file", None)
        kwargs.pop("flush", None)
        end = kwargs.pop("end", "\n")
        sep = kwargs.pop("sep", " ")
        text = sep.join(str(a) for a in args) + end
        captured_output.write(text)
        if captured_output.tell() > 10240:
            raise SecurityViolation(
                "OUTPUT_LIMIT", "MEDIUM",
                "Output exceeded 10KB limit"
            )

    safe_globals = {
        "__builtins__": {
            "print":      safe_print,
            "len":        len,
            "range":      range,
            "sum":        sum,
            "sorted":     sorted,
            "reversed":   reversed,
            "list":       list,
            "dict":       dict,
            "set":        set,
            "tuple":      tuple,
            "str":        str,
            "int":        int,
            "float":      float,
            "bool":       bool,
            "abs":        abs,
            "max":        max,
            "min":        min,
            "round":      round,
            "pow":        pow,
            "divmod":     divmod,
            "enumerate":  enumerate,
            "zip":        zip,
            "map":        map,
            "filter":     filter,
            "type":       type,
            "isinstance": isinstance,
            "repr":       repr,
            "any":        any,
            "all":        all,
            "chr":        chr,
            "ord":        ord,
            "hex":        hex,
            "oct":        oct,
            "bin":        bin,
            "format":     format,
        },
        "__name__": "__sandbox__",
    }

    def run_code():
        try:
            exec(compile(code, "<sandbox>", "exec"), safe_globals)
            exec_done[0] = True
        except SecurityViolation as e:
            exec_exception[0] = e
            exec_done[0] = True
        except MemoryError:
            exec_exception[0] = MemoryError("Memory limit exceeded")
            exec_done[0] = True
        except Exception as e:
            exec_exception[0] = e
            exec_done[0] = True

    start = time.time()
    thread = threading.Thread(target=run_code, daemon=True)
    thread.start()
    thread.join(timeout=timeout_sec)

    result["time_ms"] = round((time.time() - start) * 1000)

    if not exec_done[0]:
        result["status"] = "timeout"
        result["error"] = "Execution exceeded time limit (5 seconds)"
        return result

    if exec_exception[0] is not None:
        e = exec_exception[0]
        if isinstance(e, SecurityViolation):
            raise e
        elif isinstance(e, MemoryError):
            result["status"] = "memory_exceeded"
            result["error"] = str(e)
        else:
            result["status"] = "runtime_error"
            result["error"] = f"{type(e).__name__}: {str(e)}"
        return result

    result["status"] = "ok"
    result["output"] = captured_output.getvalue()
    return result
