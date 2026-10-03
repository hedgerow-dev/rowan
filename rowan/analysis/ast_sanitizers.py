"""AST-based sanitizer detection to augment regex-based taint analysis.

Three techniques:
1. Constant dict allowlist: SAFE_MAP[key] where all values are constants
2. Pydantic validated class: BaseModel subclasses with validators
3. UPPER_CASE constant resolution: module-level string constants
"""

from __future__ import annotations

import ast


def _base_name(node: ast.expr) -> str | None:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return node.attr
    return None


def _decorator_name(node: ast.expr) -> str | None:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return node.attr
    if isinstance(node, ast.Call):
        return _decorator_name(node.func)
    return None


def collect_safe_dicts(tree: ast.AST) -> set[str]:
    """Find module-level dict assignments where all values are constants."""
    safe: set[str] = set()
    for node in ast.iter_child_nodes(tree):
        if isinstance(node, ast.Assign) and len(node.targets) == 1:
            target = node.targets[0]
            if isinstance(target, ast.Name) and isinstance(node.value, ast.Dict):
                # An empty dict is a registry filled at runtime, not a
                # constant lookup table; `all()` over no values is True.
                if node.value.values and all(
                    isinstance(v, ast.Constant)
                    for v in node.value.values
                    if v is not None
                ):
                    safe.add(target.id)
    return safe


def collect_pydantic_validated_classes(tree: ast.AST) -> set[str]:
    """Find Pydantic BaseModel subclasses with validators."""
    validated: set[str] = set()
    pydantic_bases = {"BaseModel", "BaseSettings", "SQLModel"}
    validator_decorators = {
        "model_validator",
        "field_validator",
        "validator",
        "root_validator",
    }

    for node in ast.walk(tree):
        if isinstance(node, ast.ClassDef):
            bases = {_base_name(b) for b in node.bases}
            if bases & pydantic_bases:
                for item in node.body:
                    if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)):
                        for dec in item.decorator_list:
                            dec_name = _decorator_name(dec)
                            if dec_name in validator_decorators:
                                validated.add(node.name)
                                break
    return validated


def collect_string_constants(tree: ast.AST) -> dict[str, str]:
    """Find module-level UPPER_CASE = 'string' assignments."""
    constants: dict[str, str] = {}
    for node in ast.iter_child_nodes(tree):
        if isinstance(node, ast.Assign) and len(node.targets) == 1:
            target = node.targets[0]
            if (
                isinstance(target, ast.Name)
                and target.id.isupper()
                and isinstance(node.value, ast.Constant)
                and isinstance(node.value.value, str)
            ):
                constants[target.id] = node.value.value
    return constants


def names_on_line(tree: ast.AST, line: int) -> set[str]:
    """Collect all Name identifiers referenced on a specific line."""
    names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Name) and getattr(node, "lineno", None) == line:
            names.add(node.id)
        if isinstance(node, ast.Subscript) and getattr(node, "lineno", None) == line:
            if isinstance(node.value, ast.Name):
                names.add(node.value.id)
    return names


def call_args_all_constants(tree: ast.AST, line: int, constants: set[str]) -> bool:
    """True when some call on `line` takes a Name from `constants` and every
    positional and keyword argument of every call on the line is such a Name
    or a literal. An f-string, BinOp or other Name (request input) disqualifies:
    the constant then only decorates a tainted argument."""
    uses_constant = False
    for node in ast.walk(tree):
        if not (isinstance(node, ast.Call) and getattr(node, "lineno", None) == line):
            continue
        for arg in (*node.args, *(kw.value for kw in node.keywords)):
            if isinstance(arg, ast.Constant):
                continue
            if isinstance(arg, ast.Name) and arg.id in constants:
                uses_constant = True
                continue
            return False
    return uses_constant


def calls_on_line(tree: ast.AST, line: int) -> set[str]:
    """Collect all function/class call names on a specific line."""
    call_names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and getattr(node, "lineno", None) == line:
            if isinstance(node.func, ast.Name):
                call_names.add(node.func.id)
            elif isinstance(node.func, ast.Attribute):
                call_names.add(node.func.attr)
    return call_names


def subscripts_on_line(tree: ast.AST, line: int) -> set[str]:
    """Collect dict names used in subscript expressions on a specific line."""
    sub_names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Subscript) and getattr(node, "lineno", None) == line:
            if isinstance(node.value, ast.Name):
                sub_names.add(node.value.id)
    return sub_names


#: Call names (bare or method) that render their arguments as human-readable
#: text rather than executing them as SQL. An SQL-keyword f-string passed to
#: one of these is a log/print message, not a query sink (#304).
_LOG_CALL_NAMES = frozenset({
    "debug", "info", "warning", "warn", "error", "critical", "exception",
    "log", "print", "pprint",
    "adebug", "ainfo", "awarning", "awarn", "aerror", "acritical", "aexception", "alog",
})


def _fstring_lines(node: ast.AST) -> set[int]:
    lines: set[int] = set()
    for sub in ast.walk(node):
        if isinstance(sub, ast.JoinedStr):
            start = getattr(sub, "lineno", None)
            if start is None:
                continue
            end = getattr(sub, "end_lineno", None) or start
            lines.update(range(start, end + 1))
    return lines


def logging_fstring_lines(tree: ast.AST) -> set[int]:
    """Line numbers occupied by an f-string that is a direct argument
    to a logging/print call: `logger.warning(f"... {x}")`, `print(f"...")`.
    Used to suppress SQL-keyword f-string findings that are really log
    messages (#304). Multi-line calls are handled by spanning each f-string's
    own line range, so the finding line matches even when the call opens on an
    earlier line."""
    lines: set[int] = set()
    message_nodes: set[int] = set()
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        name = (
            func.attr if isinstance(func, ast.Attribute)
            else func.id if isinstance(func, ast.Name)
            else None
        )
        if name not in _LOG_CALL_NAMES:
            continue
        for arg in (*node.args, *(kw.value for kw in node.keywords)):
            # A nested execute/search call remains a sink even when its result
            # is logged. Only the message itself is a logging f-string.
            if isinstance(arg, ast.JoinedStr):
                lines |= _fstring_lines(arg)
                message_nodes.update(id(n) for n in ast.walk(arg) if isinstance(n, ast.JoinedStr))
    # Line-based findings cannot distinguish a logged message from another
    # f-string on the same line. Keep that ambiguous line as a possible sink.
    other_lines: set[int] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.JoinedStr) and id(node) not in message_nodes:
            other_lines |= _fstring_lines(node)
    return lines - other_lines


def fstring_assignment_lines(tree: ast.AST) -> set[int]:
    """Line numbers where an f-string is the value assigned to a variable
    (`query = f"SELECT ... {x}"`). This is the real SQL-construction shape the
    log-message suppressor must NOT touch, so it is used as a guard: a line
    that assigns an f-string is never treated as a pure log line."""
    lines: set[int] = set()
    for node in ast.walk(tree):
        if isinstance(node, (ast.Assign, ast.AnnAssign)) and node.value is not None:
            lines |= _fstring_lines(node.value)
    return lines
