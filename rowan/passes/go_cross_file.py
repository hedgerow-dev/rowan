"""Go cross-file taint pass (ADR-0005, JG-13).

A tree-sitter call-graph and return-value tracer for Go, ported from the
JG-13 prototype. Per Go module (a directory tree with a ``go.mod``, else the
scan root) it indexes function and method declarations, resolves calls by
name plus declared receiver type (interface receivers fan out to every
implementing type in the module), seeds taint from ``net/http`` and web
framework request accessors and from MCP tool arguments, and walks forward
through assignments, concatenation, call arguments, return values and
struct field reads and writes to the sink families of ``rules/go_taint.yaml``
and ``rules/go_ai_taint.yaml`` (exec, file path, SQL statement text, HTTP
request URL).

Only flows whose source and sink sit in different functions are reported:
same-function flows are Opengrep's job and would double-report.

Optional dependency: ``tree-sitter`` plus ``tree-sitter-go``
(``pip install rowan-sast[js-crossfile]``). Without the grammar the pass
records itself as degraded and returns nothing.
"""

from __future__ import annotations

import logging
import re
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from rowan.core.confidence import CROSSFILE_TAINT
from rowan.core.findings import Category, Finding, ScanResult, Severity, TaintFlow, TaintNode
from rowan.core.paths import is_within_root
from rowan.passes.base import ScanContext, scan_span
from rowan.passes.file_scan import _parts_under, is_hidden_under, is_ignored, load_ignore_patterns

logger = logging.getLogger(__name__)

try:
    import tree_sitter_go as _tsgo
    from tree_sitter import Language, Parser

    TREE_SITTER_GO_AVAILABLE = True
except ImportError:
    TREE_SITTER_GO_AVAILABLE = False

MAX_HOPS = 6
MODULE_TIMEOUT_SECONDS = 30.0
_SKIP_DIRS = {"vendor", "testdata", "node_modules"}

# Request accessors on net/http, gin, echo, fiber and chi contexts
# (rules/go_taint.yaml `web_request_go`). Gated on the receiver's declared
# type or, when the type is unknown, on the conventional receiver names.
_HTTP_SOURCE_METHODS = frozenset({
    "FormValue", "PostFormValue", "Param", "Query", "DefaultQuery", "GetQuery", "PostForm",
    "GetPostForm", "QueryParam", "FormParams", "Params", "QueryArray", "ShouldBindJSON",
    "ShouldBind", "ShouldBindQuery", "BindJSON", "Bind", "BindQuery"
})
_HTTP_SOURCE_FUNCS = frozenset({"mux.Vars", "chi.URLParam"})
_HTTP_RECEIVER_TYPE_RE = re.compile(r"(http\.Request|gin\.Context|echo\.Context|fiber\.Ctx)$")
_HTTP_RECEIVER_NAMES = frozenset({"r", "req", "request", "c", "ctx"})

# mcp-go / go-sdk tool argument accessors (rules/go_ai_taint.yaml
# `mcp_tool_arg_go`).
# The numeric and boolean accessors are deliberately absent: an int or bool
# cannot carry an injection payload into argv, a path or a statement.
_MCP_ARG_METHODS = frozenset({
    "GetString", "RequireString", "GetArguments", "GetRawArguments", "GetStringSlice",
    "RequireStringSlice", "BindArguments"
})
_MCP_RECEIVER_NAMES = frozenset({"request", "req"})

_SQL_METHODS = frozenset({
    "Query", "QueryContext", "QueryRow", "QueryRowContext", "Exec", "ExecContext", "Prepare",
    "PrepareContext", "Select", "Get", "Raw"
})
_SQL_RECEIVER_RE = re.compile(r"\b(db|DB|Db|tx|Tx|conn|Conn|pool|store|sqlx|gorm|sql)\b")
_SQL_RECEIVER_TYPE_RE = re.compile(
    r"(sql\.DB|sql\.Tx|sql\.Conn|sqlx\.DB|sqlx\.Tx|gorm\.DB|pgx\.Conn|pgxpool\.Pool)$"
)
# The path sinks of rules/go_taint.yaml and go_ai_taint.yaml. os.Stat and
# os.Lstat are not sinks: they are how containment guards probe a candidate.
_PATH_FUNCS = frozenset({
    "os.Open", "os.OpenFile", "os.ReadFile", "os.WriteFile", "os.Create", "os.Remove",
    "os.RemoveAll", "os.MkdirAll", "os.Rename", "ioutil.ReadFile", "ioutil.WriteFile"
})
_EXEC_FUNCS = frozenset({"exec.Command", "exec.CommandContext", "syscall.Exec", "os.StartProcess"})
_CLIENT_RE = re.compile(r"[cC]lient")

# Stop-list: a value that passes through one of these is treated as clean.
_SANITIZER_FUNCS = frozenset({
    "filepath.Rel", "filepath.IsLocal", "filepath.Base", "path.Base", "strconv.Atoi",
    "strconv.ParseInt", "strconv.ParseUint", "strconv.ParseFloat", "strconv.ParseBool"
})
# Guard-shaped names clear the checked arguments. `escape*`/`sanitize*`
# were listed here too, but the families this pass reports (exec, path,
# sql, ssrf) are not neutralised by an HTML or text escaper (XF-14).
_SANITIZER_NAME_RE = re.compile(r"^(validate|isAllowed|isSafe)", re.I)
_PATH_NORMALISERS = frozenset({"filepath.Clean", "filepath.Abs", "filepath.EvalSymlinks"})
# A numeric or boolean conversion cannot carry a payload.
_NUMERIC_CONVERSIONS = frozenset({
    "int", "int8", "int16", "int32", "int64", "uint", "uint8", "uint16", "uint32", "uint64",
    "float32", "float64", "bool", "len", "cap"
})
# An error value quoting the input is the error channel, not a data flow.
_ERROR_CONSTRUCTORS = frozenset(
    {"fmt.Errorf", "errors.New", "errors.Wrap", "errors.Wrapf", "errors.Errorf"}
)
_SKIP_ASSIGN_NAMES = frozenset({"err", "ok", "_"})

_FAMILY_RULES: dict[str, tuple[str, Category, int]] = {
    "exec": ("CF-GO-EXEC-001", Category.COMMAND_INJECTION, 78),
    "path": ("CF-GO-PATH-001", Category.PATH_TRAVERSAL, 22),
    "sql": ("CF-GO-SQL-001", Category.INJECTION, 89),
    "ssrf": ("CF-GO-SSRF-001", Category.SSRF, 918),
}

_Hop = tuple[str, str, int]  # (file, function display name, line)


@dataclass(frozen=True)
class _Seed:
    kind: str  # http_input | tool_param
    file: str
    line: int
    fn_key: str
    expr: str
    via: tuple[_Hop, ...] = ()  # return-path call sites accumulated on the way up


@dataclass(frozen=True)
class _Hit:
    family: str
    file: str
    line: int
    snippet: str
    origins: frozenset
    hops: tuple[_Hop, ...]  # last entry is the sink function at the sink line


@dataclass
class _Func:
    file: str
    pkg: str
    name: str
    owner: str | None
    params: list[tuple[str, str | None]]  # receiver first for methods
    seeds: set[int]  # param indexes that are MCP typed-argument structs
    variadic: bool
    ret_type: str | None
    body: Any
    line: int

    @property
    def key(self) -> str:
        return f"{self.file}:{self.name}:{self.line}"

    @property
    def display(self) -> str:
        return f"{self.owner}.{self.name}" if self.owner else self.name


@dataclass
class _Module:
    root: Path
    path: str = ""
    funcs: list[_Func] = field(default_factory=list)
    pkg_funcs: dict[str, dict[str, _Func]] = field(default_factory=dict)
    methods: dict[tuple[str, str], list[_Func]] = field(default_factory=dict)
    structs: dict[str, dict[str, str]] = field(default_factory=dict)
    ifaces: dict[str, set[str]] = field(default_factory=dict)
    imports: dict[str, dict[str, str]] = field(default_factory=dict)
    implementers: dict[str, list[str]] = field(default_factory=dict)


def _text(node: Any) -> str:
    return node.text.decode("utf-8", "replace")


def _clean_type(t: str | None) -> str | None:
    if not t:
        return None
    t = re.sub(r"\[.*?\]", "", t).replace("*", "").replace("...", "").strip()
    return t.split(".")[-1] if t else None


def _collect_go_files(root: Path, context: ScanContext) -> list[Path]:
    patterns = load_ignore_patterns(root, context.config)
    if context.source_inventory is None:
        candidates = root.rglob("*.go")
    else:
        candidates = context.source_inventory.paths_for("go", suffix=".go")
    files: list[Path] = []
    for path in candidates:
        if not path.is_file() or path.name.endswith("_test.go"):
            continue
        if is_hidden_under(path, root) or any(part in _SKIP_DIRS for part in _parts_under(path, root)):
            continue
        if path.is_symlink() and not is_within_root(path, root):
            continue
        try:
            relative = path.relative_to(root)
        except ValueError:
            continue
        if is_ignored(str(relative), patterns):
            continue
        files.append(path)
    return sorted(files)


def _group_by_module(root: Path, files: list[Path]) -> dict[Path, list[Path]]:
    """Nearest ancestor holding a go.mod owns the file; the scan root otherwise."""
    groups: dict[Path, list[Path]] = {}
    for path in files:
        module_root = root
        for parent in path.parents:
            if (parent / "go.mod").is_file():
                module_root = parent
                break
            if parent == root:
                break
        groups.setdefault(module_root, []).append(path)
    return groups


# ---------------------------------------------------------------- indexing


def _params_of(plist: Any | None) -> tuple[list[tuple[str, str | None]], bool]:
    params: list[tuple[str, str | None]] = []
    variadic = False
    if plist is None:
        return params, variadic
    for decl in plist.named_children:
        if decl.type not in ("parameter_declaration", "variadic_parameter_declaration"):
            continue
        type_node = decl.child_by_field_name("type")
        type_text = _text(type_node) if type_node is not None else None
        names = [_text(c) for c in decl.children_by_field_name("name")]
        for name in names or ["_"]:
            params.append((name, type_text))
        if decl.type == "variadic_parameter_declaration":
            variadic = True
    return params, variadic


def _typed_arg_seeds(params: list[tuple[str, str | None]]) -> set[int]:
    """go-sdk typed handlers: the parameter after ``*mcp.CallToolRequest`` is
    the decoded tool-argument struct."""
    for index, (_name, type_text) in enumerate(params):
        if type_text and "CallToolRequest" in type_text and index + 1 < len(params):
            return {index + 1}
    return set()


def _index_module(module: _Module, files: list[Path], parser: Any) -> None:
    gomod = module.root / "go.mod"
    if gomod.is_file():
        match = re.search(
            r"^module\s+(\S+)", gomod.read_text(encoding="utf-8", errors="replace"), re.M
        )
        module.path = match.group(1) if match else ""
    for path in files:
        try:
            tree = parser.parse(path.read_bytes())
        except (OSError, ValueError) as exc:
            logger.debug("GoCrossFilePass: skipping %s: %s", path, exc)
            continue
        file_str = str(path.resolve())
        pkg = str(path.resolve().parent)
        imports: dict[str, str] = {}
        for node in tree.root_node.children:
            if node.type == "import_declaration":
                specs = [n for n in node.named_children if n.type == "import_spec"]
                for lst in (n for n in node.named_children if n.type == "import_spec_list"):
                    specs.extend(n for n in lst.named_children if n.type == "import_spec")
                for spec in specs:
                    path_node = spec.child_by_field_name("path")
                    if path_node is None:
                        continue
                    import_path = _text(path_node).strip('"')
                    alias_node = spec.child_by_field_name("name")
                    alias = (
                        _text(alias_node)
                        if alias_node is not None
                        else import_path.rsplit("/", 1)[-1]
                    )
                    if module.path and import_path == module.path:
                        imports[alias] = str(module.root.resolve())
                    elif module.path and import_path.startswith(module.path + "/"):
                        imports[alias] = str(
                            (module.root / import_path[len(module.path) + 1 :]).resolve()
                        )
            elif node.type in ("function_declaration", "method_declaration"):
                _index_function(module, node, file_str, pkg)
            elif node.type == "type_declaration":
                for spec in node.named_children:
                    if spec.type != "type_spec":
                        continue
                    name_node = spec.child_by_field_name("name")
                    type_node = spec.child_by_field_name("type")
                    if name_node is None or type_node is None:
                        continue
                    if type_node.type == "struct_type":
                        fields: dict[str, str] = {}
                        for decl in (
                            n
                            for n in type_node.named_children
                            if n.type == "field_declaration_list"
                        ):
                            for fd in (
                                n for n in decl.named_children if n.type == "field_declaration"
                            ):
                                ft = fd.child_by_field_name("type")
                                for fname in fd.children_by_field_name("name"):
                                    fields[_text(fname)] = _text(ft) if ft is not None else ""
                        module.structs[_text(name_node)] = fields
                    elif type_node.type == "interface_type":
                        module.ifaces[_text(name_node)] = {
                            _text(m.child_by_field_name("name"))
                            for m in type_node.named_children
                            if m.type in ("method_elem", "method_spec")
                            and m.child_by_field_name("name") is not None
                        }
        module.imports[file_str] = imports


def _index_function(module: _Module, node: Any, file_str: str, pkg: str) -> None:
    name_node = node.child_by_field_name("name")
    body = node.child_by_field_name("body")
    if name_node is None or body is None:
        return
    params, variadic = _params_of(node.child_by_field_name("parameters"))
    seeds = _typed_arg_seeds(params)
    owner = None
    if node.type == "method_declaration":
        recv, _ = _params_of(node.child_by_field_name("receiver"))
        if recv:
            owner = _clean_type(recv[0][1])
            params = [recv[0], *params]
            seeds = {i + 1 for i in seeds}
    result = node.child_by_field_name("result")
    ret_type = (
        _clean_type(_text(result))
        if result is not None and result.type != "parameter_list"
        else None
    )
    func = _Func(
        file=file_str,
        pkg=pkg,
        name=_text(name_node),
        owner=owner,
        params=params,
        seeds=seeds,
        variadic=variadic,
        ret_type=ret_type,
        body=body,
        line=node.start_point[0] + 1,
    )
    module.funcs.append(func)
    if owner:
        module.methods.setdefault((owner, func.name), []).append(func)
    else:
        module.pkg_funcs.setdefault(pkg, {})[func.name] = func


# ---------------------------------------------------------------- analysis


class _State:
    def __init__(self, fn: _Func, depth: int, prefix_checked: set[str]) -> None:
        self.fn = fn
        self.depth = depth
        self.env: dict[str, frozenset] = {}
        self.types: dict[str, str | None] = {}
        self.ret: set = set()
        self.hits: list[_Hit] = []
        self.prefix_checked = prefix_checked


class _Analyzer:
    def __init__(self, module: _Module, deadline: float) -> None:
        self.module = module
        self.deadline = deadline
        self.timed_out = False
        self.memo: dict[tuple[str, frozenset], tuple[frozenset, list[_Hit]]] = {}
        self.active: set[tuple[str, frozenset]] = set()
        # Frames on the stack, in call order. When a call hits the recursion
        # guard on key K, every frame entered after K got K's truncated
        # summary and must not be memoised; K itself, the cycle head, may be
        # (XF-18).
        self.stack: list[tuple[str, frozenset]] = []
        self.no_memo: set[tuple[str, frozenset]] = set()
        self.flows: dict[tuple, tuple[_Seed, _Hit]] = {}

    # ---- resolution

    def _implementers(self, iface: str) -> list[str]:
        if iface not in self.module.implementers:
            wanted = self.module.ifaces.get(iface, set())
            owners: dict[str, set[str]] = {}
            for (owner, name), _funcs in self.module.methods.items():
                owners.setdefault(owner, set()).add(name)
            found = [o for o, names in owners.items() if wanted and wanted <= names]
            self.module.implementers[iface] = found
        return self.module.implementers[iface]

    def resolve(self, call: Any, fn: _Func, types: dict[str, str | None]) -> list[_Func]:
        func = call.child_by_field_name("function")
        args = call.child_by_field_name("arguments")
        nargs = len(args.named_children) if args is not None else 0
        if func.type == "identifier":
            target = self.module.pkg_funcs.get(fn.pkg, {}).get(_text(func))
            return [target] if target else []
        if func.type != "selector_expression":
            return []
        operand = func.child_by_field_name("operand")
        name = _text(func.child_by_field_name("field"))
        if operand.type == "identifier":
            pkg_dir = self.module.imports.get(fn.file, {}).get(_text(operand))
            if pkg_dir is not None and _text(operand) not in types:
                target = self.module.pkg_funcs.get(pkg_dir, {}).get(name)
                return [target] if target else []
        tname = self.type_of(operand, fn, types)
        if tname and (tname, name) in self.module.methods:
            return self.module.methods[(tname, name)]
        if tname in self.module.ifaces:
            owners = self._implementers(tname)
            found = [m for o in owners for m in self.module.methods.get((o, name), [])]
            if found:
                return found
        candidates = [
            m
            for (_owner, mname), ms in self.module.methods.items()
            if mname == name
            for m in ms
            if len(m.params) - 1 == nargs or m.variadic
        ]
        if tname in self.module.ifaces:
            return candidates
        if tname is None and candidates and len({m.owner for m in candidates}) == 1:
            return candidates
        return []

    def type_of(self, e: Any, fn: _Func, types: dict[str, str | None]) -> str | None:
        if e is None:
            return None
        if e.type == "identifier":
            return _clean_type(types.get(_text(e)))
        if e.type == "selector_expression":
            base = self.type_of(e.child_by_field_name("operand"), fn, types)
            return _clean_type(
                self.module.structs.get(base or "", {}).get(_text(e.child_by_field_name("field")))
            )
        if e.type == "call_expression":
            callees = self.resolve(e, fn, types)
            return callees[0].ret_type if callees else None
        if e.type in ("unary_expression", "parenthesized_expression"):
            return self.type_of(e.named_children[-1], fn, types) if e.named_children else None
        if e.type == "composite_literal":
            return _clean_type(_text(e.child_by_field_name("type")))
        return None

    # ---- core walk

    def analyze(self, fn: _Func, tainted: frozenset, depth: int) -> tuple[frozenset, list[_Hit]]:
        key = (fn.key, tainted)
        if key in self.memo:
            return self.memo[key]
        if key in self.active:
            self.no_memo.update(self.stack[self.stack.index(key) + 1:])
            return frozenset(), []
        if depth > MAX_HOPS or self.timed_out:
            return frozenset(), []
        if time.perf_counter() > self.deadline:
            self.timed_out = True
            return frozenset(), []
        self.active.add(key)
        self.stack.append(key)
        st = _State(fn, depth, _prefix_checked_names(fn.body))
        for index, (pname, ptype) in enumerate(fn.params):
            st.types[pname] = ptype
            origins: set = set()
            if index in tainted:
                origins.add(f"p{index}")
            if index in fn.seeds:
                origins.add(_Seed("tool_param", fn.file, fn.line, fn.key, pname))
            if origins:
                st.env[pname] = frozenset(origins)
        self.walk(fn.body, st)
        ret = frozenset(st.ret)
        summary = [h for h in st.hits if any(isinstance(o, str) for o in h.origins)]
        for hit in st.hits:
            for origin in hit.origins:
                if isinstance(origin, _Seed):
                    self._record(origin, hit, fn)
        self.active.discard(key)
        self.stack.pop()
        if key in self.no_memo:
            self.no_memo.discard(key)
        else:
            self.memo[key] = (ret, summary)
        return ret, summary

    def _record(self, seed: _Seed, hit: _Hit, fn: _Func) -> None:
        if len(hit.hops) == 1 and not seed.via and seed.fn_key == fn.key:
            return  # same function: Opengrep's job
        key = (seed.file, seed.line, hit.file, hit.line, hit.family)
        if key not in self.flows:
            self.flows[key] = (seed, hit)

    def walk(self, node: Any, st: _State) -> None:
        t = node.type
        if t in ("short_var_declaration", "assignment_statement"):
            self._assign(node, st)
            return
        if t == "var_spec":
            type_node = node.child_by_field_name("type")
            value = node.child_by_field_name("value")
            origins = (
                frozenset().union(*(self.origins(v, st) for v in value.named_children))
                if value is not None
                else frozenset()
            )
            for name in node.children_by_field_name("name"):
                st.types[_text(name)] = _text(type_node) if type_node is not None else None
                st.env[_text(name)] = origins
            return
        if t == "range_clause":
            origins = self.origins(node.child_by_field_name("right"), st)
            left = node.child_by_field_name("left")
            for item in left.named_children if left is not None else []:
                st.env[_text(item)] = origins
            return
        if t == "return_statement":
            for child in node.named_children:
                for item in child.named_children if child.type == "expression_list" else [child]:
                    if item.type == "identifier" and _text(item) in st.prefix_checked:
                        continue  # a strings.HasPrefix-contained value is returned clean
                    st.ret |= self.origins(item, st)
            return
        if t in (
            "call_expression",
            "binary_expression",
            "func_literal",
            "unary_expression",
            "selector_expression",
            "composite_literal",
        ):
            self.origins(node, st)
            return
        for child in node.children:
            self.walk(child, st)

    def _assign(self, node: Any, st: _State) -> None:
        left = node.child_by_field_name("left")
        right = node.child_by_field_name("right")
        if left is None or right is None:
            return
        lefts, rights = left.named_children, right.named_children
        right_origins = [self.origins(r, st) for r in rights]
        operator = node.child_by_field_name("operator")
        pairwise = len(lefts) == len(rights) and len(rights) > 1
        for index, target in enumerate(lefts):
            name = _text(target)
            if name in _SKIP_ASSIGN_NAMES:
                continue
            origins = right_origins[index] if pairwise else frozenset().union(*right_origins)
            if operator is not None and _text(operator) == "+=":
                origins |= st.env.get(name, frozenset())
            if len(rights) == 1 and rights[0].type == "call_expression":
                if node.type == "short_var_declaration" or name not in st.types:
                    st.types[name] = self.type_of(rights[0], st.fn, st.types)
                if _callee_text(rights[0]) in _PATH_NORMALISERS and name in st.prefix_checked:
                    origins = frozenset()  # filepath.Clean/Abs + strings.HasPrefix guard
            elif len(rights) == 1 and node.type == "short_var_declaration":
                st.types[name] = self.type_of(rights[0], st.fn, st.types)
            st.env[name] = origins

    def origins(self, e: Any, st: _State) -> frozenset:
        if e is None:
            return frozenset()
        t = e.type
        if t == "identifier":
            return st.env.get(_text(e), frozenset())
        if t == "selector_expression":
            full = _text(e)
            operand = e.child_by_field_name("operand")
            origins = st.env.get(full, frozenset()) | self.origins(operand, st)
            if full.endswith(".Params.Arguments"):
                origins |= {self._seed("tool_param", e, st, full)}
            elif _text(e.child_by_field_name("field")) == "Body" and self._is_http_receiver(
                operand, st
            ):
                origins |= {self._seed("http_input", e, st, full)}
            return origins
        if t == "func_literal":
            params, _ = _params_of(e.child_by_field_name("parameters"))
            for index, (pname, ptype) in enumerate(params):
                st.types[pname] = ptype
                if index in _typed_arg_seeds(params):
                    st.env[pname] = frozenset(
                        {_Seed("tool_param", st.fn.file, e.start_point[0] + 1, st.fn.key, pname)}
                    )
            body = e.child_by_field_name("body")
            if body is not None:
                saved_ret = st.ret
                st.ret = set()
                self.walk(body, st)
                st.ret = saved_ret
            return frozenset()
        if t == "call_expression":
            return self._call(e, st)
        if t == "index_expression":
            # `table[key]` yields the table's value, not the key: a lookup
            # keyed by tainted input in an operator-defined map is an
            # allowlist, not a flow.
            return self.origins(e.child_by_field_name("operand"), st)
        if t in (
            "interpreted_string_literal",
            "raw_string_literal",
            "int_literal",
            "float_literal",
            "nil",
            "true",
            "false",
            "type_identifier",
            "qualified_type",
        ):
            return frozenset()
        out: frozenset = frozenset()
        for child in e.named_children:
            out |= self.origins(child, st)
        return out

    def _seed(self, kind: str, e: Any, st: _State, expr: str) -> _Seed:
        return _Seed(kind, st.fn.file, e.start_point[0] + 1, st.fn.key, expr)

    def _is_http_receiver(self, operand: Any, st: _State) -> bool:
        if operand is None:
            return False
        declared = st.types.get(_text(operand)) if operand.type == "identifier" else None
        if declared:
            return bool(_HTTP_RECEIVER_TYPE_RE.search(declared))
        return operand.type == "identifier" and _text(operand) in _HTTP_RECEIVER_NAMES

    def _is_mcp_receiver(self, operand: Any, st: _State) -> bool:
        if operand is None:
            return False
        declared = st.types.get(_text(operand)) if operand.type == "identifier" else None
        if declared:
            return "CallToolRequest" in declared
        return operand.type == "identifier" and _text(operand) in _MCP_RECEIVER_NAMES

    def _call(self, e: Any, st: _State) -> frozenset:
        fn = st.fn
        func = e.child_by_field_name("function")
        args_node = e.child_by_field_name("arguments")
        arg_nodes = list(args_node.named_children) if args_node is not None else []
        args = [self.origins(a, st) for a in arg_nodes]
        if func is None:
            return frozenset().union(*args)
        if func.type == "func_literal":
            self.origins(func, st)
            return frozenset()
        ft = _text(func)
        name = ft.rsplit(".", 1)[-1]
        operand = (
            func.child_by_field_name("operand") if func.type == "selector_expression" else None
        )
        recv = self.origins(operand, st) if operand is not None else frozenset()
        line = e.start_point[0] + 1

        callees = self.resolve(e, fn, st.types)
        if _SANITIZER_NAME_RE.match(name):
            # `validateRef(ref)` / `s.validatePath(p)`: the checked arguments
            # are clean from here on, and so is whatever the guard returns.
            for arg in arg_nodes:
                if arg.type == "identifier":
                    st.env.pop(_text(arg), None)
            return frozenset()
        if callees:
            return self._apply_callees(callees, args, recv, e, st)
        if ft in _SANITIZER_FUNCS or ft in _ERROR_CONSTRUCTORS or ft in _NUMERIC_CONVERSIONS:
            return frozenset()

        seed: _Seed | None = None
        if operand is not None:
            if name in _MCP_ARG_METHODS and self._is_mcp_receiver(operand, st):
                seed = self._seed("tool_param", e, st, ft)
            elif (name == "Query" and _text(operand).endswith(".URL")) or (
                name in _HTTP_SOURCE_METHODS and self._is_http_receiver(operand, st)
            ):
                seed = self._seed("http_input", e, st, ft)
        elif ft in _HTTP_SOURCE_FUNCS:
            seed = self._seed("http_input", e, st, ft)

        tainted = recv | frozenset().union(*args)
        if seed is not None:
            tainted |= {seed}
        if tainted:
            # `json.Unmarshal(data, &v)`, `c.ShouldBindJSON(&body)`,
            # `request.BindArguments(&args)`: the pointer target receives taint.
            for arg in arg_nodes:
                if (
                    arg.type == "unary_expression"
                    and _text(arg).startswith("&")
                    and arg.named_children
                ):
                    target = arg.named_children[0]
                    if target.type == "identifier":
                        st.env[_text(target)] = st.env.get(_text(target), frozenset()) | tainted
        if seed is None:
            sink = self._sink(ft, name, operand, st, len(args))
            if sink is not None:
                family, indexes = sink
                focus = frozenset().union(*(args[i] for i in indexes if i < len(args)))
                if focus:
                    st.hits.append(
                        _Hit(
                            family,
                            fn.file,
                            line,
                            _text(e).splitlines()[0][:160],
                            focus,
                            ((fn.file, fn.display, line),),
                        )
                    )
        return tainted

    def _sink(
        self, ft: str, name: str, operand: Any, st: _State, nargs: int
    ) -> tuple[str, tuple[int, ...]] | None:
        if ft in _EXEC_FUNCS:
            return "exec", tuple(range(nargs))
        if ft in _PATH_FUNCS:
            return "path", (0, 1) if ft == "os.Rename" else (0,)
        if ft == "http.ServeFile":
            return "path", (2,)
        if ft in ("http.Get", "http.Post", "http.Head", "http.PostForm"):
            return "ssrf", (0,)
        if ft == "http.NewRequest":
            return "ssrf", (1,)
        if ft == "http.NewRequestWithContext":
            return "ssrf", (2,)
        if operand is None:
            return None
        recv_text = _text(operand)
        recv_type = st.types.get(recv_text, "") or "" if operand.type == "identifier" else ""
        if name in _SQL_METHODS and (
            _SQL_RECEIVER_RE.search(recv_text) or _SQL_RECEIVER_TYPE_RE.search(recv_type)
        ):
            statement = 1 if name.endswith("Context") or name in ("Select", "Get") else 0
            return "sql", (statement,)
        if name in ("Get", "Post", "Head", "PostForm", "Do") and (
            _CLIENT_RE.search(recv_text) or _CLIENT_RE.search(recv_type)
        ):
            return "ssrf", (0,)
        return None

    def _apply_callees(
        self, callees: list[_Func], args: list[frozenset], recv: frozenset, e: Any, st: _State
    ) -> frozenset:
        fn = st.fn
        line = e.start_point[0] + 1
        call_site: _Hop = (fn.file, fn.display, line)
        result: frozenset = frozenset()
        for callee in callees:
            actual = ([recv] if callee.owner else []) + args
            per_param: list[frozenset] = []
            for index in range(len(callee.params)):
                if callee.variadic and index == len(callee.params) - 1:
                    per_param.append(
                        frozenset().union(*actual[index:]) if len(actual) > index else frozenset()
                    )
                else:
                    per_param.append(actual[index] if index < len(actual) else frozenset())
            tainted = frozenset(i for i, o in enumerate(per_param) if o)
            ret, hits = self.analyze(callee, tainted, st.depth + 1)
            result |= _remap(ret, per_param, call_site)
            for hit in hits:
                mapped = _remap(hit.origins, per_param, None)
                if mapped:
                    st.hits.append(
                        _Hit(
                            hit.family,
                            hit.file,
                            hit.line,
                            hit.snippet,
                            mapped,
                            (call_site, *hit.hops),
                        )
                    )
        return result


def _remap(origins: frozenset, per_param: list[frozenset], call_site: _Hop | None) -> frozenset:
    """Map a callee's parameter-labelled origins back to the caller's. Seeds
    internal to the callee are kept only for return values (``call_site``
    given), where the call site becomes one more hop on the way up; for hits
    they were already recorded by the callee's own analysis."""
    out: set = set()
    for origin in origins:
        if isinstance(origin, str):
            out |= per_param[int(origin[1:])]
        elif call_site is not None:
            out.add(
                _Seed(
                    origin.kind,
                    origin.file,
                    origin.line,
                    origin.fn_key,
                    origin.expr,
                    (*origin.via, call_site),
                )
            )
    return frozenset(out)


def _callee_text(call: Any) -> str:
    func = call.child_by_field_name("function")
    return _text(func) if func is not None else ""


def _prefix_checked_names(body: Any) -> set[str]:
    """Identifiers whose value is checked with ``strings.HasPrefix`` in this
    body: assigning ``filepath.Clean``/``Abs`` to one of them is the
    canonical Go path-containment guard."""
    names: set[str] = set()
    stack = [body]
    while stack:
        node = stack.pop()
        if node.type == "call_expression" and _callee_text(node) == "strings.HasPrefix":
            args = node.child_by_field_name("arguments")
            if (
                args is not None
                and args.named_children
                and args.named_children[0].type == "identifier"
            ):
                names.add(_text(args.named_children[0]))
        stack.extend(node.named_children)
    return names


# ---------------------------------------------------------------- pass


def _build_finding(seed: _Seed, hit: _Hit, target: Path) -> Finding:
    rule_id, category, cwe = _FAMILY_RULES[hit.family]
    chain = list(seed.via) + list(hit.hops[:-1])
    sink_hop = hit.hops[-1]
    intermediate = [
        TaintNode(file_path=file, line=line, snippet=f"{name}()") for file, name, line in chain
    ]
    depth = len(chain)
    source_name = Path(seed.file).name
    sink_name = Path(hit.file).name
    return Finding(
        rule_id=rule_id,
        message=(
            f"Go cross-file taint [{depth}-hop, {seed.kind}]: {seed.expr} in {source_name} "
            f"reaches {hit.family} sink {sink_hop[1]}() in {sink_name}:{hit.line}."
        ),
        severity=Severity.HIGH,
        category=category,
        file_path=hit.file,
        start_line=hit.line,
        confidence=CROSSFILE_TAINT(max(depth - 1, 0)),
        cwe_ids=[cwe],
        engine="crossfile",
        taint_flow=TaintFlow(
            source=TaintNode(file_path=seed.file, line=seed.line, snippet=seed.expr),
            sink=TaintNode(file_path=hit.file, line=hit.line, snippet=hit.snippet),
            intermediate=intermediate,
        ),
        metadata={
            "pass": "go_crossfile",
            "cross_file": seed.file != hit.file,
            "source_kind": seed.kind,
            # Enrichment's source-origin tracer is Opengrep-only; the pass has
            # already established the boundary, so record the origin the way
            # `_SOURCE_KIND_ORIGINS` would (a tool argument is model-chosen).
            "source_origin": "http_input" if seed.kind == "http_input" else "llm_output",
            "source_confidence": 1.0 if seed.kind == "http_input" else 0.95,
            "hop_depth": depth,
            "caller": chain[0][1] if chain else sink_hop[1],
            "callee": sink_hop[1],
            "chain": [f"{Path(f).name}:{line}:{name}" for f, name, line in [*chain, sink_hop]],
        },
    )


class GoCrossFilePass:
    name = "go_crossfile"

    def run(self, context: ScanContext) -> ScanResult:
        start = time.perf_counter()
        result = ScanResult()
        target = context.target_path
        if not target.exists():
            return result
        files = _collect_go_files(target, context)
        if not files:
            return result
        if not TREE_SITTER_GO_AVAILABLE:
            result.degraded_passes[self.name] = (
                "tree-sitter-go not installed (pip install 'rowan[js-crossfile]'); "
                "Go cross-file taint was not run"
            )
            return result
        if len(files) < 2:
            return result

        parser = Parser(Language(_tsgo.language()))
        # An Opengrep dataflow finding already anchored at the sink line for
        # the same weakness is the same flow seen intra-file; a pattern-only
        # regex match at that line is not a flow and does not suppress one.
        existing = {
            (str(Path(f.file_path).resolve()), f.start_line, cwe)
            for f in context.result.findings
            if f.engine == "opengrep" and f.taint_flow is not None
            for cwe in f.cwe_ids
        }
        timed_out: list[str] = []
        emitted = 0
        for module_root, module_files in _group_by_module(target, files).items():
            module = _Module(root=module_root)
            _index_module(module, module_files, parser)
            analyzer = _Analyzer(module, time.perf_counter() + MODULE_TIMEOUT_SECONDS)
            for func in module.funcs:
                analyzer.analyze(func, frozenset(), 0)
            if analyzer.timed_out:
                timed_out.append(str(module_root))
            for seed, hit in analyzer.flows.values():
                finding = _build_finding(seed, hit, target)
                if (finding.file_path, finding.start_line, finding.cwe_ids[0]) in existing:
                    continue
                result.add_finding(finding)
                emitted += 1
        if timed_out:
            result.metadata["go_crossfile_timed_out"] = timed_out
        duration = time.perf_counter() - start
        scan_span(self.name, duration)
        logger.info(
            "GoCrossFilePass: %d files, %d findings in %.1fs", len(files), emitted, duration
        )
        return result
