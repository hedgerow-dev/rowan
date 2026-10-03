"""Shared request-source recognition (extracted from `cross_file.py`).

The set of attacker-controlled attribute chains (`request.args`, `request.json`,
...) and the AST helpers that test an expression or function body against it were
originally inline in `CrossFilePass`. They are extracted here so any pass that
needs "is this expression read from an untrusted request source?" consumes the
**same** definition instead of keeping a second copy -- the exact
duplicated-definition drift ADR-0002 warns against. `CrossFilePass` re-imports
these under its historical private names; `AuthzPass` (the BOLA/IDOR detector,
issue #171) consumes them directly.
"""

from __future__ import annotations

import ast
import re

# ---------------------------------------------------------------------------
# Known taint sources -- attribute chains that introduce attacker-controlled
# data. Matched as a dotted-prefix on attribute chains (e.g. "request.args.get"
# matches the "request.args" prefix).
# ---------------------------------------------------------------------------
KNOWN_SOURCE_PREFIXES: tuple[str, ...] = (
    "request.args", "request.form", "request.values", "request.files",
    "request.json", "request.get_json", "request.data", "request.stream", "request.cookies",
    "request.headers", "request.GET", "request.POST", "request.body",
    "request.query_params", "request.path_params",
    "sys.argv", "flask.request",
)


#: FastAPI/Starlette parameter declarations and the UI-framework inputs that
#: are attacker-controlled without going through `request.*`.
FRAMEWORK_INPUT_SHAPES: tuple[str, ...] = (
    # As an annotated parameter default only (`id: int = Path(...)`), so
    # `root = pathlib.Path(dir)` and a local `Query(` class do not count.
    r":[ \t]*[\w\[\], |.]+[ \t]*=[ \t]*(?:Body|Query|Path|Form|Header|Cookie)\(",
    r"websocket\.recv", r"websocket\.receive_text", r"st\.chat_input", r"st\.text_input",
    r"st\.file_uploader", r"gr\.File", r"gr\.UploadButton",
)

#: The one regex for "this text reads HTTP/user input" (BACKLOG CN-05). The
#: enrichment pass derives its lists from it; the source tracer consults the
#: same prefixes through `KNOWN_SOURCE_PREFIXES`.
HTTP_INPUT_RE = re.compile(
    "|".join(re.escape(p) for p in KNOWN_SOURCE_PREFIXES if p not in ("sys.argv", "flask.request"))
    + "|"
    + "|".join(FRAMEWORK_INPUT_SHAPES)
)

#: Route decorators: a file with one handles web requests even when the
#: handler reads its input through typed parameters.
ROUTE_DECORATOR_RE = re.compile(r"@(?:app|router|api|blueprint|bp)\.(?:get|post|put|delete|patch|route)\(")


def dotted_name(node: ast.AST) -> str:
    """Reconstruct a dotted attribute chain (e.g. request.args.get) from an AST node."""
    parts: list[str] = []
    cur = node
    while isinstance(cur, ast.Attribute):
        parts.append(cur.attr)
        cur = cur.value
    if isinstance(cur, ast.Name):
        parts.append(cur.id)
    return ".".join(reversed(parts))


_HTTP_VERB_DECORATORS = frozenset({"get", "post", "put", "patch", "delete"})


def is_http_route(func: ast.FunctionDef | ast.AsyncFunctionDef) -> bool:
    """A web route handler: `@x.route(...)`, `@api_view(...)`, or an HTTP-verb
    decorator whose path is a literal starting with "/".

    A verb name alone is not enough: `@mock.patch("os.path.exists")` and
    `@config.patch(debug=True)` end in `patch` but are not routes.
    """
    for dec in func.decorator_list:
        call = dec if isinstance(dec, ast.Call) else None
        tail = dotted_name(call.func if call else dec).rsplit(".", 1)[-1]
        if tail in {"route", "api_view"}:
            return True
        if tail not in _HTTP_VERB_DECORATORS or call is None:
            continue
        path = call.args[0] if call.args else next(
            (kw.value for kw in call.keywords if kw.arg == "path"), None
        )
        if isinstance(path, ast.Constant) and isinstance(path.value, str) and path.value.startswith("/"):
            return True
    return False


def _chain_matches_source(dotted: str) -> bool:
    return any(
        dotted == p or dotted.startswith(p + ".") or dotted.startswith(p + "[")
        for p in KNOWN_SOURCE_PREFIXES
    )


def expr_reads_source(expr: ast.expr) -> bool:
    """True if `expr` (or anything nested inside it) reads a known taint source."""
    for node in ast.walk(expr):
        if isinstance(node, ast.Attribute) and _chain_matches_source(dotted_name(node)):
            return True
    return False


def function_reads_source(node: ast.AST) -> bool:
    """True if the function body reads a known taint source anywhere."""
    for child in ast.walk(node):
        if isinstance(child, ast.Attribute) and _chain_matches_source(dotted_name(child)):
            return True
    return False


# ---------------------------------------------------------------------------
# LLM-output sources.
#
# Model output is attacker-influenced whenever anything untrusted reaches the
# prompt -- a retrieved document, a tool result, a user turn -- which is the
# normal case for RAG and agent code. `rules/llm_output_taint.yaml` already
# models this for the Opengrep taint engine (`$LLM.generate(...)`,
# `$CLIENT.chat.completions.create(...)`, `...choices[0].message.content`), but
# those rules are single-file: Opengrep only connects source to sink within one
# file. The cross-file pass had no notion of LLM output at all, so a flow that
# crosses a module boundary between the model call and the sink was invisible
# to both layers.
#
# The motivating case is flashrag: `self.generator.generate(...)` in
# reasoning_pipeline.py flows through `postprocess_agent_response()` into
# `eval()` in ReaRAG_utils.py. Both halves were reported -- the eval as a
# standalone "presence signal" at medium -- but nothing joined them.
#
# Kept separate from KNOWN_SOURCE_PREFIXES on purpose: AuthzPass consumes
# `expr_reads_source` to decide whether an object id is attacker-*keyed*, and
# LLM output is not a request parameter.
# ---------------------------------------------------------------------------

#: Provider-specific call chains that return model output regardless of what
#: the receiver is named. Matched as a suffix of the callee's dotted name.
LLM_OUTPUT_CALL_CHAINS: tuple[str, ...] = (
    "chat.completions.create",
    "completions.create",
    "messages.create",
    "messages.stream",
    "generate_content",
    "chat.complete",
)

#: Generic one-verb model calls. Too common to treat as a source on their own
#: (`results.generate()`, `db.invoke()`), so they additionally require the
#: receiver name to hint at a model -- the same receiver-name gating
#: `cross_file._vector_call_receiver_name` uses for vector-store reads.
LLM_OUTPUT_METHOD_TAILS: frozenset[str] = frozenset({
    "generate", "agenerate", "invoke", "ainvoke", "predict", "apredict",
    "complete", "acomplete", "chat", "achat", "stream_chat", "astream_chat",
    "chat_completion", "create_completion",
})

_LLM_RECEIVER_HINT_RE = re.compile(
    r"(?:^|[._])(llm|llms|model|models|generator|chat|agent|completion|"
    r"predictor|engine|backend)s?(?:[._]|$)",
    re.IGNORECASE,
)


def _receiver_hints_llm(callee_dotted: str) -> bool:
    """True if the receiver half of `a.b.method` names a model-ish object."""
    receiver, _, _ = callee_dotted.rpartition(".")
    if not receiver:
        return False
    return bool(_LLM_RECEIVER_HINT_RE.search(receiver))


def call_returns_llm_output(node: ast.AST) -> bool:
    """True if `node` is a call whose return value is model output."""
    if not isinstance(node, ast.Call):
        return False
    dotted = dotted_name(node.func)
    if not dotted:
        return False
    if any(
        dotted == chain or dotted.endswith("." + chain)
        for chain in LLM_OUTPUT_CALL_CHAINS
    ):
        return True
    tail = dotted.rsplit(".", 1)[-1]
    return tail in LLM_OUTPUT_METHOD_TAILS and _receiver_hints_llm(dotted)


def expr_reads_llm_output(expr: ast.expr) -> bool:
    """True if `expr` (or anything nested inside it) reads model output."""
    return any(call_returns_llm_output(node) for node in ast.walk(expr))


def function_reads_llm_output(node: ast.AST) -> bool:
    """True if the function body reads model output anywhere."""
    return any(call_returns_llm_output(child) for child in ast.walk(node))


def route_input_names(func: ast.FunctionDef | ast.AsyncFunctionDef) -> set[str]:
    """Framework-bound route/query/body parameters, excluding dependencies.

    Route parameters are external inputs even without a request object (Flask
    path arguments and FastAPI typed parameters). Dependency providers retain
    their own trust contract and are not treated as client-controlled.
    """
    if not is_http_route(func):
        return set()
    args = func.args.posonlyargs + func.args.args
    defaults = [None] * (len(args) - len(func.args.defaults)) + list(func.args.defaults)
    pairs = [*zip(args, defaults, strict=True), *zip(func.args.kwonlyargs, func.args.kw_defaults, strict=True)]
    return {
        arg.arg for arg, default in pairs
        if arg.arg not in {'self', 'cls', 'request', 'req'}
        and not (isinstance(default, ast.Call) and dotted_name(default.func).rsplit('.', 1)[-1] in {'Depends', 'Security'})
        and not (arg.annotation and any(
            isinstance(n, ast.Call) and dotted_name(n.func).rsplit('.', 1)[-1] in {'Depends', 'Security'}
            for n in ast.walk(arg.annotation)
        ))
    }
