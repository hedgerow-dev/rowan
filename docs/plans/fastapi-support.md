# FastAPI support: spec

Status: parts 1 and 2 implemented (2026-10-10). Follow-up: merge findings
that tag one bug with related CWEs (see "Measured result").

## Problem

FastAPI hands request data to a route as typed function parameters:

```python
@app.get("/file/{name}")
def read(name: str, q: str = Query(None), item: Item = Body(...)):
    return open(os.path.join("/data", name)).read()
```

Rowan's Opengrep taint rules only know request data that is read through a
request object (`request.args`, `request.query_params`, `await request.json()`).
None of them treat a FastAPI route parameter as a source. Most FastAPI code
never touches the request object, so the taint engine sees no input at all.

Two weaker layers partly cover this today:

- **Cross-file boundary pass** (`HTTP-ROUTE-001`, `rowan/passes/cross_file.py`)
  treats route parameters as untrusted, but only for its short agent-tool sink
  list: shell commands, outbound HTTP, `eval`/`exec`. It has no SQL, path,
  redirect, XSS or deserialization sinks.
- **NeuroScan regex rules** fire on some sink shapes (SQL f-strings, `pickle`,
  `FileResponse`) at medium confidence, with no source and no trace.

The authz pass and enrichment already understand FastAPI (`Depends`,
`Security`, route decorators, `FRAMEWORK_INPUT_SHAPES` in
`rowan/analysis/request_sources.py`). The gap is the taint source.

## Measured gap

A test app with 14 vulnerable FastAPI handlers and one safe `int` handler:

| Bug | Sink | Rowan 0.3.9 |
|---|---|---|
| `host: str` to shell | `subprocess.run` | HTTP-ROUTE-001 |
| `q = Query()` to SQL | f-string `execute` | regex only (medium) |
| `name = Path()` to file read | `open(os.path.join)` | **missed** |
| Pydantic body field to SSRF | `requests.get` | HTTP-ROUTE-001 |
| `next: str` open redirect | `RedirectResponse` | **missed** |
| `name: str` reflected XSS | `HTMLResponse` | **missed** |
| `Header()` to shell | `os.system` | HTTP-ROUTE-001 |
| `Form()` to pickle | `pickle.loads` | regex only |
| `path: str` file download | `FileResponse` | regex only |
| `UploadFile` to pickle | `pickle.loads` | regex only |
| `Depends()` value to shell | `check_output` | HTTP-ROUTE-001 |
| `Cookie()` to SQL | concatenated `execute` | regex only |
| `APIRouter` route to shell | `subprocess.call` | HTTP-ROUTE-001 |
| `request.query_params` to `eval` | `eval` | taint (already a source) |

Three are missed outright; five more rely on regex with no trace. Only the
`request.query_params` case reaches the taint engine.

## Proposal

### 1. New registry source fragment: `web_request_fastapi_params`

Add a fragment to `rowan/rules_registry.py`, synced into every Python taint
rule that uses `web_request` / `user_input` (same mechanism as
`web_request_js_destructured`). A parameter is a source when:

- its function is decorated `@$APP.$M(...)` with `$M` in
  `get|post|put|delete|patch|options|head|api_route|websocket`
  (covers `app`, `router`, any `APIRouter` name), sync or async;
- its annotation is a string-like or structured type: `str`, `bytes`, `Any`,
  `Optional[str]`, `str | None`, `list[str]`, or a capitalised class name
  (Pydantic models, `UploadFile`);
- the annotation is not a framework object: `Request`, `Response`,
  `WebSocket`, `BackgroundTasks`, `HTTPConnection`, `SecurityScopes`;
- the parameter is not defaulted to `Depends(...)` or `Security(...)`
  (dependency results keep their own trust contract, as in the authz pass).

Numeric, boolean, `UUID`, `date`/`datetime` and `Enum` parameters are not
sources: FastAPI validates and converts them before the handler runs.

A probe rule built this way, run with the real Opengrep binary, flags all 12 parameter-based
injectable cases above with traces, and stays silent on the `int` handler and
the `Depends()` value.

### 2. Missing FastAPI/Starlette sinks

Add where absent, each in the matching category rule:

- open redirect: `RedirectResponse(...)` unqualified (only
  `fastapi.responses.RedirectResponse` is matched today)
- XSS: `HTMLResponse(...)` with a tainted body
- path traversal: `FileResponse(...)` and `StreamingResponse(open(...))`
- `Jinja2Templates.TemplateResponse` with autoescape off (check existing
  template rules first; may already be covered)

### 3. Leave alone (v1)

- **Dependency outputs.** A `Depends(get_token)` that returns a header is
  user-controlled, but most dependencies return a trusted user or DB session.
  Tracing through the provider is a follow-up.
- **`HTTP-ROUTE-001`.** Keep it. Once taint finds the same flows, the existing
  same-sink merge should absorb the duplicates; verify that, do not remove the
  pass.
- **Flask path arguments** (`@app.route("/<name>") def f(name)`) have the
  same gap. The same fragment shape fits Flask, but it is a separate change
  with its own measurement.

## Risks

- **False positives from broad typing.** Capitalised class names include
  internal types. Pydantic field types narrow this in practice; measure.
- **Pattern cost.** `pattern-inside` over decorated functions in every Python
  taint rule may slow large scans. Time a large repo before and after.
- **Duplicate findings** with `HTTP-ROUTE-001` and the NeuroScan regex rules
  until the merge absorbs them.

## Implementation notes

- The route decorator must carry a path literal (`"/x"`, or `""` under a
  prefixed router). Without it, `@mock.patch("pkg.run")` in a test matched,
  since `patch` is also a route method.
- The FastAPI source exposed an over-broad SQL sink: `TNT-SQLI-002` and
  `TNT-ML-004` matched the whole `db.query(...)` call, so a handle tainted by
  an earlier `db.add(user_data)` made ORM lookups such as
  `db.query(User).filter(User.email == email)` look like SQL injection. Both
  now sink only the query argument (`focus-metavariable`).

## Measured result

RealVuln, 21 FastAPI repos, branch vs main: TP 253 to 274 (17 open redirect,
4 XSS; none lost), recall 0.413 to 0.447. New false positives with no labeled
bug nearby: 12. A further 90 new FP entries are real bugs already credited at
the function line and reported again at the sink by another rule. They stay
unmerged because the rules tag the same bug with different categories and
CWEs (`eval` as CWE-94, 95 and 78), which the same-sink merge requires to
match. That merge is the follow-up.

## Plan

1. Tests first: one fixture per row of the table plus negatives (`int`,
   `Depends`, `Request`, an undecorated function with the same signature)
   -> verify: new tests fail on main.
2. Add the source fragment, sync with `scripts/sync_registry.py`
   -> verify: fixture tests pass, `sync_registry.py --check` clean.
3. Add the missing sinks -> verify: redirect, XSS, `FileResponse` rows pass.
4. Measure on RealVuln's 20 FastAPI repos (`vc-*-fastapi` and
   `realvuln-vfapi`) and the full 63-repo set at `-P 2`
   -> verify: TP up, precision not down; report the per-repo changes.
5. Check duplicates and scan time on the largest FastAPI repo
   -> verify: one finding per sink, time within 10% of baseline.
6. Full suite, `/code-review`, `/security-review`, PR.
