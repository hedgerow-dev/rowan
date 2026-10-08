# Rule Catalog

Rowan ships 592 source-code rules across 48 YAML files. Model files are
scanned by [Hayward](https://github.com/hedgerow-dev/hayward), Hedgerow's
model-file scanner, which Rowan installs as a dependency.

## Engines

| Engine | Speed | Precision | Rules |
|--------|-------|-----------|-------|
| NeuroScan (regex) | Fast (<1ms/file) | Surface-level | 398 |
| Taint/structural (Opengrep) | Slower | Evidence varies by rule | 194 |
| Hayward (model files) | Fast | Format-aware, structural | [Hayward rules](https://github.com/hedgerow-dev/hayward/blob/main/docs/rules.md) |

## Selected taint rule files

| File | Count | Languages | Categories |
|------|-------|-----------|------------|
| `agent_taint.yaml` | 16 | Python | Text-to-SQL / agent-generated queries, reflection dispatch (LLM-chosen names only[^scope]), memory poisoning (read + write), PII egress (SDK-client sinks only[^scope]), logprob exposure, MCP tool poisoning (env/config/HTTP sources only[^scope]), MCP confused deputy (decorator-registered tools, credential passthrough[^scope]), model-chosen principal (authz) |
| `ai_ml_taint.yaml` | 10 | Python | Deserialization, code injection, command injection, SSRF, SSTI, AI/ML, prompt injection |
| `ml_taint.yaml` | 21 | Python | Chat template SSTI, HF pipeline, OmegaConf, vector store, agent tool, LangChain, torch.hub, vector-store filter injection, unbounded generation params, SSRF |
| `llm_output_taint.yaml` | 6 | Python | Insecure LLM output handling: text-to-SQL, shell/eval injection, SSRF, path traversal, HTML/markdown XSS |
| `web_taint.yaml` | 7 | Python | SQLi, XSS (incl. Django mark_safe/format_html escaping bypasses), path traversal, open redirect, file upload, sensitive data exposure in logs |
| `python_taint.yaml` | 8 | Python | Log injection, header injection, LDAP, arg injection, network pickle |
| `python_taint_extended.yaml` | 9 | Python | SQLi, CMDi, SSRF, SSTI, model loading, path traversal, code injection, prompt injection, NoSQLi |
| `python_web_surface_taint.yaml` | 1 | Python | Reflection / dynamic dispatch on a request-derived name (getattr/globals/import_module); taint-mode companion to the presence-only rule in `python_web_surface.yaml` |
| `supply_chain_taint.yaml` | 5 | Python | HF hub download chain, HTTP download, base64 decode, file write propagation, SSRF, deserialization, code injection, path traversal |
| `a2a_taint.yaml` | 3 | Python | Agent-to-Agent (A2A) protocol: SSRF, deserialization, prompt injection |
| `langchain_hardening_taint.yaml` | 4 | Python | LangChain hardening, taint mode: prompt-template loading path traversal, Cypher injection, Jinja SSTI, SSRF |
| `java_taint.yaml` | 15 | Java | SQLi, CMDi, path traversal, SSRF, XSS, deserialization, XXE, LDAP, EL injection, log injection, open redirect |
| `java_ai_taint.yaml` | 4 | Java | Spring AI / LangChain4j `@Tool` method parameter (model-chosen) to command execution, filesystem path, SQL text, outbound HTTP URL |
| `java_llm_taint.yaml` | 11 | Java | LLM output (Spring AI `ChatClient`, LangChain4j, openai-java, anthropic-java) to SQL, command, HTTP URL, path, servlet response, SpEL/script/Freemarker, YAML/Java deserialization; request to system prompt, vector/graph query, SnakeYAML; config to MCP stdio transport |
| `java_llm_opengrep.yaml` | 1 | Java | Search mode: `StdioMcpTransport.Builder.command(...)` / `ServerParameters.builder(...)` with a non-literal command (the aideepin DB-configured MCP shape) |
| `javascript_taint.yaml` | 10 | JS/TS | SQLi, CMDi, path traversal, SSRF, XSS, NoSQLi, log injection, header injection, open redirect |
| `typescript_agent_taint.yaml` | 7 | JS/TS | MCP tool argument (`McpServer.tool`/`registerTool`, low-level `CallToolRequestSchema` handler), Vercel AI SDK `tool({ execute })` and LangChain.js tool input (model-chosen) to command execution, filesystem path, outbound HTTP URL, SQL text; model output (AI SDK `generateText`/`generateObject`, OpenAI, Anthropic) to `eval`/`Function`/`vm` and shell; a server-supplied OAuth authorization URL to `open()` |
| `go_taint.yaml` | 12 | Go | SQLi, CMDi, path traversal, SSRF, deserialization, log injection, header injection, open redirect |
| `go_ai_taint.yaml` | 8 | Go | MCP tool argument (mcp-go `RequireString`/`GetString`/`Params.Arguments`, official go-sdk typed handler args; model-chosen) and LLM completion text (openai-go, go-openai, langchaingo, anthropic-sdk-go, ollama, genkit) to command execution, filesystem path, SQL statement text, outbound HTTP URL |
| `csharp_taint.yaml` | 9 | C# | SQLi, CMDi, path traversal, SSRF, XSS, deserialization, LDAP, log injection, open redirect |
| `guardrail_opengrep.yaml` | 3 | Python | Guardrail enforcement: result discarded, fail-open handler, verdict checked but not enforced |
| `langchain_hardening_opengrep.yaml` | 4 | Python | LangChain hardening, search mode: unsafe vector-store deserialization, Jinja few-shot injection, vector-filter injection, dangerous Cypher construction |
| `go_ai_opengrep.yaml` | 1 | Go | Search mode, inventory: SSE / streamable-HTTP MCP server bound on all interfaces (`0.0.0.0:port` or `:port`) with no auth middleware in view |

**Total: 194 taint/Opengrep rules**

`guardrail_opengrep.yaml`, `langchain_hardening_opengrep.yaml`,
`go_ai_opengrep.yaml` and `java_llm_opengrep.yaml` are the Opengrep files
whose rules are *search* mode rather than `mode: taint`.
`guardrail_opengrep.yaml`'s rules ask whether a guardrail's verdict is acted
on, which is a control-flow property no dataflow rule can express. `langchain_hardening_opengrep.yaml` holds the LangChain hardening
rulepack's pattern-only checks; its taint-mode siblings live in
`langchain_hardening_taint.yaml`.

## NeuroScan rules by file

| File | Count | Focus |
|------|-------|-------|
| `neuroscan.yaml` | 30 | Core rules: deserialization, injection, SSRF, SSTI, XSS, supply chain |
| `ai_ml_neuroscan.yaml` | 27 | Chat template SSTI, Gradio, MCP, OmegaConf, vector store, LangChain, numpy/ONNX native-code loading |
| `ai_security.yaml` | 101 | Extended AI/ML: deserialization, code exec, supply chain, prompt injection, agent tools, markdown exfiltration (named renderer libraries only[^scope]), reflection dispatch (LLM-chosen names only[^scope]), memory-write scoping, RAG isolation, unbounded consumption, model extraction/privacy (LLM logprob exposure only[^scope]), MCP attack classes (FastMCP `.run()` servers only[^scope]), MCP OAuth 2.1 authorization (audience validation, redirect URI, session-as-auth, PKCE), agent sandbox/code-interpreter escape configuration, unbounded multi-agent delegation topology, A2A agent-card trust, multimodal media-fetch SSRF on the inference path, fake-sandbox exec/eval given a hand-rolled `__builtins__` dict |
| `security_surface.yaml` | 44 | SSRF, path traversal, CMDi, SSTI, SQLi, NoSQLi, XSS, deserialization, JWT |
| `framework_rules.yaml` | 23 | Express.js, Spring, ASP.NET, Gin/Echo, Flask/Django |
| `misc_rules.yaml` | 33 | Bug bounty patterns, auth, logging, Gradio, Streamlit, container isolation, identity disclosure |
| `cloud_rules.yaml` | 7 | S3, IAM, encryption, database, logging, security groups |
| `javascript.yaml` | 10 | JS-specific: eval, child_process, XSS, deserialization |
| `java.yaml` | 10 | Java-specific: Runtime.exec, ProcessBuilder, SQL, deserialization |
| `java_ai_surface.yaml` | 5 | Java AI/MCP surface: public HTTP bind, literal provider keys, mutable tool descriptions, remote DJL model URLs, non-literal model paths |
| `go.yaml` | 11 | Go-specific: exec, template, SQL, SSRF, crypto |
| `csharp.yaml` | 11 | C#-specific: Process.Start, SqlCommand, deserialization, XSS |
| `php.yaml` | 12 | PHP-specific: eval, shell, include, SQL, deserialization |
| `ruby.yaml` | 11 | Ruby-specific: eval, YAML.load, ERB, send, SQL |
| `templates.yaml` | 3 | Server-rendered templates (.html/.jinja/.j2): autoescape disabled, `\|safe` rendering, csrf_exempt. Pattern-only -- there is no template dataflow engine |
| `rust.yaml` | 11 | Rust-specific: unsafe, Command, SQL, crypto |
| `terraform.yaml` | 12 | IaC: security groups, S3, IAM, RDS, CloudFront, EKS, KMS |
| `dockerfile.yaml` | 12 | Container: latest tag, root user, capabilities |
| `github_actions.yaml` | 7 | CI/CD: hardcoded secrets, pull_request_target, unpinned actions, context-expression injection, workflow-input and PR-head-ref injection into `run:` |
| `python_web_surface.yaml` | 7 | Bug-bounty-style web surface checks: sensitive data in query strings, XXE, ReDoS, missing cookie flags, weak randomness, default permissions |
| `ingest_surface.yaml` | 5 | Ingest-time RCE: fsspec ReferenceFileSystem unsandboxed Jinja rendering, HDF5/zarr/kerchunk artifact-internal path following |
| `inference_plane.yaml` | 5 | Inference-plane parameter and cache-key leaks: KV/routing control params on the public request schema, unkeyed or truncated cache-key derivation |

**Total: 398 NeuroScan rules**

## Model-file rules

Rowan finds model files in the scanned project (skipping virtualenvs and
vendored dependency directories) and passes each one to
[Hayward](https://github.com/hedgerow-dev/hayward). Hayward reads pickle,
PyTorch, SafeTensors, GGUF, Keras, ONNX, TensorFlow, TFLite, numpy, joblib,
skops, PMML and archives, plus Hugging Face `config.json` files, without
importing or executing anything it reads. Its findings appear in Rowan's
report with `MFV-*` rule IDs and `engine: "mfv"`.

The full rule list, severities and coverage limits are in
[Hayward's rule catalog](https://github.com/hedgerow-dev/hayward/blob/main/docs/rules.md).

`--exclude` and `.rowanignore` apply to model files as they do to source
files. Under `--ci` the repository's `.rowanignore` is not read, so a scanned
project cannot hide its own model files from the gate.

**`MFV-SKIP-*` findings are not clean verdicts.** They mean a file was not
fully analysed, and Rowan marks the scan incomplete when one appears.

## Rule ID scheme

| Prefix | Meaning | Example |
|--------|---------|---------|
| `NS-DESER-*` | NeuroScan deserialization | `NS-DESER-001` |
| `NS-INJECT-*` | NeuroScan code injection | `NS-INJECT-001` |
| `NS-SSRF-*` | NeuroScan SSRF | `NS-SSRF-001` |
| `NS-SSTI-*` | NeuroScan SSTI | `NS-SSTI-001` |
| `NS-AIML-*` | NeuroScan AI/ML | `NS-AIML-001` |
| `NS-AUTH-*` | NeuroScan auth | `NS-AUTH-001` |
| `NS-CRYPTO-*` | NeuroScan crypto | `NS-CRYPTO-001` |
| `NS-CONFIG-*` | NeuroScan config | `NS-CONFIG-001` |
| `ns-aiml-*` | AI/ML extended | `ns-aiml-030` |
| `ns-cloud-*` | Cloud/IaC | `ns-cloud-001` |
| `ns-sec-*` | Secrets (entropy/placeholder-filtered) | `ns-sec-001` |
| `ns-cicd-*` | CI/CD workflow misconfig | `ns-cicd-001` |
| `TNT-DESER-*` | Taint deserialization | `TNT-DESER-001` |
| `TNT-INJECT-*` | Taint code injection | `TNT-INJECT-001` |
| `TNT-SSRF-*` | Taint SSRF | `TNT-SSRF-001` |
| `TNT-SSTI-*` | Taint SSTI | `TNT-SSTI-001` |
| `TNT-SQLI-*` | Taint SQLi | `TNT-SQLI-001` |
| `TNT-CMDI-*` | Taint CMDi | `TNT-CMDI-001` |
| `TNT-PATH-*` | Taint path traversal | `TNT-PATH-001` |
| `TNT-XSS-*` | Taint XSS | `TNT-XSS-001` |
| `TNT-NOSQL-*` | Taint NoSQLi | `TNT-NOSQL-001` |
| `TNT-AIML-*` | Taint AI/ML general | `TNT-AIML-001` |
| `TNT-ML-*` | Taint ML-specific | `TNT-ML-001` |
| `TNT-LLMOUT-*` | Taint LLM output handling | `TNT-LLMOUT-001` |
| `TNT-AUTHZ-*` | Taint object-level authz (model-chosen principal) | `TNT-AUTHZ-001` |
| `TNT-SUPPLY-*` | Taint supply chain | `TNT-SUPPLY-001` |
| `TNT-LOG-*` | Taint log injection | `TNT-LOG-001` |
| `TNT-HEADER-*` | Taint header injection | `TNT-HEADER-001` |
| `TNT-LDAP-*` | Taint LDAP injection | `TNT-LDAP-001` |
| `MFV-PICKLE-*` | Model file: pickle stream | `MFV-PICKLE-001` |
| `MFV-ST-*` | Model file: SafeTensors | `MFV-ST-001` |
| `MFV-GGUF-*` | Model file: GGUF | `MFV-GGUF-001` |
| `MFV-KERAS-*` | Model file: Keras | `MFV-KERAS-001` |
| `MFV-ONNX-*` | Model file: ONNX | `MFV-ONNX-001` |
| `MFV-TF-*` / `MFV-TFLITE-*` | Model file: TensorFlow, TFLite | `MFV-TF-001` |
| `MFV-SKOPS-*` | Model file: skops | `MFV-SKOPS-001` |
| `MFV-PMML-*` | Model file: PMML | `MFV-PMML-001` |
| `MFV-NPZ-*` / `MFV-JOBLIB-*` / `MFV-7Z-*` | Model file: container discipline | `MFV-NPZ-001` |
| `MFV-EXEC-*` / `MFV-CONFUSE-*` | Model file: embedded binary, format confusion | `MFV-EXEC-001` |
| `MFV-SKIP-*` | Model file: **not analysed**, never a clean verdict | `MFV-SKIP-001` |

`CF-SINK-001`/`CF-RETURN-001` (cross-file propagation: a fixed two-id
family; the callee function is carried in `metadata["callee_name"]` and the
message, not in the rule id) and the structural trust-boundary findings
`AGENT-TOOL-001` (agent-tool sink detection), `TASK-QUEUE-001` (Celery/RQ
task handlers), `GRPC-001` (gRPC servicer methods), `GRAPHQL-001` (GraphQL
resolvers), and `WEBHOOK-001` (webhook/callback handlers) are not YAML rules
and aren't counted in the 592 total above: they're emitted directly by
`CrossFilePass`'s AST analysis rather than loaded from `rules/*.yaml`. See
`ARCHITECTURE.md`'s "Pass 4: CrossFilePass" section for how they're
generated.

`AUTHZ-BOLA-001` (object-level authorization, opt-in via `--authz`) and
`SER-SCOPE-001` (serialization scope widening) are likewise emitted by their own
AST passes rather than loaded from YAML, and are not in the total above.
`SER-SCOPE-001` reports a class whose `__init__` accepts a scoping parameter
(`base_path`, `sources`, `allowed_*`, ...) that its own `_to_config` / `to_dict`
never emits, so serializing and reloading the object silently drops the
constraint. See `rowan/passes/serialization_scope.py`.
`AuthzPass` (`rowan/passes/authz.py`, off by default:
`ScanConfig.enable_authz`, `--authz`) is the same kind of AST-emitted,
non-YAML rule source. It owns two rule ids, both `Category.AUTH`,
`engine="authz"` findings with no corresponding YAML file:
`AUTHZ-BOLA-001` (object-level authorization / BOLA-IDOR: a request handler
reads an ORM object keyed by an attacker-controlled id with no ownership
predicate constraining the read, ADR-0003, issues #171-175) and
`AUTHZ-LLM-001` (an authorization guard whose own condition is derived from
an LLM completion or tool-call argument rather than the server, so anything
that can steer the model can force the allow path, issue #185).

`MultiAgentPass` (`rowan/passes/multiagent.py`, off by default:
`ScanConfig.enable_multiagent`, `--multiagent`) is the same kind of
AST-emitted, non-YAML rule source, scoped to CrewAI only. It emits
`AGENT-HANDOFF-001` (`Category.AI_ML`, `engine="multiagent"`): cross-agent
injection propagation, where a low-trust agent's output reaches a
higher-privilege agent through CrewAI's `Task(context=[...])` handoff
mechanism, issue #188.

## Category coverage

| Category | NeuroScan | Taint | CWE |
|----------|-----------|-------|-----|
| Deserialization | 5+ rules | 6 rules | CWE-502 |
| Code Injection | 4+ rules | 3 rules | CWE-94, CWE-95 |
| Command Injection | 3+ rules | 3 rules | CWE-78 |
| SQL Injection | 1+ rules | 3 rules | CWE-89 |
| NoSQL Injection | 1 rule | 1 rule | CWE-943 |
| SSRF | 3+ rules | 3 rules | CWE-918 |
| SSTI | 2+ rules | 4 rules | CWE-1336 |
| XSS | 1+ rules | 1 rule | CWE-79 |
| Path Traversal | 1+ rules | 3 rules | CWE-22 |
| Supply Chain | 2+ rules | 4 rules | CWE-829 |
| AI/ML | 30+ rules | 10 rules | CWE-94, CWE-502 |
| Prompt Injection | 3+ rules | 3 rules | CWE-77 |
| Auth | 1+ rules | 0 rules | CWE-862 |
| Crypto | 2+ rules | 0 rules | CWE-327 |

## Writing custom rules

See [CONTRIBUTING.md](../CONTRIBUTING.md) for the rule format specification.

### Taint rule anatomy

```yaml
- id: TNT-EXAMPLE-001
  mode: taint
  message: >
    Description of the vulnerability and attack vector.
  severity: ERROR          # ERROR=high, WARNING=medium, INFO=low
  languages: [python]
  metadata:
    cwe: [94]
    category: injection
    confidence: HIGH       # HIGH/MEDIUM/LOW -> 0.95/0.85/0.70

  pattern-sources:         # Where user input enters
    - patterns:
        - pattern-either:
            - pattern: request.args.get(...)
            - pattern: request.form.get(...)

  pattern-sinks:           # Where dangerous function is called
    - patterns:
        - pattern-either:
            - pattern: eval(...)
            - pattern: exec(...)

  pattern-sanitizers:      # What makes the flow safe
    - patterns:
        - pattern-either:
            - pattern: ast.literal_eval(...)

  pattern-propagators:     # Functions that carry taint through (optional)
    - pattern: json.loads($X)
      from: $X
      to: $X
```

#### Sanitizer soundness

A `pattern-sanitizers` entry clears taint wherever that call shape is
*applied to the tainted value* -- but Opengrep matches by call **shape**,
not by whether the specific arguments actually neutralize the threat. Before
adding a sanitizer, ask: **does this call's safety depend only on whether it
was applied, or also on what was passed to it?**

- **Safe to add unbound** (`pattern: foo(...)`): type coercions (`int(...)`),
  dedicated escaping/quoting primitives (`html.escape`, `repr`,
  `shlex.quote`), parameterized-query APIs, safe-by-design alternative
  loaders (`yaml.safe_load` vs `yaml.load`). Their neutralizing effect is a
  fixed property of the function, independent of caller-supplied arguments.
- **Do NOT add unbound:** generic string-replace/regex-substitute calls
  (`re.sub(...)`, `.replace(...)`, `Regex.Replace(...)`,
  `strings.ReplaceAll(...)`, `.replaceAll(...)`) -- their effect is entirely
  a function of arguments the pattern doesn't pin down, so
  `re.sub(r"unrelated", "x", tainted_val)` clears taint exactly as readily
  as one that actually removes the dangerous characters. If you need a
  replace-based sanitizer, bind it to the specific literal being targeted,
  e.g. `$STR.replace("\n", ...)`, not `$STR.replace(...)`.
- **Watch for narrow-but-real primitives:** `.strip()` only trims edges, not
  an embedded newline; `.resolve()`/`normalize()`/`Path.GetFullPath(...)`
  normalize a path but don't enforce it stays under an intended root. These
  look sound (no caller-supplied arguments to misuse) but only cover part of
  the threat's real shape.
- **YAML escaping gotcha:** to match a real newline/CR escape in the target
  source (`.replace("\n", "")`), write the pattern with **single-quoted
  YAML** (`pattern: $STR.replace('\n', ...)`) or a plain unquoted scalar.
  Double-quoted YAML (`"\\n"`) processes the backslash escape itself and
  YAML-unescapes to a literal 2-character `\n`, which only matches an
  already-double-escaped edge case and silently never matches the normal
  idiom developers actually write.

Before merging a new sanitizer, verify it empirically: scan a fixture where
the sanitizer is applied to the tainted value with an *unrelated* argument,
and confirm the finding still fires. See
`tests/test_taint_sanitizer_soundness.py` for the regression-test pattern.

Java and Go application-specific path/URL guards are handled conservatively
after rule execution. A correlated `validate*Path`-style helper, a
normalization-plus-base-prefix idiom, or a parsed-host allowlist lowers the
finding to a review lead; it does not remove it. This distinction is
intentional: a helper's name and a text window cannot prove dominance or the
helper's implementation, so audit output preserves the original finding and
records `java_go_guard_evidence` metadata.

### NeuroScan rule anatomy

```yaml
- id: NS-EXAMPLE-001
  pattern: "eval\\s*\\("
  message: "eval() call detected"
  severity: high
  category: injection
  cwe: 95
  languages: [python, javascript]
  fix: "Use ast.literal_eval() or a safe parser"
```

The NeuroScan engine does not load `rules/*.yaml` directly. It loads
`rules/converted/_manifest.json`, produced by
`scripts/convert_neuroscan_to_opengrep.py`, which converts every non-taint
rule file into semgrep-native YAML plus the manifest (rule_id to category,
CWE, severity, and other metadata that opengrep does not propagate into
SARIF `properties`). After adding or editing a rule in a NeuroScan (regex)
YAML file, run:

```
python scripts/convert_neuroscan_to_opengrep.py
```

Skip this step and the new rule is invisible to a scan: it exists in the
source YAML but never reaches the manifest the engine actually reads. A
scan run with `-v` logs `Loaded conversion manifest: N rules` on startup;
confirm `N` grew by the number of rules you added.

## Scope limits on advertised categories

[^scope]: These categories are real and shipped, but narrower than the label
    suggests. Each was verified against a labelled vulnerable application
    (Langfail) where a purpose-built rule existed and produced no finding:

    * **Reflection dispatch** (`TNT-ML-012`, `TNT-ML-017`, `ns-aiml-110`)
      requires the dispatched name to come from an LLM tool call, matched as
      `$CALL.function.name` / `$CALL["function"]["name"]` or a
      `tool_use`/`tool_call`-hinted `.name`. The structural
      `AGENT-CAPABILITY-001` and `AGENT-REFLECTION-SURFACE-001` passes cover
      normalized application dispatch such as `call.get("name")` only when
      they can recover a tool registry or advertised action surface. There is
      still no generic rule for ordinary non-AI reflection.
    * **PII egress** (`TNT-ML-014`) directly recognizes SDK-object sinks
      (`$LLM.chat(...)`, `$CLIENT.chat.completions.create(...)`, ...).
      `TNT-ML-PII-EGRESS-001` additionally follows application-owned PII
      wrappers to an LLM-facing raw `requests.post(...)` call, but cannot prove
      that an opaque outbound HTTP helper is a model endpoint.
    * **Markdown exfiltration** (`TNT-ML-015`, `ns-aiml-109`) keys on named
      renderer libraries (`markdown`, `mistune`, `commonmark`, `marked`,
      `react-markdown`). A hand-rolled regex renderer is not matched.
    * **Model extraction / privacy** (`TNT-ML-023`, `ns-aiml-123`) covers only
      the LLM logprob-exposure variant (Carlini et al.). The classical
      attacks against a plain classifier -- full probability vector (Tramèr
      et al.) and per-record loss disclosure (Shokri et al.) -- have no rule.
    * **MCP attack classes** (`ns-aiml-126`, `ns-aiml-127`) cover FastMCP's
      high-level `.run(host=..., transport=...)` API. `MCP-HTTP-BIND-001`
      additionally follows a low-level imported `mcp.server.Server` through
      its `streamable_http_app()`/`sse_app()` result to `uvicorn.run(...)`,
      and also recognizes an `SseServerTransport` served with a configuration
      value that defaults to all interfaces while authentication defaults off.
      Reverse-proxy authentication and unusual ASGI hosting arrangements remain
      outside that structural check. `MCP-SAMPLING-APPROVAL-001` follows the
      Python SDK's `Client`/`ClientSession` `sampling_callback=` registration
      into a same-module callback; dynamically supplied or cross-module
      callbacks remain outside the check. `TNT-ML-024`
      additionally recognizes only env/config/HTTP sources for a mutable tool
      description, not an ORM read.
