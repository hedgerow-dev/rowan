"""Single source of truth for shared taint sources / sinks / sanitizers (issue #159).

The rule corpus historically inlined the same source/sink/sanitizer pattern
lists into every rule that needed them, hand-copied across ~30 YAML files. That
is the root cause of a whole class of drift defects logged in ``BACKLOG.md``
(DEF-10/14/15/19/26 etc.): two copies of "the same" list silently diverge, and
the divergence is only ever found by a corpus hunt after it has already shipped.

This module makes one definition authoritative and lets everything else be
generated or checked against it:

* ``scripts/sync_registry.py`` expands a fragment into the hand-written rule
  YAML between ``# rowan-registry:begin`` / ``# rowan-registry:end`` sentinel
  comments (Opengrep ignores the comments; the expanded block is what it sees).
* ``rowan/core/sanitizers.py`` builds its per-category regex table from
  :data:`SANITIZER_REGEX` here instead of keeping its own third copy.
* ``tests/test_registry_no_drift.py`` fails CI if any expanded region no longer
  matches its fragment, so a future hand-edit that reintroduces drift cannot
  merge silently.

Two surface forms are kept deliberately, because the two consumers need
different dialects:

* **Opengrep patterns** (:data:`SOURCES`, :data:`SINKS`): semgrep/opengrep
  ``pattern:`` expressions, rendered into ``pattern-either`` blocks for the
  ``mode: taint`` rule files.
* **Regexes** (:data:`SANITIZER_REGEX`): Python ``re`` patterns for the
  enrichment-layer post-filter in :mod:`rowan.core.sanitizers`.

A fragment is an ordered list of entries. An entry is either a plain string
(shorthand for ``- pattern: <string>``) or a single-key dict that is emitted
as-is under the ``pattern-either`` (``{"patterns": [...]}`` with nested
``pattern-inside`` / ``metavariable-regex`` items, for shapes a flat
``pattern:`` cannot express). A multi-line string value renders as a ``|``
block scalar. Strings are emitted verbatim, so YAML-quote a pattern that
contains a colon in the fragment itself.
"""

from __future__ import annotations

from rowan.core.findings import Category

#: One fragment entry: a bare pattern string, or a single-key mapping.
Entry = str | dict[str, object]

# --------------------------------------------------------------------------- #
# Opengrep-pattern fragments (for `mode: taint` rule YAML).
# --------------------------------------------------------------------------- #

#: Canonical HTTP/CLI/UI request-input source list. This exact 33-pattern block
#: was byte-for-byte duplicated across python_taint.yaml, ai_ml_taint.yaml,
#: ml_taint.yaml and web_taint.yaml; it is now expanded from here.
_WEB_REQUEST_SOURCES: list[str] = [
    "request.args.get(...)",
    "request.args[...]",
    "request.form.get(...)",
    "request.form[...]",
    "request.json.get(...)",
    "request.json[...]",
    "request.data",
    "request.stream",
    "request.get_json(...)",
    "request.values.get(...)",
    "request.files.get(...)",
    "request.cookies.get(...)",
    "request.headers.get(...)",
    "request.GET.get(...)",
    "request.GET[...]",
    "request.POST.get(...)",
    "request.POST[...]",
    "request.body",
    "request.query_params",
    "input(...)",
    "sys.argv",
    "os.environ[...]",
    "os.getenv(...)",
    "await request.json(...)",
    "await request.form(...)",
    "await request.body(...)",
    "await websocket.recv(...)",
    "await websocket.receive_text(...)",
    "st.chat_input(...)",
    "st.text_input(...)",
    "st.file_uploader(...)",
    "gr.File(...)",
    "gr.UploadButton(...)",
]

# Parsed CLI arguments are an additional operator-controlled source. JSON
# parsing and kwargs lookups propagate existing taint; neither creates it.
_WEB_REQUEST_ARGPARSE_SOURCES: list[str] = [*_WEB_REQUEST_SOURCES, "args.$PARAM"]

# End-user input: everything in web_request except operator-controlled CLI
# args and environment. `open(sys.argv[1])` in a CLI tool or
# `requests.get(os.environ["API_URL"])` is configuration, not an attack
# surface, so rules that never treated argv/env as a source (SSRF, path
# traversal, prompt/tool-arg injection) take this fragment instead.
_USER_INPUT_SOURCES: list[str] = [
    p for p in _WEB_REQUEST_SOURCES if p not in ("sys.argv", "os.environ[...]", "os.getenv(...)")
]

# Some rules need HTTP-only sources rather than operator input (CLI/env)
# or UI widgets. Ordinary parsing and kwargs access are propagators in both
# fragments, not independent trust boundaries.
_HTTP_REQUEST_SOURCES: list[str] = [
    p
    for p in _WEB_REQUEST_SOURCES
    if p.startswith(("request.", "await request.", "await websocket."))
]

# Model-metadata reads: values an attacker controls by publishing a malicious
# model/adapter (tokenizer/generation/adapter config fields, AutoConfig fields,
# Hub-downloaded file contents). This is the SSTI-relevant source surface for
# CVE-2026-5760 (SGLang) generalized beyond `chat_template`: the chat_template
# attribute reads themselves stay with TNT-ML-008 (its `tokenizer.chat_template`
# / `self.chat_template` / `tokenizer_config.get(...)` sources), so this list
# deliberately omits them to keep the chat_template flow's attribution clean and
# instead covers the OTHER metadata fields (generation_config, adapter/LoRA
# config, AutoConfig/AutoProcessor fields, hf_hub_download contents).
_MODEL_METADATA_SOURCES: list[str] = [
    "AutoConfig.from_pretrained(...)",
    "AutoProcessor.from_pretrained(...)",
    "PretrainedConfig.from_pretrained(...)",
    "hf_hub_download(...)",
    "snapshot_download(...)",
    "generation_config.get(...)",
    "generation_config[...]",
    "gen_config.get(...)",
    "gen_config[...]",
    "model_config.get(...)",
    "model_config[...]",
    "adapter_config.get(...)",
    "adapter_config[...]",
    "lora_config.get(...)",
    "lora_config[...]",
]

#: Document/media-ingestion channel (issue #191): none of these are user
#: request input in the web_request sense -- the untrusted party is whoever
#: authored the uploaded file the pipeline is reading FROM. Indirect prompt
#: injection through documents is the dominant real-world delivery vector
#: (OCR'd/PDF'd/transcribed text an attacker plants in a file a victim
#: pipeline ingests), and none of it was previously a taint source at all.
_DOCUMENT_INGEST_SOURCES: list[str] = [
    # OCR
    "pytesseract.image_to_string(...)",
    "$READER.readtext(...)",
    "$CLIENT.detect_document_text(...)",
    "$CLIENT.analyze_document(...)",
    "$VISION_CLIENT.text_detection(...)",
    "$VISION_CLIENT.document_text_detection(...)",
    # PDF text-layer extraction
    "$PAGE.extract_text(...)",
    "$PDF.pages[...].extract_text(...)",
    "$PDF.extract_text(...)",
    "partition(...)",
    "partition_pdf(...)",
    # Image EXIF/XMP metadata
    "$IMG._getexif(...)",
    "$IMG.getexif(...)",
    "exifread.process_file(...)",
    "piexif.load(...)",
    # Audio transcription
    "$MODEL.transcribe(...)",
    "$CLIENT.audio.transcriptions.create(...)",
    "$CLIENT.audio.translations.create(...)",
    # Office document / HTML loaders (LangChain-style)
    "UnstructuredWordDocumentLoader(...).load(...)",
    "UnstructuredHTMLLoader(...).load(...)",
    "BSHTMLLoader(...).load(...)",
    "Docx2txtLoader(...).load(...)",
    "PyPDFLoader(...).load(...)",
    "UnstructuredExcelLoader(...).load(...)",
]

#: LLM completion text as a taint source (Python; issue #133, OWASP LLM02).
#: The original 17-pattern block was hand-copied byte-for-byte into
#: TNT-LLMOUT-001..006 (llm_output_taint.yaml) and TNT-ML-019
#: (agent_taint.yaml); it is now expanded from here. TNT-ML-010/011/015/029
#: and TNT-AUTHZ-001 carry deliberately narrower variants and stay inline.
#:
#: BACKLOG PY-01 added the 2025-era agent SDK return shapes. Only the *call*
#: is listed for each: Opengrep propagates taint through the attribute read
#: (`result.final_output`, `result.output`, `resp.content`, `pred.answer`),
#: the dict lookup (`res["llm"]["replies"]`) and the loop variable of
#: `async for event in runner.run_async(...)`, so an assignment-guarded
#: attribute pattern adds nothing (verified live; see
#: tests/test_llm_output_new_shapes.py). Module-qualified names
#: (`agents.Runner.run`, `claude_agent_sdk.query`, `dspy.Predict`) rely on
#: Opengrep's import resolution: they match `Runner.run(...)` only in a file
#: that imports `Runner` from `agents`, which is what keeps a foreign
#: `Runner` class or a database `query()` out.
_LLM_OUTPUT_SOURCES: list[Entry] = [
    "$RESPONSE.choices[$N].message.content",
    "$RESPONSE.choices[$N].message.text",
    "$RESPONSE.choices[$N].text",
    "$MESSAGE.content[$N].text",
    "$CHUNK.choices[0].delta.content",
    "openai.ChatCompletion.create(...)",
    "$CLIENT.chat.completions.create(...)",
    "litellm.completion(...)",
    "litellm.acompletion(...)",
    # OpenAI Agents SDK: `from agents import Runner`.
    "agents.Runner.run(...)",
    "agents.Runner.run_sync(...)",
    "agents.Runner.run_streamed(...)",
    # Claude Agent SDK: `async for msg in query(...)` yields a ResultMessage.
    "claude_agent_sdk.query(...)",
    # DSPy: a compiled module is called, not invoked.
    "dspy.Predict(...)(...)",
    "dspy.ChainOfThought(...)(...)",
    {
        "patterns": [
            {
                "pattern-either": [
                    "$LLM.invoke(...)",
                    "$LLM.predict(...)",
                    "$LLM.generate(...)",
                    "$LLM.chat(...)",
                ]
            },
            {
                "metavariable-regex": {
                    "metavariable": "$LLM",
                    "regex": "(?i).*(llm|model|client|chat|agent|assistant|bot|gpt|openai|anthropic|deepseek|litellm).*",
                }
            },
        ]
    },
    {
        "patterns": [
            {
                "pattern-either": [
                    "$CHAIN.invoke(...)",
                    "$CHAIN.run(...)",
                    "$CHAIN.predict(...)",
                    # Pydantic AI Agent.run_sync / run_stream (run is above).
                    "$CHAIN.run_sync(...)",
                    "$CHAIN.run_stream(...)",
                ]
            },
            {
                "metavariable-regex": {
                    "metavariable": "$CHAIN",
                    "regex": "(?i).*(chain|agent|executor).*",
                }
            },
        ]
    },
    # Google ADK Runner: run_async yields events whose content.parts[].text
    # is model output; run() is the sync form. Case-sensitive on purpose:
    # ADK's runner is always an instance (`runner`, `self._runner`), and the
    # class-level `Runner.run(...)` is the OpenAI Agents shape above, which
    # is import-resolved so a foreign `Runner` class stays out.
    {
        "patterns": [
            {
                "pattern-either": [
                    "$RUNNER.run_async(...)",
                    "$RUNNER.run(...)",
                ]
            },
            {
                "metavariable-regex": {
                    "metavariable": "$RUNNER",
                    "regex": ".*runner.*",
                }
            },
        ]
    },
    # Haystack 2: Pipeline.run returns {"llm": {"replies": [...]}}. The
    # nested lookup is listed for results that cross a function boundary; a
    # bare `$X["replies"]` was deliberately left out (forum-shaped key).
    {
        "patterns": [
            "$PIPELINE.run(...)",
            {
                "metavariable-regex": {
                    "metavariable": "$PIPELINE",
                    "regex": "(?i).*(pipeline|pipe).*",
                }
            },
        ]
    },
    '$RESULT["llm"]["replies"]',
    # Semantic Kernel: agent.get_response(...).content, kernel.invoke_prompt.
    {
        "patterns": [
            {
                "pattern-either": [
                    "$KERNEL.get_response(...)",
                    "$KERNEL.invoke_prompt(...)",
                    "$KERNEL.invoke(...)",
                ]
            },
            {
                "metavariable-regex": {
                    "metavariable": "$KERNEL",
                    "regex": "(?i).*(kernel|agent).*",
                }
            },
        ]
    },
    # DSPy module held in a variable: `predictor(question=q).answer`. Anchored
    # to the whole name (optionally `self.`-prefixed) so `model.predict(x)`
    # on a scikit-learn estimator does not bind here; `.answer` is left to
    # propagation because `$OUT.answer` alone is too generic to guard.
    {
        "patterns": [
            "$PREDICTOR(...)",
            {
                "metavariable-regex": {
                    "metavariable": "$PREDICTOR",
                    "regex": "(?i)^(?:self\\.)?(?:\\w*_)?(predict|predictor|cot|react)$",
                }
            },
        ]
    },
    {
        "patterns": [
            "$MODEL.generate_content(...)",
            {
                "metavariable-regex": {
                    "metavariable": "$MODEL",
                    "regex": "(?i).*(model|gemini|genai|client).*",
                }
            },
        ]
    },
    {
        "patterns": [
            "$PIPE(...)",
            {
                "metavariable-regex": {
                    "metavariable": "$PIPE",
                    "regex": "(?i).*(pipe|pipeline|generator|classifier).*",
                }
            },
        ]
    },
]


def _java_annotated_param(annotation: str) -> Entry:
    """A method parameter carrying ``annotation`` (bare or with arguments)."""
    return {
        "patterns": [
            "$PARAM",
            {
                "pattern-inside": (
                    f"$RET $METHOD(..., {annotation} $TYPE $PARAM, ...) {{\n  ...\n}}"
                )
            },
        ]
    }


#: Java HTTP request input (servlet, Spring MVC, JAX-RS). Used by the six
#: tnt-ja-{sqli,cmdi,path,ssrf,xss,log}-001 rules in java_taint.yaml.
#: `System.getenv` lived here until EXT-19 moved it to `operator_input_java`.
_WEB_REQUEST_JAVA_SOURCES: list[Entry] = [
    "(HttpServletRequest $REQ).getParameter(...)",
    "request.getParameter(...)",
    _java_annotated_param("@RequestParam"),
    _java_annotated_param("@RequestParam(...)"),
    _java_annotated_param("@PathVariable"),
    _java_annotated_param("@PathVariable(...)"),
    _java_annotated_param("@RequestBody"),
    _java_annotated_param("@RequestBody(...)"),
    _java_annotated_param("@QueryParam"),
    _java_annotated_param("@QueryParam(...)"),
    {
        "patterns": [
            "$PARAM",
            {
                "pattern-inside": (
                    "@$MAPPING(...)\n$RET $METHOD(..., String $PARAM, ...) {\n  ...\n}"
                )
            },
            {
                "metavariable-regex": {
                    "metavariable": "$MAPPING",
                    "regex": "^(GetMapping|PostMapping|PutMapping|DeleteMapping|RequestMapping|PatchMapping)$",
                }
            },
        ]
    },
]

#: Java operator-controlled input: process environment and system properties,
#: main-method argv, Spring `Environment` lookups and `@Value` field injection.
#: Split from the request fragment (EXT-19) so the tnt-ja-*-002 siblings can
#: rate it WARNING; ADR-0005 found every Java FP on dubbo traced to
#: `System.getenv`. The `@Value` shape taints every use of the injected
#: field's name inside the class, which is the field itself in practice.
#: `System.getProperty` excludes the standard JVM keys (`user.dir`,
#: `java.io.tmpdir`, `user.home`, `os.name`, ...): those are the runtime's
#: own values, not a `-D` flag, and `new File(System.getProperty("user.dir"),
#: ...)` alone was 40 findings on mateclaw and EDDI.
_OPERATOR_INPUT_JAVA_SOURCES: list[Entry] = [
    "System.getenv(...)",
    {
        "patterns": [
            "System.getProperty($KEY, ...)",
            {"pattern-not": 'System.getProperty("=~/^(java|os|file|path|line|user)\\./", ...)'},
        ]
    },
    "args[$I]",
    "(Environment $E).getProperty(...)",
    {
        "patterns": [
            "$FIELD",
            {"pattern-inside": ('class $C {\n  ...\n  @Value("...") $TYPE $FIELD;\n  ...\n}')},
        ]
    },
]

#: Go HTTP request input (net/http and gin). `$C.Query(...)` is typed on
#: purpose: the bare form also matched `db.Query(...)`, making every database
#: query its own source and sink.
_WEB_REQUEST_GO_SOURCES: list[Entry] = [
    "$R.URL.Query()",
    "$R.FormValue(...)",
    "$R.Body",
    "$C.Param(...)",
    '"($C : *gin.Context).Query(...)"',
    "$C.ShouldBindJSON(...)",
]

#: Go operator-controlled input (env, flags, argv, viper config). Split from
#: the request fragment so a rule can rate it lower than attacker-controlled
#: request data (tnt-go-{sqli,cmdi,path,ssrf}-002). `os.Environ()` is left
#: out on purpose: its idiom is `cmd.Env = append(os.Environ(), ...)` beside
#: an `exec.Command`, and intrafile taint then flags the whole closure
#: (gogs internal/ssh/ssh.go:63), a systematic cmdi-002 false positive.
_OPERATOR_INPUT_GO_SOURCES: list[Entry] = [
    "os.Getenv(...)",
    "os.LookupEnv(...)",
    "flag.String(...)",
    "flag.Arg(...)",
    "os.Args",
    "viper.GetString(...)",
    "viper.Get(...)",
]

#: Java LLM completion text: Spring AI ChatClient/ChatResponse, LangChain4j,
#: openai-java, anthropic-java. Typed metavariables where the method name is
#: generic (text/content/chat/generate), untyped where the chain is distinctive.
_LLM_OUTPUT_JAVA_SOURCES: list[Entry] = [
    # Spring AI
    "$CLIENT.prompt(...). ... .call().content()",
    "$CLIENT.prompt(...). ... .call().chatResponse().getResult().getOutput().getText()",
    "$RESP.getResult().getOutput().getText()",
    "$RESP.getResult().getOutput().getContent()",
    # LangChain4j
    "(ChatLanguageModel $M).chat(...)",
    "(ChatModel $M).chat(...)",
    "(ChatLanguageModel $M).generate(...)",
    "(AiMessage $M).text()",
    "(Result<$T> $R).content()",
    "$RESPONSE.aiMessage().text()",
    # openai-java
    "$COMPLETION.choices().get($I).message().content()",
    "$COMPLETION.choices().get($I).message().content().orElse(...)",
    "$COMPLETION.choices().get($I).message().content().get()",
    # anthropic-java
    "$MSG.content().get($I).text().get().text()",
]

#: Java LLM tool inputs: parameters of Spring AI / LangChain4j `@Tool` methods
#: (matched by annotation name; imports are not resolvable in a pattern),
#: `@ToolParam` parameters, and the `apply` argument of a `Function<Req, Resp>`
#: registered as a Spring AI function callback.
_LLM_TOOL_PARAM_JAVA_SOURCES: list[Entry] = [
    {
        "patterns": [
            "$PARAM",
            {"pattern-inside": "@Tool\n$RET $METHOD(..., $TYPE $PARAM, ...) {\n  ...\n}"},
        ]
    },
    {
        "patterns": [
            "$PARAM",
            {"pattern-inside": "@Tool(...)\n$RET $METHOD(..., $TYPE $PARAM, ...) {\n  ...\n}"},
        ]
    },
    _java_annotated_param("@ToolParam"),
    _java_annotated_param("@ToolParam(...)"),
    {
        "patterns": [
            "$REQ",
            {"pattern-inside": "$RESP apply($REQT $REQ) {\n  ...\n}"},
            {"pattern-inside": "class $CLS implements Function<$A, $B> {\n  ...\n}"},
        ]
    },
]

#: Go LLM completion text: openai-go / go-openai, langchaingo, anthropic-sdk-go,
#: ollama api, genkit.
_LLM_OUTPUT_GO_SOURCES: list[Entry] = [
    "$RESP.Choices[$I].Message.Content",
    "$RESP.Choices[$I].Content",
    "llms.GenerateFromSinglePrompt(...)",
    "$MSG.Content[$I].Text",
    "$RESP.Message.Content",
    '"($RESP : api.GenerateResponse).Response"',
    "genkit.Generate(...)",
    "genkit.GenerateText(...)",
    '"($RESP : *ai.ModelResponse).Text()"',
]

#: Go MCP tool-call arguments: mcp-go (`request.Params.Arguments`, the
#: Get*/Require* accessors) and the official go-sdk (`req.Params.Arguments`
#: and the typed `args` parameter of a tool handler).
_MCP_TOOL_ARG_GO_SOURCES: list[Entry] = [
    "$REQ.Params.Arguments",
    "$REQ.GetArguments()",
    # GetString/GetInt/GetFloat/GetBool/RequireString/RequireInt are common
    # accessor names (cobra's *pflag.FlagSet has GetString/GetInt/GetBool
    # too), so the receiver must be typed as mcp.CallToolRequest. Without
    # this, `cmd.Flags().GetString("app-id")` in an unrelated CLI-flag
    # parser matches the source (github-mcp-server JG-08 corpus: an
    # operator-supplied `--stdio-server-cmd` flag and a GitHub App key path
    # flag both got misread as model-controlled).
    '"($REQ : mcp.CallToolRequest).GetString(...)"',
    '"($REQ : mcp.CallToolRequest).GetInt(...)"',
    '"($REQ : mcp.CallToolRequest).GetFloat(...)"',
    '"($REQ : mcp.CallToolRequest).GetBool(...)"',
    '"($REQ : mcp.CallToolRequest).RequireString(...)"',
    '"($REQ : mcp.CallToolRequest).RequireInt(...)"',
    {
        "patterns": [
            "$ARGS",
            {
                "pattern-inside": (
                    "func(ctx context.Context, $REQ *mcp.CallToolRequest, $ARGS $T) "
                    "(*mcp.CallToolResult, $OUT, error) {\n  ...\n}"
                )
            },
        ]
    },
    {
        "patterns": [
            "$ARGS",
            {
                "pattern-inside": (
                    "func $H(ctx context.Context, $REQ *mcp.CallToolRequest, $ARGS $T) "
                    "(*mcp.CallToolResult, $OUT, error) {\n  ...\n}"
                )
            },
        ]
    },
]

#: A request field destructured in an Express/Koa/Fastify handler's
#: parameters, e.g. `({ query }: Request, res) => ... query.to` (Juice Shop),
#: which never mentions `req.query`. The destructured name must be a request
#: field, and the handler must look like one: the parameter is typed as a
#: request, or a second parameter is named like a response. Added alongside
#: each JS rule's own explicit sources.
_REQUEST_FIELD = r"^(query|body|params|headers|cookies)$"
_WEB_REQUEST_JS_DESTRUCTURED_SOURCES: list[Entry] = [
    {
        "patterns": [
            {
                "pattern-either": [
                    {
                        "patterns": [
                            {
                                "pattern-either": [
                                    {"pattern-inside": "({..., $SRC, ...}: $T, ...) => {\n  ...\n}"},
                                    {"pattern-inside": "function $F({..., $SRC, ...}: $T, ...) {\n  ...\n}"},
                                ]
                            },
                            {
                                "metavariable-regex": {
                                    "metavariable": "$T",
                                    "regex": r"^(express\.)?Request$|^(FastifyRequest|NextRequest|IncomingMessage|KoaRequest)\b",
                                }
                            },
                        ]
                    },
                    {
                        "patterns": [
                            {
                                "pattern-either": [
                                    {"pattern-inside": "({..., $SRC, ...}, $RES, ...) => {\n  ...\n}"},
                                    {"pattern-inside": "function $F({..., $SRC, ...}, $RES, ...) {\n  ...\n}"},
                                ]
                            },
                            {"metavariable-regex": {"metavariable": "$RES", "regex": r"^(res|resp|response|reply)$"}},
                        ]
                    },
                ]
            },
            "$SRC",
            {"metavariable-regex": {"metavariable": "$SRC", "regex": _REQUEST_FIELD}},
        ]
    },
]

#: name -> ordered list of opengrep source entries.
SOURCES: dict[str, list[Entry]] = {
    "web_request": _WEB_REQUEST_SOURCES,
    "web_request_argparse": _WEB_REQUEST_ARGPARSE_SOURCES,
    "user_input": _USER_INPUT_SOURCES,
    "http_request": _HTTP_REQUEST_SOURCES,
    "model_metadata": _MODEL_METADATA_SOURCES,
    "document_ingest": _DOCUMENT_INGEST_SOURCES,
    "llm_output": _LLM_OUTPUT_SOURCES,
    "web_request_java": _WEB_REQUEST_JAVA_SOURCES,
    "operator_input_java": _OPERATOR_INPUT_JAVA_SOURCES,
    "web_request_go": _WEB_REQUEST_GO_SOURCES,
    "operator_input_go": _OPERATOR_INPUT_GO_SOURCES,
    "llm_output_java": _LLM_OUTPUT_JAVA_SOURCES,
    "llm_tool_param_java": _LLM_TOOL_PARAM_JAVA_SOURCES,
    "llm_output_go": _LLM_OUTPUT_GO_SOURCES,
    "mcp_tool_arg_go": _MCP_TOOL_ARG_GO_SOURCES,
    "web_request_js_destructured": _WEB_REQUEST_JS_DESTRUCTURED_SOURCES,
}

#: name -> ordered list of opengrep sink entries.
#: (Populated incrementally as sink blocks are migrated; see issue #159.)
SINKS: dict[str, list[Entry]] = {}


# --------------------------------------------------------------------------- #
# Regex sanitizer fragments (for the enrichment post-filter).
# --------------------------------------------------------------------------- #

#: Per-category sanitizer regexes. This is the authoritative copy; the runtime
#: table in :mod:`rowan.core.sanitizers` is derived from it. Values here
#: preserve the previously hand-maintained set exactly (behaviour-preserving);
#: extend here rather than in sanitizers.py so the two never drift again.
SANITIZER_REGEX: dict[Category, list[str]] = {
    Category.INJECTION: [
        # Parameterized execution on ANY DB handle, not just one literally
        # spelled `cursor` (#302): conn/db/session/self.conn all parameterize
        # the same way, and the old `cursor\.execute` form reported correctly
        # parameterized queries as "without parameterization".
        # The SQL argument is matched as either a quoted literal (commas
        # inside it are fine, `VALUES (?, ?)` is the common case) or a bare/
        # dotted name, followed by a second argument. An f-string is
        # deliberately NOT accepted: interpolation is not made safe by also
        # passing params, so that shape must stay flagged.
        r"[\w.]+\.execute(?:many)?\(\s*(?:[rbuRBU]?\"[^\"]*\"|[rbuRBU]?'[^']*'|[A-Za-z_][\w.]*)\s*,",
        r"int\(",
        r"float\(",
        r"ast\.literal_eval\(",
        r"PreparedStatement",
        r"bindparam\(",
    ],
    Category.COMMAND_INJECTION: [
        r"shlex\.quote\(",
        r"shell\s*=\s*False",
        r"subprocess\.run\(\s*\[",
    ],
    Category.PATH_TRAVERSAL: [
        r"os\.path\.basename\(",
        r"secure_filename\(",
        r"\.resolve\(\)",
        r"os\.path\.realpath\(",
    ],
    Category.SSRF: [
        r"validate_url\(",
        r"is_allowed_domain\(",
        r"urlparse\(",
        r"is_private_ip\(",
    ],
    Category.XSS: [
        r"html\.escape\(",
        r"markupsafe\.escape\(",
        r"DOMPurify",
        r"encodeURIComponent\(",
        r"bleach\.clean\(",
    ],
    Category.SSTI: [
        r"SandboxedEnvironment",
        r"ImmutableSandboxedEnvironment",
        r"render_template\s*\(",
    ],
    Category.DESERIALIZATION: [
        r"weights_only\s*=\s*True",
        r"yaml\.safe_load\(",
        r"yaml\.SafeLoader",
        r"safetensors",
        r"ast\.literal_eval\(",
        r"defusedxml",
    ],
    Category.NOSQL_INJECTION: [
        r"int\(",
        r"float\(",
        r"ObjectId\(",
        r"Schema\(",
    ],
    Category.PROMPT_INJECTION: [
        r"moderation",
        r"LlamaGuard",
        r"guardrails",
        r"content_filter",
    ],
    Category.GENERAL: [
        r"pattern\s*=\s*",
        r"regex\s*=\s*",
    ],
}


# --------------------------------------------------------------------------- #
# Rendering: turn a fragment into the exact YAML text used in the rule files.
# --------------------------------------------------------------------------- #

# Kinds addressable by a `# rowan-registry:begin <kind>=<name>` sentinel.
_FRAGMENTS: dict[str, dict[str, list[Entry]]] = {
    "source": SOURCES,
    "sink": SINKS,
}


def fragment_patterns(kind: str, name: str) -> list[Entry]:
    """Return the ordered opengrep source/sink entries for a fragment.

    Raises KeyError with a helpful message if the kind/name is unknown so a
    typo'd sentinel fails loudly at sync/check time rather than silently
    expanding to nothing.
    """
    try:
        table = _FRAGMENTS[kind]
    except KeyError:
        raise KeyError(
            f"unknown registry fragment kind {kind!r}; expected one of {sorted(_FRAGMENTS)}"
        ) from None
    try:
        return table[name]
    except KeyError:
        raise KeyError(
            f"unknown registry {kind} fragment {name!r}; defined: {sorted(table)}"
        ) from None


def render_pattern_either_block(kind: str, name: str, base_indent: int) -> str:
    """Render a fragment as a `- patterns: / pattern-either:` YAML block.

    ``base_indent`` is the column of the leading ``- patterns:`` list item (the
    same column as the sentinel comment). The nesting below it matches the hand-
    written corpus style exactly (``pattern-either`` at +4, each ``pattern`` at
    +8), so an expansion of an already-correct block is byte-identical to what
    was there before.
    """
    pad = " " * base_indent
    lines = [
        f"{pad}- patterns:",
        f"{pad}    - pattern-either:",
    ]
    lines.extend(_render_entries(fragment_patterns(kind, name), base_indent + 8))
    return "\n".join(lines)


def _render_entries(entries: list[Entry], indent: int) -> list[str]:
    """Render fragment entries as YAML list items at column ``indent``.

    A string is ``- pattern: <string>``. A single-key dict is ``- <key>:``
    followed by its value: a nested entry list at +4, a scalar mapping
    (``metavariable-regex``) at +4, a multi-line string as a ``|`` block at
    +4, or an inline scalar on the same line.
    """
    pad = " " * indent
    out: list[str] = []
    for entry in entries:
        if isinstance(entry, str):
            out.append(f"{pad}- pattern: {entry}")
            continue
        if len(entry) != 1:
            raise ValueError(f"fragment entry must have exactly one key: {entry!r}")
        ((key, value),) = entry.items()
        if isinstance(value, list):
            out.append(f"{pad}- {key}:")
            out.extend(_render_entries(value, indent + 4))
        elif isinstance(value, dict):
            out.append(f"{pad}- {key}:")
            out.extend(f"{pad}    {k}: {v}" for k, v in value.items())
        elif "\n" in value:
            out.append(f"{pad}- {key}: |")
            out.extend(f"{pad}    {line}" if line else "" for line in value.split("\n"))
        else:
            out.append(f"{pad}- {key}: {value}")
    return out
