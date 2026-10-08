"""Enrichment pass \u2014 deduplication, confidence scoring, severity escalation,
test path filtering, AI context gate, web framework gate, static redirect
suppression, source-confidence gating, exploitability severity capping, and a
dangerous-sink severity floor."""

from __future__ import annotations

import ast
import contextlib
import logging
import re
import time
from collections import Counter, defaultdict
from functools import cache
from pathlib import Path

import yaml

from rowan.analysis.bounded_log_values import BoundedLogValues
from rowan.analysis.dominance import (
    collect_dominating_candidates as _collect_dominating_candidates,
)
from rowan.analysis.dominance import (
    find_enclosing_function as _find_enclosing_function,
)
from rowan.analysis.guard_clause import check_guard_suppression
from rowan.analysis.request_sources import HTTP_INPUT_RE, ROUTE_DECORATOR_RE
from rowan.analysis.source_tracer import classify_origin as ast_classify_origin
from rowan.analysis.test_paths import is_no_attacker_path as _is_no_attacker_path
from rowan.analysis.test_paths import is_test_path as _is_test_path
from rowan.core.confidence import (
    BULK_MATCH_CAP,
    OPENGREP_TAINT,
    PATTERN_ONLY_CAP,
)
from rowan.core.findings import Category, Finding, ScanResult, Severity
from rowan.core.llm_sources import is_llm_derived_text
from rowan.core.profiles import auto_detect_profile, get_disabled_categories
from rowan.core.rules import (
    _MAX_SCAN_LINE_LEN,
    _SANITIZER_WINDOW,
    _extract_secret_value,
    _is_env_reference,
    _is_placeholder,
    _line_identifiers,
    _shannon_entropy,
)
from rowan.core.rules import (
    INLINE_SUPPRESS_RE as _INLINE_SUPPRESS_RE,
)
from rowan.core.sanitizers import get_sanitizers_for_category, sanitizer_matches
from rowan.passes.base import ScanContext, scan_span
from rowan.passes.sources import iter_python_sources

logger = logging.getLogger(__name__)


@cache
def _compile_rule_sanitizers(raw: tuple[str, ...] | None) -> tuple[re.Pattern, ...]:
    """Compile a rule's own `sanitizers:` list, as carried in the manifest.

    Mirrors `core.sanitizers.get_sanitizers_for_category`: an uncompilable
    pattern is skipped rather than failing the scan.
    """
    if not raw:
        return ()
    compiled: list[re.Pattern] = []
    for pat in raw:
        try:
            compiled.append(re.compile(pat))
        except re.error:
            logger.warning("skipping uncompilable rule sanitizer %r", pat)
    return tuple(compiled)


# Derived from the shared input registry (CN-05); do not extend inline.
_SOURCE_HTTP_RE = HTTP_INPUT_RE
_SOURCE_CLI_RE = re.compile(r"sys\.argv|argparse|click\.option|parse_args")
_SOURCE_ENV_RE = re.compile(r"os\.environ|(?:os\.)?getenv\(|env\[")
_SOURCE_FILE_RE = re.compile(r"\.read\(\)|json\.load|yaml\.safe_load|open\(|Path.*read")
_SOURCE_PARAM_RE = re.compile(r"def\s+\w+\(.*\w")
_SOURCE_MODEL_RE = re.compile(r"tokenizer\.decode|model\.generate|\.predict")

# Java/Go do not have Python AST dominance available in enrichment. These
# patterns therefore provide evidence for a conservative demotion only; they
# never suppress a finding. Compound idioms require both normalization/parsing
# and a confinement/allowlist check in the same pre-sink window.
_APP_PATH_GUARD_RE = re.compile(r"(?i)\b(?:validate|sanitize|resolve|allow|check)\w*path\s*\(")
# Go-only: a bare `.resolve(`/`.resolveForWrite(` on a workspace/root-shaped
# receiver (mcp-shell's `ws.resolve`, JG-08/JG-15) -- the method name itself
# carries no "path" token, so `_APP_PATH_GUARD_RE` above never matched it.
# Deliberately NOT added to `_APP_PATH_GUARD_RE` (which Java shares): Java's
# `java.nio.file.Path.resolve(String)` is the stdlib's raw path-join with no
# validation at all, so the same receiver-scoped pattern on a Java file
# wrongly read a plain `workspace.resolve("SKILL.md")` call as a guard and
# demoted a real finding (`SkillConsolidationService.applyGroup`, mateclaw)
# that has no guard anywhere near it. Go's `ws.resolve` is a custom,
# validating helper by the mcp-shell evidence; Go has no stdlib method of
# that name to collide with.
_GO_PATH_RESOLVE_GUARD_RE = re.compile(r"\b(?:ws|workspace|root|base|sandbox)\.resolve\w*\s*\(")
_JAVA_PATH_NORMALIZE_RE = re.compile(
    r"\.(?:normalize|toRealPath|getCanonicalPath)\s*\(|FilenameUtils\.normalize\s*\("
)
_JAVA_PATH_BOUND_RE = re.compile(r"\.startsWith\s*\(")
_GO_PATH_NORMALIZE_RE = re.compile(r"filepath\.(?:Clean|Rel|Abs)\s*\(")
_GO_PATH_BOUND_RE = re.compile(r"strings\.HasPrefix\s*\(")
_JAVA_URL_HOST_RE = re.compile(r"(?:URI\.create\s*\([^)]*\)|\w+)\.getHost\s*\(")
_GO_URL_HOST_RE = re.compile(r"url\.Parse\s*\(")
_HOST_ALLOWLIST_RE = re.compile(
    r"(?i)\b(?:allow(?:ed|list)?Hosts?|trustedHosts?|permittedHosts?)\b|"
    r"\.(?:contains|Contains|equals|EqualFold)\s*\("
)
# JG-15: command-argument allowlist idioms. Narrower than the path/host
# guards above on purpose -- `Set.of(...).contains(` and a fixed-charset
# `.matches(...)` are unambiguous allowlist checks, so a single correlated
# occurrence is evidence (mirrors `_APP_PATH_GUARD_RE`'s single-pattern use).
_JAVA_CMD_ALLOWLIST_RE = re.compile(
    r"(?:Set|List)\.of\([^)]*\)\.contains\s*\(|\.matches\s*\(\s*\"\[A-Za-z0-9_-]+\"\s*\)"
)
_GO_CMD_ALLOWLIST_RE = re.compile(
    r"regexp\.MustCompile\([^)]*\)\.MatchString\s*\(|slices\.Contains\s*\(\s*\w+\s*,"
)
# `rowan.taint.opengrep_adapter._infer_category` resolves a finding's
# category from its rule id / message against a fixed regex table (path
# traversal requires "path.traversal"/"directory.traversal", command
# injection requires "shell"/"subprocess"/"os.system"). None of those appear
# in the `tnt-{ja,go}-ai-{tool,mcptool,llmout}-{path,exec}-*` rule ids or
# messages ("...flows into a filesystem path", "...executed as a shell
# command" doesn't match either), and their own `category: security`
# metadata isn't a valid `Category` value -- both fall through to GENERAL,
# so `finding.category` alone would never route these rules into the
# category dispatch below. SSRF is unaffected (the rule ids contain "ssrf",
# which the inference table does match). Fixing the shared inference table
# is out of scope here (`rowan/taint/opengrep_adapter.py`); this reads
# the closed, already-known AI rule id vocabulary instead.
_AI_TAINT_RULE_RE = re.compile(r"^tnt-(?:ja|go)-ai-")

# mcp-shell's `ws.resolve`/`ws.resolveForWrite` guard sits 26-31 source
# lines above its sink once Go's per-call `if err != nil { return ... }`
# boilerplate is counted (confirmed by scanning the real repo) -- a 24-line
# window missed 3 of its 10 findings for that reason alone, still
# correlated to the sink's own variable so this does not widen what counts
# as evidence, only how far back it is allowed to look for it.
_JAVA_GO_GUARD_WINDOW = 40

#: LLM completion / agent tool-call output (issue #185).
#:
#: `model_output` below is scored 0.1 -- i.e. "almost certainly not
#: attacker-influenced" -- which was written for a classic ML estimator's
#: prediction (a label or a score). It predates the LLM-output-handling rule
#: family (`TNT-LLMOUT-*`, issue #133), whose entire premise is the opposite:
#: a completion is untrusted precisely BECAUSE a prompt injection can steer it.
#: Left unfixed, that inversion buried the family -- an `llm.predict(p)` result
#: reaching `subprocess.run(cmd, shell=True)` was downgraded to INFO/0.15 and
#: tagged `taint_unconfirmed`, while the identical bug via
#: `chat.completions.create` survived at medium/0.74. Same vulnerability,
#: reported or hidden depending only on which SDK the developer used, and
#: hidden exactly when the snippet most clearly says "this came from a model".
#: That is DEF-2's failure mode (severity miscalibration hiding a real finding
#: from the recommended CI gate) recurring for the AI corpus.
#:
#: Matched BEFORE every other origin so the unambiguous completion shapes win.
#: The regex itself lives in `rowan/core/llm_sources.py` -- shared with
#: `core/authz_predicates.py`'s model-derived-authorization recognizer
#: (`TNT-AUTHZ-001`/`AUTHZ-LLM-001`), which needs the identical judgment call
#: against an AST expression rather than a taint-flow snippet. One definition,
#: per this project's own drift-prevention discipline (rules_registry.py).
_SOURCE_UUID_RE = re.compile(r"\buuid\b|uuid4\(\)|UUID\(|\.replace\(['\"]-['\"]")
_SOURCE_CONFIG_RE = re.compile(r"_\w*config\b|_?\w*settings\b|CONFIG\b")

#: Origin declared by a rule's `source_kind` metadata (BACKLOG.md JG-02),
#: consulted only when the AST tracer cannot parse the file (Java/Go). Values
#: are the labels and confidences the Python tracer / snippet classifier
#: produce for the equivalent Python source, so every downstream gate
#: (`_SAFE_ORIGINS_BY_CATEGORY`, `_cap_exploitability`,
#: `_apply_sink_severity_floor`) behaves identically. A model-chosen tool
#: argument is `llm_output`, as is_llm_derived_text already treats it.
_SOURCE_KIND_ORIGINS: dict[str, tuple[str, float]] = {
    "http_input": ("http_input", 1.0),
    "llm_output": ("llm_output", 0.95),
    "tool_param": ("llm_output", 0.95),
    "config": ("config_constant", 0.4),
    "operator_input": ("cli_input", 0.9),
}

_SAFE_ORIGINS_BY_CATEGORY: dict[Category, float] = {
    Category.INJECTION: 0.3,
    Category.NOSQL_INJECTION: 0.3,
    Category.COMMAND_INJECTION: 0.7,
    Category.SSRF: 0.5,
    Category.PATH_TRAVERSAL: 0.3,
    Category.DESERIALIZATION: 0.1,
}

_EXTERNAL_BOUNDARY_RE = re.compile(
    r"@app\.(?:route|get|post|put|delete|patch|websocket)|@router|@api_view|websocket|queue.*consumer|grpc",
    re.IGNORECASE,
)
_OPERATOR_SOURCE_RE = re.compile(r"os\.environ|sys\.argv|parse_args")
_LOCAL_READ_RE = re.compile(r"\.read\(\)|json\.load|yaml\.load|open\(")

_NEVER_CAP_CATEGORIES = frozenset({Category.DESERIALIZATION, Category.PATH_TRAVERSAL})

# Categories whose sinks are unconditionally dangerous once reached: pickle/marshal
# deserialization, eval/exec, os.system/subprocess, raw SQL interpolation (BACKLOG.md
# DEF-2's own examples). An unsuppressed taint flow in these categories is
# floored to HIGH -- see _apply_sink_severity_floor.
_DANGEROUS_SINK_CATEGORIES = frozenset(
    {Category.DESERIALIZATION, Category.COMMAND_INJECTION, Category.INJECTION}
)

# Log forging (CWE-117): rides the `injection` category + taint machinery, but
# is log poisoning, not RCE, so it is exempt from the dangerous-sink HIGH floor.
_LOG_FORGING_CWE = 117

# Categories whose finding message asserts a DATAFLOW property ("user-
# controlled", "untrusted input reaches..."). A bare pattern match cannot
# establish that property, so findings here need computed evidence (a taint
# flow or a structural engine finding) to ship above MEDIUM -- see
# _cap_unverified_severity. Self-evident categories (secrets, crypto, config,
# supply_chain...) are excluded: there the matched text IS the whole claim.
_DATAFLOW_CLAIM_CATEGORIES = frozenset(
    {
        Category.INJECTION,
        Category.DESERIALIZATION,
        Category.SSRF,
        Category.SSTI,
        Category.XSS,
        Category.COMMAND_INJECTION,
        Category.PATH_TRAVERSAL,
        Category.NOSQL_INJECTION,
        Category.PROTOTYPE_POLLUTION,
    }
)

# Engines whose findings are regex/pattern matches and therefore subject to
# the pattern-only cap. Every other engine (mfv opcode analysis, the authz
# resolver graph, cross-file propagation, and the structural AST passes such
# as serialization-scope, agent-flow and the mcp-* passes) computes its own
# evidence. This used to be an allowlist of five engine names, so a new AST
# pass landed as "pattern-only" and its MEDIUMs vanished from the default
# view (PL-01). SCA (`depguard`) is neither: a CVE match is self-evident, and
# the view keeps its MEDIUMs only when marked reachable.
_PATTERN_ENGINES = frozenset({"opengrep", "neuroscan"})
_SCA_ENGINE = "depguard"


def _is_evidence_bearing_engine(engine: str) -> bool:
    # An unset engine (the Finding default) is no evidence of anything and
    # takes the pattern-only path like a regex match.
    return bool(engine) and engine not in _PATTERN_ENGINES and engine != _SCA_ENGINE

# Deserialization rules whose sink READS and unpickles attacker-reachable
# network input in a single call (ZMQ recv_pyobj, multiprocessing.connection
# Listener.recv). Unlike pickle.loads(user_input), there is no separate
# user-input source to prove: the match subsumes the source, so it is a
# self-evident RCE sink rather than an unverified dataflow claim, and is
# exempt from the pattern-only cap (see _cap_unverified_severity).
_SELF_EVIDENT_DESER_RULES = frozenset({"NS-DESER-012", "NS-DESER-013"})

_SEVERITY_RANK = {
    Severity.CRITICAL: 0,
    Severity.HIGH: 1,
    Severity.MEDIUM: 2,
    Severity.LOW: 3,
    Severity.INFO: 4,
}

# Strength of a finding's evidence (see _cap_unverified_severity), strongest
# first. Used to pick which of several findings on one sink survives a merge.
_EVIDENCE_TIER_RANK: dict[str, int] = {
    "taint-flow": 0,
    "engine": 0,
    "taint-flow-unresolved": 1,
    "self-evident": 2,
    "authorization-gap": 2,
    "pattern-only": 3,
    "source-context": 3,
    "presence": 4,
}

# Groups of rule ids that detect the SAME underlying condition via
# overlapping/near-identical regex patterns, confirmed by manual review of
# each pair's languages/category/severity/message in the manifest (not
# derived automatically -- pattern-text overlap alone is NOT sufficient
# evidence of duplication; several corpus pairs share a pattern fragment
# while checking genuinely distinct concerns, e.g. one rule's *source*
# pattern overlapping another's, or the same substring appearing in two
# rules scoped to different languages that can never co-fire on one file).
_DUPLICATE_RULE_GROUPS: tuple[frozenset[str], ...] = (
    frozenset({"NS-DESER-002", "NS-DESER-006", "ns-aiml-030"}),  # torch.load() w/o weights_only
    frozenset({"ns-aiml-032", "ns-aiml-037"}),  # np.load/pandas allow_pickle=True
    frozenset(
        {"NS-DESER-007", "ns-aiml-069", "ns-bb-008"}
    ),  # yaml.load w/o SafeLoader (DEF-39: NS-DESER-007/ns-aiml-069 confirmed duplicate; ns-bb-008 shares the yaml.unsafe_load( alternative)
    frozenset({"NS-AIML-005", "ns-grd-003"}),  # Gradio file upload w/o restriction
    frozenset({"GO-CONFIG-001", "ns-bb-004"}),  # TLS verification disabled
    frozenset({"JS-XSS-001", "NS-XSS-002"}),  # innerHTML DOM XSS
    frozenset({"NS-PATH-005", "ns-aiml-063"}),  # tarfile extractall zip-slip
    frozenset({"NS-CACHE-001", "ns-fw-js-002"}),  # CORS wildcard origin
    frozenset({"NS-DESER-010", "ns-aiml-043"}),  # Keras model_from_json code exec
    frozenset({"NS-REDIRECT-001", "ns-fw-py-003", "TNT-REDIR-001"}),
    frozenset({"NS-INJECT-001", "NS-INJECT-002", "ns-aiml-046"}),
    frozenset({"NS-CMDI-002", "NS-INJECT-003"}),
    frozenset({"NS-SSTI-001", "ns-aiml-129"}),
)

# rule_id -> canonical group key (the group's lexicographically smallest
# rule_id), built once at import time so _rule_group_key is an O(1) dict
# lookup per finding rather than a scan over _DUPLICATE_RULE_GROUPS.
_RULE_TO_GROUP_KEY: dict[str, str] = {
    rule_id: min(group) for group in _DUPLICATE_RULE_GROUPS for rule_id in group
}


def _rule_group_key(rule_id: str) -> str | None:
    """Return the canonical key identifying which _DUPLICATE_RULE_GROUPS
    group `rule_id` belongs to, or None if it's in no group."""
    return _RULE_TO_GROUP_KEY.get(rule_id)


# Test/example path recognition now lives in rowan.analysis.test_paths so
# CrossFilePass consumes the same definition; re-imported below under the
# historical private names.

_AI_IMPORT_RE = re.compile(
    r"(?:"
    # Python: `import torch` / `from transformers import ...`
    r"(?:^|\s)(?:import|from)\s+"
    r"(?:torch|transformers|langchain|langchain_core|openai|anthropic|"
    r"huggingface_hub|safetensors|keras|tensorflow|tf|gradio|streamlit|"
    r"vllm|ollama|litellm|crewai|autogen|ag2|langflow|langgraph|"
    r"mcp|fastmcp|google\.adk|pydantic_ai|smolagents|"
    r"claude_agent_sdk|semantic_kernel|haystack|dspy|letta|instructor|"
    # `agents` is the OpenAI Agents SDK top-level package. It needs a trailing
    # boundary (the others are prefix matches, `torch` covers `torchvision`)
    # because `from agents_util import` / `import agentsmith` are ordinary
    # project modules; `from myapp.agents import` never reaches here since
    # the first dotted segment is what follows `from`.
    r"agents(?=[\s.])|"
    r"sentence_transformers|chromadb|pinecone|weaviate|"
    r"mlflow|ray|accelerate|deepspeed|bitsandbytes|peft|trl)"
    # Java: `import [static] org.springframework.ai.<...>;` (JG-02)
    r"|^\s*import\s+(?:static\s+)?"
    r"(?:org\.springframework\.ai|dev\.langchain4j|com\.openai|com\.anthropic|"
    r"io\.modelcontextprotocol|ai\.djl|ai\.onnxruntime|org\.deeplearning4j)\."
    # Go: `import "github.com/..."`, or a (possibly aliased) line of an
    # import block. Line-anchored so a comment or string does not count.
    r"|^\s*(?:import\s+)?(?:[\w.]+\s+)?\"github\.com/"
    r"(?:tmc/langchaingo|openai/openai-go|sashabaranov/go-openai|"
    r"anthropics/anthropic-sdk-go|mark3labs/mcp-go|modelcontextprotocol/go-sdk|"
    r"firebase/genkit/go|ollama/ollama/api|cloudwego/eino)[/\"]"
    r")",
    re.MULTILINE,
)

_TARFILE_IMPORT_RE = re.compile(
    r"(?:^|\s)(?:import|from)\s+(?:tarfile|zipfile|shutil)",
    re.MULTILINE,
)

_TARFILE_LINE_RE = re.compile(r"\btarfile\b|\bzipfile\b")

_PATH_TRAVERSAL_RULES = frozenset({"NS-PATH-005"})

_USER_INPUT_SOURCES_RE = re.compile(
    r"request\.(?:args|form|json|data|GET|POST|body|query_params|values|files|cookies|headers)"
    r"|Body\(\)|Query\(\)|websocket\.recv|st\.chat_input|gr\.File"
    r"|sys\.argv|input\(|os\.environ|os\.getenv"
)

#: File-level "handles untrusted input" gate: the shared registry plus route
#: decorators, stdin and argv (CN-05).
_WEB_INPUT_RE = re.compile(
    HTTP_INPUT_RE.pattern + "|" + ROUTE_DECORATOR_RE.pattern + r"|input\(|sys\.argv"
)

_CONFIG_URL_PATTERN_RE = re.compile(
    r"(?:_[Uu][Rr][Ll]|_[Ee][Nn][Dd][Pp][Oo][Ii][Nn][Tt]|_[Hh][Oo][Ss][Tt]"
    r"|CONFIG|_config|_settings|_API_URL|_api_url|MARKETPLACE|base_url"
    r"|ADMIN_|INTERNAL_|METADATA_|PREFECT_|REDIS_"
    r"|_SERVICE|_SERVICES|_CLUSTER)"
)

# Server-generated / structurally-fixed SQL targets that are safe to interpolate
# (a UUID, or a hardcoded table/collection/index name). Deliberately NOT the
# bare `_id`/`_name` suffixes: those match `user_id`, `account_id`, `file_name`
# -- the most common *user-controlled* SQL-injection parameters -- so including
# them silently downgraded textbook SQLi (`WHERE id = {user_id}`) to INFO, the
# exact silent false-negative the project forbids. `_uuid` still covers the
# genuine UUID-variable case this suppressor exists for.
_IMPORT_LINE_RE = re.compile(r"^\s*(?:import|from)\s")
_UUID_PATTERN_RE = re.compile(
    r"\buuid\b|UUID\(|uuid4\(\)|\.replace\(['\"\"]-['\"\"]"
    r"|_uuid\b|table_name|collection_name|volume_name|index_name"
)

_SSRF_RULES = frozenset({"NS-SSRF-001", "NS-SSRF-007", "NS-SSRF-102", "NS-SSRF-103"})

_SQLI_RULES = frozenset({"NS-SQLI-001", "NS-SQLI-002"})

_LOG_RULES = frozenset({"ns-log-002", "ns-log-003", "NS-LOG-001"})

_PRETRAINED_RULES = frozenset({"ns-aiml-047"})
_TRUST_REMOTE_TRUE_RE = re.compile(r"trust_remote_code\s*=\s*True")
_SAFE_PRETRAINED_RE = re.compile(
    r"trust_remote_code\s*=\s*False|revision\s*=|cache_dir\s*=|local_files_only\s*=\s*True"
)

_DYNIMPORT_RULES = frozenset({"ns-aiml-048"})
_HARDCODED_IMPORT_RE = re.compile(
    r"""(?:import_module|__import__|spec_from_file_location|load_source)\s*\(\s*['\"]"""
)

_EVAL_EXEC_RULES = frozenset({"ns-aiml-046"})
_LITERAL_ARG_RE = re.compile(
    r"""(?:exec|eval|compile)\s*\(\s*(?:['\"]|True|False|None|[0-9]+|os\.|sys\.|pathlib\.|importlib\.)"""
)

# Suppress exec/eval/os.system findings in security-scanner / denylist code.
# The pattern: a file that defines a denylist of dangerous function names (e.g.
# DANGEROUS_CALLS = {"exec": ..., "os.system": ...}) will trigger the rule on
# the string keys, not on actual calls.  These files are themselves security
# enforcement code, not vulnerable code.
_DENYLIST_FILE_RE = re.compile(
    r"""DANGEROUS_CALLS|DANGEROUS_ATTR|FORBIDDEN_CALLS|_BLOCKLIST|BANNED_FUNCTIONS""",
    re.IGNORECASE,
)
# Matches the finding line being a string-in-dict-literal, not a real call
_STRING_KEY_RE = re.compile(r"""['"]\s*(?:exec|eval|os\.system|os\.popen|subprocess)['"]\s*:""")

# Suppress SQL findings in Alembic/Django/Flask migration files: these are
# DDL statements executed by the ORM/migration framework, not raw user input.
_MIGRATION_PATH_RE = re.compile(
    r"alembic[/\\]versions[/\\]|migrations[/\\][0-9a-f]+_|migrate[/\\]\d",
    re.IGNORECASE,
)

# Suppress injection/command findings in files that are clearly security
# validation/checking code (not code that executes the dangerous operations).
_SECURITY_CHECK_FILE_RE = re.compile(
    r"code_security|security_check|input_validat|sanitiz|safe_exec|sandbox",
    re.IGNORECASE,
)

_INFRA_TIMING_RULES = frozenset({"ns-infra-001"})
_AUTH_CONTEXT_RE = re.compile(
    r"\blogin\b|\bauthenticate\b|\bverify_password\b|\bpassword_hash\b"
    r"|\bbcrypt\b|\bhashlib\b|\bhmac\b|\bcheck_password\b",
    re.IGNORECASE,
)
# Lines each direction from an ns-infra-001 finding to search for
# _AUTH_CONTEXT_RE, in place of the whole file (see
# _suppress_non_auth_timing's docstring for why the whole-file check was
# too coarse).
_TIMING_AUTH_WINDOW = 20

_TOKEN_AUDIENCE_CONTEXT_RE = re.compile(
    r"\boauth\b|\bmcp\b|\bbearer\b|authorization\s*(?:header|:)"
    r"|resource[_ -]?(?:server|indicator|audience)",
    re.IGNORECASE,
)

_DESER_TORCH_RULES = frozenset({"NS-DESER-006"})
_SAFE_TORCH_LOAD_RE = re.compile(r"weights_only\s*=\s*True|safetensors\.torch\.load_file")

_AI_RULE_PREFIXES = (
    "ns-aiml-",
    "NS-AIML-",
    "AI0",
    "AI1",
    "AI2",
    "TNT-AIML-",
    "TNT-ML-",
    # Java/Go AI ports (BACKLOG.md JG-02): `tnt-ja-ai-<class>-NNN`.
    "tnt-ja-ai-",
    "tnt-go-ai-",
)

_WEB_IMPORT_RE = re.compile(
    r"(?:"
    r"(?:^|\s)(?:import|from)\s+(?:flask|django|fastapi|starlette|tornado|aiohttp|sanic|bottle|falcon|quart)"
    r"|(?:require\s*\(\s*['\"]|from\s+['\"])(?:express|fastify|koa|@?hapi|@nestjs)"
    r"|import\s+(?:org\.springframework|javax\.servlet|jakarta\.servlet"
    r"|javax\.ws\.rs|jakarta\.ws\.rs|io\.javalin|io\.ktor)\."
    r"|[\"'](?:net/http|github\.com/gin-gonic/gin|github\.com/labstack/echo|github\.com/gofiber/fiber"
    r"|github\.com/go-chi/chi(?:/v\d+)?)[\"']"
    r")",
    re.MULTILINE,
)

_WEB_RULE_CATEGORIES = frozenset({Category.SSRF, Category.XSS, Category.AUTH})
_WEB_RULE_ID_PATTERNS = ("SSRF", "XSS", "redirect", "header-injection")

_STATIC_REDIRECT_RE = re.compile(
    r"redirect\s*\(\s*['\"](?:login|logout|home|index|register|dashboard"
    r"|/|/login|/logout|/home|/index|/register|/dashboard|/signup|/auth|/admin|/api|/app|/lab)['\"]"
)

_thresholds_cache: dict[str, tuple[tuple[int, int, int, int] | None, dict]] = {}


def _is_ai_rule(rule_id: str) -> bool:
    return any(rule_id.startswith(p) for p in _AI_RULE_PREFIXES)


def _file_has_ai_imports(file_path: str) -> bool:
    try:
        with open(file_path, encoding="utf-8", errors="ignore") as f:
            head = "".join(f.readline() for _ in range(100))
        return bool(_AI_IMPORT_RE.search(head))
    except OSError:
        return False


def _is_web_rule(finding: Finding) -> bool:
    if finding.category in _WEB_RULE_CATEGORIES:
        return True
    rid = finding.rule_id.lower()
    return any(p.lower() in rid for p in _WEB_RULE_ID_PATTERNS)


_TEMPLATE_SUFFIXES = (".html", ".htm", ".jinja", ".jinja2", ".j2")


def _is_template_file(file_path: str) -> bool:
    """True for server-rendered template files (issue #268)."""
    return file_path.lower().endswith(_TEMPLATE_SUFFIXES)


_CLIENT_JS_SUFFIXES = (".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx", ".vue", ".svelte")


def _is_client_side_js(file_path: str) -> bool:
    """True for browser-side JS/TS source. A DOM-XSS sink (innerHTML,
    document.write, outerHTML) in such a file IS the web layer -- the code
    runs in a browser -- so it must not be gated on a *server* web-framework
    import the way `_suppress_web_rules_on_non_web_files` gates Python web
    rules. Without this a `el.innerHTML = userInput` in a plain client script
    (no express/react import in the file head) was floored to INFO, hiding a
    real reflected/DOM XSS. Scoped to the XSS category only: SSRF/redirect
    surface signals on JS stay gated, they are the noise that gate exists for.
    """
    return file_path.lower().endswith(_CLIENT_JS_SUFFIXES)


def _file_has_web_imports(file_path: str) -> bool:
    try:
        with open(file_path, encoding="utf-8", errors="ignore") as f:
            head = "".join(f.readline() for _ in range(50))
        return bool(_WEB_IMPORT_RE.search(head))
    except OSError:
        return False


def _has_agent_boundary_source(finding: Finding) -> bool:
    """The rule's own source is a model-chosen tool argument or model output.

    Such a finding proves its external input, so file-level guesses about
    attacker reachability (web-framework imports, a library profile) must not
    demote it. The operator-tooling cap already exempts `tool_param`.
    """
    return finding.metadata.get("source_kind") in ("tool_param", "llm_output")


def _cap_severity(finding: Finding, cap: Severity) -> None:
    if _SEVERITY_RANK[finding.severity] < _SEVERITY_RANK[cap]:
        finding.severity = cap


class EnrichmentPass:
    name = "enrichment"

    def __init__(self, dedup_threshold: int = 3):
        self._dedup_threshold = dedup_threshold
        self._file_head_cache: dict[str, str] = {}
        self._guard_ast_cache: dict[str, ast.AST | None] = {}

    def run(self, context: ScanContext) -> ScanResult:
        start = time.perf_counter()
        original_count = len(context.result.findings)

        # GitHub issue #92: Opengrep's pattern-not-regex excludes a finding
        # only when the negative match fully contains, or is fully contained
        # by, the finding's matched range (documented upstream Semgrep/
        # Opengrep containment semantics -- not a defect; confirmed by
        # reading the Opengrep 1.22.0 source and by direct experiment: an
        # exclusion spanning the finding's range works, a narrower one that
        # only overlaps doesn't). Most of the rulebase authored its
        # exclusions assuming a simpler "matches anywhere on the line" model
        # (matching how the native Python engine works) -- e.g.
        # pattern-not-regex: (?m)^\s*# only matches the '#' character itself,
        # a tiny range at the start of the line, which doesn't contain a
        # match sitting later on the same line (pickle.loads( in
        # "# pickle.loads(data)"), so the exclusion silently fails to
        # suppress it. This re-applies each rule's own pattern_not list (now
        # carried in the conversion manifest, see
        # scripts/convert_neuroscan_to_opengrep.py) as a simple per-line
        # substring/regex search -- no containment requirement -- faithfully
        # reproducing NeuroScanRule.check()'s per-line exclusion semantics so
        # legacy_neuroscan=True and the default path agree, without needing
        # every affected pattern-not rewritten to span its target. Runs
        # before everything else so no downstream step (profile filter,
        # dedup, suppressors) ever sees a finding that should never have
        # existed.
        context.result.findings = self._apply_pattern_not_fallback(context.result.findings, context)
        context.result.findings = self._apply_profile_filter(context.result.findings, context)
        # Establish the engine-based confidence baseline BEFORE the
        # suppression heuristics run. Every suppressor below only ever
        # lowers confidence via min(f.confidence, X) -- if _score_confidence
        # ran after them (as it used to), its unconditional per-engine
        # assignment would clobber those demotions back up to 0.65-0.90,
        # leaving a finding correctly downgraded to severity=INFO with a
        # misleadingly high confidence score.
        context.result.findings = self._score_confidence(context.result.findings)
        context.result.findings = self._apply_guard_clause_suppression(context.result.findings)
        context.result.findings = self._suppress_test_findings(context.result.findings, context)
        context.result.findings = self._cap_no_attacker_context(context.result.findings, context)
        context.result.findings = self._suppress_ai_on_non_ai(context.result.findings)
        context.result.findings = self._suppress_web_rules_on_non_web_files(context.result.findings)
        context.result.findings = self._suppress_non_tarfile_path_traversal(context.result.findings)
        context.result.findings = self._suppress_non_web_ssrf(context.result.findings)
        context.result.findings = self._suppress_uuid_sql_targets(context.result.findings)
        context.result.findings = self._suppress_descriptive_logs(context.result.findings)
        context.result.findings = self._suppress_safe_pretrained(context.result.findings)
        context.result.findings = self._suppress_hardcoded_dynamic_imports(context.result.findings)
        context.result.findings = self._suppress_safe_eval_exec(context.result.findings)
        context.result.findings = self._suppress_denylist_scanner_code(context.result.findings)
        context.result.findings = self._suppress_migration_sql(context.result.findings)
        context.result.findings = self._suppress_security_checker_files(context.result.findings)
        context.result.findings = self._suppress_non_auth_timing(context.result.findings)
        context.result.findings = self._suppress_contextual_false_positives(context.result.findings)
        context.result.findings = self._suppress_header_safe_reencoding(
            context.result.findings, context
        )
        context.result.findings = self._suppress_safe_torch_load(context.result.findings)
        context.result.findings = self._suppress_static_redirects(context.result.findings)
        context.result.findings = self._suppress_inline_nosec(context.result.findings)
        context.result.findings = self._suppress_secret_fps(context.result.findings, context)
        context.result.findings = self._suppress_sanitizer_window(context.result.findings, context)
        context.result.findings = self._suppress_bounded_log_forging(context.result.findings, context)
        context.result.findings = self._apply_source_confidence(context.result.findings)
        context.result.findings = self._cap_exploitability(context.result.findings)
        context.result.findings = self._cap_unverified_severity(context.result.findings)
        context.result.findings = self._apply_sink_severity_floor(context.result.findings)
        context.result.findings = self._demote_java_go_guarded_findings(context.result.findings)
        # Adjacent-line dedup runs after the line-anchored suppressors so the
        # survivor is the finding that survived on its own line, not the
        # cluster's first member; a placeholder `password = "xxx"` next to a
        # real key used to swallow the key (TE-04).
        context.result.findings = self._deduplicate(context.result.findings)
        # Runs after every suppression/escalation step above has settled
        # which findings survive and at what final severity, and before the
        # user's --severity threshold filter below -- so the threshold is
        # applied once to the single merged finding, not independently to
        # each duplicate (which could let one copy through the gate while
        # another was filtered, defeating the merge).
        context.result.findings = self._merge_duplicate_rule_groups(
            context.result.findings, context
        )
        context.result.findings = self._merge_same_sink_findings(
            context.result.findings, self._load_thresholds(context.config.thresholds_path)
        )
        context.result.findings = self._apply_thresholds(context.result.findings, context)

        duration = time.perf_counter() - start
        scan_span(self.name, duration)
        logger.info(
            "EnrichmentPass: %d findings after enrichment (was %d) in %.1fs",
            len(context.result.findings),
            original_count,
            duration,
        )
        # Unlike other passes, this one mutates/filters context.result.findings
        # in place rather than producing new findings to merge in -- returning
        # an empty ScanResult is deliberate (merge()'s extend([]) is a no-op),
        # not an omission.
        return ScanResult()

    @staticmethod
    def _suppress_bounded_log_forging(findings: list[Finding], context: ScanContext) -> list[Finding]:
        if not any(f.rule_id == "TNT-LOG-001" for f in findings):
            return findings
        trees = dict(iter_python_sources(context, owner="bounded_log_values", skip_tests=False))
        analysis = BoundedLogValues(trees)
        needed = {f.file_path for f in findings if f.rule_id == "TNT-LOG-001"}
        safe = {str(path): analysis.safe_lines(path) for path in trees if str(path) in needed}
        return [f for f in findings if f.rule_id != "TNT-LOG-001" or f.start_line not in safe.get(f.file_path, set())]

    @classmethod
    def _suppress_contextual_false_positives(cls, findings: list[Finding]) -> list[Finding]:
        """Apply AST context that regex rules cannot express precisely."""
        result: list[Finding] = []
        cache: dict[str, tuple[list[str], ast.AST | None]] = {}
        for finding in findings:
            if finding.rule_id not in {
                "NS-SQLI-005",
                "ns-aiml-159",
                "ns-aiml-168",
                "ns-bb-001",
            }:
                result.append(finding)
                continue
            if finding.file_path not in cache:
                try:
                    lines = Path(finding.file_path).read_text(encoding="utf-8").splitlines()
                except OSError:
                    lines, tree = [], None
                else:
                    try:
                        tree = ast.parse("\n".join(lines), filename=finding.file_path)
                    except SyntaxError:
                        tree = None
                cache[finding.file_path] = (lines, tree)
            lines, tree = cache[finding.file_path]
            function = cls._containing_function(tree, finding.start_line)
            if finding.rule_id == "NS-SQLI-005" and function is not None:
                if cls._sql_interpolation_is_allowlisted(function, finding.start_line):
                    continue
            if finding.rule_id == "ns-aiml-159" and function is not None:
                segment = "\n".join(lines[function.lineno - 1 : function.end_lineno])
                if not _TOKEN_AUDIENCE_CONTEXT_RE.search(segment):
                    continue
            if finding.rule_id == "ns-aiml-168" and function is not None:
                if cls._subprocess_uses_guarded_catalog_value(function, finding.start_line):
                    continue
            if finding.rule_id == "ns-bb-001":
                has_hardcoded_key = (
                    cls._jwt_call_has_hardcoded_key(tree, finding.start_line)
                    if tree is not None
                    else cls._jwt_text_call_has_hardcoded_key(lines, finding.start_line)
                )
                if not has_hardcoded_key:
                    continue
            result.append(finding)
        return result

    @staticmethod
    def _safe_header_return_functions(context: ScanContext) -> set[str]:
        definitions: dict[str, list[ast.FunctionDef | ast.AsyncFunctionDef]] = defaultdict(list)
        for _path, tree in iter_python_sources(context, owner="enrichment", skip_tests=False):
            for node in ast.walk(tree):
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    definitions[node.name].append(node)

        encoders = {
            "jwt.encode",
            "base64.urlsafe_b64encode",
            "urlsafe_b64encode",
            "urllib.parse.quote",
        }

        def call_name(node: ast.AST) -> str:
            parts: list[str] = []
            current = node
            while isinstance(current, ast.Attribute):
                parts.append(current.attr)
                current = current.value
            if isinstance(current, ast.Name):
                parts.append(current.id)
            return ".".join(reversed(parts))

        def function_is_safe(
            func: ast.FunctionDef | ast.AsyncFunctionDef, safe_names: set[str]
        ) -> bool:
            assignments: dict[str, ast.expr] = {}
            for node in ast.walk(func):
                if isinstance(node, ast.Assign) and len(node.targets) == 1:
                    if isinstance(node.targets[0], ast.Name):
                        assignments[node.targets[0].id] = node.value
                elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
                    if node.value is not None:
                        assignments[node.target.id] = node.value

            def safe_expr(expr: ast.expr, seen: set[str] | None = None) -> bool:
                seen = set() if seen is None else seen
                if isinstance(expr, ast.Await):
                    return safe_expr(expr.value, seen)
                if isinstance(expr, ast.Constant):
                    return True
                if isinstance(expr, ast.Name) and expr.id in assignments and expr.id not in seen:
                    return safe_expr(assignments[expr.id], seen | {expr.id})
                if isinstance(expr, ast.Dict):
                    return all(safe_expr(value, seen) for value in expr.values)
                if isinstance(expr, ast.Call):
                    name = call_name(expr.func)
                    return name in encoders or name.rsplit(".", 1)[-1] in safe_names
                return False

            returns = [node.value for node in ast.walk(func) if isinstance(node, ast.Return)]
            return bool(returns) and all(value is not None and safe_expr(value) for value in returns)

        safe_names: set[str] = set()
        while True:
            new = {
                name
                for name, funcs in definitions.items()
                if funcs and all(function_is_safe(func, safe_names) for func in funcs)
            }
            if new <= safe_names:
                return safe_names
            safe_names |= new

    @classmethod
    def _suppress_header_safe_reencoding(
        cls, findings: list[Finding], context: ScanContext
    ) -> list[Finding]:
        """Suppress proven safe encodings and cap unresolved service returns."""
        targets = [finding for finding in findings if finding.rule_id == "TNT-HEADER-001"]
        if not targets:
            return findings
        safe_names = cls._safe_header_return_functions(context)

        tree_cache: dict[str, ast.AST | None] = {}
        result: list[Finding] = []
        for finding in findings:
            if finding.rule_id != "TNT-HEADER-001":
                result.append(finding)
                continue
            if finding.file_path not in tree_cache:
                try:
                    tree_cache[finding.file_path] = ast.parse(
                        Path(finding.file_path).read_text(encoding="utf-8")
                    )
                except (OSError, SyntaxError):
                    tree_cache[finding.file_path] = None
            tree = tree_cache[finding.file_path]
            if tree is None:
                result.append(finding)
                continue
            func = _find_enclosing_function(tree, finding.start_line)
            if func is None:
                result.append(finding)
                continue

            sink = next(
                (
                    node
                    for node in ast.walk(func)
                    if isinstance(node, ast.Call)
                    and node.lineno <= finding.start_line <= (node.end_lineno or node.lineno)
                    and isinstance(node.func, ast.Attribute)
                    and node.func.attr == "set_cookie"
                ),
                None,
            )
            if sink is None:
                result.append(finding)
                continue
            value: ast.expr | None = sink.args[1] if len(sink.args) >= 2 else next(
                (kw.value for kw in sink.keywords if kw.arg == "value"), None
            )
            base_name = value.id if isinstance(value, ast.Name) else (
                value.value.id
                if isinstance(value, ast.Subscript) and isinstance(value.value, ast.Name)
                else None
            )
            if base_name is None:
                result.append(finding)
                continue
            producer = next(
                (
                    node.value
                    for node in ast.walk(func)
                    if isinstance(node, ast.Assign)
                    and node.lineno < sink.lineno
                    and any(isinstance(target, ast.Name) and target.id == base_name for target in node.targets)
                ),
                None,
            )
            while isinstance(producer, ast.Await):
                producer = producer.value
            if isinstance(producer, ast.Call):
                name = producer.func.attr if isinstance(producer.func, ast.Attribute) else (
                    producer.func.id if isinstance(producer.func, ast.Name) else ""
                )
                if name in safe_names:
                    continue
                if cls._header_value_from_unresolved_service(tree, func, producer, finding):
                    finding.metadata["taint_unconfirmed"] = True
                    finding.metadata["unresolved_header_return"] = True
                    finding.confidence = min(finding.confidence, 0.5)
                    _cap_severity(finding, Severity.MEDIUM)
                    finding.message = (
                        "Request input may reach a cookie value through an unresolved "
                        "service return. Verify whether the service returns raw input "
                        "or a header-safe encoding."
                    )
            result.append(finding)
        return result

    @staticmethod
    def _header_value_from_unresolved_service(
        tree: ast.AST,
        function: ast.FunctionDef | ast.AsyncFunctionDef,
        producer: ast.Call,
        finding: Finding,
    ) -> bool:
        """A trace through an imported service getter does not prove its return.

        Keep the finding, but require a callee trace before treating this as a
        confirmed HIGH. Direct request-cookie reflection never matches here.
        """
        flow = finding.taint_flow
        if flow is None or not any(node.line == producer.lineno for node in flow.intermediate):
            return False
        if any(node.file_path != finding.file_path for node in flow.intermediate):
            return False
        if not isinstance(producer.func, ast.Attribute) or not isinstance(
            producer.func.value, ast.Name
        ):
            return False
        receiver = producer.func.value.id
        assignments = [
            node
            for node in ast.walk(function)
            if isinstance(node, ast.Assign)
            and node.lineno < producer.lineno
            and any(isinstance(target, ast.Name) and target.id == receiver for target in node.targets)
        ]
        if not assignments:
            return False
        assignment = max(assignments, key=lambda node: node.lineno)
        if not isinstance(assignment.value, ast.Call) or not isinstance(
            assignment.value.func, ast.Name
        ):
            return False
        getter = assignment.value.func.id
        return any(
            isinstance(node, ast.ImportFrom)
            and any((alias.asname or alias.name) == getter for alias in node.names)
            for node in getattr(tree, "body", ())
        )

    @staticmethod
    def _jwt_call_has_hardcoded_key(tree: ast.AST, line: int) -> bool:
        """Prove that the signing-key argument at ``line`` is a literal.

        ``ns-bb-001``'s search rule deliberately supplies candidate JWT calls;
        this AST residual turns the candidate into the property its message
        claims.  A configured/dynamic key is unknown, not weak.  A literal or
        a name whose nearest prior assignment is a literal is hardcoded,
        regardless of literal length.
        """

        def dotted_name(node: ast.AST) -> str:
            parts: list[str] = []
            current = node
            while isinstance(current, ast.Attribute):
                parts.append(current.attr)
                current = current.value
            if isinstance(current, ast.Name):
                parts.append(current.id)
            return ".".join(reversed(parts))

        calls = [
            node
            for node in ast.walk(tree)
            if isinstance(node, ast.Call)
            and node.lineno <= line <= (node.end_lineno or node.lineno)
            and dotted_name(node.func) in {"jwt.encode", "jwt.sign"}
        ]
        if not calls:
            return False
        call = min(calls, key=lambda node: (node.end_lineno or node.lineno) - node.lineno)
        key_expr: ast.expr | None = call.args[1] if len(call.args) >= 2 else None
        if key_expr is None:
            key_expr = next(
                (
                    keyword.value
                    for keyword in call.keywords
                    if keyword.arg in {"key", "secret", "private_key"}
                ),
                None,
            )
        if isinstance(key_expr, ast.Constant) and isinstance(key_expr.value, (str, bytes)):
            return True
        if not isinstance(key_expr, ast.Name):
            return False

        assignments: list[tuple[int, ast.expr]] = []
        for node in ast.walk(tree):
            node_line = getattr(node, "lineno", None)
            if node_line is None or node_line >= call.lineno:
                continue
            if isinstance(node, ast.Assign):
                if any(isinstance(target, ast.Name) and target.id == key_expr.id for target in node.targets):
                    assignments.append((node_line, node.value))
            elif (
                isinstance(node, ast.AnnAssign)
                and isinstance(node.target, ast.Name)
                and node.target.id == key_expr.id
                and node.value is not None
            ):
                assignments.append((node_line, node.value))
        if not assignments:
            return False
        _, value = max(assignments, key=lambda item: item[0])
        return isinstance(value, ast.Constant) and isinstance(value.value, (str, bytes))

    @staticmethod
    def _jwt_text_call_has_hardcoded_key(lines: list[str], line: int) -> bool:
        """Conservatively prove literal JWT keys in non-Python source.

        The source rule also covers JavaScript and TypeScript, which cannot be
        parsed by Python's AST. Keep only a same-line signing call whose second
        argument is a string literal or a simple identifier assigned a string
        literal earlier in the file. Anything dynamic remains unknown and is
        suppressed rather than mislabeled as a weak key.
        """
        if not 1 <= line <= len(lines):
            return False
        match = re.search(
            r"\bjwt\.(?:encode|sign)\s*\(\s*[^,\n]+,\s*"
            r"(?P<key>['\"][^'\"]*['\"]|[A-Za-z_$][\w$]*)",
            lines[line - 1],
        )
        if match is None:
            return False
        key = match.group("key")
        if key.startswith(("'", '"')):
            return True
        assignment = re.compile(
            rf"^\s*(?:(?:const|let|var)\s+)?{re.escape(key)}\s*=\s*['\"][^'\"]*['\"]"
        )
        return any(assignment.search(source_line) for source_line in lines[: line - 1])

    @staticmethod
    def _containing_function(tree: ast.AST | None, line: int) -> ast.AST | None:
        if tree is None:
            return None
        functions = [
            node
            for node in ast.walk(tree)
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
            and node.lineno <= line <= (node.end_lineno or node.lineno)
        ]
        return max(functions, key=lambda node: node.lineno, default=None)

    @staticmethod
    def _sql_interpolation_is_allowlisted(function: ast.AST, line: int) -> bool:
        """True when every f-string expression on ``line`` was constrained by
        a dominating membership guard whose rejecting branch exits."""
        safe_expressions: set[str] = set()
        safe_names: set[str] = set()
        for node in ast.walk(function):
            if not isinstance(node, ast.If) or node.lineno >= line:
                continue
            exits = any(isinstance(stmt, (ast.Return, ast.Raise)) for stmt in node.body)
            if not exits:
                continue
            for compare in ast.walk(node.test):
                if not isinstance(compare, ast.Compare):
                    continue
                for op in compare.ops:
                    if isinstance(op, ast.NotIn):
                        safe_expressions.add(ast.dump(compare.left, include_attributes=False))
                        if isinstance(compare.left, ast.Name):
                            safe_names.add(compare.left.id)

        for node in ast.walk(function):
            if not isinstance(node, (ast.Assign, ast.AnnAssign)) or node.lineno >= line:
                continue
            value = node.value
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            if (
                len(targets) == 1
                and isinstance(targets[0], (ast.Tuple, ast.List))
                and isinstance(value, (ast.Tuple, ast.List))
            ):
                for target_item, value_item in zip(targets[0].elts, value.elts, strict=False):
                    if (
                        isinstance(target_item, ast.Name)
                        and ast.dump(value_item, include_attributes=False) in safe_expressions
                    ):
                        safe_names.add(target_item.id)
                continue
            if value is None or ast.dump(value, include_attributes=False) not in safe_expressions:
                continue
            for target in targets:
                if isinstance(target, ast.Name):
                    safe_names.add(target.id)

        interpolated: set[str] = set()
        for joined in ast.walk(function):
            if not isinstance(joined, ast.JoinedStr):
                continue
            end = joined.end_lineno or joined.lineno
            if not (joined.lineno <= line <= end):
                continue
            for formatted in joined.values:
                if isinstance(formatted, ast.FormattedValue):
                    interpolated.update(
                        node.id for node in ast.walk(formatted.value) if isinstance(node, ast.Name)
                    )
        return bool(interpolated) and interpolated <= safe_names

    @staticmethod
    def _subprocess_uses_guarded_catalog_value(function: ast.AST, line: int) -> bool:
        """Recognize a subprocess argument selected from an ALL_CAPS catalog
        with a prior missing-entry rejection."""
        selected: dict[str, str] = {}
        rejected: set[str] = set()
        for node in ast.walk(function):
            if isinstance(node, (ast.Assign, ast.AnnAssign)) and node.lineno < line:
                targets = node.targets if isinstance(node, ast.Assign) else [node.target]
                value = node.value
                if (
                    isinstance(value, ast.Call)
                    and isinstance(value.func, ast.Attribute)
                    and value.func.attr == "get"
                    and isinstance(value.func.value, ast.Name)
                    and value.func.value.id.isupper()
                    and value.args
                    and isinstance(targets[0], ast.Name)
                ):
                    key_names = [n.id for n in ast.walk(value.args[0]) if isinstance(n, ast.Name)]
                    if key_names:
                        selected[targets[0].id] = key_names[0]
            if isinstance(node, ast.If) and node.lineno < line:
                exits = any(isinstance(stmt, (ast.Return, ast.Raise)) for stmt in node.body)
                if not exits:
                    continue
                for compare in ast.walk(node.test):
                    if (
                        isinstance(compare, ast.Compare)
                        and isinstance(compare.left, ast.Name)
                        and any(isinstance(op, (ast.Is, ast.Eq)) for op in compare.ops)
                        and any(
                            isinstance(c, ast.Constant) and c.value is None
                            for c in compare.comparators
                        )
                    ):
                        rejected.add(compare.left.id)

        safe_values = set(selected) & rejected
        if not safe_values:
            return False
        for call in ast.walk(function):
            if not isinstance(call, ast.Call) or getattr(call, "lineno", None) != line:
                continue
            call_name = ""
            if isinstance(call.func, ast.Attribute):
                call_name = call.func.attr
            elif isinstance(call.func, ast.Name):
                call_name = call.func.id
            if call_name not in {"run", "call", "Popen", "check_call", "check_output"}:
                continue
            names = {node.id for node in ast.walk(call) if isinstance(node, ast.Name)}
            if names & safe_values and not names & {selected[name] for name in safe_values}:
                return True
        return False

    def _deduplicate(self, findings: list[Finding]) -> list[Finding]:
        # Cross-file/agent-tool findings carry a "caller" (the reporting
        # function -- e.g. two distinct route handlers in the same file that
        # both happen to reach the same sink) -- different callers are
        # different vulnerable entry points, not near-duplicates of each
        # other, even when their definitions sit within the line-proximity
        # window below. Folding them together by (file, rule_id) alone
        # silently dropped every entry point but one whenever two callers'
        # def lines happened to be close together.
        #
        # Cross-file findings also carry "callee_name" (issue #154 Defect 3
        # collapsed the old unbounded per-callee `CF-<name>` rule ids into
        # two fixed ids, CF-SINK-001/CF-RETURN-001) -- without it, the SAME
        # caller reaching two DIFFERENT tainted callees at nearby call sites
        # would now merge into one finding under the shared rule id, where
        # before the distinct rule ids kept them apart. callee_name is None
        # for every non-cross-file rule, so this is a no-op there.
        groups: dict[
            tuple[str, str, str | None, str | None, str | None, str | None, object], list[Finding]
        ] = defaultdict(list)
        for f in findings:
            groups[
                (
                    f.file_path,
                    f.rule_id,
                    f.metadata.get("caller"),
                    f.metadata.get("callee_name"),
                    # SCA findings have no source line; package/version identity
                    # must remain part of deduplication or separate affected
                    # components collapse into one report.
                    f.metadata.get("package"),
                    f.metadata.get("version"),
                    # Proven operations keep their sink identity. Multiple source
                    # paths to one unpickling operation merge; nearby operations
                    # remain distinct rather than collapsing by file proximity.
                    f.metadata.get("operation_id") or (
                        (f.taint_flow.sink.file_path, f.taint_flow.sink.line, f.taint_flow.sink.column)
                        if f.rule_id == "TNT-DESER-001" and f.taint_flow and f.taint_flow.sink
                        else (f.start_line, f.start_column) if f.rule_id == "TNT-DESER-001" else None
                    ),
                )
            ].append(f)

        merged: list[Finding] = []
        for (
            _file_path,
            rule_id,
            _caller,
            _callee_name,
            _package,
            _version,
            _operation,
        ), group in groups.items():
            group.sort(key=lambda f: f.start_line)
            window = 5 if rule_id.startswith("NS-") else 10

            cluster: list[Finding] = [group[0]]
            for f in group[1:]:
                if f.start_line - cluster[-1].start_line <= window:
                    cluster.append(f)
                else:
                    merged.append(self._merge_cluster(cluster))
                    cluster = [f]
            merged.append(self._merge_cluster(cluster))

        counts = Counter((f.file_path, f.rule_id) for f in merged)
        return [self._mark_bulk(f, counts) for f in merged]

    @staticmethod
    def _merge_cluster(cluster: list[Finding]) -> Finding:
        best = max(cluster, key=lambda f: f.confidence)
        if len(cluster) > 1:
            # Keep the survivor on its own line so its location, and any
            # later line-anchored check, refers to the line the finding is
            # actually about (TE-04). The cluster span is metadata.
            best.metadata["cluster_start"] = cluster[0].start_line
            best.metadata["cluster_end"] = cluster[-1].start_line
            best.metadata["occurrence_count"] = len(cluster)
        return best

    def _mark_bulk(self, finding: Finding, counts: Counter) -> Finding:
        count = counts.get((finding.file_path, finding.rule_id), 1)
        if count >= self._dedup_threshold:
            finding.metadata["bulk_match"] = True
            finding.metadata["match_count"] = count
        return finding

    def _merge_duplicate_rule_groups(
        self, findings: list[Finding], context: ScanContext
    ) -> list[Finding]:
        """Collapse findings from different rule_ids that are known
        (_DUPLICATE_RULE_GROUPS) to detect the same underlying condition via
        overlapping/near-identical patterns -- e.g. a single torch.load(name)
        call producing separate NS-DESER-006 and ns-aiml-030 findings at the
        same line, one HIGH and one MEDIUM, for what a human reading the
        report sees as one vulnerability.

        Deliberately a SEPARATE, later pass over _deduplicate's output, not a
        change to _deduplicate's own (file_path, rule_id, caller,
        callee_name) grouping -- _deduplicate handles same-rule clustering
        (multiple hits of one rule near each other) and must keep doing
        exactly that; this handles a different problem (different rules,
        same condition) with different merge semantics (no line-span
        averaging -- see below).

        Findings whose rule_id is in no _DUPLICATE_RULE_GROUPS entry, or
        whose only group-mates in the file sit more than 2 lines away, pass
        through untouched. Grouping by (file_path, group_key) first keeps
        this linear in the number of findings -- only findings that already
        share a file and a group ever get compared against each other, never
        an O(n^2) scan over the whole finding set.

        Needs `context` (unlike the other suppressors defined purely in
        terms of `findings`) solely to read thresholds.yaml for the
        survivor-selection guard documented on `_merge_duplicate_cluster` --
        several of these exact rule_ids (NS-DESER-006, NS-DESER-007,
        JS-XSS-001, ns-aiml-063, NS-DESER-010) are independently
        `enabled: false` in the built-in config/thresholds.yaml, predating
        this pass, as its own prior fix for the identical duplication
        problem via a different mechanism (DEF-16/DEF-26/DEF-39: disable one
        named side of the pair outright rather than merge). This pass must
        not pick one of those as the merge survivor, or the very next step
        in run() (_apply_thresholds) deletes the merged finding outright --
        the group's only other, perfectly valid rule_id disappears with it.
        """
        thresholds = self._load_thresholds(context.config.thresholds_path)
        buckets: dict[tuple[str, str], list[Finding]] = defaultdict(list)
        passthrough: list[Finding] = []
        for f in findings:
            key = _rule_group_key(f.rule_id)
            if key is None:
                passthrough.append(f)
                continue
            buckets[(f.file_path, key)].append(f)

        merged: list[Finding] = list(passthrough)
        for group in buckets.values():
            group.sort(key=lambda f: f.start_line)
            cluster: list[Finding] = [group[0]]
            for f in group[1:]:
                if f.start_line - cluster[-1].start_line <= 2:
                    cluster.append(f)
                else:
                    merged.append(self._merge_duplicate_cluster(cluster, thresholds))
                    cluster = [f]
            merged.append(self._merge_duplicate_cluster(cluster, thresholds))
        return merged

    @staticmethod
    def _merge_same_sink_findings(findings: list[Finding], thresholds: dict) -> list[Finding]:
        """Collapse different rules reporting the same sink: same file, same
        line, same category and at least one shared CWE.

        Unlike _DUPLICATE_RULE_GROUPS this needs no hand-kept list: a taint
        rule and a pattern rule for the same call, or two taint rules whose
        sinks overlap, land on one line with one category. The shared-CWE
        requirement keeps genuinely different issues on one line apart (a
        cookie missing both HttpOnly and Secure is two findings).

        The survivor has the strongest evidence, then the highest severity,
        so a proven flow is never replaced by a pattern match. A rule
        disabled in thresholds.yaml is never the survivor, for the reason
        given on _merge_duplicate_cluster.
        """
        buckets: dict[tuple[str, int, Category], list[Finding]] = defaultdict(list)
        for f in findings:
            buckets[(f.file_path, f.start_line, f.category)].append(f)

        def rank(f: Finding) -> tuple:
            disabled = (thresholds.get(f.rule_id) or {}).get("enabled") is False
            tier = _EVIDENCE_TIER_RANK.get(f.metadata.get("evidence_tier"), len(_EVIDENCE_TIER_RANK))
            return (disabled, tier, _SEVERITY_RANK[f.severity], f.rule_id)

        merged_away: set[int] = set()
        for bucket in buckets.values():
            survivors: list[Finding] = []
            for f in sorted(bucket, key=rank):
                into = next(
                    (
                        s for s in survivors
                        if s.rule_id != f.rule_id and set(s.cwe_ids) & set(f.cwe_ids)
                    ),
                    None,
                )
                if into is None:
                    survivors.append(f)
                    continue
                merged_away.add(id(f))
                into.metadata["duplicate_rule_ids"] = sorted(
                    {*into.metadata.get("duplicate_rule_ids", [into.rule_id]),
                     *f.metadata.get("duplicate_rule_ids", [f.rule_id])}
                )
        return [f for f in findings if id(f) not in merged_away]

    @staticmethod
    def _merge_duplicate_cluster(cluster: list[Finding], thresholds: dict) -> Finding:
        if len(cluster) == 1:
            return cluster[0]
        # A rule_id thresholds.yaml has hard-disabled (`enabled: false`) is
        # disqualified from being the merge survivor first -- see the
        # docstring above. Picking it would silently zero out the whole
        # merged finding one step later in run(), including whatever a
        # still-enabled group-mate legitimately found, which is exactly the
        # "silently dropping distinct signal" regression this feature exists
        # to avoid, not cause. Falls back to the full cluster if every
        # member is disabled -- nothing survives either way, so the choice
        # among them is moot and this stays deterministic.
        candidates = [
            f for f in cluster if (thresholds.get(f.rule_id) or {}).get("enabled") is not False
        ] or cluster
        # Best severity wins (lowest _SEVERITY_RANK); ties broken by
        # lexicographically smallest rule_id so the surviving rule_id is
        # deterministic run-to-run -- required for `--baseline` diffing to
        # see the same rule_id survive on an unchanged source file rather
        # than flip depending on incidental input ordering.
        survivor = min(candidates, key=lambda f: (_SEVERITY_RANK[f.severity], f.rule_id))
        survivor.metadata["duplicate_rule_ids"] = sorted({f.rule_id for f in cluster})
        return survivor

    def _suppress_test_findings(
        self,
        findings: list[Finding],
        context: ScanContext | None = None,
    ) -> list[Finding]:
        result: list[Finding] = []
        for f in findings:
            candidate_path = f.file_path
            if context is not None:
                with contextlib.suppress(ValueError):
                    candidate_path = str(
                        Path(f.file_path).resolve().relative_to(context.target_path.resolve())
                    )
            if _is_test_path(candidate_path):
                f.confidence = min(f.confidence, 0.4)
                f.metadata["test_context"] = True
                # Test/example code is retained in audit output but should not
                # compete with deployed code in the actionable default. A real
                # vulnerability in a fixture is evidence about the fixture,
                # not about a reachable production trust boundary.
                if f.severity in (
                    Severity.CRITICAL,
                    Severity.HIGH,
                    Severity.MEDIUM,
                ):
                    f.severity = Severity.LOW
                # An unbounded delegation topology needs a deployed graph and
                # an actual handoff cycle to be security-relevant. This
                # presence/absence rule cannot establish either property, and
                # real-project scans showed its results are overwhelmingly
                # test/example graph setup. Retain the lead for audit mode but
                # keep it out of the actionable view.
                if f.rule_id == "ns-aiml-138":
                    f.severity = Severity.LOW
                    f.confidence = min(f.confidence, 0.3)
                    f.metadata["test_topology_lead"] = True
            result.append(f)
        return result

    def _cap_no_attacker_context(
        self, findings: list[Finding], context: ScanContext
    ) -> list[Finding]:
        """Cap findings in operator-tooling paths (scripts, migrations,
        importers, benchmarks, build configs) at LOW: the code has no
        attacker-facing surface, so it must not rank beside deployed code.

        Judged on the path RELATIVE to the scan target, so directory names
        above the scan root (e.g. a corpus checked out under benchmark/)
        cannot trigger the cap.

        An LLM tool parameter (rule metadata ``source_kind: tool_param``) is
        exempt: the model is the caller, so an agent's ``tools/`` package is
        the attacker-facing surface, not operator tooling."""
        target = context.config.target
        result: list[Finding] = []
        for f in findings:
            if f.metadata.get("source_kind") == "tool_param":
                result.append(f)
                continue
            try:
                rel = str(Path(f.file_path).resolve().relative_to(target.resolve()))
            except ValueError:
                rel = f.file_path
            if _is_no_attacker_path(rel):
                f.confidence = min(f.confidence, 0.3)
                f.metadata["no_attacker_context"] = True
                if f.severity in (Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM):
                    f.severity = Severity.LOW
            result.append(f)
        return result

    def _suppress_ai_on_non_ai(self, findings: list[Finding]) -> list[Finding]:
        ai_cache: dict[str, bool] = {}
        result: list[Finding] = []
        for f in findings:
            if not _is_ai_rule(f.rule_id):
                result.append(f)
                continue
            fp = f.file_path
            if fp not in ai_cache:
                ai_cache[fp] = _file_has_ai_imports(fp)
            if ai_cache[fp]:
                result.append(f)
            else:
                f.severity = Severity.INFO
                f.confidence = min(f.confidence, 0.3)
                f.metadata["ai_context_gate"] = True
                result.append(f)
        return result

    def _suppress_web_rules_on_non_web_files(self, findings: list[Finding]) -> list[Finding]:
        web_cache: dict[str, bool] = {}
        result: list[Finding] = []
        for f in findings:
            if not _is_web_rule(f):
                result.append(f)
                continue
            # A server-rendered template IS the web layer. The gate below
            # looks for web-framework *imports*, which no .html/.jinja file
            # will ever contain, so without this a template rule would be
            # floored to INFO on every file it can possibly match (#268).
            if _is_template_file(f.file_path):
                result.append(f)
                continue
            # A DOM-XSS sink in browser-side JS/TS is the web layer itself; it
            # has no server-framework import to find, so don't floor it (see
            # _is_client_side_js). Scoped to XSS so JS SSRF/redirect surface
            # signals stay gated.
            if f.category == Category.XSS and _is_client_side_js(f.file_path):
                result.append(f)
                continue
            if f.engine == "siblinggate" or _has_agent_boundary_source(f):
                # A whole-repo consistency claim, or a rule whose source is
                # the agent boundary: the evidence is not an import here.
                result.append(f)
                continue
            if f.engine == "mfv":
                # A model file is dangerous when loaded, whatever app ships
                # it; there is no web-framework import to look for in it.
                result.append(f)
                continue
            if f.engine in ("authz", "js_authz"):
                # Object-level authz (BOLA/IDOR) findings come from the
                # resolver-graph analysis in AuthzPass/JSAuthzPass; their
                # evidence is the missing ownership predicate on the object's
                # control-flow path, not a web-framework import in this file's
                # head. A route handler often imports its framework elsewhere
                # (a router module) or destructures it, so flooring these to
                # INFO on an import miss silently hid every BOLA finding (the
                # js_authz corpus went to 0 recall in the actionable view).
                result.append(f)
                continue
            fp = f.file_path
            if fp not in web_cache:
                web_cache[fp] = _file_has_web_imports(fp)
            if web_cache[fp]:
                result.append(f)
            else:
                f.severity = Severity.INFO
                f.confidence = min(f.confidence, 0.3)
                f.metadata["web_context_gate"] = True
                result.append(f)
        return result

    def _suppress_non_tarfile_path_traversal(self, findings: list[Finding]) -> list[Finding]:
        import_cache: dict[str, bool] = {}
        line_cache: dict[str, list[str]] = {}
        result: list[Finding] = []
        for f in findings:
            if f.rule_id not in _PATH_TRAVERSAL_RULES:
                result.append(f)
                continue
            fp = f.file_path
            if fp not in import_cache:
                try:
                    with open(fp, encoding="utf-8", errors="ignore") as fh:
                        content = fh.read()
                except OSError:
                    content = ""
                import_cache[fp] = bool(_TARFILE_IMPORT_RE.search(content))
                line_cache[fp] = content.splitlines()
            if import_cache[fp]:
                result.append(f)
                continue
            lines = line_cache[fp]
            idx = f.start_line - 1
            has_tarfile_nearby = False
            for offset in range(-2, 3):
                line_idx = idx + offset
                if 0 <= line_idx < len(lines):
                    if _TARFILE_LINE_RE.search(lines[line_idx]):
                        has_tarfile_nearby = True
                        break
            if has_tarfile_nearby:
                result.append(f)
            else:
                f.severity = Severity.INFO
                f.confidence = min(f.confidence, 0.15)
                f.metadata["no_archive_import"] = True
                result.append(f)
        return result

    def _suppress_non_web_ssrf(self, findings: list[Finding]) -> list[Finding]:
        line_cache: dict[str, list[str]] = {}
        result: list[Finding] = []
        for f in findings:
            if f.rule_id not in _SSRF_RULES:
                result.append(f)
                continue
            fp = f.file_path
            if fp not in line_cache:
                try:
                    with open(fp, encoding="utf-8", errors="ignore") as fh:
                        line_cache[fp] = fh.read().splitlines()
                except OSError:
                    line_cache[fp] = []
            lines = line_cache[fp]
            idx = f.start_line - 1
            line_text = lines[idx] if 0 <= idx < len(lines) else ""
            has_user_input_this_line = bool(_USER_INPUT_SOURCES_RE.search(line_text))
            if has_user_input_this_line:
                result.append(f)
                continue
            config_nearby = False
            for offset in range(-2, 3):
                line_idx = idx + offset
                if 0 <= line_idx < len(lines):
                    if _CONFIG_URL_PATTERN_RE.search(lines[line_idx]):
                        config_nearby = True
                        break
            if config_nearby:
                f.severity = Severity.INFO
                f.confidence = min(f.confidence, 0.15)
                f.metadata["config_url_source"] = True
            result.append(f)
        return result

    def _suppress_uuid_sql_targets(self, findings: list[Finding]) -> list[Finding]:
        source_cache: dict[str, tuple[bool, bool, list[str]]] = {}
        result: list[Finding] = []
        for f in findings:
            if f.rule_id not in _SQLI_RULES:
                result.append(f)
                continue
            fp = f.file_path
            if fp not in source_cache:
                try:
                    with open(fp, encoding="utf-8", errors="ignore") as fh:
                        content = fh.read()
                except OSError:
                    content = ""
                has_web_input = bool(_WEB_INPUT_RE.search(content))
                source_cache[fp] = (has_web_input, False, content.splitlines())
            has_web_input, _unused, lines = source_cache[fp]
            if has_web_input:
                result.append(f)
                continue
            idx = f.start_line - 1
            uuid_nearby = False
            for offset in range(-3, 4):
                line_idx = idx + offset
                if 0 <= line_idx < len(lines):
                    line = lines[line_idx]
                    if _IMPORT_LINE_RE.match(line):
                        continue
                    if _UUID_PATTERN_RE.search(line):
                        uuid_nearby = True
                        break
            # Only a uuid conversion near the sink says anything about it; a
            # file-level `import uuid` used to demote every SQL finding (TE-07).
            if uuid_nearby:
                f.severity = Severity.INFO
                f.confidence = min(f.confidence, 0.15)
                f.metadata["uuid_sql_target"] = True
            result.append(f)
        return result

    def _suppress_descriptive_logs(self, findings: list[Finding]) -> list[Finding]:
        result: list[Finding] = []
        for f in findings:
            if f.rule_id not in _LOG_RULES:
                result.append(f)
                continue
            try:
                with open(f.file_path, encoding="utf-8", errors="ignore") as fh:
                    lines = fh.read().splitlines()
            except OSError:
                result.append(f)
                continue
            idx = f.start_line - 1
            if idx < 0 or idx >= len(lines):
                result.append(f)
                continue
            line_text = lines[idx]
            in_quotes = re.findall(
                r"""['\"]([^'\"]*?(?:password|secret|api_key|token|credential|ssn)[^'\"]*?)['\"]""",
                line_text,
                re.IGNORECASE,
            )
            has_var_interpolation = bool(
                re.search(r"%(?:s|d|r|\(|\))|\.format\(|\{.*\}|f['\"]", line_text)
            )
            if in_quotes and not has_var_interpolation:
                f.severity = Severity.INFO
                f.confidence = min(f.confidence, 0.15)
                f.metadata["descriptive_log"] = True
            result.append(f)
        return result

    def _suppress_safe_pretrained(self, findings: list[Finding]) -> list[Finding]:
        line_cache: dict[str, list[str]] = {}
        result: list[Finding] = []
        for f in findings:
            if f.rule_id not in _PRETRAINED_RULES:
                result.append(f)
                continue
            fp = f.file_path
            if fp not in line_cache:
                try:
                    with open(fp, encoding="utf-8", errors="ignore") as fh:
                        line_cache[fp] = fh.read().splitlines()
                except OSError:
                    line_cache[fp] = []
            lines = line_cache[fp]
            idx = f.start_line - 1
            has_trust_remote_true = False
            for offset in range(-2, 3):
                line_idx = idx + offset
                if 0 <= line_idx < len(lines):
                    if _TRUST_REMOTE_TRUE_RE.search(lines[line_idx]):
                        has_trust_remote_true = True
                        break
            if has_trust_remote_true:
                result.append(f)
            else:
                f.severity = Severity.INFO
                f.confidence = min(f.confidence, 0.1)
                f.metadata["no_trust_remote_code"] = True
                result.append(f)
        return result

    def _suppress_hardcoded_dynamic_imports(self, findings: list[Finding]) -> list[Finding]:
        line_cache: dict[str, list[str]] = {}
        source_cache: dict[str, bool] = {}
        result: list[Finding] = []
        for f in findings:
            if f.rule_id not in _DYNIMPORT_RULES:
                result.append(f)
                continue
            fp = f.file_path
            if fp not in source_cache:
                try:
                    with open(fp, encoding="utf-8", errors="ignore") as fh:
                        content = fh.read()
                except OSError:
                    content = ""
                source_cache[fp] = bool(_WEB_INPUT_RE.search(content))
                line_cache[fp] = content.splitlines()
            has_web_input = source_cache[fp]
            lines = line_cache.get(fp, [])
            idx = f.start_line - 1
            line_text = lines[idx] if 0 <= idx < len(lines) else ""
            if has_web_input and not _HARDCODED_IMPORT_RE.search(line_text):
                result.append(f)
                continue
            f.severity = Severity.INFO
            f.confidence = min(f.confidence, 0.15)
            f.metadata["hardcoded_import"] = True
            result.append(f)
        return result

    def _suppress_safe_eval_exec(self, findings: list[Finding]) -> list[Finding]:
        source_cache: dict[str, bool] = {}
        line_cache: dict[str, list[str]] = {}
        result: list[Finding] = []
        for f in findings:
            if f.rule_id not in _EVAL_EXEC_RULES:
                result.append(f)
                continue
            fp = f.file_path
            if fp not in source_cache:
                try:
                    with open(fp, encoding="utf-8", errors="ignore") as fh:
                        content = fh.read()
                except OSError:
                    content = ""
                source_cache[fp] = bool(_WEB_INPUT_RE.search(content))
                line_cache[fp] = content.splitlines()
            has_web_input = source_cache[fp]
            lines = line_cache.get(fp, [])
            idx = f.start_line - 1
            line_text = lines[idx] if 0 <= idx < len(lines) else ""
            if _LITERAL_ARG_RE.search(line_text):
                f.severity = Severity.INFO
                f.confidence = min(f.confidence, 0.1)
                f.metadata["safe_eval_arg"] = True
            elif not has_web_input:
                f.severity = Severity.INFO
                f.confidence = min(f.confidence, 0.2)
                f.metadata["no_web_input_eval"] = True
            result.append(f)
        return result

    def _suppress_denylist_scanner_code(self, findings: list[Finding]) -> list[Finding]:
        """Downgrade exec/eval/os.system findings in security-scanner / denylist files.

        Files that build denylists of dangerous calls (e.g. code_security.py) will
        contain string keys like ``{"exec": "...", "os.system": "..."}`` that match
        the rule's regex but are not executable calls: they're the scanner's own
        enforcement data.
        """
        content_cache: dict[str, str] = {}
        result: list[Finding] = []
        _cmd_rules = frozenset({"NS-INJECT-002", "NS-INJECT-004", "ns-aiml-046"})
        for f in findings:
            if f.rule_id not in _cmd_rules:
                result.append(f)
                continue
            fp = f.file_path
            if fp not in content_cache:
                try:
                    with open(fp, encoding="utf-8", errors="ignore") as _fh:
                        content_cache[fp] = _fh.read()
                except OSError:
                    content_cache[fp] = ""
            content = content_cache[fp]
            if not _DENYLIST_FILE_RE.search(content):
                result.append(f)
                continue
            lines = content.splitlines()
            idx = f.start_line - 1
            line_text = lines[idx] if 0 <= idx < len(lines) else ""
            if _STRING_KEY_RE.search(line_text):
                f.severity = Severity.INFO
                f.confidence = min(f.confidence, 0.1)
                f.metadata["denylist_scanner_fp"] = True
            result.append(f)
        return result

    def _suppress_migration_sql(self, findings: list[Finding]) -> list[Finding]:
        """Downgrade SQL-injection findings in database migration files.

        Alembic/Django/Flask migration files execute DDL (ALTER TABLE, CREATE INDEX)
        via op.execute(f"ALTER TABLE ...").  The table/column names come from the
        migration author, not from user input.  These are not SQL-injection vectors.
        """
        result: list[Finding] = []
        for f in findings:
            if f.rule_id not in _SQLI_RULES:
                result.append(f)
                continue
            if _MIGRATION_PATH_RE.search(f.file_path):
                f.severity = Severity.INFO
                f.confidence = min(f.confidence, 0.1)
                f.metadata["migration_sql"] = True
            result.append(f)
        return result

    def _suppress_security_checker_files(self, findings: list[Finding]) -> list[Finding]:
        """Downgrade injection findings in files that are themselves security checkers.

        Files named ``code_security.py``, ``input_validation.py``, etc. scan for
        dangerous patterns: they *reference* ``os.system`` and ``exec`` as strings
        to detect, not to execute.  Findings here are almost always false positives.
        """
        result: list[Finding] = []
        _cmd_rules = frozenset(
            {"NS-INJECT-002", "NS-INJECT-004", "ns-aiml-046", "NS-PATH-003", "ns-bb-015"}
        )
        for f in findings:
            if f.rule_id not in _cmd_rules:
                result.append(f)
                continue
            if _SECURITY_CHECK_FILE_RE.search(f.file_path):
                f.severity = Severity.INFO
                f.confidence = min(f.confidence, 0.1)
                f.metadata["security_checker_fp"] = True
            result.append(f)
        return result

    def _suppress_non_auth_timing(self, findings: list[Finding]) -> list[Finding]:
        """Gate ns-infra-001 (non-constant-time secret comparison) on genuine
        auth proximity, and escalate confirmed hits out of the rule's static
        `severity: info` -- the same failure mode BACKLOG.md DEF-2 fixed for
        deserialization/command-injection: a real, CWE-208-listed
        vulnerability class was permanently invisible to the README's
        recommended `--severity high` CI gate, because nothing ever raised
        it above the rule's own YAML severity even for a confirmed hit.

        DEF-2's own fix doesn't cover this: `_apply_sink_severity_floor`
        floors only `_DANGEROUS_SINK_CATEGORIES` (deserialization/command_
        injection/injection), not crypto. This is deliberately a much
        narrower escalation than that floor -- to HIGH, not automatically
        to CRITICAL -- because a timing side-channel is real but harder to
        exploit than an unconditional RCE sink; the downstream
        `_cap_exploitability` step (which runs after this one) still applies
        its own reachability judgment on top: it leaves a HIGH timing
        finding alone only when the file's head shows an external-boundary
        decorator (`@app.route` etc.), and otherwise caps it back to
        MEDIUM/LOW same as any other crypto-category finding. So this
        function's HIGH is a ceiling that's only reached for a
        network-reachable auth endpoint, not a blanket escalation.

        Originally this checked the *whole file* for `_AUTH_CONTEXT_RE` --
        too coarse. Confirmed empirically: a synthetic tokenizer utility
        file (`import hashlib` for an unrelated cache-key hash, plus a
        `token == stop_token` loop-control comparison with no security
        meaning at all) was treated as "confirmed auth context" and left
        untouched, purely because the word "hashlib" appeared anywhere in
        the file. `hashlib`/`hmac`/`bcrypt` in particular are common
        imports in general-purpose code with no auth logic (checksums,
        cache keys, content hashing). Now scoped to a window of lines
        around the finding, matching the proximity approach
        `_suppress_safe_torch_load` below already uses for the analogous
        problem -- reduces (does not eliminate; a short file or an
        auth-context word used elsewhere within the window can still
        coincide) that class of over-confirmation.
        """
        lines_cache: dict[str, list[str]] = {}
        result: list[Finding] = []
        for f in findings:
            if f.rule_id not in _INFRA_TIMING_RULES:
                result.append(f)
                continue
            fp = f.file_path
            if fp not in lines_cache:
                try:
                    with open(fp, encoding="utf-8", errors="ignore") as fh:
                        lines_cache[fp] = fh.read().splitlines()
                except OSError:
                    lines_cache[fp] = []
            lines = lines_cache[fp]
            idx = f.start_line - 1
            lo = max(0, idx - _TIMING_AUTH_WINDOW)
            hi = min(len(lines), idx + _TIMING_AUTH_WINDOW + 1)
            window = "\n".join(lines[lo:hi])
            if _AUTH_CONTEXT_RE.search(window):
                # Deliberately NOT escalated to HIGH yet. The window narrowing
                # above is measured (it demonstrably stops a tokenizer file's
                # unrelated `hashlib` import from confirming auth context); the
                # escalation is not. Measured on chainlit + flashrag: 8
                # ns-infra-001 findings, all INFO, zero reached this branch --
                # so raising severity here would ship on a plausibility
                # argument with no real-world case behind it. The marker is
                # still recorded so a future escalation can be gated on it once
                # a corpus actually exercises this path. See BACKLOG DEF-44.
                f.metadata["auth_context_confirmed"] = True
                result.append(f)
            else:
                f.severity = Severity.INFO
                f.confidence = min(f.confidence, 0.1)
                f.metadata["no_auth_context"] = True
                result.append(f)
        return result

    def _suppress_safe_torch_load(self, findings: list[Finding]) -> list[Finding]:
        line_cache: dict[str, list[str]] = {}
        import_cache: dict[str, bool] = {}
        result: list[Finding] = []
        for f in findings:
            if f.rule_id not in _DESER_TORCH_RULES:
                result.append(f)
                continue
            fp = f.file_path
            if fp not in import_cache:
                try:
                    with open(fp, encoding="utf-8", errors="ignore") as fh:
                        content = fh.read()
                except OSError:
                    content = ""
                import_cache[fp] = bool(_AI_IMPORT_RE.search(content))
                line_cache[fp] = content.splitlines()
            has_ai_import = import_cache[fp]
            lines = line_cache.get(fp, [])
            idx = f.start_line - 1
            safe_nearby = False
            for offset in range(-2, 3):
                line_idx = idx + offset
                if 0 <= line_idx < len(lines):
                    if _SAFE_TORCH_LOAD_RE.search(lines[line_idx]):
                        safe_nearby = True
                        break
            if has_ai_import and not safe_nearby:
                result.append(f)
            else:
                f.severity = Severity.INFO
                f.confidence = min(f.confidence, 0.15)
                f.metadata["safe_torch_load"] = True
                result.append(f)
        return result

    def _suppress_static_redirects(self, findings: list[Finding]) -> list[Finding]:
        line_cache: dict[str, list[str]] = {}
        result: list[Finding] = []
        for f in findings:
            is_redirect_rule = f.category == Category.SSRF or "redirect" in f.rule_id.lower()
            if not is_redirect_rule:
                result.append(f)
                continue
            fp = f.file_path
            if fp not in line_cache:
                try:
                    with open(fp, encoding="utf-8", errors="ignore") as fh:
                        line_cache[fp] = fh.readlines()
                except OSError:
                    line_cache[fp] = []
            lines = line_cache[fp]
            idx = f.start_line - 1
            if 0 <= idx < len(lines) and _STATIC_REDIRECT_RE.search(lines[idx]):
                continue
            result.append(f)
        return result

    def _suppress_inline_nosec(self, findings: list[Finding]) -> list[Finding]:
        """Suppress opengrep findings on lines with # nosec / # rowan:disable.

        Opengrep only understands # nosemgrep; this re-applies the NeuroScan-era
        inline suppression patterns for converted regex findings. See
        INLINE_SUPPRESS_RE for why `# noqa` is not one of them."""
        if not findings:
            return findings
        line_cache: dict[str, list[str]] = {}
        result: list[Finding] = []
        for f in findings:
            if f.engine != "opengrep" or f.taint_flow is not None:
                result.append(f)
                continue
            fp = f.file_path
            if fp not in line_cache:
                try:
                    with open(fp, encoding="utf-8", errors="ignore") as fh:
                        line_cache[fp] = fh.read().splitlines()
                except OSError:
                    line_cache[fp] = []
            lines = line_cache[fp]
            idx = f.start_line - 1
            if 0 <= idx < len(lines) and _INLINE_SUPPRESS_RE.search(lines[idx]):
                continue
            result.append(f)
        return result

    def _suppress_secret_fps(self, findings: list[Finding], context: ScanContext) -> list[Finding]:
        """Apply secret entropy/placeholder/env-reference filtering to opengrep regex findings.

        Reuses the same functions the NeuroScan engine uses for secret rules.
        Requires the converter manifest to identify residual:secrets rules."""
        manifest = context.metadata.get("conversion_manifest")
        if not manifest:
            return findings
        rule_map = manifest.get("rule_map", {})
        if not rule_map:
            return findings

        line_cache: dict[str, list[str]] = {}
        result: list[Finding] = []
        for f in findings:
            if f.engine != "opengrep" or f.taint_flow is not None:
                result.append(f)
                continue
            info = rule_map.get(f.rule_id)
            if not info or "secrets" not in info.get("residual", []):
                result.append(f)
                continue

            fp = f.file_path
            if fp not in line_cache:
                try:
                    with open(fp, encoding="utf-8", errors="ignore") as fh:
                        line_cache[fp] = fh.read().splitlines()
                except OSError:
                    line_cache[fp] = []
            lines = line_cache[fp]
            idx = f.start_line - 1
            if not (0 <= idx < len(lines)):
                result.append(f)
                continue
            line = lines[idx]

            if _is_env_reference(line):
                continue
            val = _extract_secret_value(line)
            if val and _is_placeholder(val):
                continue
            if val and _shannon_entropy(val) < 3.0:
                continue
            result.append(f)
        return result

    def _suppress_sanitizer_window(
        self, findings: list[Finding], context: ScanContext
    ) -> list[Finding]:
        """Apply per-category sanitizer filtering to opengrep regex findings
        (those with no `taint_flow` -- AST-based taint findings already skip
        this check entirely and go through `check_guard_suppression`
        instead).

        GitHub issue #124: prefers real dominance over the old ±10-line
        text-proximity window. Parses the finding's file, locates the
        enclosing function, and checks the category's sanitizer patterns
        against only the statements that actually dominate the finding's
        line on its control-flow path (`_dominating_lines_for_finding`,
        built on the same `collect_dominating_candidates` primitive
        `guard_clause.py` uses for issue #160's early-return guard fix) --
        a sanitizer sitting in a sibling branch that doesn't lead to the
        finding (the other arm of an if/else, or an unrelated loop) no
        longer suppresses merely because it happens to fall within ±10
        lines, and a sanitizer that genuinely dominates but sits further
        than 10 lines away now correctly suppresses.

        Falls back to the original raw ±10-line window -- matching this
        codebase's "over-flagging accepted, silent false-negative not"
        philosophy (see `guard_clause.py`'s module docstring) -- when the
        AST fails to parse (`SyntaxError`) or no enclosing function is found
        (e.g. module-level code, which has no dominance structure to
        compute over): neither silently suppressing nothing nor silently
        suppressing everything is acceptable in that case.

        The existing variable-correlation logic in
        `core.sanitizers.sanitizer_matches` (a call-shape sanitizer like
        `shell=False` suppresses regardless of proximity; an argument-taking
        one like `shlex.quote(...)` only counts if it shares an identifier
        with the finding's own line) is unchanged -- it now simply runs
        against dominance-selected lines instead of a raw window slice."""
        manifest = context.metadata.get("conversion_manifest")
        if not manifest:
            return findings
        rule_map = manifest.get("rule_map", {})
        if not rule_map:
            return findings

        line_cache: dict[str, list[str]] = {}
        tree_cache: dict[str, ast.AST | None] = {}
        result: list[Finding] = []
        for f in findings:
            if f.engine != "opengrep" or f.taint_flow is not None:
                result.append(f)
                continue
            info = rule_map.get(f.rule_id)
            if not info or "sanitizer" not in info.get("residual", []):
                result.append(f)
                continue

            fp = f.file_path
            if fp not in line_cache:
                try:
                    with open(fp, encoding="utf-8", errors="ignore") as fh:
                        line_cache[fp] = fh.read().splitlines()
                except OSError:
                    line_cache[fp] = []
            lines = line_cache[fp]
            line_num = f.start_line - 1
            total = len(lines)
            if line_num < 0 or line_num >= total:
                result.append(f)
                continue

            # A rule's own `sanitizers:` list (carried through the manifest by
            # the converter) applies on top of whatever its category declares,
            # and is the only sanitizer source for a rule in a category that
            # has no shared set of its own -- so resolve the category
            # leniently rather than bailing out before the per-rule ones are
            # considered.
            rule_sanitizers = info.get("sanitizers")
            own_patterns = list(
                _compile_rule_sanitizers(tuple(rule_sanitizers) if rule_sanitizers else None)
            )
            registry_patterns: list = []
            cat_str = info.get("category", "")
            if cat_str:
                with contextlib.suppress(ValueError):
                    registry_patterns = get_sanitizers_for_category(Category(cat_str))
            if not own_patterns and not registry_patterns:
                result.append(f)
                continue

            matched_line = lines[line_num] if 0 <= line_num < total else ""
            # A call written across several lines has its keyword arguments on
            # the *continuation* lines of the very statement that matched, and
            # Opengrep anchors the finding on the opening line. Those
            # continuation lines are not "dominating" -- they are the match
            # itself -- so without this they were invisible to every sanitizer,
            # and `set_cookie(\n ... httponly=True\n)` looked identical to the
            # one-argument form. Same statement means same execution, so this
            # is as safe as trusting `matched_line`.
            statement_lines = self._matched_statement_lines(fp, lines, f.start_line, tree_cache)
            dominating_lines = self._dominating_lines_for_finding(
                fp, lines, f.start_line, tree_cache
            )
            if dominating_lines is not None:
                check_lines = [*dominating_lines, *statement_lines]
            else:
                start = max(0, line_num - _SANITIZER_WINDOW)
                end = min(total, line_num + _SANITIZER_WINDOW + 1)
                check_lines = lines[start:end]
            if sanitizer_matches(
                own_patterns, check_lines, matched_line, whole_window=True
            ) or sanitizer_matches(registry_patterns, check_lines, matched_line):
                continue
            result.append(f)
        return result

    @staticmethod
    def _demote_java_go_guarded_findings(findings: list[Finding]) -> list[Finding]:
        """Demote Java/Go path, URL and command-argument findings with nearby
        guard evidence.

        This is deliberately not a suppressor. Java and Go currently lack the
        AST dominance proof used for Python, and application-named helpers do
        not prove their own implementation is sound. Requiring correlation to
        the sink expression avoids treating an unrelated guard elsewhere in
        the function as evidence for this finding.
        """
        line_cache: dict[str, list[str]] = {}
        for finding in findings:
            suffix = Path(finding.file_path).suffix.lower()
            category = finding.category
            if category not in {
                Category.PATH_TRAVERSAL,
                Category.SSRF,
                Category.COMMAND_INJECTION,
            } and _AI_TAINT_RULE_RE.match(finding.rule_id):
                if "path" in finding.rule_id:
                    category = Category.PATH_TRAVERSAL
                elif "exec" in finding.rule_id:
                    category = Category.COMMAND_INJECTION
            if suffix not in {".java", ".go"} or category not in {
                Category.PATH_TRAVERSAL,
                Category.SSRF,
                Category.COMMAND_INJECTION,
            }:
                continue
            if finding.file_path not in line_cache:
                try:
                    line_cache[finding.file_path] = (
                        Path(finding.file_path)
                        .read_text(encoding="utf-8", errors="ignore")
                        .splitlines()
                    )
                except OSError:
                    line_cache[finding.file_path] = []
            lines = line_cache[finding.file_path]
            sink_index = finding.start_line - 1
            if sink_index < 0 or sink_index >= len(lines):
                continue
            sink_line = lines[sink_index]
            sink_vars = _line_identifiers(sink_line)
            window = lines[max(0, sink_index - _JAVA_GO_GUARD_WINDOW) : sink_index + 1]
            window_text = "\n".join(window)
            evidence: str | None = None

            if category == Category.PATH_TRAVERSAL:
                compound = (
                    suffix == ".java"
                    and _JAVA_PATH_NORMALIZE_RE.search(window_text)
                    and _JAVA_PATH_BOUND_RE.search(window_text)
                ) or (
                    suffix == ".go"
                    and _GO_PATH_NORMALIZE_RE.search(window_text)
                    and _GO_PATH_BOUND_RE.search(window_text)
                )
                if compound and EnrichmentPass._guard_window_correlates(window, sink_vars):
                    evidence = "compound_path_confinement"
                elif EnrichmentPass._correlated_guard_call(
                    _APP_PATH_GUARD_RE, window, sink_vars
                ) or (
                    suffix == ".go"
                    and EnrichmentPass._correlated_guard_call(
                        _GO_PATH_RESOLVE_GUARD_RE, window, sink_vars
                    )
                ):
                    evidence = "application_path_guard"
            elif category == Category.SSRF:
                host_re = _JAVA_URL_HOST_RE if suffix == ".java" else _GO_URL_HOST_RE
                # The host-parse call must correlate with the sink's own
                # variable (DEF-28) -- checking window_text as a whole let a
                # url.Parse/getHost + allowlist pair on an unrelated variable
                # demote a genuinely-unguarded flow to a different sink.
                if EnrichmentPass._correlated_guard_call(
                    host_re, window, sink_vars
                ) and _HOST_ALLOWLIST_RE.search(window_text):
                    evidence = "parsed_host_allowlist"
            else:
                cmd_re = _JAVA_CMD_ALLOWLIST_RE if suffix == ".java" else _GO_CMD_ALLOWLIST_RE
                if EnrichmentPass._correlated_guard_call(cmd_re, window, sink_vars):
                    evidence = "command_allowlist_check"

            if evidence is None:
                continue
            _cap_severity(finding, Severity.LOW)
            finding.confidence = min(finding.confidence, 0.35)
            finding.metadata["java_go_guard_evidence"] = evidence
            finding.metadata["guard_effect"] = "demoted_not_suppressed"
        return findings

    @staticmethod
    def _correlated_guard_call(pattern: re.Pattern, window: list[str], sink_vars: set[str]) -> bool:
        if not sink_vars:
            return False
        for line in window:
            match = pattern.search(line)
            if match is None:
                continue
            identifiers = _line_identifiers(line)
            if identifiers & sink_vars:
                return True
            # `safePath := validatePath(raw)` / `Path safePath = ...`: the
            # assigned value, rather than the input, is what reaches the sink.
            prefix = line[: match.start()]
            assignment = re.search(r"(?P<lhs>[^;]+?)\s*(?::=|=)\s*$", prefix)
            assigned = _line_identifiers(assignment.group("lhs")) if assignment else set()
            if assigned & sink_vars:
                return True
        return False

    @staticmethod
    def _guard_window_correlates(window: list[str], sink_vars: set[str]) -> bool:
        """Require at least one guard/normalization line to name the sink value."""
        if not sink_vars:
            return False
        return any(
            _line_identifiers(line) & sink_vars
            for line in window
            if (
                _JAVA_PATH_NORMALIZE_RE.search(line)
                or _JAVA_PATH_BOUND_RE.search(line)
                or _GO_PATH_NORMALIZE_RE.search(line)
                or _GO_PATH_BOUND_RE.search(line)
            )
        )

    @staticmethod
    def _stmt_dominating_span(stmt: ast.stmt) -> tuple[int, int] | None:
        """Line range to trust as "unconditionally executed" for a single
        dominating-candidate statement returned by
        `collect_dominating_candidates`.

        A candidate that is itself a compound statement (If/For/While/With/
        Try) is guaranteed to be *entered* as a prior sibling on the sink's
        path, but its body/orelse is a conditional-or-repeated choice, not a
        guaranteed-executed set of lines -- only the header expression (the
        test/iterable/context-manager, which always evaluates exactly once)
        is safe to trust. Including the body's text here would silently
        reintroduce the old bug: a sanitizer sitting in the untaken arm of
        an if/else, or inside a loop body, would count as dominating just
        because the surrounding `if`/`for` statement is a prior sibling.
        `Try` has no single always-evaluated header expression, so it
        contributes no lines. Simple (non-compound) statements are atomic --
        if reached, they run to completion -- so their full line range is
        safe to trust."""
        if isinstance(stmt, (ast.If, ast.While)):
            end = getattr(stmt.test, "end_lineno", None) or stmt.test.lineno
            return stmt.lineno, end
        if isinstance(stmt, (ast.For, ast.AsyncFor)):
            end = getattr(stmt.iter, "end_lineno", None) or stmt.iter.lineno
            return stmt.lineno, end
        if isinstance(stmt, (ast.With, ast.AsyncWith)):
            if not stmt.items:
                return stmt.lineno, stmt.lineno
            last_expr = stmt.items[-1].context_expr
            end = getattr(last_expr, "end_lineno", None) or stmt.lineno
            return stmt.lineno, end
        if isinstance(stmt, ast.Try):
            return None
        end = getattr(stmt, "end_lineno", None) or stmt.lineno
        return stmt.lineno, end

    @classmethod
    def _matched_statement_lines(
        cls,
        fp: str,
        lines: list[str],
        start_line: int,
        tree_cache: dict[str, ast.AST | None],
    ) -> list[str]:
        """Source lines of the single statement the finding is anchored on.

        For a call spread across several lines this is the whole call,
        arguments included; for a one-line statement it is just that line.
        Falls back to the anchored line alone when the file doesn't parse.
        Compound statements (`if`/`for`/`with`/`try`) are deliberately reduced
        to their header: their body is a conditional or repeated choice, not
        part of the same unconditional execution as the match, which is the
        same distinction `_stmt_dominating_span` draws.
        """
        anchored = [lines[start_line - 1]] if 0 <= start_line - 1 < len(lines) else []
        tree = cls._parsed_tree(fp, lines, tree_cache)
        if tree is None:
            return anchored

        best: tuple[int, int] | None = None
        for node in ast.walk(tree):
            if not isinstance(node, ast.stmt):
                continue
            end = getattr(node, "end_lineno", None)
            if end is None or not (node.lineno <= start_line <= end):
                continue
            if isinstance(
                node,
                (
                    ast.If,
                    ast.For,
                    ast.AsyncFor,
                    ast.While,
                    ast.With,
                    ast.AsyncWith,
                    ast.Try,
                    ast.FunctionDef,
                    ast.AsyncFunctionDef,
                    ast.ClassDef,
                ),
            ):
                continue
            span = (node.lineno, end)
            # Innermost wins: a nested statement's span is contained in its
            # parent's, and the tighter span is the one that actually executes
            # together with the match.
            if best is None or (span[1] - span[0]) < (best[1] - best[0]):
                best = span
        if best is None:
            return anchored
        return lines[max(0, best[0] - 1) : min(len(lines), best[1])]

    @classmethod
    def _parsed_tree(
        cls,
        fp: str,
        lines: list[str],
        tree_cache: dict[str, ast.AST | None],
    ) -> ast.AST | None:
        if fp not in tree_cache:
            try:
                tree_cache[fp] = ast.parse("\n".join(lines), filename=fp)
            except SyntaxError:
                tree_cache[fp] = None
        return tree_cache[fp]

    @classmethod
    def _dominating_lines_for_finding(
        cls,
        fp: str,
        lines: list[str],
        start_line: int,
        tree_cache: dict[str, ast.AST | None],
    ) -> list[str] | None:
        """Real-dominance replacement for the old ±10-line proximity window.

        Returns the source lines of the statements that unconditionally
        execute before `start_line` on its actual control-flow path (see
        `rowan/analysis/dominance.py`), or None if the AST can't be
        parsed or no enclosing function is found -- signaling the caller to
        fall back to the raw proximity window instead."""
        tree = cls._parsed_tree(fp, lines, tree_cache)
        if tree is None:
            return None
        func = _find_enclosing_function(tree, start_line)
        if func is None:
            return None
        _, candidates = _collect_dominating_candidates(func.body, start_line)
        dominating_lines: list[str] = []
        for stmt in candidates:
            span = cls._stmt_dominating_span(stmt)
            if span is None:
                continue
            s_line, s_end = span
            dominating_lines.extend(lines[max(0, s_line - 1) : min(len(lines), s_end)])
        return dominating_lines

    def _apply_pattern_not_fallback(
        self, findings: list[Finding], context: ScanContext
    ) -> list[Finding]:
        """Re-apply each converted rule's pattern-not exclusions against the
        exact matched line (GitHub issue #92 fallback).

        Opengrep's pattern-not-regex only excludes a finding when the
        negative match fully contains, or is fully contained by, the
        finding's own matched range -- documented upstream Semgrep/Opengrep
        containment semantics, not an engine defect (confirmed by reading
        the Opengrep 1.22.0 source and by direct experiment). Most of this
        rulebase's exclusions were authored assuming a simpler "matches
        anywhere on the line" model instead, matching how the native Python
        engine works -- e.g. pattern-not-regex: (?m)^\\s*# only matches the
        '#' character itself, a tiny range at the very start of the line,
        which doesn't contain a match sitting later on the same line
        (pickle.loads( in "# pickle.loads(data)"). Confirmed on a real rule
        (NS-DESER-001): the original exclusion lets a commented-out
        pickle.loads(...) through; widening it to span the whole line
        (`.*` suffix) makes Opengrep's own containment check exclude it
        correctly -- proving the engine behaves as intended and the gap is
        in how ~298 rules' exclusions were written, not in Opengrep.

        Rather than rewrite every affected pattern-not to span its target
        (fragile, easy to regress one rule at a time), this re-runs each
        rule's own pattern_not list (carried in the conversion manifest --
        scripts/convert_neuroscan_to_opengrep.py) as a simple per-line
        substring/regex search against the single source line the finding
        is on -- no containment requirement, faithfully matching
        NeuroScanRule.check()'s per-line (not window, not whole-file)
        exclusion semantics, so legacy_neuroscan=True and the default path
        produce the same result. Findings that would have been excluded are
        dropped entirely, not demoted -- that's what the native engine does,
        and it's the behavior every pattern-not in the rulebase was authored
        against.
        """
        manifest = context.metadata.get("conversion_manifest")
        if not manifest:
            return findings
        rule_map = manifest.get("rule_map", {})
        if not rule_map:
            return findings

        line_cache: dict[str, list[str]] = {}
        compiled_cache: dict[str, list[re.Pattern]] = {}
        result: list[Finding] = []
        dropped = 0

        for f in findings:
            if f.engine != "opengrep" or f.taint_flow is not None:
                result.append(f)
                continue
            info = rule_map.get(f.rule_id)
            pattern_not = info.get("pattern_not") if info else None
            if not pattern_not:
                result.append(f)
                continue

            if f.rule_id not in compiled_cache:
                compiled: list[re.Pattern] = []
                for p in pattern_not:
                    try:
                        compiled.append(re.compile(p))
                    except re.error:
                        continue
                compiled_cache[f.rule_id] = compiled
            negative_patterns = compiled_cache[f.rule_id]

            fp = f.file_path
            if fp not in line_cache:
                try:
                    with open(fp, encoding="utf-8", errors="ignore") as fh:
                        line_cache[fp] = fh.read().splitlines()
                except OSError:
                    line_cache[fp] = []
            lines = line_cache[fp]
            line_idx = f.start_line - 1
            if 0 <= line_idx < len(lines):
                line = lines[line_idx]
                if len(line) > _MAX_SCAN_LINE_LEN:
                    line = line[:_MAX_SCAN_LINE_LEN]
                if any(p.search(line) for p in negative_patterns):
                    dropped += 1
                    continue
            result.append(f)

        if dropped:
            logger.debug(
                "Pattern-not fallback (issue #92): dropped %d finding(s) that "
                "the rule's pattern-not was authored to exclude but whose "
                "matched range doesn't contain (Opengrep's containment "
                "semantics for pattern-not-regex)",
                dropped,
            )
        return result

    def _apply_profile_filter(self, findings: list[Finding], context: ScanContext) -> list[Finding]:
        profile = getattr(context.config, "profile", "auto")
        if profile == "auto":
            inventory = getattr(context, "source_inventory", None)
            candidates = (
                inventory.paths_for("python", suffix=".py") if inventory is not None else None
            )
            candidates_by_language = None
            if inventory is not None:
                candidates_by_language = {
                    language: inventory.paths_for(language)
                    for language in ("python", "java", "kotlin", "go", "csharp")
                }
            profile = auto_detect_profile(
                context.target_path,
                candidates,
                candidates_by_language=candidates_by_language,
            )
            context.metadata["detected_profile"] = profile

        disabled = get_disabled_categories(profile)
        if not disabled:
            return findings

        result: list[Finding] = []
        for f in findings:
            # Object-level authz (BOLA/IDOR) findings are only produced when the
            # user explicitly passes --authz, so demoting them for a detected
            # "library" profile (whose disabled set includes AUTH) contradicts
            # that opt-in and silently sent every BOLA finding to INFO. The
            # authz engines do their own resolver-graph analysis; the coarse
            # profile heuristic must not override an explicitly-requested pass.
            # Model-file findings fire on load, independent of how the
            # project is deployed, so the deployment profile does not apply.
            if f.engine in ("authz", "js_authz", "mfv") or _has_agent_boundary_source(f):
                result.append(f)
                continue
            if f.category in disabled:
                f.severity = Severity.INFO
                f.confidence = min(f.confidence, 0.2)
                f.metadata["profile_filtered"] = True
            result.append(f)
        return result

    def _score_confidence(self, findings: list[Finding]) -> list[Finding]:
        # Confidence constants live in one calibratable place now (#123):
        # rowan/core/confidence.py. `hops` is the true source->sink hop
        # distance -- 0 for a direct flow (no intermediate), matching the
        # cross-file engine's own hop-distance convention -- so the two
        # engines' ladders finally agree on what a given distance is worth
        # (differing only in base trust, which is the point).
        for f in findings:
            if f.engine == "neuroscan" or (f.engine == "opengrep" and f.taint_flow is None):
                f.confidence = min(f.confidence, PATTERN_ONLY_CAP)
            elif f.engine == "opengrep" and f.taint_flow is not None:
                f.confidence = OPENGREP_TAINT(len(f.taint_flow.intermediate))

            if f.metadata.get("bulk_match"):
                f.confidence = min(f.confidence, BULK_MATCH_CAP)

        return findings

    def _parse_for_guard_clause(self, file_path: str) -> ast.AST | None:
        """Per-file AST cache for the guard-clause post-filter, scoped to
        this EnrichmentPass instance (one per scan run)."""
        if file_path not in self._guard_ast_cache:
            try:
                with open(file_path, encoding="utf-8", errors="ignore") as fh:
                    content = fh.read()
                self._guard_ast_cache[file_path] = ast.parse(content)
            except (OSError, SyntaxError, ValueError):
                self._guard_ast_cache[file_path] = None
        return self._guard_ast_cache[file_path]

    def _apply_guard_clause_suppression(self, findings: list[Finding]) -> list[Finding]:
        """GitHub issue #160: downgrade (never delete) a taint finding whose
        sink is dominated by an early-return guard clause that Opengrep's
        own `pattern-not-inside` structural exclusions can't recognize (see
        `rowan/analysis/guard_clause.py` and
        docs/taint-sanitizer-audit.md's DEF-40 correction). Runs after
        `_score_confidence` so its `min()`-based downgrade isn't clobbered
        by the unconditional per-engine baseline assignment there."""
        for f in findings:
            if f.taint_flow is None:
                continue
            tree = self._parse_for_guard_clause(f.file_path)
            if tree is None:
                continue
            kind = check_guard_suppression(tree, f.start_line, f.taint_flow)
            if kind:
                f.confidence = min(f.confidence, 0.3)
                f.metadata["guard_suppressed"] = kind
        return findings

    def _apply_source_confidence(self, findings: list[Finding]) -> list[Finding]:
        for f in findings:
            if f.engine != "opengrep" or f.taint_flow is None:
                continue
            source = f.taint_flow.source
            if source is None:
                continue
            snippet = source.snippet
            source_line = source.line if source.line else f.start_line
            # The LLM check runs ahead of the AST tracer, not after it. A
            # completion or tool-call-argument snippet is unambiguous on its
            # own, whereas the tracer only sees where the *variable* came from
            # -- and for the common agent shape (`def handler(tool_call)`) that
            # is `function_param` (0.3), which buried the finding under the
            # 0.7 default threshold. See is_llm_derived_text's docstring.
            if is_llm_derived_text(snippet):
                origin, conf = ("llm_output", 0.95)
            else:
                origin, conf = ast_classify_origin(f.file_path, snippet, source_line)
                if origin is None:
                    # No AST (Java/Go): the rule's own `source_kind` stands in
                    # for the tracer; see _SOURCE_KIND_ORIGINS.
                    origin, conf = _SOURCE_KIND_ORIGINS.get(
                        f.metadata.get("source_kind"), (None, 0.0)
                    )
                if origin is None:
                    origin, conf = self._classify_source_origin(snippet)
            if origin is None:
                continue
            f.metadata["source_confidence"] = conf
            f.metadata["source_origin"] = origin
            if f.rule_id == "TNT-DESER-001" and origin in {"cli_input", "env_variable"}:
                _cap_severity(f, Severity.MEDIUM)
                f.confidence = min(f.confidence, 0.5)
                f.metadata["operator_controlled_source"] = True
            threshold = _SAFE_ORIGINS_BY_CATEGORY.get(f.category, 0.7)
            if conf < threshold:
                f.severity = Severity.INFO
                f.confidence = 0.15
                f.metadata["taint_unconfirmed"] = True
        return findings

    @staticmethod
    def _classify_source_origin(snippet: str) -> tuple[str | None, float]:
        # Checked first: an LLM completion or a model-chosen tool-call argument
        # is a high-confidence *untrusted* origin, not a safe one. See
        # is_llm_derived_text's docstring -- without this it fell through to
        # `model_output` (0.1) or `function_param` (0.3) and was buried.
        if is_llm_derived_text(snippet):
            return ("llm_output", 0.95)
        if _SOURCE_HTTP_RE.search(snippet):
            return ("http_input", 1.0)
        if _SOURCE_CLI_RE.search(snippet):
            return ("cli_input", 0.9)
        if _SOURCE_UUID_RE.search(snippet):
            return ("server_generated", 0.2)
        if _SOURCE_CONFIG_RE.search(snippet):
            return ("config_constant", 0.4)
        if _SOURCE_ENV_RE.search(snippet):
            return ("env_variable", 0.7)
        if _SOURCE_FILE_RE.search(snippet):
            return ("file_contents", 0.5)
        if _SOURCE_PARAM_RE.search(snippet):
            return ("function_param", 0.3)
        if _SOURCE_MODEL_RE.search(snippet):
            return ("model_output", 0.1)
        return (None, 0.0)

    def _classify_source_confidence(self, snippet: str) -> float | None:
        _, conf = self._classify_source_origin(snippet)
        return conf if conf > 0.0 else None

    def _read_file_head(self, file_path: str) -> str:
        if file_path in self._file_head_cache:
            return self._file_head_cache[file_path]
        try:
            with open(file_path, encoding="utf-8", errors="ignore") as f:
                head = "".join(f.readline() for _ in range(50))
        except OSError:
            head = ""
        self._file_head_cache[file_path] = head
        return head

    def _cap_exploitability(self, findings: list[Finding]) -> list[Finding]:
        for f in findings:
            if f.category in _NEVER_CAP_CATEGORIES:
                continue
            # mcpconfig findings are about a JSON deployment artifact, not a
            # code file -- there's no route-decorator/import signal to read
            # from a "file head" here, so every one of them fell through to
            # this function's own "no signal found" default MEDIUM cap,
            # silently downgrading a HIGH-severity over-privileged-server or
            # hardcoded-secret finding regardless of how confidently the
            # scanner itself rated it. The severity mcp_config.py assigns is
            # already the real signal for this engine. smuggle (decoded hidden
            # instruction override in a prose file) and mcptoctou (a tool's
            # advertised metadata mutated after registration) are the same
            # shape: structural findings that are self-evident from the match,
            # with no code-file boundary head that could raise or lower the
            # risk -- each pass's own severity is authoritative. mfv (a model
            # file analysed by Hayward) is the same: a binary has no head.
            if f.engine in ("mcpconfig", "smuggle", "mcptoctou", "mfv"):
                continue
            if _has_agent_boundary_source(f) or (
                f.taint_flow is not None
                and not f.metadata.get("taint_unconfirmed")
                and f.metadata.get("source_origin") in {"http_input", "llm_output"}
            ):
                # The trace establishes the boundary. Unrelated local reads
                # in the file must not demote this confirmed remote flow.
                continue
            head = self._read_file_head(f.file_path)
            if _EXTERNAL_BOUNDARY_RE.search(head):
                continue
            if _OPERATOR_SOURCE_RE.search(head):
                _cap_severity(f, Severity.MEDIUM)
            elif _LOCAL_READ_RE.search(head):
                _cap_severity(f, Severity.LOW)
            else:
                _cap_severity(f, Severity.MEDIUM)
        return findings

    def _cap_unverified_severity(self, findings: list[Finding]) -> list[Finding]:
        """Cap dataflow claims without a trace at MEDIUM.

        Imports, route decorators and other file-level context do not connect
        a source to this finding's sink. Evidence tiers describe the finding,
        not the surrounding file. Self-evident and structural engine findings
        retain their own severity.
        """
        for f in findings:
            if f.engine == "authz" and f.metadata.get("evidence_tier") == "authorization-gap":
                # A trace can establish the selected object, but cannot prove
                # the intended access policy or runtime enforcement.
                continue
            if f.taint_flow is not None:
                f.metadata["evidence_tier"] = (
                    "taint-flow-unresolved"
                    if f.metadata.get("unresolved_header_return")
                    else "taint-flow"
                )
                continue
            if _is_evidence_bearing_engine(f.engine):
                if f.engine == "mfv" and f.metadata.get("rule_class") == "presence":
                    f.metadata["evidence_tier"] = "presence"
                    continue
                f.metadata["evidence_tier"] = "engine"
                continue
            if f.rule_id in _SELF_EVIDENT_DESER_RULES:
                # The sink itself reads and unpickles attacker-reachable network
                # input, so the match IS the evidence of RCE, not a dataflow
                # claim the engine failed to verify. Not capped.
                f.metadata["evidence_tier"] = "self-evident"
                continue
            if f.category not in _DATAFLOW_CLAIM_CATEGORIES:
                f.metadata["evidence_tier"] = "self-evident"
                continue
            f.metadata["evidence_tier"] = "pattern-only"
            if _SEVERITY_RANK[f.severity] < _SEVERITY_RANK[Severity.MEDIUM]:
                f.metadata["unverified_severity_capped"] = f.severity.value
                f.severity = Severity.MEDIUM
                f.message = (
                    f"{f.message.rstrip()} [pattern-only match: no dataflow "
                    "evidence for this file; severity capped]"
                )
        return findings

    def _apply_sink_severity_floor(self, findings: list[Finding]) -> list[Finding]:
        """Floor dangerous sinks with an unsuppressed taint trace to HIGH.

        Never promote a bare pattern match based on unrelated code in the
        file, or restore a finding already downgraded to LOW/INFO.
        """
        for f in findings:
            if f.category not in _DANGEROUS_SINK_CATEGORIES:
                continue
            # A route elsewhere in the file says nothing about this sink's
            # input. Never undo an origin/guard/safe-context downgrade merely
            # because a taint trace object is still attached to the finding.
            if f.taint_flow is None or f.metadata.get("taint_unconfirmed"):
                continue
            if f.severity in (Severity.LOW, Severity.INFO):
                continue
            source = f.taint_flow.source
            snippet = source.snippet if source is not None else ""
            if (
                f.metadata.get("source_origin") not in {"http_input", "llm_output"}
                and not _SOURCE_HTTP_RE.search(snippet)
                and not is_llm_derived_text(snippet)
            ):
                # CLI/env/operator input can carry taint without establishing
                # the remote boundary required for this severity floor.
                continue
            # Log forging (CWE-117) rides the `injection` category and the taint
            # machinery -- user input reaching a log call -- but its consequence
            # is log poisoning / ANSI-escape injection, not the RCE this floor
            # exists for (pickle/eval/os.system/raw-SQL). Flooring it to HIGH
            # alongside real code-execution sinks over-states it and floods the
            # HIGH tier on clean code (8 such findings across autogen+ragflow).
            # The rule authors already rate these WARNING (MEDIUM); respect that.
            if _LOG_FORGING_CWE in (f.cwe_ids or ()):
                continue
            if f.metadata.get("no_attacker_context") or f.metadata.get("test_context"):
                # Operator tooling and test code: the "remote input" tokens in
                # such files describe imported data or test harness requests,
                # not a live request surface, so they must not undo the
                # context downgrades applied above.
                continue
            if _SEVERITY_RANK[f.severity] <= _SEVERITY_RANK[Severity.HIGH]:
                continue
            f.severity = Severity.HIGH
            f.metadata["severity_floor_applied"] = "dangerous_sink_with_taint_flow"
        return findings

    @staticmethod
    def _load_thresholds(path: Path | None) -> dict:
        if path is None:
            return {}
        key = str(path)
        try:
            stat = path.stat()
            identity: tuple[int, int, int, int] | None = (
                stat.st_dev,
                stat.st_ino,
                stat.st_mtime_ns,
                stat.st_size,
            )
        except OSError:
            identity = None
        cached = _thresholds_cache.get(key)
        if cached is not None and cached[0] == identity:
            return cached[1]
        if identity is None:
            _thresholds_cache[key] = (identity, {})
            return {}
        with open(path, encoding="utf-8") as f:
            data = yaml.safe_load(f) or {}
        rules = data.get("rules", None) or {}
        _thresholds_cache[key] = (identity, rules)
        return rules

    def _apply_thresholds(self, findings: list[Finding], context: ScanContext) -> list[Finding]:
        thresholds = self._load_thresholds(context.config.thresholds_path)
        if not thresholds:
            return findings

        result: list[Finding] = []
        for f in findings:
            cfg = thresholds.get(f.rule_id)
            if cfg is None:
                result.append(f)
                continue

            if cfg.get("enabled") is False:
                continue

            min_conf = cfg.get("min_confidence")
            if min_conf is not None and f.confidence < min_conf:
                continue

            max_sev = cfg.get("max_severity")
            if max_sev is not None:
                taint_confirmed = f.taint_flow is not None
                if not taint_confirmed:
                    try:
                        cap = Severity(max_sev)
                    except ValueError:
                        cap = None
                    if cap is not None:
                        _cap_severity(f, cap)

            result.append(f)
        return result
