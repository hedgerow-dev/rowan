"""AST enrichment pass: suppresses false positives using AST analysis.

Runs AFTER CrossFilePass but BEFORE EnrichmentPass. For each Python file
with findings, parses the AST and checks whether sink arguments are:
1. Safe dict lookups (constant-value dicts)
2. Pydantic validated class constructors
3. UPPER_CASE string constants

Matched findings are suppressed or downgraded.
"""

from __future__ import annotations

import ast
import logging
import time
from pathlib import Path

from rowan.analysis.ast_sanitizers import (
    call_args_all_constants,
    calls_on_line,
    collect_pydantic_validated_classes,
    collect_safe_dicts,
    collect_string_constants,
    fstring_assignment_lines,
    logging_fstring_lines,
    subscripts_on_line,
)
from rowan.analysis.safe_sink_context import (
    resolved_regex_search,
    safe_flask_response,
    safe_flask_template_render,
    safe_pickle_roundtrip,
)
from rowan.core.findings import Category, Finding, ScanResult, Severity
from rowan.passes.base import ScanContext, scan_span

logger = logging.getLogger(__name__)


#: Regex rules whose whole premise is "a call to one of these functions
#: occurred on this line". The NeuroScan/converted engine matches the call
#: syntax as a line-by-line substring, so it also fires when the same syntax
#: appears inside a string literal (a deny-list `"eval("`, a log message
#: `f"...SELECT..."`, a docstring), a comment, or a bare name, none of which
#: is a real call. A genuine finding always has a matching `ast.Call` on its
#: line, so if the AST shows no such call, the match is spurious and is
#: suppressed (#304). Values are call *last-names* as `calls_on_line` reports
#: them (`os.system(...)` -> "system", `yaml.load(...)` -> "load"). Kept
#: conservative: only rules where the match IS definitively a call to a named
#: function, and only single-line-call patterns (so the finding line and the
#: call's own line coincide). Multi-line patterns like ns-aiml-168's
#: `@tool ... exec(` are deliberately excluded to avoid line-misalignment.
_STRING_LITERAL_CALL_RULES: dict[str, frozenset[str]] = {
    "NS-INJECT-001": frozenset({"eval"}),
    "NS-INJECT-002": frozenset({"exec"}),
    "NS-INJECT-004": frozenset({"system"}),
    "NS-DESER-001": frozenset({"load", "loads"}),
    "NS-DESER-003": frozenset({"load", "full_load", "unsafe_load"}),
    "ns-aiml-046": frozenset({"exec", "eval", "compile"}),
    "ns-aiml-069": frozenset({"load", "unsafe_load", "full_load"}),
}


class ASTEnrichmentPass:
    name = "ast_enrichment"

    def run(self, context: ScanContext) -> ScanResult:
        start = time.perf_counter()
        suppressed = 0
        downgraded = 0

        files_with_findings: dict[str, list[Finding]] = {}
        for f in context.result.findings:
            if f.file_path.endswith(".py"):
                files_with_findings.setdefault(f.file_path, []).append(f)

        ast_cache: dict[str, ast.AST | None] = {}
        autoescape_disabled_files = {
            finding.file_path
            for finding in context.result.findings
            if finding.rule_id == "NS-XSS-005"
        }

        for file_path, findings in files_with_findings.items():
            tree = self._parse_cached(file_path, ast_cache)
            if tree is None:
                continue

            safe_dicts = collect_safe_dicts(tree)
            validated_classes = collect_pydantic_validated_classes(tree)
            string_constants = collect_string_constants(tree)
            # #304: SQL-keyword f-strings that are really log messages.
            log_lines = logging_fstring_lines(tree)
            assign_lines = fstring_assignment_lines(tree)

            for finding in findings:
                line = finding.start_line

                safe_reason = None
                if finding.rule_id in {"TNT-ML-004", "TNT-LDAP-001"} and resolved_regex_search(tree, line):
                    safe_reason = "stdlib_regex_search"
                elif finding.rule_id == "NS-DESER-001" and safe_pickle_roundtrip(tree, line):
                    safe_reason = "literal_pickle_roundtrip"
                elif finding.rule_id == "TNT-XSS-001" and safe_flask_response(tree, line):
                    safe_reason = "explicit_non_html_response"
                elif (
                    finding.rule_id == "TNT-XSS-001"
                    and safe_flask_template_render(
                        tree,
                        line,
                        autoescape_disabled=file_path in autoescape_disabled_files,
                        source_path=file_path,
                        target_root=context.target_path,
                    )
                ):
                    safe_reason = "autoescaped_flask_template"
                if safe_reason:
                    finding.metadata["ast_suppressed"] = safe_reason
                    finding.confidence = 0.0
                    suppressed += 1
                    continue

                expected_calls = _STRING_LITERAL_CALL_RULES.get(finding.rule_id)
                if expected_calls is not None:
                    # A real call to the dangerous function always produces an
                    # ast.Call on this line. If none is present, the regex
                    # matched the syntax inside a string literal / comment /
                    # bare name, not a call (#304). Suppress.
                    if not (calls_on_line(tree, line) & expected_calls):
                        finding.metadata["ast_suppressed"] = "string_literal_no_call"
                        finding.confidence = 0.0
                        suppressed += 1
                        continue

                # #304: NS-SQLI-005 matches an SQL-keyword f-string. When that
                # f-string is a logging/print argument (and NOT assigned to a
                # variable, the real SQL-construction shape), it is a log
                # message, not a query. The direct `.execute(f"...")` case is
                # already excluded by the rule's own pattern-not.
                if (
                    finding.rule_id == "NS-SQLI-005"
                    and line in log_lines
                    and line not in assign_lines
                ):
                    finding.metadata["ast_suppressed"] = "sql_fstring_is_log_message"
                    finding.confidence = 0.0
                    suppressed += 1
                    continue

                if safe_dicts:
                    subs = subscripts_on_line(tree, line)
                    if subs & safe_dicts:
                        finding.metadata["ast_suppressed"] = "safe_dict_lookup"
                        finding.confidence = 0.0
                        suppressed += 1
                        continue

                if validated_classes:
                    line_calls = calls_on_line(tree, line)
                    if line_calls & validated_classes:
                        finding.metadata["ast_suppressed"] = "pydantic_validated"
                        finding.confidence = 0.0
                        suppressed += 1
                        continue

                # A sink whose arguments are all UPPER_CASE string constants
                # is not attacker-reachable. The old line-level name test also
                # fired when the constant merely decorated a tainted argument
                # (`f"{TOOL} {name}"`) and on the constant's own assignment
                # line, which demoted every one-line secret (TE-03).
                if (
                    string_constants
                    and finding.category != Category.SECRETS
                    and finding.taint_flow is None
                    and call_args_all_constants(tree, line, set(string_constants))
                ):
                    finding.metadata["ast_downgraded"] = "upper_case_constant"
                    finding.severity = Severity.LOW
                    downgraded += 1

        context.result.findings = [
            f for f in context.result.findings if f.confidence > 0.0
        ]

        duration = time.perf_counter() - start
        scan_span(self.name, duration)
        logger.info(
            "ASTEnrichmentPass: suppressed %d, downgraded %d in %.1fs",
            suppressed,
            downgraded,
            duration,
        )
        # Unlike other passes, this one mutates/filters context.result.findings
        # in place rather than producing new findings to merge in -- returning
        # an empty ScanResult is deliberate (merge()'s extend([]) is a no-op),
        # not an omission.
        return ScanResult()

    @staticmethod
    def _parse_cached(
        file_path: str, cache: dict[str, ast.AST | None]
    ) -> ast.AST | None:
        if file_path in cache:
            return cache[file_path]
        try:
            source = Path(file_path).read_text(encoding="utf-8")
            tree = ast.parse(source, filename=file_path)
        except (SyntaxError, UnicodeDecodeError, OSError) as exc:
            logger.debug("ASTEnrichmentPass: skipping %s: %s", file_path, exc)
            cache[file_path] = None
            return None
        cache[file_path] = tree
        return tree
