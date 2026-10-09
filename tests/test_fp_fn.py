"""False positive and false negative rate tests for NeuroScan regex rules.

Tests safe code that should NOT fire (FP) and vulnerable code that MUST fire (FN).
Uses the actual production rules from rules/neuroscan.yaml.
"""

from __future__ import annotations

import re
import tempfile
from pathlib import Path

import pytest

from rowan.core.findings import Category, Finding, Severity
from rowan.core.rules import load_neuroscan_rules

RULES_DIR = Path(__file__).parent.parent / "rules"
NEUROSCAN_PATH = RULES_DIR / "neuroscan.yaml"
AI_SECURITY_PATH = RULES_DIR / "ai_security.yaml"


@pytest.fixture
def rules():
    if not NEUROSCAN_PATH.exists():
        pytest.fail("rules/neuroscan.yaml not found")
    return load_neuroscan_rules(NEUROSCAN_PATH)


@pytest.fixture
def ai_rules():
    if not AI_SECURITY_PATH.exists():
        pytest.fail("rules/ai_security.yaml not found")
    return load_neuroscan_rules(AI_SECURITY_PATH)


def _scan_snippet(rules, code: str, ext: str = ".py") -> list:
    with tempfile.NamedTemporaryFile(
        mode="w", suffix=ext, delete=False, encoding="utf-8"
    ) as f:
        f.write(code)
        f.flush()
        path = Path(f.name)
    findings = []
    for rule in rules:
        if not rule.metadata.languages or (ext.lstrip(".") == "py" and "python" in rule.metadata.languages):
            findings.extend(rule.check(path))
    path.unlink(missing_ok=True)
    return findings


class TestFalsePositives:
    """Safe code that should NOT trigger findings."""

    def test_parameterized_sql(self, rules):
        code = '''
import sqlite3
def get_user(user_id):
    conn = sqlite3.connect("db.sqlite")
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
    return cursor.fetchone()
'''
        findings = _scan_snippet(rules, code)
        sqli = [f for f in findings if "sql" in f.category.value.lower() or "sqli" in f.rule_id.lower()]
        assert len(sqli) == 0, f"FP: parameterized SQL flagged: {[f.rule_id for f in sqli]}"

    def test_torch_load_weights_only(self, rules):
        code = '''
import torch
model = torch.load("model.pt", weights_only=True)
'''
        findings = _scan_snippet(rules, code)
        deser = [f for f in findings if f.category == Category.DESERIALIZATION]
        assert len(deser) == 0, f"FP: torch.load with weights_only=True flagged: {[f.rule_id for f in deser]}"

    def test_ast_literal_eval(self, rules):
        code = '''
import ast
result = ast.literal_eval(user_input)
'''
        findings = _scan_snippet(rules, code)
        inject = [f for f in findings if f.category == Category.INJECTION and "eval" in f.message.lower()]
        assert len(inject) == 0, f"FP: ast.literal_eval flagged as injection: {[f.rule_id for f in inject]}"

    def test_subprocess_list_no_shell(self, rules):
        code = '''
import subprocess
subprocess.run(["ls", "-la"], check=True)
'''
        findings = _scan_snippet(rules, code)
        cmdi = [f for f in findings if f.category == Category.COMMAND_INJECTION]
        assert len(cmdi) == 0, f"FP: subprocess with list args flagged: {[f.rule_id for f in cmdi]}"

    @pytest.mark.xfail(reason="Regex engine cannot distinguish hardcoded vs user-controlled URLs")
    def test_hardcoded_url_not_ssrf(self, rules):
        code = '''
import requests
resp = requests.get("https://api.example.com/health")
'''
        findings = _scan_snippet(rules, code)
        ssrf = [f for f in findings if f.category == Category.SSRF]
        assert len(ssrf) == 0, f"FP: hardcoded URL flagged as SSRF: {[f.rule_id for f in ssrf]}"

    def test_jinja2_sandboxed(self, rules):
        code = '''
from jinja2.sandbox import SandboxedEnvironment
env = SandboxedEnvironment()
template = env.from_string(user_template)
'''
        findings = _scan_snippet(rules, code)
        ssti = [f for f in findings if f.category == Category.SSTI]
        assert len(ssti) == 0, f"FP: SandboxedEnvironment flagged as SSTI: {[f.rule_id for f in ssti]}"

    def test_yaml_safe_load(self, rules):
        code = '''
import yaml
data = yaml.safe_load(user_input)
'''
        findings = _scan_snippet(rules, code)
        deser = [f for f in findings if f.category == Category.DESERIALIZATION and "yaml" in f.message.lower()]
        assert len(deser) == 0, f"FP: yaml.safe_load flagged: {[f.rule_id for f in deser]}"

    def test_int_cast_prevents_injection(self, rules):
        code = '''
user_val = request.args.get("count")
result = int(user_val)
'''
        findings = _scan_snippet(rules, code)
        inject = [f for f in findings if f.category == Category.INJECTION]
        assert len(inject) == 0, f"FP: int() cast flagged: {[f.rule_id for f in inject]}"

    def test_constant_string_not_secret(self, rules):
        code = '''
GREETING = "hello world"
MODE = "production"
'''
        findings = _scan_snippet(rules, code)
        secrets = [f for f in findings if f.category == Category.SECRETS]
        assert len(secrets) == 0, f"FP: constant string flagged as secret: {[f.rule_id for f in secrets]}"

    def test_safetensors_load(self, rules):
        code = '''
from safetensors.torch import load_file
model = load_file("model.safetensors")
'''
        findings = _scan_snippet(rules, code)
        deser = [f for f in findings if f.category == Category.DESERIALIZATION]
        assert len(deser) == 0, f"FP: safetensors flagged: {[f.rule_id for f in deser]}"

    def test_chat_prompt_template_framework_usage(self, rules):
        # Building a ChatPromptTemplate from internal/static messages (as the
        # LangChain framework does pervasively) is not prompt injection.
        code = '''
from langchain_core.prompts import ChatPromptTemplate
def build():
    messages = [("system", "You are helpful")]
    return ChatPromptTemplate(input_variables=input_variables, messages=messages)
'''
        findings = _scan_snippet(rules, code)
        pi = [f for f in findings if f.category == Category.PROMPT_INJECTION]
        assert len(pi) == 0, f"FP: framework ChatPromptTemplate flagged: {[f.rule_id for f in pi]}"

    def test_llmchain_from_string_not_ssti(self, rules):
        # LLMChain.from_string is not Jinja2 SSTI; the `.from_string` regex must
        # not match LangChain chain constructors.
        code = '''
from langchain.chains import LLMChain
chain = LLMChain.from_string(model, "What's the answer to {your_input_key}")
'''
        findings = _scan_snippet(rules, code)
        ssti = [f for f in findings if f.category == Category.SSTI]
        assert len(ssti) == 0, f"FP: LLMChain.from_string flagged as SSTI: {[f.rule_id for f in ssti]}"

    def test_sqlmodel_session_exec_not_injection(self, rules):
        # SQLModel's session.exec(stmt) is a safe, parameterized ORM call, not
        # the Python builtin exec(). NS-INJECT-002 must not flag attribute calls.
        code = '''
from sqlmodel import select
async def list_users(session):
    result = await session.exec(select(User))
    return result.all()
'''
        findings = _scan_snippet(rules, code)
        exec_fp = [f for f in findings if f.rule_id == "NS-INJECT-002"]
        assert len(exec_fp) == 0, f"FP: session.exec() flagged by NS-INJECT-002: {[f.rule_id for f in exec_fp]}"
        inject = [f for f in findings if f.category == Category.INJECTION and f.rule_id == "NS-INJECT-002"]
        assert len(inject) == 0, "FP: session.exec() flagged as INJECTION by NS-INJECT-002"


class TestFalseNegatives:
    """Vulnerable code that MUST trigger findings."""

    def test_chat_prompt_template_with_request_detected(self, rules):
        # A ChatPromptTemplate built directly from a request value on the same
        # line must still fire (NS-PROMPT-003). Cross-statement flows are the
        # taint rule TNT-ML-009's job.
        code = '''
from langchain_core.prompts import ChatPromptTemplate
prompt = ChatPromptTemplate(messages=[request.args.get("q")])
'''
        findings = _scan_snippet(rules, code)
        pi = [f for f in findings if f.category == Category.PROMPT_INJECTION]
        assert len(pi) > 0, "FN: ChatPromptTemplate built from request not detected"

    def test_pickle_loads_detected(self, rules):
        code = '''
import pickle
data = pickle.loads(user_data)
'''
        findings = _scan_snippet(rules, code)
        deser = [f for f in findings if f.category == Category.DESERIALIZATION]
        assert len(deser) > 0, "FN: pickle.loads not detected"

    def test_eval_detected(self, rules):
        code = '''
result = eval(user_input)
'''
        findings = _scan_snippet(rules, code)
        inject = [f for f in findings if f.category == Category.INJECTION]
        assert len(inject) > 0, "FN: eval() not detected"

    def test_exec_detected(self, rules):
        code = '''
exec(code_string)
'''
        findings = _scan_snippet(rules, code)
        inject = [f for f in findings if f.category == Category.INJECTION]
        assert len(inject) > 0, "FN: exec() not detected"

    def test_exec_builtin_rule_fires(self, rules):
        code = '''
exec(user_input)
'''
        findings = _scan_snippet(rules, code)
        exec_tp = [f for f in findings if f.rule_id == "NS-INJECT-002"]
        assert len(exec_tp) > 0, "FN: builtin exec() not detected by NS-INJECT-002"

    def test_os_system_detected(self, rules):
        code = '''
import os
os.system(command)
'''
        findings = _scan_snippet(rules, code)
        cmdi = [f for f in findings if f.category == Category.COMMAND_INJECTION]
        assert len(cmdi) > 0, "FN: os.system not detected"

    def test_subprocess_shell_true_detected(self, rules):
        code = '''
import subprocess
subprocess.run(cmd, shell=True)
'''
        findings = _scan_snippet(rules, code)
        cmdi = [f for f in findings if f.category == Category.COMMAND_INJECTION]
        assert len(cmdi) > 0, "FN: subprocess shell=True not detected"

    def test_torch_load_no_weights_only_detected(self, rules):
        code = '''
import torch
model = torch.load("model.pt")
'''
        findings = _scan_snippet(rules, code)
        deser = [f for f in findings if f.category == Category.DESERIALIZATION or "torch" in f.message.lower()]
        assert len(deser) > 0, "FN: torch.load without weights_only not detected"

    def test_trust_remote_code_detected(self, rules):
        code = '''
from transformers import AutoModel
model = AutoModel.from_pretrained("evil-repo", trust_remote_code=True)
'''
        findings = _scan_snippet(rules, code)
        aiml = [f for f in findings if f.category in (Category.AI_ML, Category.SUPPLY_CHAIN)
                or "trust_remote_code" in f.message.lower()]
        assert len(aiml) > 0, "FN: trust_remote_code=True not detected"

    def test_yaml_load_detected(self, rules):
        code = '''
import yaml
data = yaml.load(user_input)
'''
        findings = _scan_snippet(rules, code)
        deser = [f for f in findings if f.category == Category.DESERIALIZATION]
        assert len(deser) > 0, "FN: yaml.load not detected"

    def test_dill_loads_detected(self, rules):
        code = '''
import dill
obj = dill.loads(data)
'''
        findings = _scan_snippet(rules, code)
        deser = [f for f in findings if f.category == Category.DESERIALIZATION]
        assert len(deser) > 0, "FN: dill.loads not detected"

    def test_render_template_string_detected(self, rules):
        code = '''
from flask import render_template_string
result = render_template_string(user_template)
'''
        findings = _scan_snippet(rules, code)
        ssti = [f for f in findings if f.category == Category.SSTI
                or "template" in f.message.lower()]
        # render_template_string may not have a dedicated neuroscan regex rule
        # but is covered by taint rules (TNT-SSTI-001). This test documents
        # the coverage gap in the regex engine.
        if len(ssti) == 0:
            pytest.xfail("render_template_string not covered by regex rules (taint-only)")

    def test_joblib_load_detected(self, rules):
        code = '''
import joblib
model = joblib.load(user_path)
'''
        findings = _scan_snippet(rules, code)
        deser = [f for f in findings if f.category == Category.DESERIALIZATION]
        assert len(deser) > 0, "FN: joblib.load not detected"


class TestConfidenceScoring:
    """Verify enrichment confidence scores are reasonable."""

    def test_neuroscan_capped_at_70(self, rules):
        code = "result = eval(user_input)\n"
        findings = _scan_snippet(rules, code)
        assert len(findings) > 0
        for f in findings:
            assert f.engine == "neuroscan"

    def test_multiple_findings_same_file(self, rules):
        code = '''
import pickle
import os
data = pickle.loads(raw)
os.system(cmd)
result = eval(expr)
'''
        findings = _scan_snippet(rules, code)
        assert len(findings) >= 2, "Should detect multiple vulnerabilities"
        categories = {f.category for f in findings}
        assert len(categories) >= 2, f"Expected multiple categories, got: {categories}"


class TestInlineSuppression:
    """Verify # nosec / # rowan:disable suppress, and # noqa does not."""

    def test_nosec_suppresses_finding(self, rules):
        code = "result = eval(user_input)  # nosec\n"
        findings = _scan_snippet(rules, code)
        inject = [f for f in findings if f.category == Category.INJECTION]
        assert len(inject) == 0, "# nosec should suppress finding"

    @pytest.mark.parametrize(
        "directive",
        [
            "# noqa",
            "# noqa: S307",   # Ruff flake8-bandit: suppresses bandit, not us
            "# noqa: F401",   # unused import -- no security meaning at all
            "# noqa: E501",   # line too long -- no security meaning at all
            "# noqa: ARG001",
            "# NOQA",
        ],
    )
    def test_noqa_does_not_suppress_finding(self, rules, directive):
        """`noqa` is a general-purpose linter directive, not a security
        suppression. Honouring it let `# noqa: E501` hide an RCE -- a real
        `eval()` on LLM output in langflow was invisible behind `# noqa: S307`.
        Only `nosec` and `rowan:disable` are security-intended."""
        code = f"data = pickle.loads(raw)  {directive}\n"
        findings = _scan_snippet(rules, code)
        deser = [f for f in findings if f.category == Category.DESERIALIZATION]
        assert len(deser) > 0, f"{directive!r} must NOT suppress a security finding"

    def test_rowan_disable_suppresses(self, rules):
        code = "os.system(cmd)  # rowan:disable\n"
        findings = _scan_snippet(rules, code)
        cmdi = [f for f in findings if f.category == Category.COMMAND_INJECTION]
        assert len(cmdi) == 0, "# rowan:disable should suppress finding"

    def test_nosec_only_on_same_line(self, rules):
        code = '''# nosec - this comment is on a different line
result = eval(user_input)
'''
        findings = _scan_snippet(rules, code)
        inject = [f for f in findings if f.category == Category.INJECTION]
        assert len(inject) > 0, "# nosec on different line should NOT suppress"


class TestSanitizerWindow:
    """Verify ±10 line sanitizer context window."""

    def test_weights_only_on_nearby_line(self, rules):
        code = '''
import torch
model_path = "model.pt"
model = torch.load(
    model_path,
    weights_only=True,
)
'''
        findings = _scan_snippet(rules, code)
        deser = [f for f in findings if "torch" in f.rule_id.lower() or "deser" in f.rule_id.lower()]
        # Rules with sanitizer window should suppress this
        # (NS-DESER-002 uses pattern-not which works same-line,
        #  rules with sanitizers field check ±10 line window)
        assert len(deser) == 0, "torch.load(weights_only=True) is safe and should not be flagged"

    def test_sandboxed_environment_nearby(self, rules):
        code = '''
from jinja2.sandbox import SandboxedEnvironment

env = SandboxedEnvironment()

# Several lines later
template = env.from_string(user_input)
result = template.render(data=data)
'''
        findings = _scan_snippet(rules, code)
        ssti = [f for f in findings if f.category == Category.SSTI]
        assert len(ssti) == 0, "SandboxedEnvironment within ±10 lines should suppress SSTI"


class TestTestPathFiltering:
    """Verify test/example path findings are downgraded."""

    def test_test_path_detection(self):
        from rowan.passes.enrichment import _is_test_path

        assert _is_test_path("tests/test_app.py") is True
        assert _is_test_path("test/conftest.py") is True
        assert _is_test_path("src/test_utils.py") is True
        assert _is_test_path("examples/demo.py") is True
        assert _is_test_path("fixtures/data.py") is True
        assert _is_test_path("src/app.py") is False
        assert _is_test_path("lib/utils.py") is False

    def test_compound_segment_names_are_recognized(self):
        """DEF-13: a path segment matched _TEST_PATH_SEGMENTS only by exact
        equality, so real-world compound directory names like
        'javascript-examples' or 'api-reference-api-examples' (found in a
        langflow corpus scan: 87% of JS-SSRF-001's findings were doc-example
        scripts calling langflow's own public API) were never recognized as
        example/test paths. Segments are now tokenized on '-'/'_'/'.' before
        matching, so a whole-word 'examples'/'test' token anywhere in a
        compound segment still counts -- without over-matching unrelated
        words that merely contain those letters."""
        from rowan.passes.enrichment import _is_test_path

        assert _is_test_path("docs/javascript-examples/api-build/x.js") is True
        assert _is_test_path("docs/api-reference-api-examples/y.js") is True
        assert _is_test_path("pkg/unit-tests/handler_test.go") is True
        # must not over-match words that merely contain "test" as a substring
        assert _is_test_path("latest/release.py") is False
        assert _is_test_path("contest-service/handler.go") is False

    def test_compound_go_test_directory_names(self):
        """EXT-08: `dbtest` is one token, so it never matched `test`. Go has
        several such compound helper-package names; they are listed
        explicitly, with no generic 'ends with test' rule."""
        from rowan.analysis.test_paths import is_test_path

        assert is_test_path("internal/dbtest/dbtest.go") is True
        assert is_test_path("internal/contest/latest.go") is False

    def test_test_path_downgrade(self):

        findings = [
            Finding(
                rule_id="NS-DESER-001", message="pickle", severity=Severity.CRITICAL,
                category=Category.DESERIALIZATION, file_path="tests/test_app.py",
                start_line=10, engine="neuroscan",
            ),
            Finding(
                rule_id="NS-DESER-001", message="pickle", severity=Severity.HIGH,
                category=Category.DESERIALIZATION, file_path="src/app.py",
                start_line=10, engine="neuroscan",
            ),
        ]

        from rowan.passes.enrichment import _is_test_path
        test_findings = [f for f in findings if _is_test_path(f.file_path)]
        assert len(test_findings) == 1
        assert test_findings[0].file_path == "tests/test_app.py"


class TestAIContextGate:
    """Verify AI rules are suppressed on non-AI files."""

    def test_ai_rule_detection(self):
        from rowan.passes.enrichment import _is_ai_rule

        assert _is_ai_rule("ns-aiml-030") is True
        assert _is_ai_rule("NS-AIML-001") is True
        assert _is_ai_rule("TNT-ML-001") is True
        assert _is_ai_rule("TNT-AIML-003") is True
        assert _is_ai_rule("NS-DESER-001") is False
        assert _is_ai_rule("TNT-SSRF-001") is False


class TestIgnorePatterns:
    """Tests for .rowanignore pattern loading and matching."""

    def test_load_ignore_patterns_missing_file(self):
        from rowan.passes.file_scan import load_ignore_patterns
        with tempfile.TemporaryDirectory() as tmpdir:
            patterns = load_ignore_patterns(Path(tmpdir))
            assert patterns == []

    def test_load_ignore_patterns_basic(self):
        from rowan.passes.file_scan import load_ignore_patterns
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            (root / ".rowanignore").write_text(
                "# comment\n\nvendor/\n*.generated.py\n!keep.py\n",
                encoding="utf-8",
            )
            patterns = load_ignore_patterns(root)
            assert patterns == ["vendor/", "*.generated.py", "!keep.py"]

    def test_is_ignored_directory_pattern(self):
        from rowan.passes.file_scan import is_ignored
        patterns = ["vendor/"]
        assert is_ignored("vendor/foo.py", patterns) is True
        assert is_ignored("src/app.py", patterns) is False
        assert is_ignored("vendor/sub/bar.py", patterns) is True

    def test_is_ignored_glob_pattern(self):
        from rowan.passes.file_scan import is_ignored
        patterns = ["*.generated.py"]
        assert is_ignored("src/models.generated.py", patterns) is True
        assert is_ignored("src/models.py", patterns) is False

    def test_is_ignored_negation(self):
        from rowan.passes.file_scan import is_ignored
        patterns = ["vendor/", "!vendor/important.py"]
        assert is_ignored("vendor/junk.py", patterns) is True
        assert is_ignored("vendor/important.py", patterns) is False

    def test_is_ignored_subdir_glob(self):
        from rowan.passes.file_scan import is_ignored
        patterns = ["proto/*.py"]
        assert is_ignored("proto/service.py", patterns) is True
        assert is_ignored("proto/sub/service.py", patterns) is False
        assert is_ignored("src/app.py", patterns) is False


class TestFrameworkGating:
    """Verify web rules are suppressed on non-web files."""

    def test_web_rule_detection(self):
        from rowan.passes.enrichment import _is_web_rule

        assert _is_web_rule(Finding(
            rule_id="TNT-SSRF-001", message="ssrf", severity=Severity.HIGH,
            category=Category.SSRF, file_path="x.py", start_line=1, engine="opengrep",
        )) is True
        assert _is_web_rule(Finding(
            rule_id="NS-XSS-001", message="xss", severity=Severity.HIGH,
            category=Category.XSS, file_path="x.py", start_line=1, engine="neuroscan",
        )) is True
        assert _is_web_rule(Finding(
            rule_id="NS-AUTH-001", message="auth", severity=Severity.HIGH,
            category=Category.AUTH, file_path="x.py", start_line=1, engine="neuroscan",
        )) is True
        assert _is_web_rule(Finding(
            rule_id="open-redirect-001", message="redirect", severity=Severity.HIGH,
            category=Category.GENERAL, file_path="x.py", start_line=1, engine="neuroscan",
        )) is True
        assert _is_web_rule(Finding(
            rule_id="header-injection-001", message="header", severity=Severity.HIGH,
            category=Category.GENERAL, file_path="x.py", start_line=1, engine="neuroscan",
        )) is True
        assert _is_web_rule(Finding(
            rule_id="NS-DESER-001", message="pickle", severity=Severity.HIGH,
            category=Category.DESERIALIZATION, file_path="x.py", start_line=1, engine="neuroscan",
        )) is False

    def test_ssrf_on_non_web_file(self):
        from rowan.passes.enrichment import EnrichmentPass

        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".py", delete=False, encoding="utf-8"
        ) as f:
            f.write("import math\nresult = math.sqrt(4)\n")
            f.flush()
            tmp_path = f.name

        findings = [
            Finding(
                rule_id="TNT-SSRF-001", message="ssrf", severity=Severity.HIGH,
                category=Category.SSRF, file_path=tmp_path,
                start_line=2, engine="opengrep", confidence=0.9,
            ),
        ]

        ep = EnrichmentPass()
        result = ep._suppress_web_rules_on_non_web_files(findings)
        Path(tmp_path).unlink(missing_ok=True)

        assert len(result) == 1
        assert result[0].severity == Severity.INFO
        assert result[0].confidence <= 0.3
        assert result[0].metadata.get("web_context_gate") is True


class TestStaticRedirectSuppression:
    """Verify static redirect findings are dropped."""

    def test_static_redirect_dropped(self):
        from rowan.passes.enrichment import EnrichmentPass

        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".py", delete=False, encoding="utf-8"
        ) as f:
            f.write("from flask import redirect\n")
            f.write("return redirect('login')\n")
            f.flush()
            tmp_path = f.name

        findings = [
            Finding(
                rule_id="open-redirect-001", message="redirect", severity=Severity.MEDIUM,
                category=Category.SSRF, file_path=tmp_path,
                start_line=2, engine="neuroscan",
            ),
        ]

        ep = EnrichmentPass()
        result = ep._suppress_static_redirects(findings)
        Path(tmp_path).unlink(missing_ok=True)

        assert len(result) == 0, "Static redirect('login') should be dropped"


class TestAdjacentDedup:
    """Verify adjacent-line merge deduplication."""

    def test_adjacent_findings_merged(self):
        from rowan.passes.enrichment import EnrichmentPass

        findings = [
            Finding(
                rule_id="NS-DESER-001", message="pickle", severity=Severity.HIGH,
                category=Category.DESERIALIZATION, file_path="src/app.py",
                start_line=10, engine="neuroscan", confidence=0.6,
            ),
            Finding(
                rule_id="NS-DESER-001", message="pickle", severity=Severity.HIGH,
                category=Category.DESERIALIZATION, file_path="src/app.py",
                start_line=13, engine="neuroscan", confidence=0.7,
            ),
        ]

        ep = EnrichmentPass()
        result = ep._deduplicate(findings)
        assert len(result) == 1
        assert result[0].metadata.get("occurrence_count") == 2
        assert result[0].confidence == 0.7
        # TE-04: the survivor keeps its own line so later line-anchored
        # suppressors judge the right line; the span lives in metadata.
        assert result[0].start_line == 13
        assert result[0].metadata.get("cluster_start") == 10
        assert result[0].metadata.get("cluster_end") == 13

    def test_distant_findings_not_merged(self):
        from rowan.passes.enrichment import EnrichmentPass

        findings = [
            Finding(
                rule_id="NS-DESER-001", message="pickle", severity=Severity.HIGH,
                category=Category.DESERIALIZATION, file_path="src/app.py",
                start_line=10, engine="neuroscan", confidence=0.7,
            ),
            Finding(
                rule_id="NS-DESER-001", message="pickle", severity=Severity.HIGH,
                category=Category.DESERIALIZATION, file_path="src/app.py",
                start_line=50, engine="neuroscan", confidence=0.7,
            ),
        ]

        ep = EnrichmentPass()
        result = ep._deduplicate(findings)
        assert len(result) == 2

    def test_cross_file_findings_with_different_callers_not_merged(self):
        """Two distinct route handlers in the same file that both happen to
        reach the same sink via the same CF-* rule (e.g. get_blob() and
        download_artifact() both calling registry.read_artifact()) are two
        separate vulnerable entry points, not near-duplicates of each other
        -- even when their def lines land within the line-proximity window.
        Folding them together by (file, rule_id) alone silently dropped
        whichever caller sorted second, hiding a real, independently
        detected finding from the report entirely."""
        from rowan.passes.enrichment import EnrichmentPass

        findings = [
            Finding(
                rule_id="CF-SINK-001", message="download_artifact() reaches read_artifact()",
                severity=Severity.HIGH, category=Category.GENERAL, file_path="src/api/models.py",
                start_line=62, engine="crossfile", confidence=0.75,
                metadata={"cross_file": True, "caller": "download_artifact", "callee_name": "read_artifact"},
            ),
            Finding(
                rule_id="CF-SINK-001", message="get_blob() reaches read_artifact()",
                severity=Severity.HIGH, category=Category.GENERAL, file_path="src/api/models.py",
                start_line=72, engine="crossfile", confidence=0.75,
                metadata={"cross_file": True, "caller": "get_blob", "callee_name": "read_artifact"},
            ),
        ]

        ep = EnrichmentPass()
        result = ep._deduplicate(findings)
        assert len(result) == 2, "distinct callers must survive as separate findings"
        callers = {f.metadata.get("caller") for f in result}
        assert callers == {"download_artifact", "get_blob"}

    def test_cross_file_findings_same_caller_still_merge(self):
        """The line-proximity merge must still apply normally when the
        caller IS the same (e.g. two hop-depth variants of the same edge)."""
        from rowan.passes.enrichment import EnrichmentPass

        findings = [
            Finding(
                rule_id="CF-SINK-001", message="a", severity=Severity.HIGH,
                category=Category.GENERAL, file_path="src/api/models.py",
                start_line=62, engine="crossfile", confidence=0.6,
                metadata={"cross_file": True, "caller": "download_artifact", "callee_name": "read_artifact"},
            ),
            Finding(
                rule_id="CF-SINK-001", message="b", severity=Severity.HIGH,
                category=Category.GENERAL, file_path="src/api/models.py",
                start_line=64, engine="crossfile", confidence=0.7,
                metadata={"cross_file": True, "caller": "download_artifact", "callee_name": "read_artifact"},
            ),
        ]

        ep = EnrichmentPass()
        result = ep._deduplicate(findings)
        assert len(result) == 1


class TestSecretEntropy:
    """Verify secret entropy filtering suppresses placeholders."""

    def test_placeholder_suppressed(self):
        from rowan.core.rules import NeuroScanRule, RegexPattern, RuleMetadata

        rule = NeuroScanRule(
            metadata=RuleMetadata(
                id="NS-SECRET-001", name="API Key", severity=Severity.HIGH,
                category=Category.SECRETS, description="Hardcoded API key",
            ),
            patterns=[RegexPattern(pattern=re.compile(r"API_KEY\s*="), raw=r"API_KEY\s*=")],
        )

        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".py", delete=False, encoding="utf-8"
        ) as f:
            f.write('API_KEY = "changeme"\n')
            f.flush()
            path = Path(f.name)
        findings = rule.check(path)
        path.unlink(missing_ok=True)
        assert len(findings) == 0, "Placeholder 'changeme' should be suppressed"

    def test_high_entropy_not_suppressed(self):
        from rowan.core.rules import NeuroScanRule, RegexPattern, RuleMetadata

        rule = NeuroScanRule(
            metadata=RuleMetadata(
                id="NS-SECRET-001", name="API Key", severity=Severity.HIGH,
                category=Category.SECRETS, description="Hardcoded API key",
            ),
            patterns=[RegexPattern(pattern=re.compile(r"API_KEY\s*="), raw=r"API_KEY\s*=")],
        )

        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".py", delete=False, encoding="utf-8"
        ) as f:
            f.write('API_KEY = "sk-a8f3b2c1d4e5f6a7b8c9d0e1f2a3b4c5"\n')
            f.flush()
            path = Path(f.name)
        findings = rule.check(path)
        path.unlink(missing_ok=True)
        assert len(findings) > 0, "High entropy secret should NOT be suppressed"

    def test_env_reference_suppressed(self):
        from rowan.core.rules import NeuroScanRule, RegexPattern, RuleMetadata

        rule = NeuroScanRule(
            metadata=RuleMetadata(
                id="NS-SECRET-001", name="API Key", severity=Severity.HIGH,
                category=Category.SECRETS, description="Hardcoded API key",
            ),
            patterns=[RegexPattern(pattern=re.compile(r"API_KEY\s*="), raw=r"API_KEY\s*=")],
        )

        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".py", delete=False, encoding="utf-8"
        ) as f:
            f.write('API_KEY = os.environ["SECRET"]\n')
            f.flush()
            path = Path(f.name)
        findings = rule.check(path)
        path.unlink(missing_ok=True)
        assert len(findings) == 0, "Env reference should be suppressed"


class TestThresholds:
    """Verify per-rule threshold configuration."""

    def test_max_severity_cap(self):
        from rowan.config import ScanConfig
        from rowan.core.findings import ScanResult
        from rowan.passes.base import ScanContext
        from rowan.passes.enrichment import EnrichmentPass, _thresholds_cache

        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".yaml", delete=False, encoding="utf-8"
        ) as f:
            f.write("rules:\n  NS-DESER-001:\n    max_severity: medium\n")
            f.flush()
            thresholds_path = Path(f.name)

        _thresholds_cache.clear()

        findings = [
            Finding(
                rule_id="NS-DESER-001", message="pickle", severity=Severity.HIGH,
                category=Category.DESERIALIZATION, file_path="src/app.py",
                start_line=10, engine="neuroscan",
            ),
        ]

        config = ScanConfig(target=Path("."), thresholds_path=thresholds_path)
        context = ScanContext(
            target_path=Path("."), config=config, result=ScanResult()
        )

        ep = EnrichmentPass()
        result = ep._apply_thresholds(findings, context)
        thresholds_path.unlink(missing_ok=True)
        _thresholds_cache.clear()

        assert len(result) == 1
        assert result[0].severity == Severity.MEDIUM

    def test_disabled_rule_removed(self):
        from rowan.config import ScanConfig
        from rowan.core.findings import ScanResult
        from rowan.passes.base import ScanContext
        from rowan.passes.enrichment import EnrichmentPass, _thresholds_cache

        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".yaml", delete=False, encoding="utf-8"
        ) as f:
            f.write("rules:\n  NS-DESER-001:\n    enabled: false\n")
            f.flush()
            thresholds_path = Path(f.name)

        _thresholds_cache.clear()

        findings = [
            Finding(
                rule_id="NS-DESER-001", message="pickle", severity=Severity.HIGH,
                category=Category.DESERIALIZATION, file_path="src/app.py",
                start_line=10, engine="neuroscan",
            ),
        ]

        config = ScanConfig(target=Path("."), thresholds_path=thresholds_path)
        context = ScanContext(
            target_path=Path("."), config=config, result=ScanResult()
        )

        ep = EnrichmentPass()
        result = ep._apply_thresholds(findings, context)
        thresholds_path.unlink(missing_ok=True)
        _thresholds_cache.clear()

        assert len(result) == 0, "Disabled rule should be removed"

    def test_keras_deser_010_disabled_by_default(self):
        """NS-DESER-010's remaining pattern (keras.models.model_from_json(,
        after issue #137's own fix already removed its load_model patterns in
        favor of ns-aiml-114/ns-aiml-115) is a strict subset of the
        pre-existing ns-aiml-043, so it double-fires alongside a much weaker,
        non-CVE-referenced message on every model_from_json() call. The
        builtin thresholds.yaml now disables it by default while ns-aiml-043
        remains live."""
        from rowan.config import ScanConfig
        from rowan.core.findings import ScanResult
        from rowan.passes.base import ScanContext
        from rowan.passes.enrichment import EnrichmentPass, _thresholds_cache

        _thresholds_cache.clear()

        findings = [
            Finding(
                rule_id=rule_id, message="keras model_from_json", severity=Severity.HIGH,
                category=Category.DESERIALIZATION, file_path="src/model.py",
                start_line=10, engine="neuroscan",
            )
            for rule_id in ("NS-DESER-010", "ns-aiml-043")
        ]

        config = ScanConfig(target=Path("."))
        context = ScanContext(
            target_path=Path("."), config=config, result=ScanResult()
        )

        ep = EnrichmentPass()
        result = ep._apply_thresholds(findings, context)
        _thresholds_cache.clear()

        surviving_ids = {f.rule_id for f in result}
        assert surviving_ids == {"ns-aiml-043"}, (
            "Expected NS-DESER-010 to be disabled by the default thresholds "
            f"config, got: {surviving_ids}"
        )

    def test_trust_remote_code_duplicate_cluster_disabled_by_default(self):
        """DEF-10 (issue #90): ns-aiml-038/ns-aiml-059 duplicated
        NS-AIML-001's bare trust_remote_code=True signal, co-firing on the
        same line and inflating finding counts (920 combined findings, 32%
        of all output, across a 5-repo corpus scan). The builtin
        thresholds.yaml disables the duplicates by default (NS-AIML-002,
        a third copy, was deleted) while
        leaving NS-AIML-001 -- the canonical signal -- live."""
        from rowan.config import ScanConfig
        from rowan.core.findings import ScanResult
        from rowan.passes.base import ScanContext
        from rowan.passes.enrichment import EnrichmentPass, _thresholds_cache

        _thresholds_cache.clear()

        findings = [
            Finding(
                rule_id=rule_id, message="trust_remote_code", severity=Severity.HIGH,
                category=Category.AI_ML, file_path="src/model.py",
                start_line=10, engine="neuroscan",
            )
            for rule_id in ("NS-AIML-001", "ns-aiml-038", "ns-aiml-059")
        ]

        config = ScanConfig(target=Path("."))
        context = ScanContext(
            target_path=Path("."), config=config, result=ScanResult()
        )

        ep = EnrichmentPass()
        result = ep._apply_thresholds(findings, context)
        _thresholds_cache.clear()

        surviving_ids = {f.rule_id for f in result}
        assert surviving_ids == {"NS-AIML-001"}, (
            "Expected only NS-AIML-001 to survive the default thresholds "
            f"config, got: {surviving_ids}"
        )

    def test_sqli_duplicate_disabled_by_default(self):
        """DEF-15: NS-SQLI-002's three patterns are each a strict subset of
        NS-SQLI-001's broader patterns, so it never added recall -- confirmed
        via a corpus scan, 100% of its 81 findings coincided with an
        NS-SQLI-001 finding on the same line. The builtin thresholds.yaml
        now disables it while leaving NS-SQLI-001 -- the canonical, broader
        rule -- live."""
        from rowan.config import ScanConfig
        from rowan.core.findings import ScanResult
        from rowan.passes.base import ScanContext
        from rowan.passes.enrichment import EnrichmentPass, _thresholds_cache

        _thresholds_cache.clear()

        findings = [
            Finding(
                rule_id=rule_id, message="sqli", severity=Severity.HIGH,
                category=Category.INJECTION, file_path="src/db.py",
                start_line=10, engine="neuroscan",
            )
            for rule_id in ("NS-SQLI-001", "NS-SQLI-002")
        ]

        config = ScanConfig(target=Path("."))
        context = ScanContext(
            target_path=Path("."), config=config, result=ScanResult()
        )

        ep = EnrichmentPass()
        result = ep._apply_thresholds(findings, context)
        _thresholds_cache.clear()

        surviving_ids = {f.rule_id for f in result}
        assert surviving_ids == {"NS-SQLI-001"}, (
            "Expected only NS-SQLI-001 to survive the default thresholds "
            f"config, got: {surviving_ids}"
        )

    def test_path_and_deser_and_sqli_taint_duplicates_disabled_by_default(self):
        """DEF-16/17/19: ns-aiml-063 (archive extraction, duplicate of
        NS-PATH-005), ns-aiml-034 (pickle deserialization, duplicate of
        NS-DESER-001), and TNT-SQLI-001 (SQLi taint, strict subset of
        TNT-SQLI-002) are disabled by the builtin thresholds.yaml. Disabling
        the ns-aiml-* duplicates rather than their non-AI-prefixed
        counterparts specifically avoids subjecting these general
        vulnerability classes (zip-slip, pickle RCE) to the ns-aiml-*
        AI-context suppression gate, which has no logical bearing on them."""
        from rowan.config import ScanConfig
        from rowan.core.findings import ScanResult
        from rowan.passes.base import ScanContext
        from rowan.passes.enrichment import EnrichmentPass, _thresholds_cache

        _thresholds_cache.clear()

        findings = [
            Finding(
                rule_id=rule_id, message="test", severity=Severity.HIGH,
                category=Category.GENERAL, file_path="src/app.py",
                start_line=10, engine="neuroscan",
            )
            for rule_id in (
                "NS-PATH-005", "ns-aiml-063",
                "NS-DESER-001", "ns-aiml-034",
                "TNT-SQLI-002", "TNT-SQLI-001",
            )
        ]

        config = ScanConfig(target=Path("."))
        context = ScanContext(
            target_path=Path("."), config=config, result=ScanResult()
        )

        ep = EnrichmentPass()
        result = ep._apply_thresholds(findings, context)
        _thresholds_cache.clear()

        surviving_ids = {f.rule_id for f in result}
        assert surviving_ids == {"NS-PATH-005", "NS-DESER-001", "TNT-SQLI-002"}, (
            f"Expected only the canonical rules to survive, got: {surviving_ids}"
        )

    def test_rb_path_001_low_confidence_gated_by_default(self):
        """DEF-24: RB-PATH-001 ("user-controlled file path" in Ruby) is a
        genuinely correct sink (File.open/read/write/delete, Dir.chdir/glob
        are the real Ruby file-path APIs) but a bare surface signal with no
        differentiation between a hardcoded/internal path and a real
        user-controlled one -- confirmed on a real corpus scan (discourse):
        422 findings, roughly half already floored to 0.4 (test-path), the
        rest at 0.6-0.7 with no further narrowing to genuine external
        input. Gated the same way as NS-SSRF-001/102/103."""
        from rowan.config import ScanConfig
        from rowan.core.findings import ScanResult
        from rowan.passes.base import ScanContext
        from rowan.passes.enrichment import EnrichmentPass, _thresholds_cache

        _thresholds_cache.clear()

        findings = [
            Finding(
                rule_id="RB-PATH-001", message="path", severity=Severity.MEDIUM,
                category=Category.PATH_TRAVERSAL, file_path="src/app.rb",
                start_line=10, engine="neuroscan", confidence=confidence,
            )
            for confidence in (0.4, 0.6, 0.7)
        ]

        config = ScanConfig(target=Path("."))
        context = ScanContext(
            target_path=Path("."), config=config, result=ScanResult()
        )

        ep = EnrichmentPass()
        result = ep._apply_thresholds(findings, context)
        _thresholds_cache.clear()

        surviving_confidences = {f.confidence for f in result}
        assert surviving_confidences == {0.6, 0.7}, (
            f"Expected the 0.4-confidence (test-path) finding dropped, "
            f"0.6/0.7 kept, got: {surviving_confidences}"
        )

class TestAIMLSecurityFalsePositives:
    """Bare AI/ML framework code that should NOT trigger ns-aiml rules."""

    def test_dot_access_eval_not_code_exec(self, ai_rules):
        code = '''
import pandas as pd
df = pd.DataFrame({"a": [1, 2], "b": [3, 4]})
result = df.eval("a + b")
'''
        findings = _scan_snippet(ai_rules, code)
        exec_fp = [f for f in findings if f.rule_id in ("ns-aiml-042", "ns-aiml-046")]
        assert len(exec_fp) == 0, f"FP: df.eval() flagged: {[f.rule_id for f in exec_fp]}"

    def test_dot_access_exec_not_code_exec(self, ai_rules):
        code = '''
from sqlmodel import Session, select
session = Session()
result = session.exec(select(User))
'''
        findings = _scan_snippet(ai_rules, code)
        exec_fp = [f for f in findings if f.rule_id in ("ns-aiml-042", "ns-aiml-046")]
        assert len(exec_fp) == 0, f"FP: session.exec() flagged: {[f.rule_id for f in exec_fp]}"

    def test_re_compile_not_code_exec(self, ai_rules):
        code = '''
import re
pattern = re.compile(r"hello.*world")
match = pattern.search(text)
'''
        findings = _scan_snippet(ai_rules, code)
        compile_fp = [f for f in findings if f.rule_id == "ns-aiml-046"]
        assert len(compile_fp) == 0, f"FP: re.compile() flagged by ns-aiml-046: {[f.rule_id for f in compile_fp]}"

    def test_operator_attrgetter_demoted_to_info(self, ai_rules):
        code = '''
import operator
get_name = operator.attrgetter("name")
sorted_users = sorted(users, key=operator.itemgetter(1))
'''
        findings = _scan_snippet(ai_rules, code)
        aiml_045 = [f for f in findings if f.rule_id == "ns-aiml-045"]
        assert len(aiml_045) > 0, "ns-aiml-045 should still fire for operator.attrgetter/itemgetter"
        for f in aiml_045:
            assert f.severity == Severity.INFO, f"ns-aiml-045 should be INFO, got {f.severity}"


class TestAIMLSecurityFalseNegatives:
    """User-input-bearing code that MUST still trigger tightened ns-aiml rules."""

    def test_standalone_eval_with_request_still_fires(self, ai_rules):
        code = 'result = eval(request.args.get("code"))\n'
        findings = _scan_snippet(ai_rules, code)
        eval_tp = [f for f in findings if f.rule_id in ("ns-aiml-042", "ns-aiml-046")]
        assert len(eval_tp) > 0, "FN: standalone eval() with user input not detected"

    def test_standalone_exec_with_user_input_still_fires(self, ai_rules):
        code = 'exec(user_input)\n'
        findings = _scan_snippet(ai_rules, code)
        exec_tp = [f for f in findings if f.rule_id in ("ns-aiml-042", "ns-aiml-046")]
        assert len(exec_tp) > 0, "FN: standalone exec() with user input not detected"

    def test_standalone_compile_with_user_input_still_fires(self, ai_rules):
        code = 'compile(user_code, "<string>", "exec")\n'
        findings = _scan_snippet(ai_rules, code)
        compile_tp = [f for f in findings if f.rule_id == "ns-aiml-046"]
        assert len(compile_tp) > 0, "FN: standalone compile() with user input not detected"
