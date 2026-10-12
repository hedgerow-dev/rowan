"""End-to-end pipeline scenario tests.

Runs the full ScanPipeline on synthetic projects and verifies
the output format, severity filtering, and finding correctness.
"""

from __future__ import annotations

import json
import tempfile
from pathlib import Path

import pytest

from rowan.config import ScanConfig
from rowan.core.findings import (
    Category,
    Finding,
    ScanResult,
    Severity,
    TaintFlow,
    TaintNode,
)
from rowan.passes.enrichment import EnrichmentPass
from rowan.pipeline import ScanPipeline
from rowan.reporters import to_json, to_sarif, to_text
from rowan.taint.opengrep_adapter import OpengrepAdapter


@pytest.fixture
def mixed_project():
    with tempfile.TemporaryDirectory(prefix="rowan_e2e_") as tmpdir:
        root = Path(tmpdir)
        src = root / "src"
        src.mkdir()

        (src / "vuln_deser.py").write_text(
            "import pickle\n"
            "from flask import request\n"
            "\n"
            "def load():\n"
            "    data = request.args.get('payload')\n"
            "    return pickle.loads(data.encode())\n",
            encoding="utf-8",
        )

        (src / "vuln_cmdi.py").write_text(
            "import os\n\ndef run(cmd):\n    os.system(cmd)\n",
            encoding="utf-8",
        )

        (src / "vuln_eval.py").write_text(
            "def compute(expr):\n    return eval(expr)\n",
            encoding="utf-8",
        )

        (src / "vuln_ssti.py").write_text(
            "from flask import render_template_string\n"
            "\n"
            "def greet(name):\n"
            "    return render_template_string(f'Hello {name}')\n",
            encoding="utf-8",
        )

        (src / "safe_code.py").write_text(
            "import ast\n"
            "\n"
            "def safe_eval(expr):\n"
            "    return ast.literal_eval(expr)\n"
            "\n"
            "def add(a, b):\n"
            "    return a + b\n",
            encoding="utf-8",
        )

        (src / "safe_torch.py").write_text(
            "import torch\n"
            "\n"
            "def load_model():\n"
            "    return torch.load('model.pt', weights_only=True)\n",
            encoding="utf-8",
        )

        yield root


class TestFullPipeline:
    def test_pipeline_finds_vulnerabilities(self, mixed_project):
        config = ScanConfig(
            target=mixed_project,
            no_taint=True,
            no_sca=True,
            languages=["python"],
            legacy_neuroscan=True,
        )
        pipeline = ScanPipeline(config)
        result = pipeline.run()

        assert result.files_scanned > 0
        assert result.total_count > 0

        rule_ids = {f.rule_id for f in result.findings}
        assert len(rule_ids) > 0

    def test_pipeline_detects_multiple_categories(self, mixed_project):
        config = ScanConfig(
            target=mixed_project,
            no_taint=True,
            no_sca=True,
            languages=["python"],
            legacy_neuroscan=True,
        )
        result = ScanPipeline(config).run()

        categories = {f.category for f in result.findings}
        assert len(categories) >= 2, f"Expected multiple categories, got: {categories}"

    def test_safe_code_not_flagged(self, mixed_project):
        config = ScanConfig(
            target=mixed_project,
            no_taint=True,
            no_sca=True,
            languages=["python"],
            legacy_neuroscan=True,
        )
        result = ScanPipeline(config).run()

        safe_files = {"safe_code.py", "safe_torch.py"}
        safe_findings = [f for f in result.findings if Path(f.file_path).name in safe_files]
        assert len(safe_findings) == 0, (
            f"Safe files should not be flagged: "
            f"{[(Path(f.file_path).name, f.rule_id) for f in safe_findings]}"
        )


class TestSeverityFiltering:
    def test_severity_filter_high(self, mixed_project):
        config = ScanConfig(
            target=mixed_project,
            no_taint=True,
            no_sca=True,
            languages=["python"],
            severity=Severity.HIGH,
            legacy_neuroscan=True,
        )
        result = ScanPipeline(config).run()

        low = [f for f in result.findings if f.severity in (Severity.LOW, Severity.INFO)]
        assert len(low) == 0, "Severity filter should exclude low/info findings"

    def test_severity_filter_critical_may_be_empty(self, mixed_project):
        config = ScanConfig(
            target=mixed_project,
            no_taint=True,
            no_sca=True,
            languages=["python"],
            severity=Severity.CRITICAL,
        )
        result = ScanPipeline(config).run()
        assert isinstance(result.total_count, int)


class TestLanguageFiltering:
    def test_python_only(self, mixed_project):
        config = ScanConfig(
            target=mixed_project,
            no_taint=True,
            no_sca=True,
            languages=["python"],
            legacy_neuroscan=True,
        )
        result = ScanPipeline(config).run()

        for f in result.findings:
            ext = Path(f.file_path).suffix
            assert ext == ".py", f"Expected .py files only, got: {f.file_path}"


class TestOutputFormats:
    def test_sarif_structure(self, mixed_project):
        config = ScanConfig(
            target=mixed_project,
            no_taint=True,
            no_sca=True,
            languages=["python"],
            legacy_neuroscan=True,
        )
        result = ScanPipeline(config).run()
        data = to_sarif(result, str(mixed_project))

        assert data["version"] == "2.1.0"
        assert "$schema" in data
        assert len(data["runs"]) == 1
        run = data["runs"][0]
        assert "tool" in run
        assert "results" in run
        assert run["tool"]["driver"]["name"] == "Rowan"

        for r in run["results"]:
            assert "ruleId" in r
            assert "message" in r
            assert "locations" in r
            assert len(r["locations"]) > 0

    def test_json_structure(self, mixed_project):
        config = ScanConfig(
            target=mixed_project,
            no_taint=True,
            no_sca=True,
            languages=["python"],
            legacy_neuroscan=True,
        )
        result = ScanPipeline(config).run()
        output = to_json(result)
        data = json.loads(output)

        assert "scanner" in data
        assert data["scanner"] == "rowan"
        assert "summary" in data
        assert "total" in data["summary"]
        assert "findings" in data
        assert isinstance(data["findings"], list)

        for f in data["findings"]:
            assert "rule_id" in f
            assert "severity" in f
            assert "category" in f
            assert "file" in f
            assert "line" in f

    def test_text_output_not_empty(self, mixed_project):
        config = ScanConfig(
            target=mixed_project,
            no_taint=True,
            no_sca=True,
            languages=["python"],
            legacy_neuroscan=True,
        )
        result = ScanPipeline(config).run()
        text = to_text(result)
        assert len(text) > 0
        assert "Rowan" in text

    def test_text_contains_findings(self, mixed_project):
        config = ScanConfig(
            target=mixed_project,
            no_taint=True,
            no_sca=True,
            languages=["python"],
            legacy_neuroscan=True,
        )
        result = ScanPipeline(config).run()
        text = to_text(result)
        if result.total_count > 0:
            assert "Findings:" in text or "finding" in text.lower()


class TestEnrichmentIntegration:
    def test_dedup_in_pipeline(self, mixed_project):
        config = ScanConfig(
            target=mixed_project,
            no_taint=True,
            no_sca=True,
            languages=["python"],
            legacy_neuroscan=True,
        )
        result = ScanPipeline(config).run()

        keys = [(f.file_path, f.rule_id, f.start_line) for f in result.findings]
        assert len(keys) == len(set(keys)), "Duplicates should be removed by enrichment"

    def test_confidence_bounded(self, mixed_project):
        config = ScanConfig(
            target=mixed_project,
            no_taint=True,
            no_sca=True,
            languages=["python"],
            legacy_neuroscan=True,
        )
        result = ScanPipeline(config).run()

        for f in result.findings:
            assert 0.0 <= f.confidence <= 1.0, f"Confidence out of range: {f.confidence}"


class TestEdgeCases:
    def test_empty_directory(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            config = ScanConfig(
                target=Path(tmpdir),
                no_taint=True,
                no_sca=True,
                legacy_neuroscan=True,
            )
            result = ScanPipeline(config).run()
            assert result.total_count == 0

    def test_nonexistent_directory(self):
        with pytest.raises(ValueError, match="target does not exist"):
            ScanConfig(
                target=Path("/nonexistent/path"),
                no_taint=True,
                no_sca=True,
            )


class TestRowanIgnore:
    def test_ignored_files_not_scanned(self):
        with tempfile.TemporaryDirectory(prefix="rowan_ignore_") as tmpdir:
            root = Path(tmpdir)

            (root / ".rowanignore").write_text(
                "# Ignore generated code\ngenerated/\n",
                encoding="utf-8",
            )

            gen = root / "generated"
            gen.mkdir()
            (gen / "bad.py").write_text(
                "result = eval(user_input)\n",
                encoding="utf-8",
            )

            src = root / "src"
            src.mkdir()
            (src / "also_bad.py").write_text(
                "result = eval(user_input)\n",
                encoding="utf-8",
            )

            config = ScanConfig(
                target=root,
                no_taint=True,
                no_sca=True,
                languages=["python"],
                legacy_neuroscan=True,
            )
            result = ScanPipeline(config).run()

            ignored_findings = [f for f in result.findings if "generated" in f.file_path]
            assert len(ignored_findings) == 0, (
                f"Files in generated/ should be ignored: {ignored_findings}"
            )

            src_findings = [f for f in result.findings if "also_bad" in f.file_path]
            assert len(src_findings) > 0, "Non-ignored files should still be scanned"

    def test_negation_pattern_un_ignores(self):
        with tempfile.TemporaryDirectory(prefix="rowan_neg_") as tmpdir:
            root = Path(tmpdir)

            (root / ".rowanignore").write_text(
                "vendor/\n!vendor/important.py\n",
                encoding="utf-8",
            )

            vendor = root / "vendor"
            vendor.mkdir()
            (vendor / "junk.py").write_text("eval(x)\n", encoding="utf-8")
            (vendor / "important.py").write_text("eval(x)\n", encoding="utf-8")

            config = ScanConfig(
                target=root,
                no_taint=True,
                no_sca=True,
                languages=["python"],
                legacy_neuroscan=True,
            )
            result = ScanPipeline(config).run()

            junk_findings = [f for f in result.findings if "junk" in f.file_path]
            assert len(junk_findings) == 0, "vendor/junk.py should be ignored"

            important_findings = [f for f in result.findings if "important" in f.file_path]
            assert len(important_findings) > 0, (
                "vendor/important.py should NOT be ignored (negation pattern)"
            )


class TestFPSuppression:
    def test_http_source_keeps_severity(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            fp = Path(tmpdir) / "app.py"
            fp.write_text(
                "from flask import request\n"
                "@app.route('/x')\n"
                "def handler():\n"
                "    v = request.args.get('x')\n",
                encoding="utf-8",
            )
            findings = [
                Finding(
                    rule_id="TNT-INJ-001",
                    message="injection",
                    severity=Severity.HIGH,
                    category=Category.INJECTION,
                    file_path=str(fp),
                    start_line=4,
                    engine="opengrep",
                    taint_flow=TaintFlow(
                        source=TaintNode(
                            file_path=str(fp),
                            line=4,
                            snippet="v = request.args.get('x')",
                        ),
                        sink=TaintNode(file_path=str(fp), line=4),
                    ),
                ),
            ]
            ctx = type(
                "Ctx",
                (),
                {
                    "target_path": Path(tmpdir),
                    "config": ScanConfig(target=Path(tmpdir)),
                    "result": ScanResult(findings=findings),
                    "metadata": {},
                },
            )()
            EnrichmentPass().run(ctx)
            f = ctx.result.findings[0]
            assert f.severity == Severity.HIGH

    def test_env_source_capped_at_medium(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            fp = Path(tmpdir) / "worker.py"
            fp.write_text(
                "import os\nval = os.environ['KEY']\ndo_stuff(val)\n",
                encoding="utf-8",
            )
            findings = [
                Finding(
                    rule_id="TNT-INJ-002",
                    message="injection",
                    severity=Severity.HIGH,
                    category=Category.INJECTION,
                    file_path=str(fp),
                    start_line=3,
                    engine="opengrep",
                    taint_flow=TaintFlow(
                        source=TaintNode(
                            file_path=str(fp),
                            line=2,
                            snippet="val = os.environ['KEY']",
                        ),
                        sink=TaintNode(file_path=str(fp), line=3),
                    ),
                ),
            ]
            ctx = type(
                "Ctx",
                (),
                {
                    "target_path": Path(tmpdir),
                    "config": ScanConfig(target=Path(tmpdir)),
                    "result": ScanResult(findings=findings),
                    "metadata": {},
                },
            )()
            EnrichmentPass().run(ctx)
            f = ctx.result.findings[0]
            assert f.severity == Severity.MEDIUM

    def test_operator_config_deserialization_is_not_remote_critical(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            fp = Path(tmpdir) / "loader.py"
            fp.write_text(
                "import os\n"
                "import pickle\n"
                "path = os.environ['MODEL']\n"
                "obj = pickle.loads(open(path, 'rb').read())\n",
                encoding="utf-8",
            )
            findings = [
                Finding(
                    rule_id="TNT-DESER-001",
                    message="pickle deserialization",
                    severity=Severity.CRITICAL,
                    category=Category.DESERIALIZATION,
                    file_path=str(fp),
                    start_line=4,
                    engine="opengrep",
                    taint_flow=TaintFlow(
                        source=TaintNode(
                            file_path=str(fp),
                            line=3,
                            snippet="path = os.environ['MODEL']",
                        ),
                        sink=TaintNode(file_path=str(fp), line=4),
                    ),
                ),
            ]
            ctx = type(
                "Ctx",
                (),
                {
                    "target_path": Path(tmpdir),
                    "config": ScanConfig(target=Path(tmpdir)),
                    "result": ScanResult(findings=findings),
                    "metadata": {},
                },
            )()
            EnrichmentPass().run(ctx)
            f = ctx.result.findings[0]
            assert f.severity == Severity.MEDIUM
            assert f.metadata["source_origin"] == "env_variable"
            assert f.metadata["operator_controlled_source"] is True


@pytest.mark.skipif(
    not OpengrepAdapter().is_installed(),
    reason="Opengrep binary not installed; this test needs the default (non-legacy) engine path.",
)
class TestPatternNotFallbackDefaultPath:
    """Regression test for GitHub issue #92, run through the real pipeline
    on the actual default engine path (legacy_neuroscan=False) -- not a
    hand-rolled Opengrep invocation. Opengrep 1.22.0 silently ignores
    pattern-not-regex on rules whose only positive pattern is pattern-regex,
    so every pattern-not exclusion in the regex rulebase had no effect on
    this path until EnrichmentPass._apply_pattern_not_fallback re-applies
    them per-line as a fallback."""

    def test_commented_out_dangerous_line_produces_no_finding(self, tmp_path):
        (tmp_path / "config.py").write_text(
            "# trust_remote_code=True\nx = 1\n",
            encoding="utf-8",
        )
        config = ScanConfig(
            target=tmp_path,
            no_taint=True,
            no_sca=True,
            languages=["python"],
        )
        result = ScanPipeline(config).run()
        assert result.findings == [], (
            f"A fully commented-out line must not produce a finding on the "
            f"default engine path, got: {[(f.rule_id, f.start_line) for f in result.findings]}"
        )

    def test_rule_specific_safe_alternative_exclusion_applies(self, tmp_path):
        """NS-SSTI-001/102's ByteStream.from_string exclusion (a rule-specific
        pattern-not, not the generic comment/test skip) must also take effect
        on the default path."""
        (tmp_path / "converters.py").write_text(
            "source = ByteStream.from_string(json.dumps(data))\n",
            encoding="utf-8",
        )
        config = ScanConfig(
            target=tmp_path,
            no_taint=True,
            no_sca=True,
            languages=["python"],
        )
        result = ScanPipeline(config).run()
        ssti_findings = [f for f in result.findings if "SSTI" in f.rule_id]
        assert ssti_findings == [], (
            f"ByteStream.from_string must not trigger an SSTI finding, got: "
            f"{[(f.rule_id, f.start_line) for f in ssti_findings]}"
        )

    def test_safe_tarfile_filter_does_not_trigger_zip_slip(self, tmp_path):
        (tmp_path / "archive.py").write_text(
            "import tarfile\n"
            "with tarfile.open(fileobj=data, mode='r:gz') as archive:\n"
            "    archive.extractall(destination, filter='data')\n",
            encoding="utf-8",
        )
        config = ScanConfig(
            target=tmp_path,
            no_taint=True,
            no_sca=True,
            languages=["python"],
        )
        result = ScanPipeline(config).run()
        path_findings = [f for f in result.findings if f.rule_id == "NS-PATH-005"]
        assert path_findings == []

    def test_genuine_finding_still_fires_on_default_path(self, tmp_path):
        """Sanity check the fallback isn't over-suppressing: an uncommented,
        non-excluded dangerous line must still produce a finding."""
        (tmp_path / "vuln.py").write_text(
            "import pickle\nx = pickle.loads(y)\n",
            encoding="utf-8",
        )
        config = ScanConfig(
            target=tmp_path,
            no_taint=True,
            no_sca=True,
            languages=["python"],
        )
        result = ScanPipeline(config).run()
        assert any("DESER" in f.rule_id.upper() for f in result.findings), (
            f"Expected a deserialization finding, got: {[f.rule_id for f in result.findings]}"
        )
