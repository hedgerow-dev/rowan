"""Tests for deployment profiles and dependency reachability."""

from __future__ import annotations

import tempfile
from pathlib import Path

from rowan.core.findings import Category, Finding, Severity
from rowan.core.profiles import auto_detect_profile, get_disabled_categories
from rowan.core.vuln_functions import get_vulnerable_functions


class TestDeploymentProfiles:

    def test_server_disables_nothing(self):
        assert get_disabled_categories("server") == set()

    def test_library_disables_web_categories(self):
        disabled = get_disabled_categories("library")
        assert Category.SSRF in disabled
        assert Category.XSS in disabled
        assert Category.AUTH in disabled
        assert Category.INJECTION not in disabled

    def test_cli_disables_web_categories(self):
        disabled = get_disabled_categories("cli")
        assert Category.SSRF in disabled
        assert Category.XSS in disabled

    def test_desktop_keeps_xss(self):
        disabled = get_disabled_categories("desktop")
        assert Category.SSRF in disabled
        assert Category.XSS not in disabled

    def test_unknown_profile_disables_nothing(self):
        assert get_disabled_categories("unknown") == set()

    def test_auto_detect_flask(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            (root / "app.py").write_text(
                "from flask import Flask\napp = Flask(__name__)\n",
                encoding="utf-8",
            )
            assert auto_detect_profile(root) == "server"

    def test_auto_detect_no_framework(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            (root / "lib.py").write_text(
                "def add(a, b):\n    return a + b\n",
                encoding="utf-8",
            )
            assert auto_detect_profile(root) == "library"

    def test_auto_detect_uses_authoritative_candidates(self, tmp_path):
        """An excluded framework file must not widen a pipeline's scope."""
        framework = tmp_path / "app.py"
        framework.write_text("from flask import Flask\n", encoding="utf-8")
        library = tmp_path / "lib.py"
        library.write_text("def add(a, b): return a + b\n", encoding="utf-8")

        assert auto_detect_profile(tmp_path, candidates=[library]) == "library"

    def test_auto_detect_uses_all_language_inventory_without_walking(
        self, tmp_path, monkeypatch
    ):
        java = tmp_path / "Api.java"
        java.write_text(
            "import org.springframework.web.bind.annotation.RestController;\n",
            encoding="utf-8",
        )

        def unexpected_walk(self, pattern):
            raise AssertionError(f"unexpected repository walk: {self} {pattern}")

        monkeypatch.setattr(Path, "rglob", unexpected_walk)
        profile = auto_detect_profile(
            tmp_path,
            candidates_by_language={
                "python": (),
                "java": (java,),
                "kotlin": (),
                "go": (),
                "csharp": (),
            },
        )
        assert profile == "server"

    def test_auto_detect_empty_dir(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            assert auto_detect_profile(Path(tmpdir)) == "library"

    def test_auto_detect_spring_boot(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            (root / "Api.java").write_text(
                "package com.example;\n\n"
                "import org.springframework.web.bind.annotation.RestController;\n\n"
                "@RestController\n"
                "public class Api {\n"
                "}\n",
                encoding="utf-8",
            )
            assert auto_detect_profile(root) == "server"

    def test_auto_detect_go_gin(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            (root / "main.go").write_text(
                "package main\n\n"
                'import "github.com/gin-gonic/gin"\n\n'
                "func main() {\n"
                "    r := gin.Default()\n"
                "    r.Run()\n"
                "}\n",
                encoding="utf-8",
            )
            assert auto_detect_profile(root) == "server"

    def test_auto_detect_go_cli(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            (root / "main.go").write_text(
                "package main\n\n"
                'import "flag"\n\n'
                "func main() {\n"
                "    name := flag.String(\"name\", \"\", \"name to greet\")\n"
                "    flag.Parse()\n"
                "    println(*name)\n"
                "}\n",
                encoding="utf-8",
            )
            assert auto_detect_profile(root) == "cli"

    def test_auto_detect_ktor(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            (root / "Server.kt").write_text(
                "import io.ktor.server.application.*\n"
                "import io.ktor.server.engine.*\n\n"
                "fun main() {\n"
                "    embeddedServer(Netty, port = 8080).start()\n"
                "}\n",
                encoding="utf-8",
            )
            assert auto_detect_profile(root) == "server"

    def test_auto_detect_aspnetcore(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            (root / "WeatherController.cs").write_text(
                "using Microsoft.AspNetCore.Mvc;\n\n"
                "[ApiController]\n"
                "public class WeatherController : ControllerBase {\n"
                "}\n",
                encoding="utf-8",
            )
            assert auto_detect_profile(root) == "server"

    def test_auto_detect_java_library(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            (root / "Util.java").write_text(
                "package com.example;\n\n"
                "public class Util {\n"
                "    public static int add(int a, int b) { return a + b; }\n"
                "}\n",
                encoding="utf-8",
            )
            assert auto_detect_profile(root) == "library"


class TestProfileDeterminism:
    """#63: the auto profile looked at the first 20 Python files in directory
    enumeration order, so the same repository was "server" on one filesystem
    and "library" on another, and "library" demotes SSRF/XSS/AUTH to INFO."""

    def _repo(self, root: Path) -> list[Path]:
        utils = []
        for i in range(22):
            p = root / f"util_{i:02d}.py"
            p.write_text("def f(x):\n    return x\n", encoding="utf-8")
            utils.append(p)
        views = root / "views.py"
        views.write_text("from flask import Flask, request\napp = Flask(__name__)\n", encoding="utf-8")
        return [*utils, views]

    def test_profile_does_not_depend_on_file_order(self, tmp_path):
        files = self._repo(tmp_path)
        assert auto_detect_profile(tmp_path, files) == "server"
        assert auto_detect_profile(tmp_path, list(reversed(files))) == "server"
        assert auto_detect_profile(tmp_path, sorted(files)) == "server"

    def test_library_profile_does_not_demote_a_taint_flow(self, tmp_path):
        from rowan.config import ScanConfig
        from rowan.core.findings import ScanResult, TaintFlow, TaintNode
        from rowan.passes.base import ScanContext
        from rowan.passes.enrichment import EnrichmentPass

        def ssrf(flow):
            return Finding(
                rule_id="TNT-SSRF-002", message="m", severity=Severity.HIGH, category=Category.SSRF,
                file_path="a.py", start_line=3,
                taint_flow=TaintFlow(source=TaintNode("a.py", 2), sink=TaintNode("a.py", 3)) if flow else None,
            )

        ctx = ScanContext(config=ScanConfig(target=tmp_path, profile="library"), target_path=tmp_path, result=ScanResult())
        flowed, bare = ssrf(True), ssrf(False)
        EnrichmentPass()._apply_profile_filter([flowed, bare], ctx)

        assert flowed.severity == Severity.HIGH
        assert bare.severity == Severity.INFO


class TestDependencyReachability:

    def test_torch_functions(self):
        funcs = get_vulnerable_functions("torch")
        assert "torch.load" in funcs
        assert "load" in funcs

    def test_pyyaml_functions(self):
        funcs = get_vulnerable_functions("pyyaml")
        assert "yaml.load" in funcs

    def test_unknown_package(self):
        assert get_vulnerable_functions("some-unknown-pkg") == []

    def test_case_insensitive(self):
        assert get_vulnerable_functions("PyYAML") == get_vulnerable_functions("pyyaml")

    def test_reachable_finding(self):
        from rowan.passes.sca import SCAPass

        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            (root / "app.py").write_text(
                "import torch\nmodel = torch.load('model.pt')\n",
                encoding="utf-8",
            )
            findings = [
                Finding(
                    rule_id="SCA-CVE-2025-32434",
                    message="CVE in torch",
                    severity=Severity.HIGH,
                    category=Category.SUPPLY_CHAIN,
                    file_path="",
                    start_line=0,
                    engine="depguard",
                    metadata={"package": "torch", "ecosystem": "PyPI"},
                ),
            ]
            sca = SCAPass()
            sca._apply_reachability(findings, root)
            assert findings[0].metadata["reachability"] == "reachable"
            assert findings[0].severity == Severity.HIGH

    def test_unreachable_finding(self):
        from rowan.passes.sca import SCAPass

        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            (root / "app.py").write_text(
                "import torch\nx = torch.tensor([1, 2, 3])\n",
                encoding="utf-8",
            )
            findings = [
                Finding(
                    rule_id="SCA-CVE-2025-32434",
                    message="CVE in torch",
                    severity=Severity.HIGH,
                    category=Category.SUPPLY_CHAIN,
                    file_path="",
                    start_line=0,
                    engine="depguard",
                    metadata={"package": "torch", "ecosystem": "PyPI"},
                ),
            ]
            sca = SCAPass()
            sca._apply_reachability(findings, root)
            # A missing application-level call is indeterminate: dynamic
            # dispatch, framework callbacks and dependency code are outside
            # this narrow index and must not be asserted safe.
            assert findings[0].metadata["reachability"] == "unknown"
            assert findings[0].severity == Severity.HIGH


class TestCategorySanitizers:

    def test_sanitizers_exist_for_key_categories(self):
        from rowan.core.sanitizers import get_sanitizers_for_category

        for cat in [
            Category.INJECTION, Category.COMMAND_INJECTION,
            Category.XSS, Category.SSTI, Category.DESERIALIZATION,
            Category.SSRF, Category.PATH_TRAVERSAL,
        ]:
            patterns = get_sanitizers_for_category(cat)
            assert len(patterns) > 0, f"No sanitizers for {cat}"

    def test_xss_sanitizers_not_in_sqli(self):
        from rowan.core.sanitizers import CATEGORY_SANITIZERS

        xss_pats = set(CATEGORY_SANITIZERS.get(Category.XSS, []))
        sqli_pats = set(CATEGORY_SANITIZERS.get(Category.INJECTION, []))
        xss_only = xss_pats - sqli_pats
        assert len(xss_only) > 0, "XSS should have sanitizers not in SQLI"

    def test_compiled_patterns_are_regex(self):
        import re

        from rowan.core.sanitizers import get_sanitizers_for_category

        patterns = get_sanitizers_for_category(Category.DESERIALIZATION)
        for p in patterns:
            assert isinstance(p, re.Pattern)
