"""Tests for SCAPass dependency-manifest parsers.

_find_dep_files detects ~16 manifest formats, but _extract_packages used to
only parse 3 of them (requirements.txt, package.json, pyproject.toml) --
every other detected file (Pipfile, Cargo.toml, go.mod, Gemfile.lock, ...)
was silently skipped, producing false-negative CVE coverage for those
ecosystems. This adds parsers for the remaining formats and covers the OSV
querybatch chunking that keeps a single large lockfile from exceeding the
API's per-request cap.
"""

from __future__ import annotations

import threading
import time
from unittest.mock import MagicMock, patch

from rowan.passes.sca import OSV_BATCH_CHUNK_SIZE, SCAPass


def _write(tmp_path, name: str, content: str):
    p = tmp_path / name
    p.write_text(content, encoding="utf-8")
    return p


class TestPipfile:
    def test_parses_packages_and_dev_packages(self, tmp_path):
        p = _write(tmp_path, "Pipfile", (
            "[packages]\n"
            'requests = "*"\n'
            'flask = ">=2.0"\n\n'
            "[dev-packages]\n"
            'pytest = "*"\n'
        ))
        pkgs = SCAPass()._extract_packages(p)
        names = {pk["name"] for pk in pkgs}
        assert names == {"requests", "flask", "pytest"}
        assert all(pk["ecosystem"] == "PyPI" for pk in pkgs)


class TestFindingProvenance:
    def test_dependency_finding_uses_manifest_as_file_location(self, tmp_path):
        manifest = _write(tmp_path, "requirements.txt", "requests==2.31.0\n")
        sca = SCAPass()
        package = {
            "name": "requests",
            "version": "2.31.0",
            "ecosystem": "PyPI",
            "direct": True,
            "source_file": str(manifest),
        }
        advisory = {
            "id": "CVE-2024-9999",
            "summary": "test advisory",
            "affected": [],
            "severity": [{
                "type": "CVSS_V3",
                "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            }],
        }
        with patch.object(sca, "_query_osv_batch", return_value=[{"vulns": [advisory]}]), patch.object(
            sca, "_hydrate_vuln_details"
        ):
            findings, dropped = sca._check_vulnerabilities([package])

        assert dropped == 0
        assert len(findings) == 1
        assert findings[0].file_path == str(manifest)
        assert findings[0].start_line == 0
        assert findings[0].metadata["source_file"] == str(manifest)


class TestPipfileLock:
    def test_parses_default_and_develop(self, tmp_path):
        p = _write(tmp_path, "Pipfile.lock", (
            '{"default": {"requests": {"version": "==2.28.0"}}, '
            '"develop": {"pytest": {"version": "==7.0.0"}}}'
        ))
        pkgs = SCAPass()._extract_packages(p)
        by_name = {pk["name"]: pk for pk in pkgs}
        assert by_name["requests"]["version"] == "2.28.0"
        assert by_name["pytest"]["ecosystem"] == "PyPI"


class TestPoetryLock:
    def test_parses_package_entries(self, tmp_path):
        p = _write(tmp_path, "poetry.lock", (
            '[[package]]\nname = "requests"\nversion = "2.28.0"\n\n'
            '[[package]]\nname = "flask"\nversion = "2.2.0"\n'
        ))
        pkgs = SCAPass()._extract_packages(p)
        names = {pk["name"] for pk in pkgs}
        assert names == {"requests", "flask"}


class TestUvLock:
    def test_parses_package_entries(self, tmp_path):
        p = _write(tmp_path, "uv.lock", (
            '[[package]]\nname = "requests"\nversion = "2.28.0"\n\n'
            '[[package]]\nname = "flask"\nversion = "2.2.0"\n'
        ))
        pkgs = SCAPass()._extract_packages(p)
        names = {pk["name"] for pk in pkgs}
        assert names == {"requests", "flask"}
        assert all(pk["ecosystem"] == "PyPI" for pk in pkgs)


class TestPreferLockfiles:
    def test_skips_pyproject_toml_when_uv_lock_present(self, tmp_path):
        pyproject = _write(tmp_path, "pyproject.toml", "[project]\nname = \"x\"\n")
        uv_lock = _write(tmp_path, "uv.lock", '[[package]]\nname = "requests"\nversion = "2.28.0"\n')
        kept = SCAPass()._prefer_lockfiles([pyproject, uv_lock])
        assert kept == [uv_lock]

    def test_skips_pyproject_toml_when_poetry_lock_present(self, tmp_path):
        pyproject = _write(tmp_path, "pyproject.toml", "[project]\nname = \"x\"\n")
        poetry_lock = _write(tmp_path, "poetry.lock", '[[package]]\nname = "requests"\nversion = "2.28.0"\n')
        kept = SCAPass()._prefer_lockfiles([pyproject, poetry_lock])
        assert kept == [poetry_lock]

    def test_keeps_pyproject_toml_when_no_lockfile_present(self, tmp_path):
        pyproject = _write(tmp_path, "pyproject.toml", "[project]\nname = \"x\"\n")
        kept = SCAPass()._prefer_lockfiles([pyproject])
        assert kept == [pyproject]

    def test_keeps_manifest_when_lockfile_is_malformed(self, tmp_path):
        pyproject = _write(tmp_path, "pyproject.toml", (
            "[project]\nname = \"x\"\ndependencies = [\"requests==2.0\"]\n"
        ))
        lockfile = _write(tmp_path, "uv.lock", "not valid toml [[")
        kept = SCAPass()._prefer_lockfiles([pyproject, lockfile])
        assert kept == [pyproject, lockfile]

    def test_does_not_cross_directories(self, tmp_path):
        sub = tmp_path / "backend"
        sub.mkdir()
        pyproject = _write(sub, "pyproject.toml", "[project]\nname = \"x\"\n")
        _write(tmp_path, "uv.lock", '[[package]]\nname = "requests"\nversion = "2.28.0"\n')
        kept = SCAPass()._prefer_lockfiles([pyproject])
        assert kept == [pyproject]


class TestPackageLockJson:
    def test_parses_v2_packages_key(self, tmp_path):
        p = _write(tmp_path, "package-lock.json", (
            '{"packages": {"": {}, "node_modules/lodash": {"version": "4.17.21"}}}'
        ))
        pkgs = SCAPass()._extract_packages(p)
        by_name = {pk["name"]: pk for pk in pkgs}
        assert by_name["lodash"]["version"] == "4.17.21"
        assert by_name["lodash"]["ecosystem"] == "npm"
        assert by_name["lodash"]["direct"] is True

    def test_parses_v1_dependencies_key(self, tmp_path):
        p = _write(tmp_path, "package-lock.json", (
            '{"dependencies": {"lodash": {"version": "4.17.21"}}}'
        ))
        pkgs = SCAPass()._extract_packages(p)
        by_name = {pk["name"]: pk for pk in pkgs}
        assert by_name["lodash"]["version"] == "4.17.21"
        assert by_name["lodash"]["ecosystem"] == "npm"

    def test_v1_uses_package_json_to_classify_transitives(self, tmp_path):
        _write(tmp_path, "package.json", '{"dependencies": {"express": "4.18.0"}}')
        p = _write(tmp_path, "package-lock.json", (
            '{"dependencies": {"express": {"version": "4.18.0"}, '
            '"qs": {"version": "6.5.0"}}}'
        ))
        by_name = {pk["name"]: pk for pk in SCAPass()._extract_packages(p)}
        assert by_name["express"]["direct"] is True
        assert by_name["qs"]["direct"] is False

    def test_parses_npm_shrinkwrap_with_same_lockfile_rules(self, tmp_path):
        p = _write(tmp_path, "npm-shrinkwrap.json", (
            '{"packages": {"": {"dependencies": {"lodash": "4.17.21"}}, '
            '"node_modules/lodash": {"version": "4.17.21"}}}'
        ))
        by_name = {pk["name"]: pk for pk in SCAPass()._extract_packages(p)}
        assert by_name["lodash"]["version"] == "4.17.21"

    def test_malformed_dependency_file_is_reported_by_pipeline(self, tmp_path):
        p = _write(tmp_path, "package.json", "{not-json")
        context = MagicMock(target_path=tmp_path)
        result = SCAPass().run(context)
        assert result.metadata["dependency_files"] == [{"path": str(p), "status": "unparsed"}]
        assert "sca" in result.degraded_passes

    def test_package_json_without_dependencies_does_not_degrade(self, tmp_path):
        """gogs ships `{"name": "gogs", "private": true, "packageManager": ...}`.
        Valid JSON with nothing to check is not a parse failure."""
        p = _write(tmp_path, "package.json", '{"name": "gogs", "private": true}')
        context = MagicMock(target_path=tmp_path)
        result = SCAPass().run(context)
        assert result.metadata["dependency_files"] == [
            {"path": str(p), "status": "no-dependencies"}
        ]
        assert "sca" not in result.degraded_passes

    def test_nuget_lockfile_with_empty_framework_map_does_not_degrade(self, tmp_path):
        """bitwarden/server: 26 packages.lock.json files shaped like this."""
        p = _write(tmp_path, "packages.lock.json", '{"version": 1, "dependencies": {"net10.0": {}}}')
        context = MagicMock(target_path=tmp_path)
        result = SCAPass().run(context)
        assert result.metadata["dependency_files"] == [
            {"path": str(p), "status": "no-dependencies"}
        ]
        assert "sca" not in result.degraded_passes

    def test_csproj_without_package_references_does_not_degrade(self, tmp_path):
        """bitwarden/server: 18 csproj files with only a FrameworkReference."""
        p = _write(tmp_path, "HttpExtensions.csproj", (
            '<Project Sdk="Microsoft.NET.Sdk"><ItemGroup>'
            '<FrameworkReference Include="Microsoft.AspNetCore.App" />'
            "</ItemGroup></Project>"
        ))
        context = MagicMock(target_path=tmp_path)
        result = SCAPass().run(context)
        assert result.metadata["dependency_files"] == [
            {"path": str(p), "status": "no-dependencies"}
        ]
        assert "sca" not in result.degraded_passes

    def test_bom_pom_without_dependencies_does_not_degrade(self, tmp_path):
        """javalin-bom/pom.xml only has dependencyManagement."""
        p = _write(tmp_path, "pom.xml", (
            '<project xmlns="http://maven.apache.org/POM/4.0.0">'
            "<groupId>io.javalin</groupId><artifactId>javalin-bom</artifactId>"
            "<dependencyManagement><dependencies><dependency>"
            "<groupId>io.javalin</groupId><artifactId>javalin</artifactId>"
            "<version>6.0.0</version></dependency></dependencies></dependencyManagement>"
            "</project>"
        ))
        context = MagicMock(target_path=tmp_path)
        result = SCAPass().run(context)
        assert result.metadata["dependency_files"] == [
            {"path": str(p), "status": "no-dependencies"}
        ]
        assert "sca" not in result.degraded_passes


class TestYarnLock:
    def test_parses_version_after_selector(self, tmp_path):
        p = _write(tmp_path, "yarn.lock", (
            'lodash@^4.17.0:\n  version "4.17.21"\n  resolved "https://x"\n\n'
            'left-pad@^1.0.0, left-pad@^1.3.0:\n  version "1.3.0"\n'
        ))
        pkgs = SCAPass()._extract_packages(p)
        by_name = {pk["name"]: pk for pk in pkgs}
        assert by_name["lodash"]["version"] == "4.17.21"
        assert by_name["left-pad"]["version"] == "1.3.0"


class TestPnpmLock:
    def test_parses_v6_packages_and_direct_names(self, tmp_path):
        _write(tmp_path, "package.json", '{"dependencies": {"express": "4.18.0"}}')
        p = _write(tmp_path, "pnpm-lock.yaml", (
            "lockfileVersion: '6.0'\n"
            "packages:\n"
            "  /express@4.18.0:\n"
            "    resolution: {integrity: sha512-x}\n"
            "  /qs@6.5.0:\n"
            "    resolution: {integrity: sha512-y}\n"
        ))
        by_name = {pkg["name"]: pkg for pkg in SCAPass()._extract_packages(p)}
        assert by_name["express"]["version"] == "4.18.0"
        assert by_name["express"]["direct"] is True
        assert by_name["qs"]["direct"] is False


class TestGradleKotlin:
    def test_parses_common_coordinate_notation(self, tmp_path):
        p = _write(tmp_path, "build.gradle.kts", (
            'dependencies { implementation("org.example:widget:1.2.3") }\n'
        ))
        pkgs = SCAPass()._extract_packages(p)
        assert pkgs == [{
            "name": "org.example:widget", "version": "1.2.3",
            "ecosystem": "Maven", "direct": True,
        }]

    def test_parses_gradle_map_notation(self, tmp_path):
        p = _write(tmp_path, "build.gradle", (
            "dependencies { implementation group: 'org.example', "
            "name: 'widget', version: '1.2.3' }\n"
        ))
        assert SCAPass()._extract_packages(p)[0]["name"] == "org.example:widget"

    def test_two_part_coordinate_is_unpinned(self, tmp_path):
        """ktor-samples: version comes from a BOM or the Ktor plugin."""
        p = _write(tmp_path, "build.gradle.kts", (
            'plugins { id("org.jetbrains.kotlin.jvm") version "2.4.10" }\n'
            'repositories { maven { url = uri("https://maven.pkg.jetbrains.space/x") } }\n'
            "dependencies {\n"
            '    implementation("io.ktor:ktor-server-core-jvm")\n'
            '    implementation("org.example:widget:1.2.3")\n'
            "}\n"
        ))
        pkgs = SCAPass()._extract_packages(p)
        assert pkgs == [
            {"name": "io.ktor:ktor-server-core-jvm", "version": "*", "ecosystem": "Maven", "direct": True},
            {"name": "org.example:widget", "version": "1.2.3", "ecosystem": "Maven", "direct": True},
        ]

    def test_property_version_resolved_from_gradle_properties(self, tmp_path):
        _write(tmp_path, "gradle.properties", "kotlin_version=2.4.10\nlogback_version=1.5.21\n")
        sub = tmp_path / "app"
        sub.mkdir()
        p = _write(sub, "build.gradle.kts", (
            "dependencies {\n"
            '    implementation("ch.qos.logback:logback-classic:$logback_version")\n'
            '    testImplementation("org.jetbrains.kotlin:kotlin-test-junit:${kotlin_version}")\n'
            '    implementation("org.example:widget:$missing_version")\n'
            "}\n"
        ))
        pkgs = SCAPass()._extract_packages(p)
        by_name = {pk["name"]: pk["version"] for pk in pkgs}
        assert by_name == {
            "ch.qos.logback:logback-classic": "1.5.21",
            "org.jetbrains.kotlin:kotlin-test-junit": "2.4.10",
            "org.example:widget": "*",
        }

    def test_catalog_alias_only_build_file_does_not_degrade(self, tmp_path):
        p = _write(tmp_path, "build.gradle.kts", (
            'plugins { alias(libs.plugins.kotlin.jvm) }\n'
            "dependencies {\n"
            "    implementation(libs.ktor.server.core)\n"
            '    implementation(project(":shared"))\n'
            "}\n"
        ))
        context = MagicMock(target_path=tmp_path)
        result = SCAPass().run(context)
        assert result.metadata["dependency_files"] == [
            {"path": str(p), "status": "no-dependencies"}
        ]
        assert "sca" not in result.degraded_passes


class TestGradleVersionCatalog:
    def test_parses_literal_and_referenced_library_versions(self, tmp_path):
        p = _write(tmp_path, "libs.versions.toml", (
            '[versions]\nktor = "2.3.0"\n'
            '[libraries]\n'
            'ktor-core = { module = "io.ktor:ktor-client-core", version.ref = "ktor" }\n'
            'slf4j = { module = "org.slf4j:slf4j-api", version = "2.0.9" }\n'
            'bundle-only = { name = "ignored" }\n'
        ))
        by_name = {pkg["name"]: pkg for pkg in SCAPass()._extract_packages(p)}
        assert by_name["io.ktor:ktor-client-core"]["version"] == "2.3.0"
        assert by_name["org.slf4j:slf4j-api"]["version"] == "2.0.9"
        assert "bundle-only" not in by_name

    def test_skips_unresolved_or_malformed_library_entries(self, tmp_path):
        p = _write(tmp_path, "libs.versions.toml", (
            '[libraries]\n'
            'missing-version = { module = "a:b" }\n'
            'invalid-module = { module = "a:b:c", version = "1" }\n'
        ))
        assert SCAPass()._extract_packages(p) == []


class TestNuGetPackagesConfig:
    def test_parses_packages_config(self, tmp_path):
        p = _write(tmp_path, "packages.config", (
            '<packages><package id="Newtonsoft.Json" version="13.0.1" />'
            '</packages>'
        ))
        assert SCAPass()._extract_packages(p) == [{
            "name": "Newtonsoft.Json", "version": "13.0.1",
            "ecosystem": "NuGet", "direct": True,
        }]

    def test_parses_csproj_package_references(self, tmp_path):
        p = _write(tmp_path, "app.csproj", (
            '<Project><ItemGroup>'
            '<PackageReference Include="Newtonsoft.Json" Version="13.0.1" />'
            '<PackageReference Include="Serilog"><Version>3.0.0</Version></PackageReference>'
            '</ItemGroup></Project>'
        ))
        by_name = {pkg["name"]: pkg for pkg in SCAPass()._extract_packages(p)}
        assert by_name["Newtonsoft.Json"]["version"] == "13.0.1"
        assert by_name["Serilog"]["version"] == "3.0.0"

    def test_parses_packages_lock_json_direct_and_transitive(self, tmp_path):
        p = _write(tmp_path, "packages.lock.json", (
            '{"version": 1, "dependencies": {"net8.0": {'
            '"Newtonsoft.Json": {"type": "Direct", "requested": "[13, 14)", "resolved": "13.0.3"},'
            '"System.Text.Json": {"type": "Transitive", "resolved": "8.0.4"}'
            '}}}'
        ))
        by_name = {pkg["name"]: pkg for pkg in SCAPass()._extract_packages(p)}
        assert by_name["Newtonsoft.Json"]["direct"] is True
        assert by_name["System.Text.Json"]["direct"] is False
        assert by_name["System.Text.Json"]["version"] == "8.0.4"

    def test_merges_packages_lock_frameworks(self, tmp_path):
        p = _write(tmp_path, "packages.lock.json", (
            '{"dependencies": {"net8.0": {"Example": {"resolved": "1.2.3"}}, '
            '"netstandard2.0": {"Example": {"type": "Direct", "resolved": "1.2.3"}}}}'
        ))
        pkgs = SCAPass()._extract_packages(p)
        assert len(pkgs) == 1
        assert pkgs[0]["direct"] is True
        assert "net8.0" in pkgs[0]["frameworks"] and "netstandard2.0" in pkgs[0]["frameworks"]


class TestComposerDevDependencies:
    def test_parses_require_dev(self, tmp_path):
        p = _write(tmp_path, "composer.json", (
            '{"require": {"monolog/monolog": "^2.0"}, '
            '"require-dev": {"phpunit/phpunit": "^10.0"}}'
        ))
        names = {pkg["name"] for pkg in SCAPass()._extract_packages(p)}
        assert names == {"monolog/monolog", "phpunit/phpunit"}


class TestMavenPom:
    def test_excludes_dependency_management_catalog(self, tmp_path):
        p = _write(tmp_path, "pom.xml", (
            '<project><dependencyManagement><dependencies>'
            '<dependency><groupId>org.example</groupId><artifactId>managed</artifactId>'
            '<version>1.0.0</version></dependency></dependencies></dependencyManagement>'
            '<dependencies><dependency><groupId>org.example</groupId>'
            '<artifactId>runtime</artifactId><version>2.0.0</version></dependency>'
            '</dependencies></project>'
        ))
        pkgs = SCAPass()._extract_packages(p)
        assert [pkg["name"] for pkg in pkgs] == ["org.example:runtime"]


class TestGoMod:
    def test_parses_require_block(self, tmp_path):
        p = _write(tmp_path, "go.mod", (
            "module example.com/foo\n\ngo 1.21\n\n"
            "require (\n"
            "\tgithub.com/pkg/errors v0.9.1\n"
            "\tgolang.org/x/text v0.3.7 // indirect\n"
            ")\n"
        ))
        pkgs = SCAPass()._extract_packages(p)
        by_name = {pk["name"]: pk for pk in pkgs}
        assert by_name["github.com/pkg/errors"]["version"] == "v0.9.1"
        assert by_name["golang.org/x/text"]["ecosystem"] == "Go"

    def test_parses_single_line_require(self, tmp_path):
        p = _write(tmp_path, "go.mod", "module foo\n\nrequire github.com/pkg/errors v0.9.1\n")
        pkgs = SCAPass()._extract_packages(p)
        assert pkgs == [{
            "name": "github.com/pkg/errors", "version": "v0.9.1", "ecosystem": "Go", "direct": True,
        }]

    def test_applies_remote_replace_version(self, tmp_path):
        p = _write(tmp_path, "go.mod", (
            "module example.com/foo\n\n"
            "require github.com/old/module v1.2.0\n"
            "replace github.com/old/module => github.com/new/module v1.3.0\n"
        ))
        assert SCAPass()._extract_packages(p) == [{
            "name": "github.com/new/module", "version": "v1.3.0",
            "ecosystem": "Go", "direct": True,
        }]

    def test_omits_local_replace(self, tmp_path):
        p = _write(tmp_path, "go.mod", (
            "module example.com/foo\n\n"
            "require github.com/old/module v1.2.0\n"
            "replace github.com/old/module => ../local-module\n"
        ))
        assert SCAPass()._extract_packages(p) == []

    def test_go_work_inventories_bounded_local_modules(self, tmp_path):
        module = tmp_path / "services" / "api"
        module.mkdir(parents=True)
        _write(module, "go.mod", (
            "module example.com/api\n\n"
            "require golang.org/x/text v0.3.7\n"
        ))
        p = _write(tmp_path, "go.work", "go 1.21\n\nuse (\n ./services/api\n)\n")
        assert SCAPass()._extract_packages(p) == [{
            "name": "golang.org/x/text", "version": "v0.3.7",
            "ecosystem": "Go", "direct": True,
        }]

    def test_go_work_ignores_paths_outside_workspace(self, tmp_path):
        p = _write(tmp_path, "go.work", "go 1.21\nuse ../outside\n")
        assert SCAPass()._extract_packages(p) == []


class TestCargo:
    def test_cargo_workspace_dependencies_are_inventoried(self, tmp_path):
        p = _write(tmp_path, "Cargo.toml", (
            "[workspace]\nmembers = [\"crates/app\"]\n\n"
            "[workspace.dependencies]\nserde = { version = \"1.0\", features = [\"derive\"] }\n"
            "tokio = \"1.36\"\n"
        ))
        pkgs = SCAPass()._extract_packages(p)
        by_name = {pkg["name"]: pkg for pkg in pkgs}
        assert by_name["serde"]["version"] == "1.0"
        assert by_name["tokio"]["version"] == "1.36"
        assert all(pkg["direct"] for pkg in pkgs)

    def test_cargo_toml_parses_dependencies(self, tmp_path):
        p = _write(tmp_path, "Cargo.toml", (
            '[dependencies]\nserde = "1.0"\ntokio = { version = "1", features = ["full"] }\n'
        ))
        pkgs = SCAPass()._extract_packages(p)
        by_name = {pk["name"]: pk for pk in pkgs}
        assert by_name["serde"]["version"] == "1.0"
        assert by_name["tokio"]["version"] == "1"
        assert by_name["serde"]["ecosystem"] == "crates.io"

    def test_cargo_lock_parses_packages(self, tmp_path):
        p = _write(tmp_path, "Cargo.lock", '[[package]]\nname = "serde"\nversion = "1.0.150"\n')
        pkgs = SCAPass()._extract_packages(p)
        assert len(pkgs) == 1
        assert pkgs[0]["name"] == "serde"
        assert pkgs[0]["version"] == "1.0.150"
        assert pkgs[0]["ecosystem"] == "crates.io"


class TestGemfile:
    def test_gemfile_parses_gem_declarations(self, tmp_path):
        p = _write(tmp_path, "Gemfile", "gem 'rails', '~> 7.0'\ngem \"rack\"\n")
        pkgs = SCAPass()._extract_packages(p)
        by_name = {pk["name"]: pk for pk in pkgs}
        assert by_name["rails"]["version"] == "~> 7.0"
        assert by_name["rack"]["version"] == "*"

    def test_gemfile_lock_parses_top_level_specs_only(self, tmp_path):
        p = _write(tmp_path, "Gemfile.lock", (
            "GEM\n  remote: https://rubygems.org/\n  specs:\n"
            "    actionpack (7.0.4)\n"
            "      actionview (= 7.0.4)\n"
            "    actionview (7.0.4)\n"
            "\nPLATFORMS\n  ruby\n"
        ))
        pkgs = SCAPass()._extract_packages(p)
        names = {pk["name"] for pk in pkgs}
        # Only the 4-space-indented top-level specs, not their nested deps.
        assert names == {"actionpack", "actionview"}
        by_name = {pk["name"]: pk for pk in pkgs}
        assert by_name["actionpack"]["version"] == "7.0.4"
        assert by_name["actionpack"]["ecosystem"] == "RubyGems"


class TestPomXml:
    def test_parses_dependency_elements(self, tmp_path):
        p = _write(tmp_path, "pom.xml", (
            "<project>\n<dependencies>\n<dependency>\n"
            "<groupId>com.fasterxml.jackson.core</groupId>\n"
            "<artifactId>jackson-databind</artifactId>\n"
            "<version>2.13.0</version>\n"
            "</dependency>\n</dependencies>\n</project>\n"
        ))
        pkgs = SCAPass()._extract_packages(p)
        assert pkgs == [{
            "name": "com.fasterxml.jackson.core:jackson-databind",
            "version": "2.13.0",
            "ecosystem": "Maven",
            "direct": True,
        }]

    def test_malformed_xml_returns_empty_not_raises(self, tmp_path):
        p = _write(tmp_path, "pom.xml", "<project><unterminated>\n")
        pkgs = SCAPass()._extract_packages(p)
        assert pkgs == []

    def test_xxe_billion_laughs_is_rejected_not_expanded(self, tmp_path):
        """defusedxml must reject entity-expansion attacks from a scanned
        (untrusted) pom.xml instead of expanding them."""
        p = _write(tmp_path, "pom.xml", (
            '<?xml version="1.0"?>\n'
            "<!DOCTYPE lolz [\n"
            '  <!ENTITY lol "lol">\n'
            '  <!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">\n'
            "]>\n"
            "<project><dependencies><dependency>"
            "<groupId>&lol2;</groupId><artifactId>x</artifactId><version>1</version>"
            "</dependency></dependencies></project>\n"
        ))
        pkgs = SCAPass()._extract_packages(p)
        assert pkgs == []


class TestBuildGradle:
    def test_parses_string_notation_dependencies(self, tmp_path):
        p = _write(tmp_path, "build.gradle", (
            "dependencies {\n"
            "    implementation 'com.squareup.okhttp3:okhttp:4.10.0'\n"
            '    testImplementation "junit:junit:4.13.2"\n'
            "}\n"
        ))
        pkgs = SCAPass()._extract_packages(p)
        names = {pk["name"] for pk in pkgs}
        assert "com.squareup.okhttp3:okhttp" in names
        assert "junit:junit" in names


class TestComposer:
    def test_composer_json_parses_require(self, tmp_path):
        p = _write(tmp_path, "composer.json", '{"require": {"monolog/monolog": "^2.0", "php": ">=8.0"}}')
        pkgs = SCAPass()._extract_packages(p)
        assert pkgs == [{
            "name": "monolog/monolog", "version": "^2.0", "ecosystem": "Packagist", "direct": True,
        }]

    def test_composer_lock_parses_packages(self, tmp_path):
        p = _write(tmp_path, "composer.lock", '{"packages": [{"name": "monolog/monolog", "version": "2.8.0"}]}')
        pkgs = SCAPass()._extract_packages(p)
        assert len(pkgs) == 1
        assert pkgs[0]["name"] == "monolog/monolog"
        assert pkgs[0]["version"] == "2.8.0"
        assert pkgs[0]["ecosystem"] == "Packagist"
        assert pkgs[0]["direct"] is True  # no companion composer.json in this fixture dir


class TestUnknownDetectedFileHasNoParser:
    def test_returns_empty_list_not_error(self, tmp_path):
        # Simulates a detected-but-genuinely-unparseable manifest shape.
        p = _write(tmp_path, "unexpected.lock", "garbage")
        # _extract_packages dispatches purely on filename; an unrecognized
        # name (one that wouldn't even match REQUIREMENT_PATTERNS in
        # practice) must not raise.
        pkgs = SCAPass()._extract_packages(p)
        assert pkgs == []


class TestOsvBatchChunking:
    def test_pagination_only_requeries_active_packages(self):
        sca = SCAPass()
        packages = [
            {"name": "paginated", "version": "1.0", "ecosystem": "PyPI"},
            {"name": "complete", "version": "1.0", "ecosystem": "PyPI"},
        ]
        responses = iter([
            {"results": [
                {"vulns": [{"id": "VULN-1"}], "next_page_token": "page-2"},
                {"vulns": [{"id": "VULN-2"}]},
            ]},
            {"results": [{"vulns": [{"id": "VULN-3"}], "next_page_token": "page-3"}]},
            {"results": [{"vulns": [{"id": "VULN-4"}]}]},
        ])

        def fake_post(*_args, **_kwargs):
            response = MagicMock()
            response.raise_for_status.return_value = None
            response.json.return_value = next(responses)
            return response

        with patch("httpx.post", side_effect=fake_post) as mock_post:
            results = sca._query_osv_batch(packages)

        assert results is not None
        assert [v["id"] for v in results[0]["vulns"]] == ["VULN-1", "VULN-3", "VULN-4"]
        assert [v["id"] for v in results[1]["vulns"]] == ["VULN-2"]
        assert [len(call.kwargs["json"]["queries"]) for call in mock_post.call_args_list] == [2, 1, 1]
        assert [
            query.get("page_token") for query in mock_post.call_args_list[1].kwargs["json"]["queries"]
        ] == ["page-2"]

    def test_pagination_repeated_token_marks_chunk_unchecked(self):
        sca = SCAPass()
        package = [{"name": "stuck", "version": "1.0", "ecosystem": "PyPI"}]

        def fake_post(*_args, **_kwargs):
            response = MagicMock()
            response.raise_for_status.return_value = None
            response.json.return_value = {
                "results": [{"vulns": [], "next_page_token": "same-token"}]
            }
            return response

        with patch("httpx.post", side_effect=fake_post), patch("time.sleep"):
            assert sca._query_osv_batch(package) is None

    def test_large_package_list_is_split_into_chunks(self):
        sca = SCAPass()
        packages = [{"name": f"pkg{i}", "version": "1.0", "ecosystem": "PyPI"} for i in range(OSV_BATCH_CHUNK_SIZE + 50)]

        def fake_post(*_args, json, **_kwargs):
            response = MagicMock()
            response.raise_for_status.return_value = None
            response.json.return_value = {
                "results": [{"vulns": []} for _ in json["queries"]]
            }
            return response

        with patch("httpx.post", side_effect=fake_post) as mock_post:
            _, dropped = sca._check_vulnerabilities(packages)

        assert dropped == 0
        assert mock_post.call_count == 2
        first_call_queries = mock_post.call_args_list[0].kwargs["json"]["queries"]
        second_call_queries = mock_post.call_args_list[1].kwargs["json"]["queries"]
        assert len(first_call_queries) == OSV_BATCH_CHUNK_SIZE
        assert len(second_call_queries) == 50

    def test_small_package_list_is_a_single_request(self):
        sca = SCAPass()
        packages = [{"name": "requests", "version": "2.0", "ecosystem": "PyPI"}]

        fake_response = MagicMock()
        fake_response.raise_for_status.return_value = None
        fake_response.json.return_value = {"results": [{"vulns": []}]}

        with patch("httpx.post", return_value=fake_response) as mock_post:
            _, dropped = sca._check_vulnerabilities(packages)

        assert dropped == 0
        assert mock_post.call_count == 1

    def test_one_chunk_failing_does_not_misalign_another_chunks_results(self):
        """If chunk 1 fails after retries, chunk 2's results must still pair
        with chunk 2's packages, not get shifted."""
        sca = SCAPass()
        chunk_size = OSV_BATCH_CHUNK_SIZE
        packages = (
            [{"name": f"bad{i}", "version": "1.0", "ecosystem": "PyPI"} for i in range(chunk_size)]
            + [{"name": "vulnerable-pkg", "version": "1.0", "ecosystem": "PyPI"}]
        )

        call_count = 0

        def fake_post(*args, **kwargs):
            nonlocal call_count
            call_count += 1
            queries = kwargs["json"]["queries"]
            resp = MagicMock()
            resp.raise_for_status.return_value = None
            if len(queries) == chunk_size:
                raise __import__("httpx").ConnectError("boom")
            resp.json.return_value = {
                "results": [{"vulns": [{"id": "CVE-2099-0001", "summary": "test vuln"}]}]
            }
            return resp

        with patch("httpx.post", side_effect=fake_post), patch("time.sleep"):
            findings, dropped = sca._check_vulnerabilities(packages)

        assert len(findings) == 1
        assert findings[0].metadata["package"] == "vulnerable-pkg"
        assert dropped == chunk_size


class TestDroppedChunksMarkScanDegraded:
    """#115: an exhausted-retries OSV chunk must surface as a degraded pass,
    not silently present an incomplete scan as clean."""

    @staticmethod
    def _make_context(tmp_path):
        from rowan.config import ScanConfig
        from rowan.core.findings import ScanResult
        from rowan.passes.base import ScanContext

        return ScanContext(
            target_path=tmp_path,
            config=ScanConfig(target=tmp_path),
            result=ScanResult(),
        )

    def test_run_marks_sca_degraded_when_a_chunk_is_dropped(self, tmp_path):
        (tmp_path / "requirements.txt").write_text("requests==2.0\n")
        sca = SCAPass()

        with (
            patch.object(sca, "_check_vulnerabilities", return_value=([], 3)),
            patch.object(sca, "_apply_reachability"),
        ):
            result = sca.run(self._make_context(tmp_path))

        assert "sca" in result.degraded_passes
        assert "3" in result.degraded_passes["sca"]

    def test_run_reports_every_degraded_cause(self, tmp_path):
        (tmp_path / "requirements.txt").write_text("requests==2.0\n")
        (tmp_path / "package.json").write_text("{not-json")
        sca = SCAPass()

        with (
            patch.object(sca, "_check_vulnerabilities", return_value=([], 3)),
            patch.object(sca, "_apply_reachability"),
        ):
            result = sca.run(self._make_context(tmp_path))

        assert "Could not parse 1 dependency file" in result.degraded_passes["sca"]
        assert "exhausted retries for 3 package" in result.degraded_passes["sca"]

    def test_run_does_not_mark_degraded_when_nothing_dropped(self, tmp_path):
        (tmp_path / "requirements.txt").write_text("requests==2.0\n")
        sca = SCAPass()

        with (
            patch.object(sca, "_check_vulnerabilities", return_value=([], 0)),
            patch.object(sca, "_apply_reachability"),
        ):
            result = sca.run(self._make_context(tmp_path))

        assert "sca" not in result.degraded_passes


class TestVulnFunctionLookupNormalization:
    """#111: underscored package names (huggingface_hub) must still resolve
    to their vulnerable-function list -- the lookup key strips '_' but the
    map keys didn't, so the lookup could never match."""

    def test_underscored_package_name_matches(self):
        from rowan.core.vuln_functions import get_vulnerable_functions

        assert get_vulnerable_functions("huggingface_hub") != []

    def test_hyphenated_package_name_matches(self):
        from rowan.core.vuln_functions import get_vulnerable_functions

        assert get_vulnerable_functions("huggingface-hub") != []

    def test_underscored_and_hyphenated_forms_agree(self):
        from rowan.core.vuln_functions import get_vulnerable_functions

        assert get_vulnerable_functions("huggingface_hub") == get_vulnerable_functions(
            "huggingface-hub"
        )


class TestCvssSeverityMapping:
    """#114: the old alias-scans-for-'CRITICAL' check was dead code (aliases
    are CVE/GHSA ids, never containing that word); severity should come from
    OSV's structured severity[] CVSS data instead."""

    def test_cvss_v3_vector_critical(self):
        sca = SCAPass()
        vuln = {"severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}]}
        assert sca._map_osv_severity(vuln).value == "critical"

    def test_cvss_v3_vector_medium(self):
        sca = SCAPass()
        vuln = {
            "severity": [
                {"type": "CVSS_V3", "score": "CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N"}
            ]
        }
        assert sca._map_osv_severity(vuln).value == "low"

    def test_bare_numeric_score(self):
        sca = SCAPass()
        vuln = {"severity": [{"type": "CVSS_V3", "score": "9.8"}]}
        assert sca._map_osv_severity(vuln).value == "critical"

    def test_alias_containing_the_word_critical_is_not_used(self):
        """Regression guard for the removed dead check: an alias that
        happens to contain 'CRITICAL' must not influence severity."""
        sca = SCAPass()
        vuln = {"aliases": ["GHSA-CRITICAL-XYZW"], "database_specific": {"severity": "LOW"}}
        assert sca._map_osv_severity(vuln).value != "critical"

    def test_falls_back_to_database_specific_severity(self):
        sca = SCAPass()
        vuln = {"database_specific": {"severity": "HIGH"}}
        assert sca._map_osv_severity(vuln).value == "high"


class TestReadTextSizeCap:
    """Issue #227 (related item): _read_text had no size cap at all, so a
    planted multi-GB dependency manifest would OOM the process."""

    def test_oversized_file_is_not_read(self, tmp_path):
        p = tmp_path / "requirements.txt"
        with open(p, "wb") as f:
            f.seek(SCAPass.MAX_DEP_FILE_BYTES + 1)
            f.write(b"x")
        assert p.stat().st_size > SCAPass.MAX_DEP_FILE_BYTES

        assert SCAPass._read_text(p) is None

    def test_normal_sized_file_still_read(self, tmp_path):
        p = tmp_path / "requirements.txt"
        p.write_text("requests==2.31.0\n")

        assert SCAPass._read_text(p) == "requests==2.31.0\n"


class TestSharedNetworkBudget:
    def test_advisory_hydration_respects_scan_network_budget(self):
        """SCA's internal pool must not bypass the pipeline I/O cap."""
        sca = SCAPass()
        sca._network_semaphore = threading.BoundedSemaphore(1)
        active = 0
        maximum_active = 0
        lock = threading.Lock()

        def response_for(url, **_kwargs):
            nonlocal active, maximum_active
            with lock:
                active += 1
                maximum_active = max(maximum_active, active)
            time.sleep(0.01)
            with lock:
                active -= 1
            response = MagicMock()
            response.json.return_value = {"id": url.rsplit("/", 1)[-1]}
            return response

        with patch("rowan.passes.sca.httpx.get", side_effect=response_for):
            failed = sca._hydrate_vuln_details({"OSV-1", "OSV-2", "OSV-3"})

        assert failed == set()
        assert maximum_active == 1
