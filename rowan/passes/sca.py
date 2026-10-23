"""SCA pass: scans dependency files for known CVEs."""

from __future__ import annotations

import io
import json
import logging
import math
import os
import re
import stat
import time
from collections.abc import Iterable
from contextlib import nullcontext
from pathlib import Path
from typing import Any, ClassVar

import defusedxml
import defusedxml.ElementTree as ET  # noqa: N817 -- standard stdlib-matching alias
import httpx
import yaml

from rowan import cvss4
from rowan.artifacts import (
    DEPENDENCY_MANIFEST_PATTERNS,
    DEPENDENCY_SKIP_DIRS,
    is_dependency_manifest,
)
from rowan.core.advisory_functions import extract_vulnerable_symbols
from rowan.core.findings import Category, Finding, ScanResult, Severity
from rowan.core.install_hooks import scan_install_hooks
from rowan.core.paths import is_within_root
from rowan.core.phantom_deps import (
    collect_imported_modules,
    collect_local_module_names,
    find_phantom_dependencies,
)
from rowan.core.reachability import collect_reachable_calls, is_package_reachable
from rowan.core.typosquat import nearest_popular
from rowan.core.version_ranges import (
    is_exact_version,
    nearest_fixed_version,
    spec_overlaps_vulnerable_intervals,
)
from rowan.core.vuln_functions import get_vulnerable_functions
from rowan.passes.base import ScanContext, SourceInventory, scan_span
from rowan.passes.file_scan import _parts_under

logger = logging.getLogger(__name__)

# Batching cap for OSV.dev's querybatch endpoint -- keeps a single request
# from growing unbounded on large monorepos with many dependency files.
OSV_BATCH_CHUNK_SIZE = 1000

REQUIREMENT_PATTERNS = list(DEPENDENCY_MANIFEST_PATTERNS)

OSV_API = "https://api.osv.dev/v1/querybatch"
# querybatch returns only {id, modified} per vuln -- the rich fields
# (details, affected, aliases, severity) needed for advisory-derived
# reachability, EPSS aliasing, nearest-fix, range narrowing, and severity
# mapping live only on the full record, fetched per-id from this endpoint.
OSV_VULN_API = "https://api.osv.dev/v1/vulns"
OSV_MAX_RETRIES = 3
OSV_RETRY_DELAY = 2.0
OSV_HYDRATE_WORKERS = 8

# Fields that only appear on a full OSV vuln record, never on a bare
# querybatch {id, modified} entry -- their presence means an entry is already
# hydrated and needs no per-id fetch.
_OSV_RICH_FIELDS = ("details", "affected", "summary", "severity", "aliases")


def _vuln_is_hydrated(vuln: dict[str, Any]) -> bool:
    return any(vuln.get(field) for field in _OSV_RICH_FIELDS)

# FIRST.org EPSS (Exploit Prediction Scoring System) -- the probability a CVE
# is exploited in the wild in the next 30 days. Commercial SCA tools surface
# this alongside CVSS for prioritization; a CVSS-critical CVE with a 0.1% EPSS
# is a very different triage decision than one at 60%.
EPSS_API = "https://api.first.org/data/v1/epss"
EPSS_BATCH_CHUNK_SIZE = 100
_CVE_RE = re.compile(r"^CVE-\d{4}-\d+$")



def _affected_for(pkg: dict[str, Any], affected: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """The advisory's `affected` entries for this package only (SC-09).

    One OSV advisory can list several packages (Go `foo` and `foo/v2`, or
    several ecosystems); their ranges and fixes must not apply to `pkg`.
    Falls back to the whole list when no entry names a package we can match.
    """
    def key(name: str, ecosystem: str) -> tuple[str, str]:
        name = name.lower()
        if ecosystem.lower() == "pypi":
            name = re.sub(r"[-_.]+", "-", name)
        return name, ecosystem.lower()

    wanted = key(str(pkg.get("name", "")), str(pkg.get("ecosystem", "")))
    scoped = [
        entry for entry in affected
        if key(str(entry.get("package", {}).get("name", "")),
               str(entry.get("package", {}).get("ecosystem", ""))) == wanted
    ]
    return scoped or affected

class SCAPass:
    name = "sca"

    # A dependency manifest this large is not a real lockfile; generous
    # enough to never reject a legitimate one (a large monorepo's
    # package-lock.json runs a few MB at most), but bounds the cost of a
    # planted multi-GB file (issue #227's "related, lower severity" item:
    # _read_text had no cap at all).
    MAX_DEP_FILE_BYTES = 50_000_000

    def __init__(
        self,
        osv_api_url: str = OSV_API,
        epss_api_url: str = EPSS_API,
        osv_vuln_url: str = OSV_VULN_API,
    ):
        self._osv_api_url = osv_api_url
        self._epss_api_url = epss_api_url
        self._osv_vuln_url = osv_vuln_url
        self._vuln_cache: dict[str, dict[str, Any] | None] = {}
        # IDs whose rich advisory record could not be fetched.  Keep these
        # findings visible, but surface the incomplete enrichment to callers.
        self._hydration_failures: set[str] = set()
        self._network_semaphore = None
        # Upper bound for the gradle.properties walk in _gradle_properties,
        # and the boundary no file read by _read_text may leave.
        self._scan_root: Path | None = None
        # Files _read_text refused to open: path -> reason. Reported as
        # degraded so a skipped companion file is never silent.
        self._skipped_files: dict[str, str] = {}

    def run(self, context: ScanContext) -> ScanResult:
        start = time.perf_counter()
        self._network_semaphore = context.network_semaphore
        result = ScanResult()
        self._scan_root = context.target_path
        self._skipped_files = {}

        source_inventory = getattr(context, "source_inventory", None)
        if not isinstance(source_inventory, SourceInventory):
            source_inventory = None
        all_dep_files = self._find_dep_files(
            context.target_path,
            None if source_inventory is None else source_inventory.dependency_manifests,
        )
        if not all_dep_files:
            return result

        dep_files = self._prefer_lockfiles(all_dep_files)
        logger.info("SCAPass: found %d dependency files", len(dep_files))

        dropped_packages = 0
        hydration_failures: set[str] = set()
        declared_pypi: set[str] = set()
        component_inventory: dict[tuple[str, str, str], dict[str, Any]] = {}
        dependency_status: list[dict[str, str]] = []
        for dep_file in dep_files:
            packages = self._extract_packages(dep_file)
            if not packages:
                content = self._read_text(dep_file)
                if str(dep_file) in self._skipped_files:
                    dependency_status.append({"path": str(dep_file), "status": "skipped"})
                    continue
                if content is not None and not content.strip():
                    status = "empty"
                elif self._declares_no_dependencies(dep_file, content):
                    status = "no-dependencies"
                else:
                    status = "unparsed"
                dependency_status.append({"path": str(dep_file), "status": status})
                continue
            dependency_status.append({"path": str(dep_file), "status": "parsed"})

            for pkg in packages:
                pkg["source_file"] = str(dep_file)
                if pkg.get("ecosystem") == "PyPI":
                    declared_pypi.add(pkg["name"])
                # Full component inventory for the SBOM, deduped across files
                # by (ecosystem, name, version).
                key = (pkg.get("ecosystem", ""), pkg["name"], pkg.get("version", "*"))
                if key not in component_inventory:
                    component_inventory[key] = {
                        "name": pkg["name"],
                        "version": pkg.get("version", "*"),
                        "ecosystem": pkg.get("ecosystem", ""),
                        "direct": pkg.get("direct", True),
                        "source_files": [str(dep_file)],
                    }
                    if pkg.get("chain"):
                        component_inventory[key]["dependency_chain"] = list(pkg["chain"])
                elif str(dep_file) not in component_inventory[key]["source_files"]:
                    component_inventory[key]["source_files"].append(str(dep_file))
                if pkg.get("chain") and key in component_inventory:
                    # Keep the shortest known path when the same component is
                    # encountered through multiple manifests.
                    current = component_inventory[key].get("dependency_chain")
                    candidate = list(pkg["chain"])
                    if current is None or len(candidate) < len(current):
                        component_inventory[key]["dependency_chain"] = candidate

            vulns, dropped = self._check_vulnerabilities(packages)
            for vuln in vulns:
                result.add_finding(vuln)
            dropped_packages += dropped
            hydration_failures.update(self._hydration_failures)

        degraded: list[str] = []
        if component_inventory:
            result.metadata["dependencies"] = list(component_inventory.values())
        if dependency_status:
            result.metadata["dependency_files"] = dependency_status
            unparsed = [item["path"] for item in dependency_status if item["status"] == "unparsed"]
            if unparsed:
                degraded.append(
                    f"Could not parse {len(unparsed)} dependency file(s): "
                    + ", ".join(unparsed[:5])
                    + (" ..." if len(unparsed) > 5 else "")
                )

        if self._skipped_files:
            skipped = [f"{path} ({reason})" for path, reason in sorted(self._skipped_files.items())]
            message = (
                f"Skipped {len(skipped)} dependency file(s) that are not regular "
                "files inside the scan root: "
                + ", ".join(skipped[:5])
                + (" ..." if len(skipped) > 5 else "")
            )
            degraded.append(message)
            logger.warning("SCAPass DEGRADED: %s", message)

        if dropped_packages:
            message = (
                f"OSV query exhausted retries for {dropped_packages} package(s) -- "
                f"those dependencies were not checked for known vulnerabilities"
            )
            degraded.append(message)
            logger.warning("SCAPass DEGRADED: %s", message)

        if hydration_failures:
            ids = sorted(hydration_failures)
            message = (
                f"OSV advisory hydration failed for {len(ids)} advisory(ies); "
                "findings were retained with limited metadata"
            )
            if len(ids) <= 5:
                message += ": " + ", ".join(ids)
            degraded.append(message)
            logger.warning("SCAPass DEGRADED: %s", message)
        if degraded:
            result.degraded_passes["sca"] = "; ".join(degraded)

        python_sources = (
            source_inventory.paths_for("python", suffix=".py")
            if source_inventory is not None else None
        )
        self._apply_reachability(result.findings, context.target_path, python_sources)
        self._apply_epss(result.findings)

        for phantom_finding in self._detect_phantom_dependencies(
            declared_pypi, context.target_path, python_sources
        ):
            result.add_finding(phantom_finding)

        for typo_finding in self._detect_typosquatting(component_inventory.values()):
            result.add_finding(typo_finding)

        for hook_finding in self._scan_install_hooks(all_dep_files):
            result.add_finding(hook_finding)

        duration = time.perf_counter() - start
        scan_span(self.name, duration)
        logger.info("SCAPass: %d findings in %.1fs", len(result.findings), duration)
        return result

    # Manifest -> lockfile names that pin exact resolved versions. When both
    # a manifest and one of its lockfiles are present in the same directory,
    # the manifest's loose version ranges add nothing but imprecise, often
    # already-patched duplicate findings -- the lockfile is authoritative.
    _MANIFEST_LOCKFILES: ClassVar[dict[str, tuple[str, ...]]] = {
        "pyproject.toml": ("uv.lock", "poetry.lock"),
        "Pipfile": ("Pipfile.lock",),
        "package.json": ("package-lock.json", "npm-shrinkwrap.json", "yarn.lock"),
        "Cargo.toml": ("Cargo.lock",),
        "Gemfile": ("Gemfile.lock",),
        "composer.json": ("composer.lock",),
        "packages.config": ("packages.lock.json",),
    }

    def _prefer_lockfiles(self, dep_files: list[Path]) -> list[Path]:
        by_dir: dict[Path, set[str]] = {}
        for f in dep_files:
            by_dir.setdefault(f.parent, set()).add(f.name)

        kept: list[Path] = []
        for f in dep_files:
            lockfiles = self._MANIFEST_LOCKFILES.get(f.name)
            usable_lockfiles = {
                lock_name
                for lock_name in (by_dir[f.parent] & set(lockfiles or ()))
                if self._extract_packages(f.parent / lock_name)
            }
            if lockfiles and usable_lockfiles:
                logger.debug(
                    "SCAPass: skipping %s -- lockfile present in same directory", f
                )
                continue
            kept.append(f)
        return kept

    def _find_dep_files(
        self, target: Path, candidates: tuple[Path, ...] | None = None
    ) -> list[Path]:
        if candidates is not None:
            return list(candidates)

        files: list[Path] = []
        for f in target.rglob("*"):
            if any(p in DEPENDENCY_SKIP_DIRS for p in _parts_under(f, target)):
                continue
            if not f.is_file():
                continue
            # A symlinked dependency file can point outside the scan root
            # (CWE-59): its extracted package names would otherwise be POSTed
            # to api.osv.dev sourced from an arbitrary host file.
            if f.is_symlink() and not is_within_root(f, target):
                continue
            if is_dependency_manifest(f):
                files.append(f)

        return files

    @staticmethod
    def _declares_no_dependencies(dep_file: Path, content: str | None) -> bool:
        """True when the manifest parsed cleanly and simply lists nothing to check.

        The parsers return ``[]`` for both "malformed" and "valid but empty", and
        only the former should degrade the scan. Called only after the parser
        found nothing, so a document that loads cleanly is by construction one
        with no dependencies to check. Covers the shapes seen on real repos:
        any JSON manifest that loads as an object but lists nothing (gogs'
        bare ``package.json``, bitwarden's ``packages.lock.json`` with an
        empty framework map), any XML manifest that parses but lists nothing
        (a BOM ``pom.xml`` with only ``dependencyManagement``, javalin-bom; a
        ``.csproj`` with only a ``FrameworkReference``, bitwarden), and a Gradle build file with
        no quoted ``group:artifact`` coordinate at all (ktor-samples: only
        version-catalog aliases, which are checked via libs.versions.toml).
        Other manifests keep the conservative "unparsed" status.
        """
        if content is None:
            return False
        if dep_file.name in ("build.gradle", "build.gradle.kts"):
            return not SCAPass._GRADLE_COORDINATE_RE.search(content)
        if dep_file.suffix == ".json":
            try:
                return isinstance(json.loads(content), dict)
            except json.JSONDecodeError:
                return False
        if dep_file.suffix in (".xml", ".csproj", ".config"):
            try:
                ET.fromstring(content)
            except (ET.ParseError, defusedxml.DefusedXmlException):
                return False
            return True
        return False

    def _extract_packages(self, dep_file: Path) -> list[dict[str, str]]:
        name = dep_file.name

        if name.endswith(".txt") and "requirements" in name.lower():
            return self._parse_requirements_txt(dep_file)
        if name == "package.json":
            return self._parse_package_json(dep_file)
        if name == "pnpm-lock.yaml":
            return self._parse_pnpm_lock(dep_file)
        if name == "pyproject.toml":
            return self._parse_pyproject_toml(dep_file)
        if name == "Pipfile":
            return self._parse_pipfile(dep_file)
        if name == "Pipfile.lock":
            return self._parse_pipfile_lock(dep_file)
        if name == "poetry.lock":
            return self._parse_poetry_lock(dep_file)
        if name == "uv.lock":
            return self._parse_uv_lock(dep_file)
        if name in ("package-lock.json", "npm-shrinkwrap.json"):
            return self._parse_package_lock_json(dep_file)
        if name == "yarn.lock":
            return self._parse_yarn_lock(dep_file)
        if name == "go.mod":
            return self._parse_go_mod(dep_file)
        if name == "go.work":
            return self._parse_go_work(dep_file)
        if name == "Cargo.toml":
            return self._parse_cargo_toml(dep_file)
        if name == "Cargo.lock":
            return self._parse_cargo_lock(dep_file)
        if name in ("Gemfile", "Gemfile.lock"):
            return self._parse_gemfile(dep_file)
        if name == "pom.xml":
            return self._parse_pom_xml(dep_file)
        if name == "packages.config":
            return self._parse_packages_config(dep_file)
        if name == "packages.lock.json":
            return self._parse_packages_lock_json(dep_file)
        if name.endswith(".csproj"):
            return self._parse_csproj(dep_file)
        if name in ("build.gradle", "build.gradle.kts"):
            return self._parse_build_gradle(dep_file)
        if name == "libs.versions.toml":
            return self._parse_gradle_version_catalog(dep_file)
        if name in ("composer.json", "composer.lock"):
            return self._parse_composer(dep_file)

        logger.debug("SCAPass: %s matched a dependency pattern but has no parser -- skipping", dep_file)
        return []

    def _parse_requirements_txt(self, file_path: Path) -> list[dict[str, str]]:
        packages: list[dict[str, str]] = []
        content = self._read_text(file_path)  # honours MAX_DEP_FILE_BYTES (SC-11)
        if content is None:
            return packages
        try:
            for line in content.splitlines():
                line = line.strip()
                if not line or line.startswith("#") or line.startswith("-"):
                    continue
                # Inline comments, environment markers (`; python_version<'3.8'`)
                # and hash options (`--hash=sha256:...`) are not part of the version.
                line = line.split("#", 1)[0].split(";", 1)[0].split(" --", 1)[0].strip()
                match = re.match(r"^([a-zA-Z0-9_.-]+)(?:\[[^\]]+\])?\s*([><=!~]+.+)?$", line)
                if not match:
                    continue
                pkg_name = match.group(1).lower()
                version_spec = match.group(2)
                # Strip extras and normalize exact PEP 440 pins before they
                # reach OSV.  OSV expects `2.0`, not `==2.0`; extras are
                # distribution metadata, not part of the package identity.
                # Range specs are kept verbatim for the range-overlap check.
                version = version_spec.strip() if version_spec else "*"
                if version.startswith("=="):
                    version = version[2:].strip()
                packages.append({"name": pkg_name, "version": version, "ecosystem": "PyPI", "direct": True})
        except OSError:
            pass
        return packages

    def _parse_package_json(self, file_path: Path) -> list[dict[str, str]]:
        packages: list[dict[str, str]] = []
        try:
            content = self._read_text(file_path)  # honours MAX_DEP_FILE_BYTES (SC-11)
            data = json.loads(content) if content is not None else {}
            if not isinstance(data, dict):
                return packages
            for dep_type in ("dependencies", "devDependencies"):
                for name, version in data.get(dep_type, {}).items():
                    packages.append({"name": name, "version": str(version), "ecosystem": "npm", "direct": True})
        except (json.JSONDecodeError, OSError):
            pass
        return packages

    @staticmethod
    def _load_toml(content: str) -> dict[str, Any] | None:
        """Best-effort TOML load; returns None if no TOML library is available."""
        try:
            import tomllib
        except ImportError:
            try:
                import tomli as tomllib  # type: ignore[no-redef]
            except ImportError:
                return None
        try:
            return tomllib.loads(content)
        except Exception:
            return None

    def _read_text(self, file_path: Path) -> str | None:
        """Read one dependency file from the scanned repo, or None.

        Every file this pass opens comes through here, companion files
        included. It must be a regular file, reached without a symlink,
        inside the scan root and at most MAX_DEP_FILE_BYTES. Anything else
        is skipped and recorded in ``_skipped_files`` for the report: a FIFO
        or device hangs the read, and a symlink out of the repo (say
        gradle.properties -> ~/.gradle) would put host secrets into the
        report and the OSV query. A file that does not exist is silent.
        """
        if not os.path.lexists(file_path):
            return None
        # Check and open the same normalized path, so a ".." the check
        # resolved lexically cannot be re-resolved through a symlink.
        path = Path(os.path.abspath(file_path))
        reason = self._unsafe_path_reason(path)
        if reason is not None:
            self._skipped_files[str(file_path)] = reason
            return None
        try:
            # O_NOFOLLOW closes the race between the check above and the
            # open; O_NONBLOCK keeps a FIFO swapped in meanwhile from hanging.
            # Neither flag exists on Windows, which has no FIFOs to open.
            flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
            fd = os.open(path, flags)
        except OSError:
            self._skipped_files[str(file_path)] = "could not be opened safely"
            return None
        with os.fdopen(fd, "rb") as handle:
            info = os.fstat(handle.fileno())
            if not stat.S_ISREG(info.st_mode):
                self._skipped_files[str(file_path)] = "not a regular file"
                return None
            if info.st_size > self.MAX_DEP_FILE_BYTES:
                self._skipped_files[str(file_path)] = "over the size cap"
                return None
            raw = handle.read(self.MAX_DEP_FILE_BYTES + 1)
        if len(raw) > self.MAX_DEP_FILE_BYTES:
            self._skipped_files[str(file_path)] = "over the size cap"
            return None
        # Same decoding and newline handling as Path.read_text.
        return io.TextIOWrapper(io.BytesIO(raw), encoding="utf-8", errors="ignore").read()

    def _unsafe_path_reason(self, path: Path) -> str | None:
        """Why the absolute, normalized ``path`` must not be opened, or None.

        Without a scan root (a parser called directly) only the final
        component is checked; the open itself refuses a symlink there.
        """
        if self._scan_root is None:
            return "a symlink" if path.is_symlink() else None
        root = Path(os.path.abspath(self._scan_root))
        root_real = Path(os.path.realpath(root))
        for base in (root, root_real):
            if path == base or base in path.parents:
                relative = path.relative_to(base)
                break
        else:
            return "outside the scan root"
        # Resolving changes nothing below the root only when no component
        # from the root down is a symlink (or a "..").
        if Path(os.path.realpath(path)) != root_real / relative:
            return "reached through a symlink"
        return None

    def _parse_pyproject_toml(self, file_path: Path) -> list[dict[str, str]]:
        packages: list[dict[str, str]] = []
        content = self._read_text(file_path)
        if content is None:
            return packages

        data = self._load_toml(content)
        if data is not None:
            for dep in data.get("project", {}).get("dependencies", []):
                m = re.match(r"^([a-zA-Z0-9_.-]+)\s*(.*)$", dep)
                if m:
                    name, spec = m.group(1).lower(), m.group(2).strip()
                    packages.append({"name": name, "version": spec or "*", "ecosystem": "PyPI", "direct": True})
            # Poetry's own dependency table (`[tool.poetry.dependencies]`) is
            # a distinct, older-than-PEP-621 format most poetry projects
            # still use -- `project.dependencies` above is simply absent for
            # them, not empty as a matter of having no deps.
            for name, spec in data.get("tool", {}).get("poetry", {}).get("dependencies", {}).items():
                if name.lower() == "python":
                    continue
                version = spec if isinstance(spec, str) else spec.get("version", "*") if isinstance(spec, dict) else "*"
                packages.append({"name": name.lower(), "version": version or "*", "ecosystem": "PyPI", "direct": True})
            return packages

        in_deps = False
        for line in content.splitlines():
            stripped = line.strip()
            if stripped.startswith("dependencies"):
                in_deps = True
                continue
            if in_deps and stripped.startswith("["):
                break
            if in_deps:
                match = re.match(r'"([^"]+)"\s*', stripped)
                if match:
                    packages.append({"name": match.group(1).lower(), "version": "*", "ecosystem": "PyPI", "direct": True})
        return packages

    def _direct_pypi_names(self, dir_path: Path) -> set[str] | None:
        """Direct-dependency names from a companion pyproject.toml/Pipfile in
        the same directory as a Python lockfile -- returns None (unknown)
        when no companion manifest is found, so callers can fall back to
        treating every package as direct rather than mislabeling everything
        as transitive."""
        pyproject = dir_path / "pyproject.toml"
        if pyproject.exists():
            return {pkg["name"] for pkg in self._parse_pyproject_toml(pyproject)}
        pipfile = dir_path / "Pipfile"
        if pipfile.exists():
            return {pkg["name"] for pkg in self._parse_pipfile(pipfile)}
        return None

    def _parse_pipfile(self, file_path: Path) -> list[dict[str, str]]:
        packages: list[dict[str, str]] = []
        content = self._read_text(file_path)
        if content is None:
            return packages
        data = self._load_toml(content)
        if data is None:
            return packages
        for section in ("packages", "dev-packages"):
            for name, spec in data.get(section, {}).items():
                version = spec if isinstance(spec, str) else spec.get("version", "*") if isinstance(spec, dict) else "*"
                packages.append({"name": name.lower(), "version": version or "*", "ecosystem": "PyPI", "direct": True})
        return packages

    def _parse_pipfile_lock(self, file_path: Path) -> list[dict[str, str]]:
        packages: list[dict[str, str]] = []
        content = self._read_text(file_path)
        if content is None:
            return packages
        try:
            data = json.loads(content)
        except json.JSONDecodeError:
            return packages
        # Pipfile.lock doesn't record dependency edges, so a full transitive
        # chain isn't derivable -- but the companion Pipfile's own [packages]/
        # [dev-packages] names give an authoritative direct/transitive split.
        direct_names = self._direct_pypi_names(file_path.parent)
        for section in ("default", "develop"):
            for name, spec in data.get(section, {}).items():
                version = str(spec.get("version", "*")).lstrip("=") if isinstance(spec, dict) else "*"
                direct = True if direct_names is None else name.lower() in direct_names
                packages.append({
                    "name": name.lower(), "version": version or "*", "ecosystem": "PyPI", "direct": direct,
                })
        return packages

    def _parse_poetry_lock(self, file_path: Path) -> list[dict[str, str]]:
        packages: list[dict[str, str]] = []
        content = self._read_text(file_path)
        if content is None:
            return packages
        data = self._load_toml(content)
        if data is None:
            return packages

        edges: dict[str, set[str]] = {}
        for pkg in data.get("package", []):
            name = pkg.get("name")
            if not name:
                continue
            # poetry.lock's [package.dependencies] is a {name: version_spec}
            # table -- the keys are this package's own direct dependencies.
            edges[name.lower()] = {dep.lower() for dep in pkg.get("dependencies", {})}

        direct_names = self._direct_pypi_names(file_path.parent)
        chains = self._bfs_chains(direct_names, edges) if direct_names is not None else {}

        for pkg in data.get("package", []):
            name = pkg.get("name")
            if not name:
                continue
            key = name.lower()
            chain = chains.get(key)
            packages.append({
                "name": key, "version": pkg.get("version", "*"), "ecosystem": "PyPI",
                "direct": True if direct_names is None else key in direct_names,
                "chain": chain,
            })
        return packages

    def _parse_uv_lock(self, file_path: Path) -> list[dict[str, str]]:
        packages: list[dict[str, str]] = []
        content = self._read_text(file_path)
        if content is None:
            return packages
        data = self._load_toml(content)
        if data is None:
            return packages

        edges: dict[str, set[str]] = {}
        for pkg in data.get("package", []):
            name = pkg.get("name")
            if not name:
                continue
            # uv.lock's dependencies is a list of {name = "..."} tables,
            # unlike poetry.lock's {name: spec} table.
            edges[name.lower()] = {
                dep.get("name", "").lower() for dep in pkg.get("dependencies", []) if dep.get("name")
            }

        direct_names = self._direct_pypi_names(file_path.parent)
        chains = self._bfs_chains(direct_names, edges) if direct_names is not None else {}

        for pkg in data.get("package", []):
            name = pkg.get("name")
            if not name:
                continue
            key = name.lower()
            chain = chains.get(key)
            packages.append({
                "name": key, "version": pkg.get("version", "*"), "ecosystem": "PyPI",
                "direct": True if direct_names is None else key in direct_names,
                "chain": chain,
            })
        return packages

    @staticmethod
    def _bfs_chains(direct_names: set[str] | None, edges: dict[str, set[str]]) -> dict[str, list[str]]:
        """Shortest dependency chain from any direct dependency to each
        package reachable from it, via BFS over the lockfile's own
        declared package->dependency edges. A package this doesn't reach
        (not declared by any direct dep, transitively) is left absent --
        callers fall back to treating it as direct (best-effort per issue
        #80, rather than guessing an unfounded transitive label)."""
        from collections import deque

        if not direct_names:
            return {}
        chains: dict[str, list[str]] = {}
        queue: deque[str] = deque()
        for d in direct_names:
            if d not in chains:
                chains[d] = [d]
                queue.append(d)
        while queue:
            cur = queue.popleft()
            for nxt in edges.get(cur, ()):
                if nxt not in chains:
                    chains[nxt] = [*chains[cur], nxt]
                    queue.append(nxt)
        return chains

    def _parse_package_lock_json(self, file_path: Path) -> list[dict[str, str]]:
        packages: list[dict[str, str]] = []
        content = self._read_text(file_path)
        if content is None:
            return packages
        try:
            data = json.loads(content)
        except json.JSONDecodeError:
            return packages

        # npm lockfile v2/v3: "packages" keyed by node_modules path (root is
        # "" -- the project itself, not a dependency). The path IS the real
        # install nesting chain: "node_modules/a/node_modules/b" means b is
        # only reachable via a, so it doubles as the dependency chain with
        # no separate graph/BFS needed.
        package_entries = data.get("packages", {})
        root_spec = package_entries.get("", {})
        direct_names = {
            name
            for section in ("dependencies", "devDependencies", "optionalDependencies")
            for name in root_spec.get(section, {})
        }
        direct_unknown = not any(
            section in root_spec
            for section in ("dependencies", "devDependencies", "optionalDependencies")
        )
        for path, spec in package_entries.items():
            if not path or not isinstance(spec, dict):
                continue
            chain = [seg.rstrip("/") for seg in path.split("node_modules/") if seg]
            name = spec.get("name") or (chain[-1] if chain else path.rsplit("node_modules/", 1)[-1])
            packages.append({
                "name": name, "version": str(spec.get("version", "*")), "ecosystem": "npm",
                "direct": (len(chain) <= 1 if direct_unknown else name in direct_names),
                "chain": chain or None,
            })

        # npm lockfile v1: flat "dependencies" map -- no nesting/path info,
        # so direct/transitive can't be derived here.
        if not packages:
            package_json = file_path.parent / "package.json"
            direct_names: set[str] | None = None
            if package_json.exists():
                direct_names = {
                    pkg["name"] for pkg in self._parse_package_json(package_json)
                }
            for name, spec in data.get("dependencies", {}).items():
                if isinstance(spec, dict):
                    packages.append({
                        "name": name,
                        "version": str(spec.get("version", "*")),
                        "ecosystem": "npm",
                        "direct": True if direct_names is None else name in direct_names,
                    })
        return packages

    def _parse_yarn_lock(self, file_path: Path) -> list[dict[str, str]]:
        packages: list[dict[str, str]] = []
        content = self._read_text(file_path)
        if content is None:
            return packages

        # yarn.lock doesn't record dependency edges itself, so a full chain
        # isn't derivable here -- but the companion package.json's own
        # dependencies/devDependencies give an authoritative direct set.
        direct_names: set[str] | None = None
        package_json = file_path.parent / "package.json"
        if package_json.exists():
            direct_names = {pkg["name"] for pkg in self._parse_package_json(package_json)}

        pending_names: list[str] = []
        for line in content.splitlines():
            if line and not line[0].isspace() and line.rstrip().endswith(":"):
                # e.g. `foo@^1.0.0, foo@^1.2.0:` -- one or more selectors for
                # the same resolved package; take the first package name.
                entries = line.rstrip(":\n").split(", ")
                names = set()
                for entry in entries:
                    m = re.match(r'^"?(@?[^@"]+)@', entry)
                    if m:
                        names.add(m.group(1))
                pending_names = list(names)
            elif pending_names and line.strip().startswith("version"):
                m = re.search(r'"([^"]+)"', line)
                version = m.group(1) if m else "*"
                for name in pending_names:
                    direct = True if direct_names is None else name in direct_names
                    packages.append({"name": name, "version": version, "ecosystem": "npm", "direct": direct})
                pending_names = []
        return packages

    def _parse_pnpm_lock(self, file_path: Path) -> list[dict[str, str]]:
        """Extract resolved npm packages from pnpm lockfile v6/v9 shapes.

        pnpm stores resolved package identities under `packages` (v6) or
        `snapshots` (v9), using keys such as `/lodash@4.17.21` and
        `/@scope/pkg@1.2.3`.  Dependency edges are intentionally left to the
        lockfile's own resolver; this parser reports resolved inventory and
        marks packages direct when the companion package.json declares them.
        """
        content = self._read_text(file_path)
        if content is None:
            return []
        try:
            data = yaml.safe_load(content) or {}
        except yaml.YAMLError:
            return []
        package_json = file_path.parent / "package.json"
        direct_names = None
        if package_json.exists():
            direct_names = {p["name"] for p in self._parse_package_json(package_json)}
        packages: list[dict[str, str]] = []
        for section in ("packages", "snapshots"):
            for raw_key in (data.get(section) or {}):
                key = str(raw_key).lstrip("/")
                match = re.match(r"^(@[^/]+/[^@]+|[^@/]+)@([^()]+)", key)
                if not match:
                    continue
                name, version = match.groups()
                packages.append({
                    "name": name,
                    "version": version,
                    "ecosystem": "npm",
                    "direct": True if direct_names is None else name in direct_names,
                })
            if packages:
                break
        return packages

    def _parse_go_mod(self, file_path: Path) -> list[dict[str, str]]:
        packages: list[dict[str, str]] = []
        content = self._read_text(file_path)
        if content is None:
            return packages

        in_require_block = False
        requirements: list[tuple[str, str, bool]] = []
        replacements: dict[str, tuple[str, str | None]] = {}
        for line in content.splitlines():
            stripped = line.strip()
            if stripped.startswith("replace ("):
                # Replacement blocks are handled below using the same syntax
                # as single-line directives; entering this block here keeps
                # the require parser from mistaking them for dependencies.
                continue
            if stripped.startswith("require ("):
                in_require_block = True
                continue
            if in_require_block and stripped == ")":
                in_require_block = False
                continue
            if in_require_block or stripped.startswith("require "):
                entry = stripped[len("require "):] if stripped.startswith("require ") else stripped
                # go.mod marks each transitive requirement with a trailing
                # "// indirect" comment (Go's own module graph pruning
                # already resolves the full transitive set into this same
                # require block, unlike front-end lockfiles) -- an
                # authoritative direct/transitive split with no extra file
                # to cross-reference.
                is_indirect = "// indirect" in entry
                entry = entry.split("//")[0].strip()
                parts = entry.split()
                if len(parts) >= 2:
                    requirements.append((parts[0], parts[1], not is_indirect))
            if stripped.startswith("replace ") or ("=>" in stripped and not in_require_block):
                entry = stripped[len("replace "):] if stripped.startswith("replace ") else stripped
                entry = entry.split("//")[0].strip()
                sides = [side.strip() for side in entry.split("=>", 1)]
                if len(sides) != 2:
                    continue
                old = sides[0].split()
                new = sides[1].split()
                if old and new:
                    # A local replacement (./fork or an absolute path) has
                    # no module version for OSV to query, so omit it.
                    replacements[old[0]] = (new[0], new[1] if len(new) > 1 else None)

        for name, version, direct in requirements:
            replacement = replacements.get(name)
            if replacement:
                replacement_name, replacement_version = replacement
                if replacement_name.startswith((".", "/")):
                    continue
                if replacement_version:
                    name, version = replacement_name, replacement_version
            packages.append({
                "name": name, "version": version, "ecosystem": "Go", "direct": direct,
            })
        return packages

    def _parse_go_work(self, file_path: Path) -> list[dict[str, str]]:
        """Inventory modules listed by a Go workspace file.

        ``go.work`` contains local module paths rather than registry package
        versions.  Resolve only bounded, in-tree ``go.mod`` files and reuse
        the normal module parser; arbitrary paths and nested workspace
        expansion are intentionally ignored.
        """
        content = self._read_text(file_path)
        if content is None:
            return []
        use_paths: list[str] = []
        in_use_block = False
        for raw_line in content.splitlines():
            line = raw_line.split("//", 1)[0].strip()
            if not line:
                continue
            if line == "use (":
                in_use_block = True
                continue
            if in_use_block and line == ")":
                in_use_block = False
                continue
            if line.startswith("use "):
                line = line[4:].strip()
            elif not in_use_block:
                continue
            if line and not line.startswith("("):
                use_paths.append(line.split()[0])

        packages: list[dict[str, str]] = []
        workspace_root = file_path.parent.resolve()
        for raw_path in use_paths[:128]:
            module_dir = (workspace_root / raw_path).resolve()
            try:
                module_dir.relative_to(workspace_root)
            except ValueError:
                continue
            go_mod = module_dir / "go.mod"
            if not go_mod.is_file() or go_mod.is_symlink():
                continue
            packages.extend(self._parse_go_mod(go_mod))
        return packages

    def _parse_cargo_toml(self, file_path: Path) -> list[dict[str, str]]:
        packages: list[dict[str, str]] = []
        content = self._read_text(file_path)
        if content is None:
            return packages
        data = self._load_toml(content)
        if data is None:
            return packages
        for section in ("dependencies", "dev-dependencies", "build-dependencies", "workspace.dependencies"):
            # Cargo workspaces commonly keep shared versions in the root
            # manifest.  Include those declarations when scanning the root;
            # member manifests using ``workspace = true`` remain represented
            # by their lockfile when one is available.
            section_data: Any = data
            for part in section.split("."):
                section_data = section_data.get(part, {}) if isinstance(section_data, dict) else {}
            for name, spec in section_data.items():
                version = spec if isinstance(spec, str) else spec.get("version", "*") if isinstance(spec, dict) else "*"
                packages.append({"name": name.lower(), "version": version or "*", "ecosystem": "crates.io", "direct": True})
        return packages

    def _direct_crate_names(self, dir_path: Path) -> set[str] | None:
        cargo_toml = dir_path / "Cargo.toml"
        if not cargo_toml.exists():
            return None
        return {pkg["name"] for pkg in self._parse_cargo_toml(cargo_toml)}

    def _parse_cargo_lock(self, file_path: Path) -> list[dict[str, str]]:
        packages: list[dict[str, str]] = []
        content = self._read_text(file_path)
        if content is None:
            return packages
        data = self._load_toml(content)
        if data is None:
            return packages

        edges: dict[str, set[str]] = {}
        for pkg in data.get("package", []):
            name = pkg.get("name")
            if not name:
                continue
            # Each entry is "name" or "name version" or "name version (source)" --
            # the bare name is always the first whitespace-separated token.
            edges[name.lower()] = {dep.split()[0].lower() for dep in pkg.get("dependencies", []) if dep.split()}

        direct_names = self._direct_crate_names(file_path.parent)
        chains = self._bfs_chains(direct_names, edges) if direct_names is not None else {}

        for pkg in data.get("package", []):
            name = pkg.get("name")
            if not name:
                continue
            key = name.lower()
            packages.append({
                "name": key, "version": pkg.get("version", "*"), "ecosystem": "crates.io",
                "direct": True if direct_names is None else key in direct_names,
                "chain": chains.get(key),
            })
        return packages

    def _parse_gemfile(self, file_path: Path) -> list[dict[str, str]]:
        packages: list[dict[str, str]] = []
        content = self._read_text(file_path)
        if content is None:
            return packages

        if file_path.name == "Gemfile.lock":
            # Bundler flattens every *resolved* gem (direct and transitive
            # alike) into 4-space-indented top-level entries under specs: --
            # the 6+-space lines beneath each are that gem's own dependency
            # *edges* (name + constraint, no version), not separate package
            # entries needing their own extraction. The DEPENDENCIES section
            # at the bottom is Bundler's own authoritative record of which
            # names were requested directly by the Gemfile.
            in_specs = False
            in_dependencies = False
            direct_names: set[str] = set()
            edges: dict[str, set[str]] = {}
            current: str | None = None
            versions: dict[str, str] = {}
            for line in content.splitlines():
                stripped = line.strip()
                if stripped == "specs:":
                    in_specs = True
                    in_dependencies = False
                    continue
                if stripped == "DEPENDENCIES":
                    in_dependencies = True
                    in_specs = False
                    continue
                if line.strip() == "":
                    in_specs = False
                    in_dependencies = False
                    continue
                if in_dependencies:
                    m = re.match(r"^\s*([\w.-]+)", line)
                    if m:
                        direct_names.add(m.group(1))
                    continue
                if not in_specs:
                    continue
                if line.startswith("    ") and not line.startswith("      "):
                    m = re.match(r"^\s{4}([\w.-]+)\s+\(([^)]+)\)", line)
                    if m:
                        current = m.group(1)
                        versions[current] = m.group(2)
                        edges.setdefault(current, set())
                elif current and line.startswith("      "):
                    m = re.match(r"^\s{6}([\w.-]+)", line)
                    if m:
                        edges[current].add(m.group(1))

            chains = self._bfs_chains(direct_names, edges)
            for name, version in versions.items():
                packages.append({
                    "name": name, "version": version, "ecosystem": "RubyGems",
                    "direct": name in direct_names, "chain": chains.get(name),
                })
        else:
            for line in content.splitlines():
                m = re.match(r"^\s*gem\s+['\"]([\w.-]+)['\"](?:\s*,\s*['\"]([^'\"]+)['\"])?", line.strip())
                if m:
                    packages.append({"name": m.group(1), "version": m.group(2) or "*", "ecosystem": "RubyGems", "direct": True})
        return packages

    def _parse_pom_xml(self, file_path: Path) -> list[dict[str, str]]:
        packages: list[dict[str, str]] = []
        content = self._read_text(file_path)
        if content is None:
            return packages
        try:
            root = ET.fromstring(content)
        except (ET.ParseError, defusedxml.DefusedXmlException):
            # A pom.xml comes from the code being *scanned* -- untrusted
            # input. defusedxml raises its own exceptions (DTDForbidden,
            # EntitiesForbidden, ExternalReferenceForbidden) for XXE/entity-
            # expansion attempts, on top of the normal malformed-XML case.
            return packages

        ns = ""
        if root.tag.startswith("{"):
            ns = root.tag.split("}")[0] + "}"

        # `${spring.version}` is resolved from this file's <properties> and
        # its own <version> (SC-14); an undefined property stays literal.
        properties: dict[str, str] = {}
        props = root.find(f"{ns}properties")
        for prop in props if props is not None else ():
            if prop.text:
                properties[prop.tag.rsplit("}", 1)[-1]] = prop.text.strip()
        own_version = root.find(f"{ns}version")
        if own_version is not None and own_version.text:
            properties.setdefault("project.version", own_version.text.strip())
            properties.setdefault("pom.version", own_version.text.strip())

        def substitute(m: re.Match[str]) -> str:
            value = properties.get(m.group(1))
            return value if value is not None and self._is_plain_version(value) else m.group(0)

        def resolve(text: str) -> str:
            return re.sub(r"\$\{([^}]+)\}", substitute, text.strip())

        def visit(node: ET.Element, in_dependency_management: bool = False) -> None:
            section = node.tag.rsplit("}", 1)[-1]
            in_dependency_management |= section == "dependencyManagement"
            if section == "dependency" and not in_dependency_management:
                group_id = node.find(f"{ns}groupId")
                artifact_id = node.find(f"{ns}artifactId")
                version = node.find(f"{ns}version")
                if group_id is not None and artifact_id is not None:
                    name = f"{group_id.text}:{artifact_id.text}"
                    packages.append({
                        "name": name,
                        "version": resolve(version.text) if version is not None and version.text else "*",
                        "ecosystem": "Maven",
                        "direct": True,
                    })
            for child in node:
                visit(child, in_dependency_management)

        visit(root)
        return packages

    def _parse_packages_config(self, file_path: Path) -> list[dict[str, str]]:
        packages: list[dict[str, str]] = []
        content = self._read_text(file_path)
        if content is None:
            return packages
        try:
            root = ET.fromstring(content)
        except (ET.ParseError, defusedxml.DefusedXmlException):
            return packages
        for node in root.iter():
            if node.tag.rsplit("}", 1)[-1] != "package":
                continue
            name, version = node.attrib.get("id"), node.attrib.get("version")
            if name and version:
                packages.append({
                    "name": name, "version": version,
                    "ecosystem": "NuGet", "direct": True,
                })
        return packages

    def _parse_packages_lock_json(self, file_path: Path) -> list[dict[str, str]]:
        """Parse NuGet ``packages.lock.json`` resolved dependencies.

        NuGet writes one dependency map per target framework.  Entries marked
        ``Direct`` are requested by the project; all other entries are
        transitive.  When the same package occurs for multiple frameworks,
        retain the first resolved version and merge its framework provenance.
        """
        content = self._read_text(file_path)
        if content is None:
            return []
        try:
            data = json.loads(content)
        except (json.JSONDecodeError, TypeError):
            return []
        dependencies = data.get("dependencies") if isinstance(data, dict) else None
        if not isinstance(dependencies, dict):
            return []
        packages: dict[tuple[str, str], dict[str, str]] = {}
        for framework, entries in dependencies.items():
            if not isinstance(entries, dict):
                continue
            for name, spec in entries.items():
                if not isinstance(spec, dict):
                    continue
                version = spec.get("resolved")
                if not isinstance(name, str) or not isinstance(version, str) or not version:
                    continue
                key = (name.lower(), version)
                item = packages.setdefault(key, {
                    "name": name, "version": version, "ecosystem": "NuGet",
                    "direct": str(spec.get("type", "")).lower() == "direct",
                    "frameworks": framework,
                })
                if str(spec.get("type", "")).lower() == "direct":
                    item["direct"] = True
                if framework not in item["frameworks"].split(","):
                    item["frameworks"] += "," + framework
        return list(packages.values())

    def _parse_csproj(self, file_path: Path) -> list[dict[str, str]]:
        packages: list[dict[str, str]] = []
        content = self._read_text(file_path)
        if content is None:
            return packages
        try:
            root = ET.fromstring(content)
        except (ET.ParseError, defusedxml.DefusedXmlException):
            return packages
        for node in root.iter():
            if node.tag.rsplit("}", 1)[-1] != "PackageReference":
                continue
            name = node.attrib.get("Include") or node.attrib.get("Update")
            version = node.attrib.get("Version")
            if version is None:
                child = next((c for c in node if c.tag.rsplit("}", 1)[-1] == "Version"), None)
                version = child.text.strip() if child is not None and child.text else None
            if name and version:
                packages.append({
                    "name": name, "version": version,
                    "ecosystem": "NuGet", "direct": True,
                })
        return packages

    # A quoted Maven coordinate: "group:artifact" or "group:artifact:version".
    # The closing quote is required so a three-part string is never also
    # reported as a two-part match of its prefix, and the group must start
    # right after the quote so ":shared" project paths and "https://..." URLs
    # cannot match.
    _GRADLE_COORDINATE_RE = re.compile(
        r"""['"]([\w.-]+):([\w.-]+)(?::(\$\{?[\w.]+\}?|[\w.\[\](),+-]+))?['"]"""
    )

    # A plain version: dotted numbers with optional short qualifiers
    # ("1.2.3", "2.0.0-RC1", "5.3.20.RELEASE", "33.0.0-jre"). Property
    # interpolation only ever substitutes values of this shape, so a secret
    # in gradle.properties or a pom <properties> block cannot reach the OSV
    # query or the report by being referenced as a version.
    _PLAIN_VERSION_RE = re.compile(r"\d+(?:\.\d+)*(?:[.+-][A-Za-z0-9]+)*")

    @classmethod
    def _is_plain_version(cls, value: str) -> bool:
        return len(value) <= 64 and cls._PLAIN_VERSION_RE.fullmatch(value) is not None

    def _gradle_properties(self, file_path: Path) -> dict[str, str]:
        """Merge ``gradle.properties`` from the build file's directory up to the
        scan root (nearest file wins), so ``$logback_version`` can be resolved."""
        props: dict[str, str] = {}
        root = self._scan_root or file_path.parent.parent
        directory = file_path.parent
        while True:
            content = self._read_text(directory / "gradle.properties")
            for line in (content or "").splitlines():
                key, sep, value = line.partition("=")
                if sep and key.strip() and not key.lstrip().startswith("#"):
                    props.setdefault(key.strip(), value.strip())
            if directory == root or directory.parent == directory:
                return props
            directory = directory.parent

    def _parse_build_gradle(self, file_path: Path) -> list[dict[str, str]]:
        """Best-effort: matches the 'group:artifact[:version]' string notation
        (a missing version means it comes from a BOM or plugin; a
        ``$property`` version is looked up in gradle.properties) and the
        map-style notation. Version-catalog aliases need a real Groovy/Kotlin
        DSL parser and are covered by parsing libs.versions.toml instead."""
        packages: list[dict[str, str]] = []
        content = self._read_text(file_path)
        if content is None:
            return packages
        props: dict[str, str] | None = None
        for m in self._GRADLE_COORDINATE_RE.finditer(content):
            group, artifact, version = m.groups()
            if version and version.startswith("$"):
                if props is None:
                    props = self._gradle_properties(file_path)
                version = props.get(version.strip("${}"))
                if version is not None and not self._is_plain_version(version):
                    version = None
            packages.append({"name": f"{group}:{artifact}", "version": version or "*", "ecosystem": "Maven", "direct": True})
        for m in re.finditer(
            r"group\s*:\s*['\"]([^'\"]+)['\"]\s*,\s*"
            r"name\s*:\s*['\"]([^'\"]+)['\"]\s*,\s*"
            r"version\s*:\s*['\"]([^'\"]+)['\"]",
            content,
        ):
            group, artifact, version = m.groups()
            packages.append({"name": f"{group}:{artifact}", "version": version, "ecosystem": "Maven", "direct": True})
        return packages

    def _parse_gradle_version_catalog(self, file_path: Path) -> list[dict[str, str]]:
        """Parse resolved library entries from a Gradle version catalog.

        Catalog aliases are declarations rather than resolved dependencies, but
        a concrete ``module`` plus a literal version (or ``version.ref``) is
        sufficient for an OSV inventory.  Bundles and plugin aliases are
        intentionally ignored because they do not identify Maven components.
        """
        content = self._read_text(file_path)
        if content is None:
            return []
        data = self._load_toml(content)
        if not data:
            return []
        versions = data.get("versions", {})
        libraries = data.get("libraries", {})
        packages: list[dict[str, str]] = []
        for entry in libraries.values():
            if not isinstance(entry, dict):
                continue
            module = entry.get("module")
            if not isinstance(module, str) or module.count(":") != 1:
                continue
            version = entry.get("version")
            if isinstance(version, dict):
                ref = version.get("ref")
                version = versions.get(ref) if isinstance(ref, str) else None
            if not isinstance(version, (str, int, float)):
                continue
            packages.append({
                "name": module,
                "version": str(version),
                "ecosystem": "Maven",
                "direct": True,
            })
        return packages

    def _parse_composer(self, file_path: Path) -> list[dict[str, str]]:
        packages: list[dict[str, str]] = []
        content = self._read_text(file_path)
        if content is None:
            return packages
        try:
            data = json.loads(content)
        except json.JSONDecodeError:
            return packages

        if file_path.name == "composer.lock":
            edges: dict[str, set[str]] = {}
            for pkg in data.get("packages", []) + data.get("packages-dev", []):
                name = pkg.get("name")
                if not name:
                    continue
                edges[name] = {
                    dep for dep in pkg.get("require", {}) if dep != "php" and not dep.startswith("ext-")
                }

            composer_json = file_path.parent / "composer.json"
            direct_names: set[str] | None = None
            if composer_json.exists():
                direct_names = {pkg["name"] for pkg in self._parse_composer(composer_json)}
            chains = self._bfs_chains(direct_names, edges) if direct_names is not None else {}

            for pkg in data.get("packages", []):
                name = pkg.get("name")
                if not name:
                    continue
                packages.append({
                    "name": name, "version": pkg.get("version", "*"), "ecosystem": "Packagist",
                    "direct": True if direct_names is None else name in direct_names,
                    "chain": chains.get(name),
                })
        else:
            for section in ("require", "require-dev"):
                for name, version in data.get(section, {}).items():
                    if name == "php" or name.startswith("ext-"):
                        continue
                    packages.append({"name": name, "version": str(version), "ecosystem": "Packagist", "direct": True})
        return packages

    def _query_osv_batch(self, packages: list[dict[str, str]]) -> list[dict[str, Any]] | None:
        """POST one chunk of packages to OSV's querybatch endpoint, with retries.

        Returns None (not []) on exhausted retries, so the caller can tell
        "queried, no vulns" apart from "this chunk's results are missing" --
        conflating the two would misalign the positional pairing with
        packages for every later chunk.
        """
        query_entries: list[dict[str, Any]] = []
        for pkg in packages:
            entry: dict[str, Any] = {
                "package": {"name": pkg["name"], "ecosystem": pkg["ecosystem"]},
            }
            version = pkg.get("version", "*")
            # OSV's querybatch checks a single exact version against each
            # vuln's affected ranges -- it isn't a range solver. Sending it
            # a raw range spec ("*", ">=1.0", "^2.0.0") as `version` doesn't
            # do anything meaningful, so omit the field entirely for
            # anything that isn't an exact pin; the caller applies its own
            # range-overlap check against the (broader) results this
            # returns instead (see _filter_range_spec_vulns).
            if version and is_exact_version(version):
                exact = version[2:].strip() if version.startswith("==") else version
                # OSV records Go and Packagist versions without the `v` prefix.
                entry["version"] = exact[1:] if exact.startswith("v") else exact
            query_entries.append(entry)

        for attempt in range(OSV_MAX_RETRIES):
            try:
                with self._network_slot():
                    response = httpx.post(
                        self._osv_api_url, json={"queries": query_entries}, timeout=30
                    )
                response.raise_for_status()
                body = response.json()
                results = body.get("results")
                if not isinstance(results, list) or len(results) != len(packages):
                    raise ValueError(
                        f"OSV returned {len(results) if isinstance(results, list) else 'invalid'} "
                        f"results for {len(packages)} queries"
                    )

                if not all(isinstance(item, dict) for item in results):
                    raise ValueError("OSV returned a non-object query result")

                # querybatch paginates individual query results. Preserve the
                # original positional result contract, but send subsequent
                # requests only for queries which actually returned a token.
                # Re-sending completed queries would re-fetch page one and
                # can duplicate findings indefinitely while another package
                # continues paginating.
                pending = [
                    (index, token)
                    for index, item in enumerate(results)
                    if (token := item.get("next_page_token"))
                ]
                seen_tokens = set(pending)
                while pending:
                    next_entries = []
                    for index, token in pending:
                        next_entry = dict(query_entries[index])
                        next_entry["page_token"] = token
                        next_entries.append(next_entry)
                    with self._network_slot():
                        page_response = httpx.post(
                            self._osv_api_url,
                            json={"queries": next_entries},
                            timeout=30,
                        )
                    page_response.raise_for_status()
                    page_body = page_response.json()
                    page_results = page_body.get("results")
                    if not isinstance(page_results, list) or len(page_results) != len(pending):
                        raise ValueError("OSV pagination returned an invalid result shape")
                    if not all(isinstance(item, dict) for item in page_results):
                        raise ValueError("OSV pagination returned a non-object query result")

                    next_pending: list[tuple[int, str]] = []
                    for (index, _token), page_item in zip(pending, page_results, strict=True):
                        item = results[index]
                        existing_ids = {
                            vuln.get("id") for vuln in item.get("vulns", [])
                            if isinstance(vuln, dict) and vuln.get("id")
                        }
                        for vuln in page_item.get("vulns", []):
                            if not isinstance(vuln, dict) or vuln.get("id") not in existing_ids:
                                item.setdefault("vulns", []).append(vuln)
                                if isinstance(vuln, dict) and vuln.get("id"):
                                    existing_ids.add(vuln["id"])

                        token = page_item.get("next_page_token")
                        if token:
                            key = (index, token)
                            if key in seen_tokens:
                                raise ValueError("OSV pagination repeated a page token")
                            seen_tokens.add(key)
                            next_pending.append(key)
                        else:
                            item.pop("next_page_token", None)
                    pending = next_pending
                return results
            except (httpx.HTTPError, json.JSONDecodeError, ValueError, TypeError) as e:
                logger.warning("OSV API error (attempt %d/%d): %s", attempt + 1, OSV_MAX_RETRIES, e)
                if attempt < OSV_MAX_RETRIES - 1:
                    time.sleep(OSV_RETRY_DELAY * (attempt + 1))
        return None

    def _fetch_one_vuln(self, vuln_id: str) -> dict[str, Any] | None:
        """Fetch a single full OSV vuln record, or None on any error."""
        try:
            with self._network_slot():
                response = httpx.get(f"{self._osv_vuln_url}/{vuln_id}", timeout=15)
            response.raise_for_status()
            data = response.json()
            return data if isinstance(data, dict) else None
        except (httpx.HTTPError, json.JSONDecodeError):
            return None

    def _network_slot(self):
        """Acquire the scan-wide I/O budget when this pass has a context.

        Direct unit callers retain the historical, unbounded behavior; a
        pipeline scan always installs the shared semaphore before a request.
        """
        return self._network_semaphore or nullcontext()

    def _hydrate_vuln_details(self, vuln_ids: set[str]) -> set[str]:
        """Populate ``self._vuln_cache`` with full records for each id.

        querybatch only returns ``{id, modified}``; the fields the rest of
        the pass relies on (details, affected, aliases, severity) live only on
        the full record. Fetched once per unique id (cached across dep files),
        in parallel, and best-effort -- an id that fails to hydrate falls back
        to the minimal record downstream rather than dropping the finding.
        """
        from concurrent.futures import ThreadPoolExecutor

        to_fetch = sorted(v for v in vuln_ids if v and v not in self._vuln_cache)
        if not to_fetch:
            return {v for v in vuln_ids if v and self._vuln_cache.get(v) is None}
        workers = min(OSV_HYDRATE_WORKERS, len(to_fetch))
        with ThreadPoolExecutor(max_workers=workers) as executor:
            for vid, full in zip(to_fetch, executor.map(self._fetch_one_vuln, to_fetch), strict=True):
                self._vuln_cache[vid] = full
        return {vid for vid in to_fetch if self._vuln_cache.get(vid) is None}

    def _check_vulnerabilities(
        self, packages: list[dict[str, str]]
    ) -> tuple[list[Finding], int]:
        findings: list[Finding] = []
        self._hydration_failures = set()
        if not packages:
            return findings, 0

        # Chunk to stay under OSV's querybatch size limit -- a single large
        # lockfile (package-lock.json, poetry.lock) can easily list thousands
        # of transitive packages.
        dropped_packages = 0
        paired: list[tuple[dict[str, str], dict[str, Any]]] = []
        for i in range(0, len(packages), OSV_BATCH_CHUNK_SIZE):
            chunk = packages[i:i + OSV_BATCH_CHUNK_SIZE]
            results = self._query_osv_batch(chunk)
            if results is None:
                dropped_packages += len(chunk)
                continue
            paired.extend(zip(chunk, results, strict=False))

        # querybatch gives only {id, modified} per vuln; hydrate each unique id
        # to its full record so severity/affected/details/aliases are available.
        # Only "thin" entries (no rich fields already present) need fetching --
        # this skips anything a future OSV response, or a test, already
        # provided in full.
        self._hydration_failures = self._hydrate_vuln_details(
            {
                v.get("id", "")
                for _, item in paired
                for v in item.get("vulns", [])
                if not _vuln_is_hydrated(v)
            }
        )

        # OSV's querybatch response does not echo the queried package back in
        # each result -- results[i] corresponds positionally to queries[i],
        # and thus to packages[i]. Without this pairing, item.get("package")
        # is always empty, which silently breaks both the CVE message
        # ("CVE in ?: ...") and reachability matching (metadata["package"]
        # would be "", so get_vulnerable_functions("") always returns []).
        for pkg, item in paired:
            vulns = item.get("vulns", [])
            if not vulns:
                continue

            version = pkg.get("version", "*")
            exact = bool(version and is_exact_version(version))
            is_transitive = pkg.get("direct") is False
            chain = pkg.get("chain")

            for vuln in vulns:
                # Prefer the hydrated full record (details/affected/aliases/
                # severity); fall back to the minimal querybatch entry if
                # hydration failed for this id.
                full = self._vuln_cache.get(vuln.get("id", "")) or vuln
                affected = _affected_for(pkg, full.get("affected", []))

                confidence = 0.8
                indeterminate = False
                if not exact:
                    # We queried without a version (see _query_osv_batch), so
                    # OSV returned every known vuln for this package name --
                    # narrow it down by checking whether our declared range
                    # could actually select an affected version.
                    overlap = spec_overlaps_vulnerable_intervals(version, affected)
                    if overlap is False:
                        continue  # spec provably can't reach a vulnerable version
                    if overlap is None:
                        indeterminate = True
                        confidence = 0.5

                # OSV surfaces known-malicious packages as advisories with a
                # `MAL-` id (its malicious-packages feed). These are not
                # ordinary CVEs -- the package itself is the threat -- so they
                # get CRITICAL severity, a distinct label, and are exempted
                # from the reachability downgrade downstream (installing it at
                # all is the risk, regardless of which function is called).
                vuln_id = full.get("id", "") or vuln.get("id", "")
                is_malicious = vuln_id.upper().startswith("MAL-")

                if is_malicious:
                    message = f"Malicious package {pkg['name']}: {full.get('summary', '')}"
                else:
                    message = f"CVE in {pkg['name']}: {full.get('summary', '')}"

                fixed_version = nearest_fixed_version(version, affected)
                if fixed_version and not is_malicious:
                    message += f" (fix: upgrade to >= {fixed_version})"

                metadata: dict[str, Any] = {
                    "cve_id": vuln_id,
                    "package": pkg["name"],
                    "version": version,
                    "ecosystem": pkg["ecosystem"],
                    "details": full.get("details", ""),
                    "direct": not is_transitive,
                }
                if is_malicious:
                    metadata["malicious"] = True
                if fixed_version:
                    metadata["fixed_version"] = fixed_version
                # OSV's primary id is often a GHSA; EPSS keys on CVE ids, so
                # keep any CVE alias for the EPSS lookup below.
                aliases = full.get("aliases", [])
                if aliases:
                    metadata["aliases"] = aliases
                if vuln_id in self._hydration_failures:
                    metadata["advisory_hydration_failed"] = True
                if is_transitive and chain:
                    metadata["dependency_chain"] = chain
                if pkg.get("source_file"):
                    metadata["source_file"] = pkg["source_file"]
                if indeterminate:
                    metadata["version_indeterminate"] = True

                findings.append(
                    Finding(
                        rule_id=f"SCA-{vuln_id or 'UNKNOWN'}",
                        message=message,
                        severity=Severity.CRITICAL if is_malicious else self._map_osv_severity(full),
                        category=Category.SUPPLY_CHAIN,
                        # Dependency findings have no source-code line, but the
                        # manifest/lockfile is still the actionable location
                        # for remediation. Keep it in the canonical finding
                        # location as well as metadata so every reporter and
                        # deduplication path can identify the occurrence.
                        file_path=pkg.get("source_file", ""),
                        start_line=0,
                        confidence=0.9 if is_malicious else confidence,
                        engine="depguard",
                        metadata=metadata,
                    )
                )

        return findings, dropped_packages

    def _map_osv_severity(self, vuln: dict[str, Any]) -> Severity:
        # OSV's structured severity[] gives a CVSS vector string, not a bare
        # score -- pull the base score out of it (works for both 3.x's
        # ".../S:U/C:H/..." style and the numeric-suffix v2 form) rather than
        # trying to hand-roll a full CVSS parser.
        # A CVSS 4.0 vector only fills in when no other entry scores, so an
        # advisory that also carries 3.x keeps the severity it had (SC-15).
        entries = sorted(
            vuln.get("severity", []),
            key=lambda entry: str(entry.get("score", "")).startswith("CVSS:4"),
        )
        for entry in entries:
            score = self._cvss_base_score(str(entry.get("score", "")))
            if score is not None:
                if score >= 9.0:
                    return Severity.CRITICAL
                if score >= 7.0:
                    return Severity.HIGH
                if score >= 4.0:
                    return Severity.MEDIUM
                return Severity.LOW
        severity_str = vuln.get("database_specific", {}).get("severity", "")
        if "CRITICAL" in str(severity_str).upper():
            return Severity.CRITICAL
        if "HIGH" in str(severity_str).upper():
            return Severity.HIGH
        return Severity.MEDIUM

    _CVSS3_AV: ClassVar[dict[str, float]] = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}
    _CVSS3_AC: ClassVar[dict[str, float]] = {"L": 0.77, "H": 0.44}
    _CVSS3_PR_U: ClassVar[dict[str, float]] = {"N": 0.85, "L": 0.62, "H": 0.27}  # scope unchanged
    _CVSS3_PR_C: ClassVar[dict[str, float]] = {"N": 0.85, "L": 0.68, "H": 0.5}  # scope changed
    _CVSS3_UI: ClassVar[dict[str, float]] = {"N": 0.85, "R": 0.62}
    _CVSS3_CIA: ClassVar[dict[str, float]] = {"H": 0.56, "L": 0.22, "N": 0.0}

    @classmethod
    def _cvss_base_score(cls, score: str) -> float | None:
        """Extract a numeric base score from an OSV severity[].score value.

        Handles a bare numeric score ("9.8") as well as OSV/GHSA's usual
        CVSS v3.x vector string form ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/
        C:H/I:H/A:H"), computing the official base-score formula from the
        vector's metrics. Returns None for anything else (e.g. a CVSS v2
        vector, which uses a different metric set) rather than guessing.
        """
        try:
            return float(score)
        except ValueError:
            pass
        if score.startswith("CVSS:4"):
            # FIRST's reference algorithm, ported in rowan.cvss4 (SC-15).
            return cvss4.base_score(score)
        if not score.startswith("CVSS:3"):
            return None
        metrics = dict(part.split(":", 1) for part in score.split("/")[1:] if ":" in part)
        try:
            av = cls._CVSS3_AV[metrics["AV"]]
            ac = cls._CVSS3_AC[metrics["AC"]]
            ui = cls._CVSS3_UI[metrics["UI"]]
            scope_changed = metrics["S"] == "C"
            pr = (cls._CVSS3_PR_C if scope_changed else cls._CVSS3_PR_U)[metrics["PR"]]
            c = cls._CVSS3_CIA[metrics["C"]]
            i = cls._CVSS3_CIA[metrics["I"]]
            a = cls._CVSS3_CIA[metrics["A"]]
        except KeyError:
            return None

        iss = 1 - (1 - c) * (1 - i) * (1 - a)
        if scope_changed:
            impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15
        else:
            impact = 6.42 * iss
        if impact <= 0:
            return 0.0
        exploitability = 8.22 * av * ac * pr * ui
        raw = (impact + exploitability) * (1.08 if scope_changed else 1)
        return math.ceil(min(raw, 10.0) * 10) / 10

    def _apply_reachability(
        self,
        findings: list[Finding],
        target: Path,
        candidates: Iterable[Path] | None = None,
    ) -> None:
        """Mark each SCA finding reachable/unreachable via AST call-graph analysis.

        Reachable means: a vulnerable function of the flagged package is
        actually invoked somewhere in the codebase, verified through a real
        AST Call node whose receiver resolves (via import aliasing) back to
        that package -- not merely a substring match anywhere in the file
        (comments, docstrings, and unrelated same-named local functions no
        longer count).
        """
        py_files = self._collect_python_files(target, candidates)
        if not py_files:
            return
        resolved_calls = collect_reachable_calls(py_files)
        if not resolved_calls:
            return

        for f in findings:
            # A malicious package is dangerous by its mere presence -- there
            # is no "safe if the vulnerable function isn't called" for
            # deliberately-planted malware, so never downgrade it.
            if f.metadata.get("malicious"):
                continue
            # The call graph is Python-only; an npm `requests` must not be
            # judged by Python `requests.get()` calls (SC-10).
            if str(f.metadata.get("ecosystem", "")).lower() != "pypi":
                continue
            pkg = f.metadata.get("package", "")
            # Curated map first (hand-verified, highest precision); fall back
            # to per-CVE symbols mined from this advisory's own text for the
            # long tail of packages the map doesn't cover.
            vuln_funcs = get_vulnerable_functions(pkg)
            source = "curated"
            if not vuln_funcs:
                vuln_funcs = extract_vulnerable_symbols(f.metadata.get("details", ""), pkg)
                source = "advisory"
            if not vuln_funcs:
                # No vulnerable-function signal at all -> keep full severity
                # rather than guess (never a false downgrade).
                continue

            f.metadata["vuln_func_source"] = source
            # Record the exact candidates tested. This describes analysis
            # evidence; it does not claim that any candidate is reachable.
            f.metadata["vulnerable_symbols"] = list(vuln_funcs)
            reachable, evidence = is_package_reachable(pkg, vuln_funcs, resolved_calls)
            if reachable:
                f.metadata["reachability"] = "reachable"
                f.metadata["reachability_evidence"] = evidence
            else:
                # Absence from this narrow Python call-name index is not
                # proof that vulnerable code is never executed.  Dynamic
                # dispatch, instance methods, framework callbacks and calls
                # from dependency code are outside this analysis.  Preserve
                # the advisory severity and report an indeterminate result;
                # only a positive AST call is strong enough for reachability.
                f.metadata["reachability"] = "unknown"
                f.metadata["reachability_reason"] = "no_verified_call_in_application_index"

    def _detect_typosquatting(self, inventory) -> list[Finding]:
        """Flag declared packages one edit from a popular squat target."""
        findings: list[Finding] = []
        seen: set[tuple[str, str]] = set()
        for dep in inventory:
            name = dep.get("name", "")
            ecosystem = dep.get("ecosystem", "")
            key = (ecosystem, name.lower())
            if not name or key in seen:
                continue
            seen.add(key)
            popular = nearest_popular(name, ecosystem)
            if not popular:
                continue
            findings.append(
                Finding(
                    rule_id="SCA-TYPOSQUAT-001",
                    message=(
                        f"Possible typosquat: dependency '{name}' is one "
                        f"character from the popular package '{popular}' "
                        f"({ecosystem}). Verify it is the intended package."
                    ),
                    severity=Severity.MEDIUM,
                    category=Category.SUPPLY_CHAIN,
                    file_path="",
                    start_line=0,
                    confidence=0.5,
                    engine="depguard",
                    metadata={
                        "typosquat": True,
                        "package": name,
                        "ecosystem": ecosystem,
                        "resembles": popular,
                    },
                )
            )
        if findings:
            logger.info("SCAPass: %d possible typosquat(s) detected", len(findings))
        return findings

    def _scan_install_hooks(self, dep_files: list[Path]) -> list[Finding]:
        """Flag suspicious npm install lifecycle hooks in package.json files.

        Scans the pre-lockfile-preference file set: install hooks live in
        package.json, which `_prefer_lockfiles` may otherwise drop when a
        lockfile is present.
        """
        findings: list[Finding] = []
        for dep_file in dep_files:
            if dep_file.name != "package.json":
                continue
            content = self._read_text(dep_file)
            if content is None:
                continue
            try:
                data = json.loads(content)
            except json.JSONDecodeError:
                continue
            if not isinstance(data, dict):
                continue
            for hook in scan_install_hooks(data):
                findings.append(
                    Finding(
                        rule_id="SCA-INSTALL-001",
                        message=(
                            f"Suspicious npm '{hook.hook}' install hook "
                            f"({hook.reason}): {hook.command}"
                        ),
                        severity=Severity.HIGH,
                        category=Category.SUPPLY_CHAIN,
                        file_path=str(dep_file),
                        start_line=0,
                        confidence=0.7,
                        engine="depguard",
                        metadata={
                            "install_hook": hook.hook,
                            "reason": hook.reason,
                            "command": hook.command,
                        },
                    )
                )
        if findings:
            logger.info("SCAPass: %d suspicious install hook(s) detected", len(findings))
        return findings

    @staticmethod
    def _finding_cve(finding: Finding) -> str | None:
        """The CVE id for a finding, from its primary id or a CVE alias.

        OSV's primary id is frequently a GHSA/PYSEC id; EPSS only indexes
        CVEs, so fall back to the first CVE-shaped alias.
        """
        cve_id = finding.metadata.get("cve_id", "")
        if _CVE_RE.match(cve_id):
            return cve_id
        for alias in finding.metadata.get("aliases", []):
            if _CVE_RE.match(str(alias)):
                return str(alias)
        return None

    def _query_epss_batch(self, cves: list[str]) -> dict[str, dict[str, float]]:
        """Fetch EPSS score + percentile for a batch of CVEs.

        Best-effort enrichment: a network/parse error returns an empty map
        (the CVE simply carries no EPSS), never a degraded-scan marker --
        unlike an OSV failure, a missing EPSS score doesn't make the
        vulnerability results themselves incomplete.
        """
        scores: dict[str, dict[str, float]] = {}
        try:
            with self._network_slot():
                response = httpx.get(
                    self._epss_api_url, params={"cve": ",".join(cves)}, timeout=30
                )
            response.raise_for_status()
            for row in response.json().get("data", []):
                cve = row.get("cve")
                if not cve:
                    continue
                try:
                    scores[cve] = {
                        "epss": float(row.get("epss", 0.0)),
                        "percentile": float(row.get("percentile", 0.0)),
                    }
                except (TypeError, ValueError):
                    continue
        except (httpx.HTTPError, json.JSONDecodeError) as e:
            logger.warning("EPSS API error (enrichment skipped): %s", e)
        return scores

    def _apply_epss(self, findings: list[Finding]) -> None:
        """Attach EPSS exploit-probability scores to dependency CVE findings."""
        cve_by_finding: dict[int, str] = {}
        for f in findings:
            if f.engine != "depguard":
                continue
            cve = self._finding_cve(f)
            if cve:
                cve_by_finding[id(f)] = cve
        if not cve_by_finding:
            return

        unique_cves = sorted(set(cve_by_finding.values()))
        scores: dict[str, dict[str, float]] = {}
        for i in range(0, len(unique_cves), EPSS_BATCH_CHUNK_SIZE):
            scores.update(self._query_epss_batch(unique_cves[i:i + EPSS_BATCH_CHUNK_SIZE]))

        for f in findings:
            cve = cve_by_finding.get(id(f))
            if cve and cve in scores:
                f.metadata["epss"] = scores[cve]["epss"]
                f.metadata["epss_percentile"] = scores[cve]["percentile"]

    def _detect_phantom_dependencies(
        self,
        declared_pypi: set[str],
        target: Path,
        candidates: Iterable[Path] | None = None,
    ) -> list[Finding]:
        """Report third-party imports that no manifest/lockfile declares.

        Requires a Python baseline: if the project declares no PyPI packages
        at all, there is nothing to be "undeclared" *relative to* (the repo
        may simply have no Python manifest), so detection is skipped rather
        than flagging every import. Emits INFO-severity supply-chain
        findings -- a phantom dependency is a risk surface, not itself a
        confirmed vulnerability.
        """
        if not declared_pypi:
            return []
        py_files = self._collect_python_files(target, candidates)
        if not py_files:
            return []

        imported = collect_imported_modules(py_files)
        if not imported:
            return []
        local_modules = collect_local_module_names(
            target, py_files, authoritative=candidates is not None
        )
        phantoms = find_phantom_dependencies(imported, declared_pypi, local_modules)

        findings: list[Finding] = []
        for phantom in phantoms:
            findings.append(
                Finding(
                    rule_id="SCA-PHANTOM-001",
                    message=(
                        f"Phantom dependency: '{phantom.import_name}' is imported "
                        f"in code but not declared in any manifest or lockfile "
                        f"(likely PyPI package '{phantom.distribution}'). Its "
                        f"version is uncontrolled and it is invisible to "
                        f"manifest-based vulnerability scanning."
                    ),
                    severity=Severity.INFO,
                    category=Category.SUPPLY_CHAIN,
                    file_path="",
                    start_line=0,
                    confidence=0.6,
                    engine="depguard",
                    metadata={
                        "phantom_dependency": True,
                        "import_name": phantom.import_name,
                        "package": phantom.distribution,
                        "ecosystem": "PyPI",
                    },
                )
            )
        if findings:
            logger.info("SCAPass: %d phantom dependencies detected", len(findings))
        return findings

    @staticmethod
    def _collect_python_files(
        target: Path, candidates: Iterable[Path] | None = None
    ) -> list[Path]:
        skip_dirs = {".git", "node_modules", "venv", ".venv", "__pycache__", "dist", "build"}
        return [
            py_file
            for py_file in (target.rglob("*.py") if candidates is None else candidates)
            if not any(p in skip_dirs for p in _parts_under(py_file, target))
            and not (py_file.is_symlink() and not is_within_root(py_file, target))
            # A FIFO or device named *.py would hang the reachability read.
            and py_file.is_file()
        ]
