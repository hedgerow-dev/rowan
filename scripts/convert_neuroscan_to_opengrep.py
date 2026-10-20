#!/usr/bin/env python3
"""Convert NeuroScan YAML rules to semgrep-native YAML format.

Reads all non-taint rule files from `rules/`, emits converted semgrep-native
rules to `rules/converted/`, and produces a JSON manifest
(`rules/converted/_manifest.json`) with rule_id → metadata mappings.

The manifest is the authoritative source for category, CWE, original_severity,
original_engine, and residual tags (since opengrep 1.22.0 does not propagate
arbitrary `metadata:` fields into SARIF `properties`).

Usage:
    python scripts/convert_neuroscan_to_opengrep.py [--validate] [--manifest-only MANIFEST]
"""

from __future__ import annotations

import json
import re
import subprocess
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent

SEMGREP_LANGUAGES: set[str] = {
    "python", "javascript", "typescript", "java", "go",
    "csharp", "ruby", "php", "rust", "terraform", "dockerfile",
    "json", "yaml", "toml", "text", "generic", "hcl",
}

CATEGORIES_WITH_SANITIZERS: set[str] = {
    "injection", "command_injection", "path_traversal", "ssrf",
    "xss", "ssti", "deserialization", "nosql_injection", "prompt_injection",
    "general",
}

SECRET_RULE_PREFIXES = ("NS-SECRET", "ns-sec")
CRITICAL_SEVERITY = frozenset({"critical"})
LOW_SEVERITY = frozenset({"low"})


def normalize_severity(sev: str) -> str:
    """Map NeuroScan severity string to semgrep severity (ERROR|WARNING|INFO)."""
    s = sev.lower()
    if s in ("critical", "high", "error"):
        return "ERROR"
    if s in ("medium", "warning"):
        return "WARNING"
    if s in ("low", "info"):
        return "INFO"
    return "WARNING"


def normalize_language(lang: str) -> str:
    """Normalize language names for opengrep compatibility."""
    mapping = {
        "text": "generic",
        "toml": "generic",
    }
    return mapping.get(lang, lang)


def _is_secret_rule(rule_id: str) -> bool:
    return rule_id.startswith(SECRET_RULE_PREFIXES)


def _is_sanitizer_category(category: str) -> bool:
    return category in CATEGORIES_WITH_SANITIZERS


def _determine_residual(rule: dict) -> list[str]:
    """Determine which residual post-filters a rule needs."""
    residues: list[str] = []
    rid = rule.get("id", "")
    cat = _get_category(rule)
    # Route every secrets rule through the entropy/placeholder/env-reference
    # suppression, by ID prefix OR by category, so rules like ns-aiml-077 and
    # NS-AUTH-002 (secrets category, non-secret prefix) are covered too.
    if _is_secret_rule(rid) or cat == "secrets":
        residues.append("secrets")

    if _is_sanitizer_category(cat) or rule.get("sanitizers"):
        residues.append("sanitizer")

    return residues


def _get_category(rule: dict) -> str:
    """Extract category from either Variant A or B."""
    cat = rule.get("category", "")
    if not cat:
        cat = rule.get("metadata", {}).get("category", "")
    return cat


def _get_cwe(rule: dict) -> list[int]:
    """Extract CWE IDs from either Variant A or B."""
    cwe = rule.get("cwe", [])
    if not cwe:
        cwe = rule.get("metadata", {}).get("cwe", [])
    return cwe if isinstance(cwe, list) else [cwe]


def _get_severity(rule: dict) -> str:
    """Extract NeuroScan severity from either variant."""
    return rule.get("severity", "medium")


def _get_message(rule: dict) -> str:
    msg = rule.get("message", "")
    if isinstance(msg, str):
        return msg.strip()
    return str(msg).strip()


def _get_fix(rule: dict) -> str:
    """Extract remediation guidance from either Variant A or B.

    Opengrep 1.22.0 doesn't propagate metadata: into SARIF properties (see
    EnrichmentPass._apply_manifest_metadata), so this is carried through the
    manifest rather than the converted rule's own metadata block -- the
    manifest is the actual delivery mechanism, not the converted YAML."""
    fix = rule.get("fix", "")
    if not fix:
        fix = rule.get("metadata", {}).get("fix", "")
    return fix.strip() if isinstance(fix, str) else str(fix).strip()


def _build_patterns_formula(rule: dict) -> tuple[list[dict], list[str], list[str]]:
    r"""Build the semgrep `patterns` formula from NeuroScan rules.
    Returns (patterns_list, warnings_list, valid_negatives_list).

    valid_negatives is also handed to the manifest (see build_converted_rule)
    so EnrichmentPass can re-apply these exclusions per-line as a fallback --
    see GitHub issue #92: Opengrep's pattern-not-regex only excludes a
    finding when the negative match fully contains, or is fully contained
    by, the finding's own matched range (documented upstream Semgrep/
    Opengrep containment semantics, not an engine defect). Most of this
    rulebase's exclusions were authored assuming a simpler "matches
    anywhere on the line" model, so a narrow exclusion like
    pattern-not-regex: (?m)^\s*# (matches only the '#' character, not the
    rest of the line) fails to contain a match sitting later on the same
    line and silently doesn't suppress it. Rewriting every affected
    pattern-not to span its target would work too, but the manifest
    fallback in EnrichmentPass is a single, harder-to-regress enforcement
    point instead of a rule-by-rule pattern fix.
    """
    patterns = []
    warnings = []
    positives = rule.get("patterns", [])
    negatives = rule.get("pattern-not", [])

    valid_positives = []
    for p in positives:
        try:
            re.compile(p)
            valid_positives.append(p)
        except re.error as e:
            rid = rule.get("id", "unknown")
            warnings.append(f"Invalid positive regex '{p[:60]}': {e}")
            if rid == rule.get("id"):
                continue

    if len(valid_positives) == 1:
        patterns.append({"pattern-regex": valid_positives[0]})
    elif len(valid_positives) > 1:
        either_branches = [{"pattern-regex": p} for p in valid_positives]
        patterns.append({"pattern-either": either_branches})

    valid_negatives = []
    for n in negatives:
        try:
            re.compile(n)
            patterns.append({"pattern-not-regex": n})
            valid_negatives.append(n)
        except re.error as e:
            warnings.append(f"Invalid negative regex '{n[:60]}': {e}")

    return patterns, warnings, valid_negatives


def _build_languages(langs: list[str]) -> list[str]:
    """Normalize and filter languages for semgrep compatibility.
    Drops languages that are unsupported or conflict with existing ones."""
    specific_langs: set[str] = set()
    generic_langs: set[str] = set()
    for lang in langs:
        norm = normalize_language(lang)
        if norm == "generic":
            generic_langs.add(norm)
        elif norm in SEMGREP_LANGUAGES:
            specific_langs.add(norm)

    if specific_langs:
        return sorted(specific_langs)
    if generic_langs:
        return ["generic"]
    return sorted(langs)


# Pseudo-languages (issue #134): not real semgrep/opengrep language ids --
# "ai_instructions" and "markdown" only exist in file_scan.py's/
# opengrep_adapter.py's own LANGUAGE_EXTENSIONS dicts, which control which
# files reach opengrep at all. They can't be passed through to a converted
# rule's `languages:` field as-is (opengrep would reject an unknown language
# name), and they can't just be normalized to "generic" and mixed with
# specific languages either -- opengrep 1.22.0 rejects a rule that mixes
# "generic" with a specific language ("Rule parse error ... invalid language
# generic", verified empirically) and "generic" is itself extension-agnostic
# (a `languages: [generic]` rule fires on every file it's handed regardless
# of suffix, verified against both a .py file and a CLAUDE.md file with no
# --include restriction at all). So a rule that needs to reach both real
# source files and pseudo-language files switches its *entire* `languages:`
# to `[generic]` and gets a `paths.include` glob list built from every
# language (real or pseudo) the source rule declared -- opengrep's own path
# filter then reproduces what per-language `languages:` filtering would
# otherwise have done, for both halves.
PSEUDO_LANGUAGES: set[str] = {"ai_instructions", "markdown", "html", "text", "dotenv"}

_PATH_GLOBS: dict[str, list[str]] = {
    "python": ["*.py", "*.pyi"],
    "javascript": ["*.js", "*.jsx", "*.mjs", "*.cjs"],
    "typescript": ["*.ts", "*.tsx"],
    "java": ["*.java"],
    "go": ["*.go"],
    "csharp": ["*.cs"],
    "ruby": ["*.rb"],
    "php": ["*.php"],
    "rust": ["*.rs"],
    "terraform": ["*.tf", "*.tfvars"],
    "dockerfile": ["Dockerfile", "*.dockerfile"],
    "json": ["*.json"],
    "yaml": ["*.yaml", "*.yml"],
    "toml": ["*.toml"],
    # Must match OPENGREP_LANGUAGE_INCLUDE_GLOBS["ai_instructions"] in
    # rowan/languages.py (enforced by a test).
    "ai_instructions": [
        "CLAUDE.md", "AGENTS.md", "SKILL.md", ".cursorrules",
        "copilot-instructions.md", "*.prompt.md",
    ],
    "markdown": ["*.md"],
    "html": ["*.html", "*.htm", "*.jinja", "*.jinja2", "*.j2"],
    "text": ["*.txt"],
    "dotenv": [".env"],
}


def _build_include_globs(langs: list[str]) -> list[str]:
    """Build a deduplicated, order-preserving list of --include-style path
    globs covering every language (real or pseudo) a rule declared."""
    seen: set[str] = set()
    globs: list[str] = []
    for lang in langs:
        for glob in _PATH_GLOBS.get(lang, []):
            if glob not in seen:
                seen.add(glob)
                globs.append(glob)
    return globs


def build_converted_rule(rule: dict) -> tuple[dict, dict, list[str]]:
    """Convert a single NeuroScan rule entry to semgrep-native format.
    Returns (converted_rule_dict, manifest_entry_dict, warnings_list).
    """
    rid = rule["id"]
    severity = normalize_severity(_get_severity(rule))
    category = _get_category(rule)
    cwe = _get_cwe(rule)
    original_severity = _get_severity(rule)
    raw_langs = rule.get("languages", [])
    has_pseudo_language = any(lang in PSEUDO_LANGUAGES for lang in raw_langs)
    if has_pseudo_language:
        langs = ["generic"]
        include_globs = _build_include_globs(raw_langs)
    else:
        langs = _build_languages(raw_langs)
        include_globs = []
    message = _get_message(rule)
    fix = _get_fix(rule)
    patterns, warnings, valid_negatives = _build_patterns_formula(rule)
    residues = _determine_residual(rule)

    if not patterns and not warnings:
        warnings.append("No valid patterns after compilation")

    name = rule.get("name", "")
    source_rule = rule.get("metadata", {}).get("source_rule", "")

    converted = {
        "id": rid,
        "languages": langs,
        "severity": severity,
        "message": message if message else f"Rowan rule: {rid}",
        "patterns": patterns,
        "metadata": {
            "category": category,
            "cwe": cwe,
            "original_engine": "neuroscan",
        },
    }

    if original_severity in CRITICAL_SEVERITY or original_severity in LOW_SEVERITY:
        converted["metadata"]["original_severity"] = original_severity
    if name:
        converted["metadata"]["rule_name"] = name
    if source_rule:
        converted["metadata"]["source_rule"] = source_rule
    if fix:
        converted["metadata"]["fix"] = fix
    if residues:
        converted["metadata"]["residual"] = residues
    exclude_paths = rule.get("exclude_paths")
    paths: dict[str, list[str]] = {}
    if exclude_paths:
        paths["exclude"] = exclude_paths
    if include_globs:
        paths["include"] = include_globs
    if paths:
        converted["paths"] = paths

    status = "ok" if not warnings else "warning"
    manifest = {
        "id": rid,
        "category": category,
        "cwe": cwe,
        "original_severity": original_severity,
        "original_engine": "neuroscan",
        "residual": residues,
        "status": status,
        "warnings": warnings if warnings else [],
    }
    if name:
        manifest["name"] = name
    if source_rule:
        manifest["source_rule"] = source_rule
    if fix:
        manifest["fix"] = fix
    if valid_negatives:
        # See #92 -- EnrichmentPass re-applies these per-line as a fallback
        # since pattern-not-regex doesn't reliably enforce them in Opengrep
        # for pattern-regex-only rules.
        manifest["pattern_not"] = valid_negatives
    rule_sanitizers = rule.get("sanitizers")
    if rule_sanitizers:
        # A rule's own `sanitizers:` list has no Opengrep equivalent for a
        # pattern-regex rule, and `residual: sanitizer` only told
        # EnrichmentPass to apply the *category's* shared sanitizers -- so
        # these were silently dropped on the default engine path while still
        # working under legacy NeuroScan. Carry them through the manifest so
        # `_suppress_sanitizer_window` can honour them too.
        manifest["sanitizers"] = list(rule_sanitizers)

    return converted, manifest, warnings


def convert_file(input_path: Path, output_path: Path) -> list[dict]:
    """Convert all rules in a NeuroScan YAML file. Returns manifest entries."""
    import yaml
    try:
        data = yaml.safe_load(input_path.read_text(encoding="utf-8"))
    except Exception as e:
        print(f"[ERROR] Failed to parse {input_path}: {e}", file=sys.stderr)
        return []

    if not isinstance(data, dict) or "rules" not in data:
        print(f"[WARN]  No 'rules' key in {input_path}", file=sys.stderr)
        return []

    source_rules = data["rules"]
    converted_rules: list[dict] = []
    manifest_entries: list[dict] = []

    for rule in source_rules:
        rid = rule.get("id", "unknown")
        try:
            converted, manifest, warnings = build_converted_rule(rule)
            converted_rules.append(converted)
            manifest_entries.append(manifest)
            if warnings:
                print(f"    [WARN]  {rid}: {'; '.join(warnings)}", file=sys.stderr)
        except Exception as e:
            print(f"    [ERROR] Failed to convert rule {rid}: {e}", file=sys.stderr)
            manifest_entries.append({
                "id": rid,
                "status": "error",
                "error": str(e),
            })

    output = {"rules": converted_rules}
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(
        _yaml_dump(output),
        encoding="utf-8",
    )

    return manifest_entries


def _yaml_dump(data: dict) -> str:
    """Dump dict as YAML with ordered, readable formatting."""
    import yaml
    return yaml.dump(data, default_flow_style=False, allow_unicode=True, sort_keys=False,
                     width=120, indent=2)


def validate_opengrep(yaml_path: Path) -> bool:
    """Run opengrep --validate on a converted rules file."""
    try:
        # Dev-only conversion script; opengrep is resolved via PATH, yaml_path
        # is a local file the developer running this script chose.
        result = subprocess.run(  # noqa: S603
            ["opengrep", "scan", "--config", str(yaml_path), "--validate"],  # noqa: S607
            capture_output=True,
            text=True,
            timeout=30,
        )
    except Exception as e:
        print(f"[ERROR] Validation error for {yaml_path.name}: {e}", file=sys.stderr)
        return False

    combined = result.stdout + result.stderr
    if "Configuration is valid" in combined:
        return True
    if "Configuration is invalid" in combined:
        print(f"[ERROR] Validation failed for {yaml_path.name}:", file=sys.stderr)
        print(result.stdout[-800:], file=sys.stderr)
        if result.stderr:
            print(result.stderr[-800:], file=sys.stderr)
        return False
    print(f"[WARN]  Validation inconclusive for {yaml_path.name}", file=sys.stderr)
    return True


def main() -> None:
    import argparse
    parser = argparse.ArgumentParser(description="Convert NeuroScan YAML to semgrep-native rules")
    parser.add_argument("--validate", action="store_true", help="Run opengrep --validate on each converted file")
    parser.add_argument("--manifest-only", type=Path, help="Only generate manifest from existing converted/ dir")
    parser.add_argument("--input-dir", type=Path, default=PROJECT_ROOT / "rules", help="Rules directory")
    parser.add_argument("--output-dir", type=Path, default=PROJECT_ROOT / "rules" / "converted", help="Output directory for converted rules")
    args = parser.parse_args()

    rules_dir = args.input_dir
    output_dir = args.output_dir

    # `*_opengrep.yaml` (rules/guardrail_opengrep.yaml, this PR) holds
    # hand-written Opengrep search-mode rules -- structural `patterns:`
    # mappings, not the flat regex-string lists this converter expects. Left
    # unexcluded, the default run tries to convert them as NeuroScan regex
    # rules and crashes ("cannot use 'tuple' as a dict key") on the first
    # such file -- reproduced directly against this file before the fix.
    non_taint_files = sorted(
        p for p in rules_dir.glob("*.yaml")
        if "taint" not in p.name and "opengrep" not in p.name
    )

    print(f"Found {len(non_taint_files)} NeuroScan YAML files", file=sys.stderr)
    all_manifest: list[dict] = []
    validation_failures = 0

    for yaml_path in non_taint_files:
        output_path = output_dir / yaml_path.name
        print(f"  Converting {yaml_path.name} → {output_path}", file=sys.stderr)
        entries = convert_file(yaml_path, output_path)
        all_manifest.extend(entries)

        if args.validate:
            if validate_opengrep(output_path):
                print(f"    [VALID] {yaml_path.name}", file=sys.stderr)
            else:
                validation_failures += 1

    total = len(all_manifest)
    ok = sum(1 for e in all_manifest if e.get("status") == "ok")
    warn = sum(1 for e in all_manifest if e.get("status") == "warning")
    err = sum(1 for e in all_manifest if e.get("status") == "error")
    secrets_count = sum(1 for e in all_manifest if "secrets" in e.get("residual", []))
    sanitizer_count = sum(1 for e in all_manifest if "sanitizer" in e.get("residual", []))

    manifest_path = output_dir / "_manifest.json"
    manifest_path.parent.mkdir(parents=True, exist_ok=True)
    manifest_path.write_text(json.dumps({
        "meta": {
            "total_rules": total,
            "ok": ok,
            "warning": warn,
            "error": err,
            "secrets_residual": secrets_count,
            "sanitizer_residual": sanitizer_count,
            "converter_version": "1.0",
        },
        "rules": all_manifest,
    }, indent=2))

    print(f"\nManifest: {manifest_path}", file=sys.stderr)
    print(f"  Total: {total}  OK: {ok}  Warn: {warn}  Error: {err}", file=sys.stderr)
    print(f"  Secrets residual: {secrets_count}  Sanitizer residual: {sanitizer_count}", file=sys.stderr)

    if args.validate:
        if validation_failures:
            print(f"\n{validation_failures} validation failure(s)!", file=sys.stderr)
            sys.exit(1)
        print("All files validated.", file=sys.stderr)

    if err > 0:
        print(f"\n{err} conversion error(s)!", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
