"""Finding and severity models for Rowan."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class Category(str, Enum):
    INJECTION = "injection"
    DESERIALIZATION = "deserialization"
    SSRF = "ssrf"
    SSTI = "ssti"
    XSS = "xss"
    COMMAND_INJECTION = "command_injection"
    PATH_TRAVERSAL = "path_traversal"
    SECRETS = "secrets"
    SUPPLY_CHAIN = "supply_chain"
    AI_ML = "ai_ml"
    PROMPT_INJECTION = "prompt_injection"
    NOSQL_INJECTION = "nosql_injection"
    PROTOTYPE_POLLUTION = "prototype_pollution"
    AUTH = "auth"
    CRYPTO = "crypto"
    CONFIG = "config"
    GENERAL = "general"


@dataclass
class TaintNode:
    """A single node in a taint flow path."""

    file_path: str
    line: int
    column: int | None = None
    snippet: str = ""


@dataclass
class TaintFlow:
    """Complete taint flow from source to sink."""

    source: TaintNode | None = None
    sink: TaintNode | None = None
    intermediate: list[TaintNode] = field(default_factory=list)
    sanitizers: list[str] = field(default_factory=list)


@dataclass
class Finding:
    """A single vulnerability finding."""

    rule_id: str
    message: str
    severity: Severity
    category: Category
    file_path: str
    start_line: int
    end_line: int | None = None
    start_column: int | None = None
    end_column: int | None = None
    confidence: float = 1.0
    cwe_ids: list[int] = field(default_factory=list)
    owasp_ids: list[str] = field(default_factory=list)
    taint_flow: TaintFlow | None = None
    metadata: dict[str, Any] = field(default_factory=dict)
    engine: str = ""  # "neuroscan", "opengrep", "depguard"

    @property
    def severity_order(self) -> int:
        order = {Severity.CRITICAL: 0, Severity.HIGH: 1, Severity.MEDIUM: 2, Severity.LOW: 3, Severity.INFO: 4}
        return order.get(self.severity, 5)

    def reported_rule_ids(self) -> set[str]:
        """This finding's rule plus any rules merged into it as duplicates."""
        return {self.rule_id, *self.metadata.get("duplicate_rule_ids", ())}

    def match_key(self) -> tuple[str, str, int, str]:
        """Key for deduplication: (file, rule, start_line, category)."""
        return (self.file_path, self.rule_id, self.start_line, self.category.value)


@dataclass
class ScanResult:
    """Aggregate result of a scan run."""

    findings: list[Finding] = field(default_factory=list)
    files_scanned: int = 0
    duration_seconds: float = 0.0
    errors: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)
    degraded_passes: dict[str, str] = field(default_factory=dict)

    def add_finding(self, finding: Finding) -> None:
        self.findings.append(finding)

    def add_findings(self, findings: list[Finding]) -> None:
        self.findings.extend(findings)

    def merge(self, other: ScanResult) -> None:
        self.findings.extend(other.findings)
        # file_scan reports the full file set; other passes report subsets of it,
        # so the scanned-file count is the max across passes, not the sum
        # (summing double-counts the same files).
        self.files_scanned = max(self.files_scanned, other.files_scanned)
        self.errors.extend(other.errors)
        self.metadata.update(other.metadata)
        self.degraded_passes.update(other.degraded_passes)

    @property
    def degraded(self) -> bool:
        return bool(self.degraded_passes)

    @property
    def critical_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.CRITICAL)

    @property
    def high_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.HIGH)

    @property
    def medium_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.MEDIUM)

    @property
    def low_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.LOW)

    @property
    def total_count(self) -> int:
        return len(self.findings)

    @property
    def sca_count(self) -> int:
        """Findings from the dependency-CVE (SCA) engine, not code analysis."""
        return sum(1 for f in self.findings if f.engine == "depguard")

    @property
    def code_count(self) -> int:
        """Findings from code-analysis engines (everything but SCA)."""
        return self.total_count - self.sca_count

    def summary(self) -> str:
        return (
            f"Findings: {self.total_count} total "
            f"({self.critical_count} critical, {self.high_count} high, "
            f"{self.medium_count} medium, {self.low_count} low) | "
            f"Files: {self.files_scanned} | Duration: {self.duration_seconds:.1f}s"
        )
