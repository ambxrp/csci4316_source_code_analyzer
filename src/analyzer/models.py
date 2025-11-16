import dataclasses
from dataclasses import dataclass, field
from typing import List, Literal, Optional

# Data Models (from Part 1)

# Defines severity levels
Severity = Literal["Low", "Medium", "High"]

@dataclass
class Options:
    # Configuration for a scan.
    path: str
    outputFormat: Literal["text", "json", "html"] = "text"
    rulesEnabled: List[str] = field(default_factory=list)
    severityThreshold: Severity = "Low"

@dataclass
class Finding:
    # A single vulnerability instance.
    id: str
    ruleId: str
    category: str
    severity: Severity
    file: str
    line: int
    message: str
    recommendation: str
    timestamp: str

@dataclass
class RunInfo:
    # Metadata about the scan run.
    toolVersion: str
    timestamp: str
    rootPath: str

@dataclass
class ScanResult:
    # The complete result of a scan.
    runInfo: RunInfo
    findings: List[Finding]

# Context for Rules (NEW IN PART 3)

@dataclass
class RuleContext:
    # Data passed to a rule during execution, providing
# context about the file being scanned.
    file_path: str
    file_content_lines: List[str]
    