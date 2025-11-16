# Source Code Vulnerability Analyzer

A lightweight static analysis tool built for our Software Engineering course project. This tool scans Python source code for common security vulnerabilities, categorizes them by severity, and produces both summary and detailed reports.

---

## Project Overview

The analyzer reads source files or entire project directories, parses them into an Abstract Syntax Tree (AST), and runs a set of detection rules. Each finding is assigned a severity (High, Medium, Low) and written to a human-readable report. Future enhancements will support additional output formats (JSON, HTML) and expanded rule sets.

---

## Features (v1 scope)

* Analyze a single file or a full project directory
* Parse Python code into AST for more precise detection (fewer false positives)
* Apply a base set of vulnerability rules:

  * Hardcoded credentials
  * Dangerous `exec()` usage
  * Insecure SQL concatenation
  * Weak cryptography
  * Broad exception handling
* Assign and summarize findings by severity
* Generate text reports with both summary and detailed sections

---

## Planned Enhancements

* Optional output formats: JSON and HTML
* Support for custom rule sets
* Expanded rules beyond the base five

---

## Requirements → Features Mapping

| Requirement (from Needs Statement)                    | Implemented in UML / Code Design                      |
| ----------------------------------------------------- | ----------------------------------------------------- |
| Analyze files or full project directories             | `Analyzer.analyzeFile`, `Analyzer.analyzePath`        |
| Parse code into structured form (AST)                 | `Parser` / `PythonParser`                             |
| Detect 5 vulnerability categories                     | `Rule` subclasses (5 base rules)                      |
| Assign severity to findings                           | `Rule.severity`, `Finding.severity`                   |
| Generate human-readable report with summary + details | `Reporter.toText`, `ScanResult` + `Finding`           |
| Provide summary by severity and category              | `ScanResult.bySeverity()`, `byCategory()`             |
| Document rules with descriptions + recommendations    | `Rule.description`, `Rule.recommendation`             |
| Planned JSON/HTML outputs                             | `Reporter.toJSON`, `Reporter.toHTML`                  |
| Ensure repeatable/verifiable outputs                  | `RunInfo` metadata (timestamp, toolVersion, rootPath) |

---

## Project Structure (planned)

```
/src
  /cli          # Entry point & argument parsing
  /analyzer     # Core analyzer & file walker
  /parser       # AST parsing logic
  /rules        # Rule engine & individual rules
  /reporting    # Reporter & report formats
/tests          # Unit tests for components
```

---

## Getting Started

### Prerequisites

* Python 3.11+
* Git

### Clone the repository

```bash
git clone https://github.com/<your-org>/<your-repo>.git
cd <your-repo>
```

### Run the analyzer (once implemented)

```bash
python -m src.cli --path ./example_project --format text
```

---

## Team

This project is developed as a group assignment for our Software Engineering course. Each member contributes to analysis, design, coding, and documentation.

---
Contributions (Alejandra)

Alejandra implemented the final reporting and CLI functionality for the analyzer, including:
	•	Reporter and Final Wiring
	•	Developed Reporter.toText to generate human-readable reports from ScanResult.
	•	Reports include header metadata (tool version, scanned path, timestamp), summary counts by severity (High / Medium / Low), and detailed findings with severity, rule ID, file, line number, message, and recommendation.
	•	Integrated Reporter into AnalyzerService.format_report_text for consistent use in both CLI and Streamlit UI.
	•	Sorted findings deterministically for stable and verifiable outputs.
	•	Command-Line Interface (cli.py)
	•	Provides an interface to scan a single file or an entire project directory.
	•	Outputs human-readable text reports in the terminal.
	•	Uses the same backend (AnalyzerService) as the UI for consistency.
	•	Analyzer Enhancements (analyzer.py)
	•	Implemented file discovery for single files and directories, returning a ScanResult skeleton with RunInfo.
	•	Prepares the pipeline for future rule evaluation and parsing.
	•	Integrated with AnalyzerService.run_scan to support end-to-end scanning from CLI or UI.
	•	Integration
	•	Ensured that CLI, UI, and reporting all use the same AnalyzerService backend.
	•	Enabled the “Download Report” button in the UI to share the same reporting logic as the CLI.
## License

Educational use only. Not intended for production security auditing.
