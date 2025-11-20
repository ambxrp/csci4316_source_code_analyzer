import logging
from collections import Counter
from .models import ScanResult, Finding, Severity
import json
from dataclasses import asdict

logger = logging.getLogger(__name__)

class Reporter:
    # Formats a ScanResult into human-readable text.

    @staticmethod
    def toText(result: ScanResult) -> str:
        # Generates a complete, human-readable text report.
        logger.debug("Generating text report")
        findings = result.findings
        run_info = result.runInfo
        
        # Build Summary
        summary_lines = []
        summary_lines.append("=== Scan Summary ===")
        summary_lines.append(f"Path:     {run_info.rootPath}")
        summary_lines.append(f"Version:  {run_info.toolVersion}")
        summary_lines.append(f"Time:     {run_info.timestamp}")
        
        severity_counts = Counter(f.severity for f in findings)
        total = len(findings)
        high = severity_counts.get("High", 0)
        medium = severity_counts.get("Medium", 0)
        low = severity_counts.get("Low", 0)
        
        summary_lines.append(
            f"Findings: {total} (High: {high}, Medium: {medium}, Low: {low})"
        )

        # Build Detailed Findings
        detailed_lines = []
        detailed_lines.append("\n=== Detailed Findings ===")
        
        if not findings:
            detailed_lines.append("No findings.")
        else:
            # Sort by severity, then file, then line
            sorted_findings = sorted(
                findings, 
                key=lambda f: (
                    {"High": 1, "Medium": 2, "Low": 3}.get(f.severity, 4),
                    f.file,
                    f.line
                )
            )
            
            for f in sorted_findings:
                detailed_lines.append(
                    f"\n[{f.severity.upper()}] {f.ruleId}: {f.message}"
                )
                detailed_lines.append(
                    f"  -> {f.file}:{f.line}"
                )
                detailed_lines.append(
                    f"  >> {f.recommendation}"
                )
        
        return "\n".join(summary_lines + detailed_lines)
    
    @staticmethod
    def toJSON(result: ScanResult) -> str:
        """
        Generates a complete JSON report by serializing the ScanResult object.
        """
        logger.debug("Generating JSON report")
        
        # Convert the ScanResult dataclass instance (which contains nested dataclasses)
        # into a serializable dictionary structure.
        report_dict = asdict(result)
        
        # Calculate summary counts for the summary section
        findings = result.findings
        severity_counts = Counter(f.severity for f in findings)
        
        # Add a summary section to the root of the JSON for convenience
        report_dict['summary'] = {
            "Total": len(findings),
            "High": severity_counts.get("High", 0),
            "Medium": severity_counts.get("Medium", 0),
            "Low": severity_counts.get("Low", 0)
        }
        
        # Return the pretty-printed JSON string
        return json.dumps(report_dict, indent=4)