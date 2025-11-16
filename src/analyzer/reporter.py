# part 4
# app/Reporter.py
from datetime import datetime

class Reporter:
    def toText(self, res, opt):
        # 1. Count how many findings by severity
        severity_counts = {"High": 0, "Medium": 0, "Low": 0}
        for f in res.findings:
            if f.severity in severity_counts:
                severity_counts[f.severity] += 1

        # 2. Header info for the report
        lines = [
            "Source Code Analyzer Report",
            f"Version: {res.runInfo.toolVersion}",
            f"Scanned Path: {res.runInfo.rootPath}",
            f"Timestamp: {res.runInfo.timestamp}",
            "",
            f"Summary – High:{severity_counts['High']}  "
            f"Medium:{severity_counts['Medium']}  "
            f"Low:{severity_counts['Low']}",
            "-" * 60,
        ]

        # 3. Sort findings (High → Medium → Low)
        sev_order = {"High": 0, "Medium": 1, "Low": 2}
        sorted_findings = sorted(
            res.findings,
            key=lambda f: (sev_order.get(f.severity, 99), f.file, f.line),
        )

        # 4. Add each finding’s details
        for f in sorted_findings:
            lines += [
                f"[{f.severity}] {f.ruleId} {f.file}:{f.line}",
                f"  {f.message}",
                f"  Recommendation: {f.recommendation}",
                "",
            ]

        # 5. If there are no findings
        if not res.findings:
            lines.append("No findings detected.")

        # 6. Combine everything into one text string
        return "\n".join(lines)