# part 4
import argparse
from services.analyzer_service import AnalyzerService
from reporting.reporter import Reporter

def main():
    parser = argparse.ArgumentParser(
        description="🔍 Python Source Code Vulnerability Scanner (CLI)"
    )
    parser.add_argument(
        "--path",
        required=True,
        help="Path to a single Python file or a directory to scan"
    )
    parser.add_argument(
        "--format",
        choices=["text", "json"],
        default="text",
        help="Output format for the report (default: text)"
    )
    parser.add_argument(
        "--output",
        help="Optional path to save the report output"
    )

    args = parser.parse_args()

    # Create analyzer and scan
    service = AnalyzerService()
    scan_result = service.run_scan(args.path)

    # Generate report
    reporter = Reporter()
    report = reporter.generate_report(scan_result, output_format=args.format)

    # Output or save report
    if args.output:
        with open(args.output, "w") as f:
            f.write(report)
        print(f"✅ Report saved to {args.output}")
    else:
        print(report)


if __name__ == "__main__":
    main()