import argparse
import sys

from .models import Options
from .analyzer import Analyzer
from .reporter import Reporter

def main():
    # Main CLI entry point for the scanner.
    parser = argparse.ArgumentParser(
        description="Source Code Vulnerability Analyzer"
    )
    parser.add_argument(
        "path", 
        help="The file or directory path to scan."
    )
    
    if len(sys.argv) == 1:
        parser.print_help(sys.stderr)
        sys.exit(1)
        
    args = parser.parse_args()
    
    # 1. Create Options
    options = Options(path=args.path)
    
    print(f"[CLI] Starting scan on: {options.path}")
    
    # 2. Instantiate Analyzer
    analyzer = Analyzer()
    
    # 3. Call analyze
    result = analyzer.analyze(options)
    
    # 4. Call Reporter
    report_text = Reporter.toText(result)
    
    # 5. Print to stdout
    print("\n" + report_text)
    
    if len(result.findings) > 0:
        print("\n[CLI] Scan complete. Vulnerabilities found.")
        sys.exit(1) # Exit with error code if findings exist
    else:
        print("\n[CLI] Scan complete. No vulnerabilities found.")
        sys.exit(0)

if __name__ == "__main__":
    main()
    
