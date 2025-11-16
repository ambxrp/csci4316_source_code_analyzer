import argparse
import sys
import logging
from pathlib import Path

from .models import Options
from .analyzer import Analyzer
from .reporter import Reporter

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger(__name__)

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
    
    try:
        args = parser.parse_args()
        
        # 1. Validate path exists
        target_path = Path(args.path)
        if not target_path.exists():
            logger.error(f"Path does not exist: {args.path}")
            print(f"Error: Path '{args.path}' does not exist.", file=sys.stderr)
            sys.exit(1)
        
        # 2. Validate path is a file or directory
        if not (target_path.is_file() or target_path.is_dir()):
            logger.error(f"Path is not a file or directory: {args.path}")
            print(f"Error: Path '{args.path}' is not a valid file or directory.", file=sys.stderr)
            sys.exit(1)
        
        # 3. For files, validate it's a Python file
        if target_path.is_file() and target_path.suffix != '.py':
            logger.error(f"File is not a Python file: {args.path}")
            print(f"Error: File '{args.path}' is not a Python file (.py).", file=sys.stderr)
            print("This analyzer only supports Python source code files.", file=sys.stderr)
            sys.exit(1)
        
        # 4. Create Options
        options = Options(path=args.path)
        
        logger.info(f"Starting scan on: {options.path}")
        
        # 5. Instantiate Analyzer
        analyzer = Analyzer()
        
        # 6. Call analyze
        result = analyzer.analyze(options)
        
        # 7. Call Reporter
        report_text = Reporter.toText(result)
        
        # 8. Print to stdout
        print("\n" + report_text)
        
        if len(result.findings) > 0:
            logger.info(f"Scan complete. Found {len(result.findings)} vulnerabilities.")
            sys.exit(1) # Exit with error code if findings exist
        else:
            logger.info("Scan complete. No vulnerabilities found.")
            sys.exit(0)
    
    except KeyboardInterrupt:
        logger.warning("Scan interrupted by user")
        print("\nScan interrupted by user.", file=sys.stderr)
        sys.exit(130)
    
    except Exception as e:
        logger.exception(f"Unexpected error during scan: {e}")
        print(f"\nError: An unexpected error occurred: {e}", file=sys.stderr)
        print("Please check the logs for more details.", file=sys.stderr)
        sys.exit(1)

if __name__ == "__main__":
    main()
    
