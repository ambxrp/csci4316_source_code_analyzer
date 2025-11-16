import datetime
import ast
import logging
from typing import List
from pathlib import Path

# Import models (P1/P3)
from .models import Options, ScanResult, RunInfo, RuleContext, Finding

# Import Parser (P2)
from .parser import PythonParser, SourceFile

logger = logging.getLogger(__name__) 

# Import Engine and Rules (P3/P4)
from .engine import RuleEngine
from .rules import (
    ExecRule, 
    BroadExceptionRule,
    InsecureSQLConcatRule,
    HardcodedCredRule,
    WeakCryptoRule
)

# Tool version
TOOL_VERSION = "1.0.0"

class Analyzer:
    # Orchestrates the scan:
    # 1. Handles file/directory paths (P4)
    # 2. Reads files (P2)
    # 3. Parses files (P2)
    # 4. Runs the rule engine (P3)
    # 5. Returns the result
    
    def __init__(self):
        self.parser = PythonParser()
        self.rule_engine = RuleEngine()
        self._register_default_rules()

    def _register_default_rules(self) -> None:
        # Registers all 5 rules for P3 and P4.
        # Part 3 Rules
        self.rule_engine.register_rule(ExecRule())
        self.rule_engine.register_rule(BroadExceptionRule())
        # Part 4 Rules
        self.rule_engine.register_rule(InsecureSQLConcatRule())
        self.rule_engine.register_rule(HardcodedCredRule())
        self.rule_engine.register_rule(WeakCryptoRule())

    def _analyze_file(self, file_path: Path) -> List[Finding]:
        # Helper to scan a single file.
        logger.debug(f"Analyzing file: {file_path}")
        
        # Validate that the file is a Python file
        if file_path.suffix != '.py':
            logger.warning(f"Skipping non-Python file: {file_path}")
            return []
        
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
        except IOError as e:
            logger.error(f"IO error reading file {file_path}: {e}")
            return []
        except UnicodeDecodeError as e:
            logger.error(f"Unicode decode error in file {file_path}: {e}")
            return []
        except Exception as e:
            logger.error(f"Unexpected error reading file {file_path}: {e}", exc_info=True)
            return []

        source_file = SourceFile(path=str(file_path), content=content)

        ast_node = self.parser.parse(source_file)
        if ast_node is None:
            # Parse failed (e.g., syntax error)
            return []
            
        rule_context = RuleContext(
            file_path=str(file_path.resolve()),
            file_content_lines=source_file.lines
        )
        
        return self.rule_engine.process(ast_node, rule_context)

    def analyze(self, options: Options) -> ScanResult:
        # Runs a scan based on the provided options.
        
        run_info = RunInfo(
            toolVersion=TOOL_VERSION,
            timestamp=datetime.datetime.now(datetime.timezone.utc).isoformat(),
            rootPath=options.path
        )
        
        all_findings: List[Finding] = []
        p = Path(options.path)

        if not p.exists():
            logger.error(f"Path does not exist: {options.path}")
            return ScanResult(runInfo=run_info, findings=[])

        if p.is_dir():
            # Part 4: Directory scanning
            logger.info(f"Scanning directory: {p}")
            files_to_scan = list(p.rglob('*.py'))
            run_info.rootPath = str(p.resolve())
            logger.info(f"Found {len(files_to_scan)} Python file(s) to scan")
        elif p.is_file():
            # Part 2: Single file scan
            logger.info(f"Scanning single file: {p}")
            files_to_scan = [p]
            run_info.rootPath = str(p.parent.resolve())
        else:
            logger.error(f"Path is not a file or directory: {p}")
            return ScanResult(runInfo=run_info, findings=[])

        for idx, file_path in enumerate(files_to_scan, 1):
            logger.debug(f"Processing file {idx}/{len(files_to_scan)}: {file_path}")
            all_findings.extend(self._analyze_file(file_path))
        
        return ScanResult(
            runInfo=run_info,
            findings=all_findings
        )
        
