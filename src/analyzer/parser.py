import ast
import logging
from dataclasses import dataclass, field
from typing import List, Optional

logger = logging.getLogger(__name__)

# This is a minimal, functional implementation of Part 2's contract
# Your teammates can expand this file later.

@dataclass
class SourceFile:
    # A simple container for file data.
    path: str
    content: str
    lines: List[str] = field(init=False)

    def __post_init__(self):
        self.lines = self.content.splitlines()


class PythonParser:
    # Parses Python source code into an AST.
    
    def parse(self, file: SourceFile) -> Optional[ast.AST]:
        # Tries to parse file content into an AST.
        # Returns None on syntax error.
        try:
            logger.debug(f"Parsing file: {file.path}")
            return ast.parse(file.content, filename=file.path)
        except SyntaxError as e:
            logger.warning(f"Syntax error in {file.path} at line {e.lineno}: {e.msg}")
            return None
        except Exception as e:
            logger.error(f"Unexpected error parsing {file.path}: {e}", exc_info=True)
            return None
        