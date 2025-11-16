import ast
from dataclasses import dataclass, field
from typing import List, Optional

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
            return ast.parse(file.content, filename=file.path)
        except SyntaxError as e:
            print(f"Syntax error in {file.path}: {e}")
            return None
        