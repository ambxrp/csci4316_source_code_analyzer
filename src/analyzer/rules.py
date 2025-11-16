import ast
import uuid
import datetime
import re
from abc import ABC, abstractmethod
from typing import List, Optional

# Import our models
from .models import Finding, RuleContext, Severity

# Abstract Base Class (New in Part 3)

class Rule(ABC, ast.NodeVisitor):
# Abstract Base Class for all vulnerability rules.
# Inherits from ast.NodeVisitor to traverse the AST.
    
    def __init__(self):
        self.findings: List[Finding] = []
        # The engine will set this context before visiting
        self.context: Optional[RuleContext] = None

    @property
    @abstractmethod
    def RULE_ID(self) -> str:
        # A unique identifier for the rule.
        pass

    @property
    @abstractmethod
    def SEVERITY(self) -> Severity:
        # The severity of findings from this rule.
        pass

    @property
    @abstractmethod
    def CATEGORY(self) -> str:
        # The category of vulnerability (e.g., 'Dangerous Function').
        pass

    @property
    @abstractmethod
    def MESSAGE(self) -> str:
        # The main message for the finding.
        pass
        
    @property
    @abstractmethod
    def RECOMMENDATION(self) -> str:
        # The suggested fix for the finding.
        pass

    def _create_finding(self, line: int, custom_message: str = "") -> None:
        # Helper to create a new Finding object and add it.
        if not self.context:
            raise ValueError("RuleContext not set by the engine.")
            
        finding = Finding(
            id=str(uuid.uuid4()),
            ruleId=self.RULE_ID,
            category=self.CATEGORY,
            severity=self.SEVERITY,
            file=self.context.file_path,
            line=line,
            message=custom_message or self.MESSAGE,
            recommendation=self.RECOMMENDATION,
            timestamp=datetime.datetime.now(datetime.timezone.utc).isoformat()
        )
        self.findings.append(finding)

# Part 3 Rules

class ExecRule(Rule):
    # Detects the use of 'exec' and 'eval'.
    RULE_ID = "PY-101"
    SEVERITY = "High"
    CATEGORY = "Dangerous Function"
    MESSAGE = "Use of 'exec' or 'eval' function detected."
    RECOMMENDATION = "Avoid 'exec' and 'eval'. Use safer alternatives like 'ast.literal_eval' for data."

    def visit_Call(self, node: ast.Call):
        func_name = ""
        if isinstance(node.func, ast.Name):
            func_name = node.func.id

        if func_name == 'exec':
            self._create_finding(line=node.lineno, custom_message="Use of 'exec' function detected.")
        elif func_name == 'eval':
            self._create_finding(line=node.lineno, custom_message="Use of 'eval' function detected.")
        
        self.generic_visit(node)

class BroadExceptionRule(Rule):
    # Detects broad exception handlers like 'except Exception:'.
    RULE_ID = "PY-102"
    SEVERITY = "Medium"
    CATEGORY = "Code Quality"
    MESSAGE = "Broad exception handler detected (e.g., 'except Exception')."
    RECOMMENDATION = "Catch more specific exceptions to avoid unintentionally hiding unrelated errors."

    def visit_Try(self, node: ast.Try):
        broad_exception_names = ('Exception', 'BaseException')
        
        for handler in node.handlers:
            if isinstance(handler.type, ast.Name) and handler.type.id in broad_exception_names:
                self._create_finding(line=handler.lineno)
            elif isinstance(handler.type, ast.Tuple):
                for extype in handler.type.elts:
                    if isinstance(extype, ast.Name) and extype.id in broad_exception_names:
                        self._create_finding(line=extype.lineno)
                        break 
        
        self.generic_visit(node)

# Part 4 Rules

class InsecureSQLConcatRule(Rule):
    # Detects f-string or '+' concatenation in SQL strings.
    RULE_ID = "PY-201"
    SEVERITY = "High"
    CATEGORY = "SQL Injection"
    MESSAGE = "Insecure SQL string concatenation detected."
    RECOMMENDATION = "Use parameterized queries (e.g., 'cursor.execute(query, params)') to prevent SQL injection."

    SQL_KEYWORDS = re.compile(r'\b(SELECT|INSERT|UPDATE|DELETE|FROM|WHERE)\b', re.IGNORECASE)

    def _contains_sql(self, node: ast.AST) -> bool:
        # Quick check if a string node contains SQL keywords.
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            return bool(self.SQL_KEYWORDS.search(node.value))
        return False

    def visit_BinOp(self, node: ast.BinOp):
        # Check for 'SELECT ...' + user_input
        if isinstance(node.op, ast.Add):
            if self._contains_sql(node.left) or self._contains_sql(node.right):
                self._create_finding(line=node.lineno)
        self.generic_visit(node)

    def visit_JoinedStr(self, node: ast.JoinedStr):
        # Check for f"SELECT ... {user_input}"
        for val in node.values:
            if self._contains_sql(val):
                self._create_finding(line=node.lineno)
                break
        self.generic_visit(node)

class HardcodedCredRule(Rule):
    # Detects hardcoded credentials in variables.
    RULE_ID = "PY-202"
    SEVERITY = "Medium"
    CATEGORY = "Security"
    MESSAGE = "Hardcoded credential detected."
    RECOMMENDATION = "Store credentials in environment variables or a secure vault, not in source code."

    # Simple regex for variable names
    CRED_VARS = re.compile(r'^(PASSWORD|SECRET|API_KEY|PASSWD|ACCESS_TOKEN)$', re.IGNORECASE)

    def visit_Assign(self, node: ast.Assign):
        if not isinstance(node.value, ast.Constant) or not isinstance(node.value.value, str):
            # We only care about simple string assignments
            self.generic_visit(node)
            return

        for target in node.targets:
            if isinstance(target, ast.Name) and self.CRED_VARS.match(target.id):
                self._create_finding(line=node.lineno, 
                                     custom_message=f"Hardcoded credential found in variable '{target.id}'.")
        self.generic_visit(node)

class WeakCryptoRule(Rule):
    # Detects use of weak crypto algorithms like MD5 and SHA1.
    RULE_ID = "PY-203"
    SEVERITY = "Low"
    CATEGORY = "Security"
    MESSAGE = "Use of weak cryptographic hash (MD5/SHA1) detected."
    RECOMMENDATION = "Use a strong hashing algorithm like SHA-256 or SHA-3, or 'hashlib.scrypt' for passwords."

    def visit_Call(self, node: ast.Call):
        # Check for hashlib.md5() or hashlib.sha1()
        if isinstance(node.func, ast.Attribute):
            attr = node.func
            if isinstance(attr.value, ast.Name) and attr.value.id == 'hashlib':
                if attr.attr in ('md5', 'sha1'):
                    self._create_finding(line=node.lineno, 
                                         custom_message=f"Use of weak hash 'hashlib.{attr.attr}' detected.")
        
        self.generic_visit(node)
        