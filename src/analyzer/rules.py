import ast
import uuid
import datetime
import re
import logging
from abc import ABC, abstractmethod
from typing import List, Optional

# Import our models
from .models import Finding, RuleContext, Severity

logger = logging.getLogger(__name__)

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
            error_msg = f"RuleContext not set by the engine for rule {self.RULE_ID}"
            logger.error(error_msg)
            raise ValueError(error_msg)
        
        logger.debug(f"Creating finding for {self.RULE_ID} at {self.context.file_path}:{line}")
        
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
    # Detects hardcoded credentials in string literals and suspicious variable assignments.
    RULE_ID = "PY-202"
    SEVERITY = "High"  # Increased from Medium since hardcoded secrets are critical
    CATEGORY = "Security"
    MESSAGE = "Hardcoded credential detected."
    RECOMMENDATION = "Store credentials in environment variables or a secure vault, not in source code."

    # Patterns for common API key/secret formats in string literals
    API_KEY_PATTERNS = [
        # OpenAI keys (sk- followed by optional prefix and long string)
        re.compile(r'sk-[a-zA-Z0-9\-]{20,}'),
        # GitHub tokens
        re.compile(r'gh[pousr]_[a-zA-Z0-9]{36,}'),
        # AWS Access Key ID
        re.compile(r'AKIA[0-9A-Z]{16}'),
        # Generic API keys (long alphanumeric strings that look like secrets)
        re.compile(r'^[a-zA-Z0-9]{32,}$'),
        # JWT tokens
        re.compile(r'eyJ[a-zA-Z0-9_\-]+\.eyJ[a-zA-Z0-9_\-]+\.[a-zA-Z0-9_\-]+'),
    ]
    
    # Variable names that suggest credentials (for additional checking)
    CRED_VARS = re.compile(r'^(PASSWORD|SECRET|API_KEY|PASSWD|ACCESS_TOKEN|PRIVATE_KEY|AUTH_TOKEN)$', re.IGNORECASE)

    def _check_string_for_secrets(self, string_value: str, line_number: int) -> bool:
        """Check if a string contains potential API keys or secrets."""
        # Skip short strings and common non-secret patterns
        if len(string_value) < 20:
            return False
        
        # Skip obvious non-secrets
        if string_value.lower() in ['your_api_key_here', 'replace_with_your_key', 'todo', 'fixme']:
            return False
        
        # Check against all patterns
        for pattern in self.API_KEY_PATTERNS:
            if pattern.search(string_value):
                self._create_finding(
                    line=line_number,
                    custom_message=f"Potential hardcoded API key or secret detected in string literal."
                )
                return True
        return False

    def visit_Constant(self, node: ast.Constant):
        """Visit all string constants to detect hardcoded secrets."""
        if isinstance(node.value, str):
            self._check_string_for_secrets(node.value, node.lineno)
        self.generic_visit(node)

    def visit_Assign(self, node: ast.Assign):
        """Check variable assignments with suspicious names."""
        if not isinstance(node.value, ast.Constant) or not isinstance(node.value.value, str):
            self.generic_visit(node)
            return

        # Check if variable name suggests credentials
        for target in node.targets:
            if isinstance(target, ast.Name) and self.CRED_VARS.match(target.id):
                # Only flag if the value looks like a real secret (not placeholder)
                value = node.value.value
                if len(value) > 8 and value.lower() not in ['your_api_key_here', 'replace_with_your_key', 'todo', 'fixme']:
                    self._create_finding(
                        line=node.lineno,
                        custom_message=f"Hardcoded credential found in variable '{target.id}'."
                    )
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
        