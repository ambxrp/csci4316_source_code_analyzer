import ast
from typing import List

from .models import Finding, RuleContext
from .rules import Rule

class RuleEngine:
    # The RuleEngine class registers rules and processes an AST
    # to find vulnerabilities.
    
    def __init__(self):
        self.rules: List[Rule] = []

    def register_rule(self, rule: Rule) -> None:
        # Adds a rule instance to the engine.
        print(f"[Engine] Registering rule: {rule.RULE_ID}")
        self.rules.append(rule)

    def process(self, ast_node: ast.AST, context: RuleContext) -> List[Finding]:
        # Runs all registered rules against the given AST node and context.
        all_findings: List[Finding] = []
        
        for rule in self.rules:
            # 1. Reset/set context for the rule
            rule.findings = []  # Clear findings from previous files
            rule.context = context
            
            # 2. Run the rule's visitor methods
            rule.visit(ast_node)
            
            # 3. Collect the findings
            all_findings.extend(rule.findings)
            
        return all_findings
    