import ast
import logging
from typing import List

from .models import Finding, RuleContext
from .rules import Rule

logger = logging.getLogger(__name__)

class RuleEngine:
    # The RuleEngine class registers rules and processes an AST
    # to find vulnerabilities.
    
    def __init__(self):
        self.rules: List[Rule] = []

    def register_rule(self, rule: Rule) -> None:
        # Adds a rule instance to the engine.
        logger.info(f"Registering rule: {rule.RULE_ID} - {rule.CATEGORY}")
        self.rules.append(rule)

    def process(self, ast_node: ast.AST, context: RuleContext) -> List[Finding]:
        # Runs all registered rules against the given AST node and context.
        all_findings: List[Finding] = []
        
        logger.debug(f"Processing file: {context.file_path} with {len(self.rules)} rules")
        
        for rule in self.rules:
            try:
                # 1. Reset/set context for the rule
                rule.findings = []  # Clear findings from previous files
                rule.context = context
                
                # 2. Run the rule's visitor methods
                rule.visit(ast_node)
                
                # 3. Collect the findings
                findings_count = len(rule.findings)
                if findings_count > 0:
                    logger.debug(f"Rule {rule.RULE_ID} found {findings_count} issue(s)")
                all_findings.extend(rule.findings)
            
            except Exception as e:
                logger.error(f"Error processing rule {rule.RULE_ID} on {context.file_path}: {e}", exc_info=True)
                # Continue processing other rules even if one fails
                continue
            
        return all_findings
    