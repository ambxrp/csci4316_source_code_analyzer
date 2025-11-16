import ast
from unittest.mock import MagicMock, patch

from src.analyzer.engine import RuleEngine
from src.analyzer.rules import Rule
from src.analyzer.models import RuleContext, Finding

# A minimal fake rule for testing
class MockRule(Rule):
    RULE_ID = "MOCK-001"
    SEVERITY = "High"
    CATEGORY = "Mock"
    MESSAGE = "Mock finding"
    RECOMMENDATION = "Mock rec"
    
    def __init__(self, findings_to_return=0):
        super().__init__()
        self._findings_to_return = findings_to_return

    def visit(self, node):
        # Overriding visit to not require specific node types
        # Create the number of findings we were told to
        for i in range(self._findings_to_return):
            self._create_finding(line=i + 1)
        
        # Call the real generic_visit to simulate traversal
        # self.generic_visit(node)

def test_engine_registers_rules():
    # Tests that the engine's register_rule method works.
    engine = RuleEngine()
    assert len(engine.rules) == 0
    
    engine.register_rule(MockRule())
    assert len(engine.rules) == 1
    assert isinstance(engine.rules[0], MockRule)

def test_engine_process_calls_visit_on_rules():
    # Tests that the process() method calls visit() on each rule.
    engine = RuleEngine()
    
    # Create a mock rule and "spy" on its visit method
    mock_rule = MockRule()
    mock_rule.visit = MagicMock()
    
    engine.register_rule(mock_rule)
    
    # Create dummy AST node and Context
    mock_ast = ast.parse("x = 1")
    mock_context = RuleContext(file_path="test.py", file_content_lines=["x = 1"])
    
    # Run the engine
    engine.process(mock_ast, mock_context)
    
    # Check that visit was called exactly once
    mock_rule.visit.assert_called_once_with(mock_ast)

def test_engine_collects_and_returns_findings():
    # Tests that the engine correctly gathers findings from all rules.
    engine = RuleEngine()
    
    # Create two rules. One will find 1 issue, the other 2.
    rule1 = MockRule(findings_to_return=1)
    rule2 = MockRule(findings_to_return=2)
    
    engine.register_rule(rule1)
    engine.register_rule(rule2)
    
    mock_ast = ast.parse("x = 1")
    mock_context = RuleContext(file_path="test.py", file_content_lines=["x = 1"])
    
    # Run the engine
    all_findings = engine.process(mock_ast, mock_context)
    
    # Check that we got all 3 findings back
    assert len(all_findings) == 3
    assert all_findings[0].line == 1 # From rule 1
    assert all_findings[1].line == 1 # From rule 2
    assert all_findings[2].line == 2 # From rule 2
    