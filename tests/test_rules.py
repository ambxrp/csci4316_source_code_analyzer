import pytest
from src.analyzer.analyzer import Analyzer
from src.analyzer.models import Options
from typing import List
from src.analyzer.models import Finding

def run_scan_on_fixture(file_name: str) -> List[Finding]:
    # A helper function to run the full analyzer on a single fixture file.
    # We assume fixtures are in the 'fixtures/' directory
    path = f"fixtures/{file_name}"
    
    analyzer = Analyzer()
    options = Options(path=path)
    result = analyzer.analyze(options)
    
    # Sort findings by line number to make tests predictable
    return sorted(result.findings, key=lambda f: f.line)

def test_exec_rule():
    # Tests the ExecRule against exec.py
    findings = run_scan_on_fixture("exec.py")
    
    assert len(findings) == 2
    
    assert findings[0].ruleId == "PY-101"
    assert findings[0].line == 4
    assert "exec" in findings[0].message
    
    assert findings[1].ruleId == "PY-101"
    assert findings[1].line == 7
    assert "eval" in findings[1].message

def test_broad_exception_rule():
    # Tests the BroadExceptionRule against exception.py
    findings = run_scan_on_fixture("exception.py")
    
    assert len(findings) == 2
    
    assert findings[0].ruleId == "PY-102"
    assert findings[0].line == 10
    
    assert findings[1].ruleId == "PY-102"
    assert findings[1].line == 15 

def test_sql_injection_rule():
    # Tests the InsecureSQLConcatRule against sql.py
    findings = run_scan_on_fixture("sql.py")
    
    assert len(findings) == 2
    
    assert findings[0].ruleId == "PY-201"
    assert findings[0].line == 6  
    
    assert findings[1].ruleId == "PY-201"
    assert findings[1].line == 9   

def test_hardcoded_creds_rule():
    # Tests the HardcodedCredRule against creds.py
    findings = run_scan_on_fixture("creds.py")
    
    assert len(findings) == 2
    
    assert findings[0].ruleId == "PY-202"
    assert findings[0].line == 4
    assert "API_KEY" in findings[0].message
    
    assert findings[1].ruleId == "PY-202"
    assert findings[1].line == 7
    assert "PASSWORD" in findings[1].message

def test_weak_crypto_rule():
    # Tests the WeakCryptoRule against crypto.py
    findings = run_scan_on_fixture("crypto.py")
    
    assert len(findings) == 2
    
    assert findings[0].ruleId == "PY-203"
    assert findings[0].line == 8 
    
    assert findings[1].ruleId == "PY-203"
    assert findings[1].line == 11

def test_safe_code_produces_no_findings():
    # Tests that a safe file produces 0 findings (no false positives).
    # This is one of the most important tests!
    findings = run_scan_on_fixture("safe_code.py")
    
    assert len(findings) == 0
    
