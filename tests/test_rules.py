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
    
def test_enhanced_secrets_detection():
    # Tests the enhanced HardcodedCredRule that detects string literals
    findings = run_scan_on_fixture("secrets.py")
    
    # Filter only PY-202 findings (hardcoded credentials)
    secret_findings = [f for f in findings if f.ruleId == "PY-202"]
    
    # Should detect multiple hardcoded secrets (we have: openai_key, github_token, aws_key, jwt, api_key, client call, config dict)
    assert len(secret_findings) >= 5, f"Expected at least 5 secret findings, got {len(secret_findings)}"
    
    # Verify findings exist across different line numbers (means we're catching various patterns)
    line_numbers = [f.line for f in secret_findings]
    assert len(set(line_numbers)) >= 5, "Should detect secrets on multiple different lines"

def test_openai_api_key_detection():
    # Tests detection of OpenAI API keys in string literals
    import tempfile
    import os
    
    code = '''
# OpenAI API key hardcoded
client = OpenAI(api_key="sk-proj-1234567890abcdefghijklmnopqrstuvwxyz")
'''
    
    # Create temp file
    with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
        f.write(code)
        temp_path = f.name
    
    try:
        analyzer = Analyzer()
        options = Options(path=temp_path)
        result = analyzer.analyze(options)
        
        secret_findings = [f for f in result.findings if f.ruleId == "PY-202"]
        assert len(secret_findings) >= 1, "Should detect OpenAI API key in string literal"
    finally:
        os.unlink(temp_path)

def test_github_token_detection():
    # Tests detection of GitHub tokens
    import tempfile
    import os
    
    code = '''
# GitHub token hardcoded
headers = {"Authorization": "Bearer ghp_1234567890abcdefghijklmnopqrstuvwxyz123"}
'''
    
    with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
        f.write(code)
        temp_path = f.name
    
    try:
        analyzer = Analyzer()
        options = Options(path=temp_path)
        result = analyzer.analyze(options)
        
        secret_findings = [f for f in result.findings if f.ruleId == "PY-202"]
        assert len(secret_findings) >= 1, "Should detect GitHub token in string literal"
    finally:
        os.unlink(temp_path)

def test_aws_access_key_detection():
    # Tests detection of AWS access keys
    import tempfile
    import os
    
    code = '''
# AWS credentials hardcoded
aws_access_key = "AKIAIOSFODNN7EXAMPLE"
'''
    
    with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
        f.write(code)
        temp_path = f.name
    
    try:
        analyzer = Analyzer()
        options = Options(path=temp_path)
        result = analyzer.analyze(options)
        
        secret_findings = [f for f in result.findings if f.ruleId == "PY-202"]
        assert len(secret_findings) >= 1, "Should detect AWS access key"
    finally:
        os.unlink(temp_path)

def test_jwt_token_detection():
    # Tests detection of JWT tokens
    import tempfile
    import os
    
    code = '''
# JWT token hardcoded
token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
'''
    
    with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
        f.write(code)
        temp_path = f.name
    
    try:
        analyzer = Analyzer()
        options = Options(path=temp_path)
        result = analyzer.analyze(options)
        
        secret_findings = [f for f in result.findings if f.ruleId == "PY-202"]
        assert len(secret_findings) >= 1, "Should detect JWT token"
    finally:
        os.unlink(temp_path)

def test_secrets_in_function_calls():
    # Tests detection of secrets passed directly to functions
    import tempfile
    import os
    
    code = '''
import openai
# Secret directly in function call
openai.api_key = "sk-1234567890abcdefghijklmnopqrstuvwxyz"
response = openai.ChatCompletion.create(model="gpt-4")
'''
    
    with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
        f.write(code)
        temp_path = f.name
    
    try:
        analyzer = Analyzer()
        options = Options(path=temp_path)
        result = analyzer.analyze(options)
        
        secret_findings = [f for f in result.findings if f.ruleId == "PY-202"]
        assert len(secret_findings) >= 1, "Should detect secrets in function calls"
    finally:
        os.unlink(temp_path)

def test_secrets_in_dict_config():
    # Tests detection of secrets in configuration dictionaries
    import tempfile
    import os
    
    code = '''
# Secret in config dictionary
config = {
    "api_key": "a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0u1v2w3x4y5z6",
    "endpoint": "https://api.example.com"
}
'''
    
    with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
        f.write(code)
        temp_path = f.name
    
    try:
        analyzer = Analyzer()
        options = Options(path=temp_path)
        result = analyzer.analyze(options)
        
        secret_findings = [f for f in result.findings if f.ruleId == "PY-202"]
        assert len(secret_findings) >= 1, "Should detect secrets in dictionaries"
    finally:
        os.unlink(temp_path)

def test_env_variables_not_flagged():
    # Tests that environment variables are NOT flagged (safe pattern)
    import tempfile
    import os
    
    code = '''
import os
# Safe - using environment variables
api_key = os.getenv("API_KEY")
password = os.environ.get("PASSWORD")
secret = os.environ["SECRET"]
'''
    
    with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
        f.write(code)
        temp_path = f.name
    
    try:
        analyzer = Analyzer()
        options = Options(path=temp_path)
        result = analyzer.analyze(options)
        
        secret_findings = [f for f in result.findings if f.ruleId == "PY-202"]
        assert len(secret_findings) == 0, "Should NOT flag environment variables"
    finally:
        os.unlink(temp_path)

def test_placeholders_not_flagged():
    # Tests that placeholder strings are NOT flagged
    import tempfile
    import os
    
    code = '''
# These are placeholders, not real secrets
api_key = "your_api_key_here"
password = "replace_with_your_key"
secret = "TODO"
token = "FIXME"
'''
    
    with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
        f.write(code)
        temp_path = f.name
    
    try:
        analyzer = Analyzer()
        options = Options(path=temp_path)
        result = analyzer.analyze(options)
        
        secret_findings = [f for f in result.findings if f.ruleId == "PY-202"]
        assert len(secret_findings) == 0, "Should NOT flag placeholder text"
    finally:
        os.unlink(temp_path)

def test_short_strings_not_flagged():
    # Tests that short strings are NOT flagged (too short to be API keys)
    import tempfile
    import os
    
    code = '''
        # Short strings should not be flagged
        password = "test123"
        key = "abc"
        token = "short"
        '''
    
    with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
        f.write(code)
        temp_path = f.name
    
    try:
        analyzer = Analyzer()
        options = Options(path=temp_path)
        result = analyzer.analyze(options)
        
        secret_findings = [f for f in result.findings if f.ruleId == "PY-202"]
        assert len(secret_findings) == 0, "Should NOT flag short strings"
    finally:
        os.unlink(temp_path)
    
