import pytest
import tempfile
import os
from pathlib import Path
from src.analyzer.analyzer import Analyzer
from src.analyzer.models import Options

# Tests for the Analyzer class

def test_analyzer_initialization():
    # Tests that the analyzer initializes correctly with parser and rule engine
    analyzer = Analyzer()
    
    assert analyzer.parser is not None
    assert analyzer.rule_engine is not None
    # Should have 5 rules registered by default
    assert len(analyzer.rule_engine.rules) == 5

def test_analyze_single_file():
    # Tests analyzing a single Python file
    analyzer = Analyzer()
    options = Options(path="fixtures/exec.py")
    result = analyzer.analyze(options)
    
    assert result is not None
    assert result.runInfo is not None
    assert result.runInfo.toolVersion == "1.0.0"
    assert len(result.findings) >= 2  # exec.py should have at least 2 findings

def test_analyze_directory():
    # Tests analyzing an entire directory
    analyzer = Analyzer()
    options = Options(path="fixtures/")
    result = analyzer.analyze(options)
    
    assert result is not None
    assert len(result.findings) > 0  # Should find vulnerabilities across multiple files

def test_analyze_nonexistent_path():
    # Tests that analyzer handles non-existent paths gracefully
    analyzer = Analyzer()
    options = Options(path="nonexistent_file.py")
    result = analyzer.analyze(options)
    
    assert result is not None
    assert len(result.findings) == 0  # No findings for non-existent file

def test_analyze_non_python_file():
    # Tests that analyzer skips non-Python files
    import tempfile
    import os
    
    # Create a temporary non-Python file
    with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
        f.write("This is not a Python file")
        temp_path = f.name
    
    try:
        analyzer = Analyzer()
        options = Options(path=temp_path)
        result = analyzer.analyze(options)
        
        # Should have no findings for non-Python file
        assert len(result.findings) == 0
    finally:
        os.unlink(temp_path)

def test_analyze_file_with_syntax_error():
    # Tests that analyzer handles files with syntax errors gracefully
    import tempfile
    import os
    
    # Create a temporary Python file with syntax error
    code = '''
# This file has a syntax error
def broken_function(
    # Missing closing parenthesis and colon
'''
    
    with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
        f.write(code)
        temp_path = f.name
    
    try:
        analyzer = Analyzer()
        options = Options(path=temp_path)
        result = analyzer.analyze(options)
        
        # Should handle gracefully and return no findings
        assert result is not None
        assert len(result.findings) == 0
    finally:
        os.unlink(temp_path)

def test_analyze_safe_code():
    # Tests that analyzer produces no findings for safe code
    analyzer = Analyzer()
    options = Options(path="fixtures/safe_code.py")
    result = analyzer.analyze(options)
    
    assert result is not None
    assert len(result.findings) == 0  # Safe code should have zero findings

def test_analyze_multiple_vulnerabilities():
    # Tests that analyzer detects multiple different vulnerability types
    analyzer = Analyzer()
    options = Options(path="fixtures/")
    result = analyzer.analyze(options)
    
    # Get unique rule IDs
    rule_ids = set(f.ruleId for f in result.findings)
    
    # Should detect multiple different types of vulnerabilities
    assert len(rule_ids) >= 3  # Should find at least 3 different rule violations

def test_analyze_file_with_unicode():
    # Tests that analyzer handles Unicode content correctly
    import tempfile
    import os
    
    code = '''
# File with Unicode characters
message = "Hello, 世界! 🌍"
# This should still be analyzed normally
exec("print('test')")  # This should be flagged
'''
    
    with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False, encoding='utf-8') as f:
        f.write(code)
        temp_path = f.name
    
    try:
        analyzer = Analyzer()
        options = Options(path=temp_path)
        result = analyzer.analyze(options)
        
        # Should handle Unicode and still detect the exec() call
        assert result is not None
        assert len(result.findings) >= 1
        assert any(f.ruleId == "PY-101" for f in result.findings)
    finally:
        os.unlink(temp_path)

def test_analyze_empty_file():
    # Tests that analyzer handles empty Python files
    import tempfile
    import os
    
    with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
        f.write("")  # Empty file
        temp_path = f.name
    
    try:
        analyzer = Analyzer()
        options = Options(path=temp_path)
        result = analyzer.analyze(options)
        
        # Empty file should have no findings
        assert result is not None
        assert len(result.findings) == 0
    finally:
        os.unlink(temp_path)

def test_analyze_directory_with_subdirectories():
    # Tests that analyzer recursively scans subdirectories
    import tempfile
    import os
    from pathlib import Path
    
    # Create a temporary directory structure
    temp_dir = tempfile.mkdtemp()
    
    try:
        # Create subdirectory
        sub_dir = Path(temp_dir) / "subdir"
        sub_dir.mkdir()
        
        # Create Python file in subdirectory
        sub_file = sub_dir / "test.py"
        sub_file.write_text('exec("malicious code")')
        
        analyzer = Analyzer()
        options = Options(path=temp_dir)
        result = analyzer.analyze(options)
        
        # Should find the vulnerability in the subdirectory
        assert len(result.findings) >= 1
    finally:
        # Clean up
        import shutil
        shutil.rmtree(temp_dir)

def test_analyze_preserves_finding_details():
    # Tests that findings contain all necessary information
    analyzer = Analyzer()
    options = Options(path="fixtures/exec.py")
    result = analyzer.analyze(options)
    
    assert len(result.findings) > 0
    
    # Check that first finding has all required fields
    finding = result.findings[0]
    assert hasattr(finding, 'ruleId')
    assert hasattr(finding, 'severity')
    assert hasattr(finding, 'message')
    assert hasattr(finding, 'line')
    assert hasattr(finding, 'category')
    assert hasattr(finding, 'recommendation')
    
    # Verify values are populated
    assert finding.ruleId is not None
    assert finding.severity is not None
    assert finding.message is not None
    assert finding.line > 0

def test_run_info_populated():
    # Tests that RunInfo contains correct metadata
    analyzer = Analyzer()
    options = Options(path="fixtures/exec.py")
    result = analyzer.analyze(options)
    
    assert result.runInfo is not None
    assert result.runInfo.toolVersion == "1.0.0"
    assert result.runInfo.timestamp is not None
    assert result.runInfo.rootPath is not None