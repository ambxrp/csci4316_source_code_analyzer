import streamlit as st
import sys
import os
import pandas as pd
import json
from io import StringIO
from typing import List
import tempfile
import shutil
from collections import Counter

# Path and Setup
# Set up the Python path to allow imports from the 'src' directory
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

# -------------------------------------------------------------------
# 1. Imports and Backend Initialization (MODIFIED TO USE ANALYZER/REPORTER DIRECTLY)
# -------------------------------------------------------------------

try:
    # Import the real data models
    from src.analyzer.models import Options, Finding, ScanResult
    # Import Analyzer and Reporter directly, ignoring AnalyzerService
    from src.analyzer.analyzer import Analyzer
    from src.analyzer.reporter import Reporter
    
    # Instantiate the Analyzer
    analyzer = Analyzer()

except ImportError as e:
    st.error(f"Failed to import backend services: {e}. Check your path setup.")
    sys.exit(1)

# -------------------------------------------------------------------
# 2. Utility Functions
# -------------------------------------------------------------------

# Helper to save Streamlit's UploadedFile object to a temporary disk path.
# We use st.cache_data to save the file once per upload/hash and return the path.
@st.cache_data
def save_uploaded_file_to_temp(uploaded_file, file_name):
    """Saves the uploaded file to a temporary directory."""
    # Create a unique temporary directory
    temp_dir = tempfile.mkdtemp()
    temp_file_path = os.path.join(temp_dir, file_name)
    
    # Write the file content to the temp path
    with open(temp_file_path, "wb") as f:
        f.write(uploaded_file.getbuffer())
    
    # Return the directory path for cleanup, and the file path for the Analyzer
    return temp_dir, temp_file_path

def cleanup_temp_dir(temp_dir):
    """Cleans up the temporary directory."""
    if temp_dir and os.path.exists(temp_dir):
        shutil.rmtree(temp_dir)

def _findings_to_df(findings: List[Finding]) -> pd.DataFrame:
    """Converts a list of Finding objects to a DataFrame for display."""
    if not findings:
        return pd.DataFrame(columns=["Severity", "Rule ID", "File", "Line", "Message", "Recommendation"])
    
    # Sort findings deterministically (High -> Medium -> Low, then by file:line)
    sorted_findings = sorted(
        findings, 
        key=lambda f: (
            {"High": 1, "Medium": 2, "Low": 3}.get(f.severity, 4),
            f.file,
            f.line
        )
    )
    
    data = [
        {
            "Severity": f.severity,
            "Rule ID": f.ruleId,
            # Use os.path.basename to keep the file name short for the UI table
            "File": os.path.basename(f.file), 
            "Line": f.line,
            "Message": f.message,
            "Recommendation": f.recommendation,
        }
        for f in sorted_findings
    ]
    return pd.DataFrame(data)

def _summarize_findings(findings: List[Finding]) -> dict:
    """Calculates severity counts from a list of Finding objects."""
    severity_counts = Counter(f.severity for f in findings)
    # Ensure all three keys are present for display
    return {
        "High": severity_counts.get("High", 0),
        "Medium": severity_counts.get("Medium", 0),
        "Low": severity_counts.get("Low", 0)
    }

# -------------------------------------------------------------------
# 3. Report Display Function (MODIFIED TO USE REPORTER DIRECTLY)
# -------------------------------------------------------------------

def display_report_section(result: ScanResult, file_name: str, options: Options):
    # Uses the actual ScanResult object
    st.markdown("---")
    st.header(f"✅ Scan Complete for: `{file_name}`")
    
    findings = result.findings
    
    # 1. Summary Metrics
    df = _findings_to_df(findings)
    summary = _summarize_findings(findings)
    total_findings = len(findings)

    st.subheader(f"Summary: {total_findings} Vulnerabilities Found")

    col1, col2, col3 = st.columns(3)
    col1.metric("High Severity", summary.get('High', 0), delta_color="inverse")
    col2.metric("Medium Severity", summary.get('Medium', 0), delta_color="off")
    col3.metric("Low Severity", summary.get('Low', 0))

    # 2. Detailed Findings (Preview)
    st.subheader("Detailed Findings Preview")
    
    st.dataframe(
        df,
        column_order=("Severity", "Rule ID", "File", "Line", "Message", "Recommendation"),
        hide_index=True,
        use_container_width=True,
        column_config={
            "Severity": st.column_config.Column(
                "Severity",
                help="The potential security impact.",
                width="small",
            ),
        },
    )

    # 3. Download Buttons (Text and JSON)
    st.markdown("### Export Report")
    
    col_dl_1, col_dl_2 = st.columns(2)
    
    # --- Text Report Download (Existing) ---
    text_report_content = Reporter.toText(result)
    col_dl_1.download_button(
        label="⬇️ Download Text Report",
        data=text_report_content,
        file_name=f"vulnerability_report_{file_name.replace('.', '_')}.txt",
        mime="text/plain",
        key='download_text'
    )
    
    # --- JSON Report Download (New) ---
    # Call the new Reporter.toJSON method
    json_report_content = Reporter.toJSON(result) 
    col_dl_2.download_button(
        label="⬇️ Download JSON Report",
        data=json_report_content,
        file_name=f"vulnerability_report_{file_name.replace('.', '_')}.json",
        mime="application/json",
        key='download_json'
    )
    
# -------------------------------------------------------------------
# 4. Main Application Logic (MODIFIED TO USE ANALYZER DIRECTLY)
# -------------------------------------------------------------------

def main_app():
    st.title("🛡️ Python Source Code Vulnerability Scanner")
    st.markdown("---")

    # Initialize state variables to hold the scan results and file path
    if 'result' not in st.session_state: 
        st.session_state.result = None
    if 'file_name' not in st.session_state: 
        st.session_state.file_name = None
    if 'file_path' not in st.session_state: 
        st.session_state.file_path = None
    if 'temp_dir' not in st.session_state: 
        st.session_state.temp_dir = None
    if 'options' not in st.session_state: 
        st.session_state.options = None
    if 'scan_just_finished' not in st.session_state:
        st.session_state.scan_just_finished = False

    # Sidebar for Options (Kept as placeholder per requirements)
    st.sidebar.header("Scan Options")
    language = st.sidebar.selectbox("Target Language", ["Python (Default)"], index=0)
    
    # Placeholder for rule configuration (Future Part)
    st.sidebar.subheader("Ruleset Configuration (Placeholder)")
    rules_enabled = [] 
    severity_threshold = "Low" 

    # Main action area
    st.header("Upload File or Directory")

    scan_type = st.radio(
        "Select Scan Target", 
        ("Single File", "Project Directory"),
        index=0,
        horizontal=True
    )
    
    # Logic for Single File
    if scan_type == "Single File":
        uploaded_file = st.file_uploader(
            "Upload a Python file (`.py`) to scan", 
            type=['py']
        )
        
        if uploaded_file is not None:
            # 1. Validation
            if not uploaded_file.name.endswith('.py'):
                st.error(f"❌ Invalid file type: '{uploaded_file.name}'")
                st.info("This analyzer only supports Python source code files (.py)")
                st.stop()
            
            # 2. File State Management
            if st.session_state.file_name != uploaded_file.name:
                
                # Cleanup previous temp dir
                if st.session_state.temp_dir:
                    cleanup_temp_dir(st.session_state.temp_dir)
                    
                # Save the new file and update state
                temp_dir, temp_file_path = save_uploaded_file_to_temp(uploaded_file, uploaded_file.name)
                
                st.session_state.temp_dir = temp_dir
                st.session_state.file_path = temp_file_path
                st.session_state.file_name = uploaded_file.name
                st.session_state.result = None # Clear old results
                st.session_state.scan_just_finished = False
                st.session_state.options = None
            
            st.success(f"✅ File '{st.session_state.file_name}' ready for scanning.")
            
            # 3. Scan Trigger (Calls Analyzer directly)
            if st.session_state.result is None:
                if st.button("Start Scan", key="start_single_scan"):
                    
                    with st.spinner(f"Scanning {st.session_state.file_name}..."):
                        
                        # Create the Options object
                        scan_options = Options(
                            path=st.session_state.file_path,
                            outputFormat="text", 
                            rulesEnabled=rules_enabled,
                            severityThreshold=severity_threshold
                        )
                        st.session_state.options = scan_options
                        
                        try:
                            # Call the real Analyzer directly
                            result = analyzer.analyze(scan_options)
                            st.session_state.result = result
                            
                        except Exception as e:
                            st.error(f"An unexpected error occurred during scan.")
                            st.exception(e)
                            st.session_state.result = None
                            
                        st.session_state.scan_just_finished = True
                    
                    st.rerun() 

    elif scan_type == "Project Directory":
        st.warning("Directory scanning is implemented in the backend but is not supported by the Streamlit file uploader in this web prototype.")
        st.info("Please use the 'Single File' option for this prototype.")
        st.text_input("Simulated Directory Path (e.g., /home/user/my_project)")


    # Report Display Area (Conditional)
    if st.session_state.result is not None:
        display_report_section(
            st.session_state.result, 
            st.session_state.file_name,
            st.session_state.options
        )
        
        if st.session_state.scan_just_finished:
            st.toast("Scan complete! Report generated.")
            st.session_state.scan_just_finished = False


# Run the application
if __name__ == "__main__":
    main_app()