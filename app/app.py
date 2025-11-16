import streamlit as st
import sys
import os
import pandas as pd
import json
from io import StringIO

# Utility Functions for Mocking

# This mock function simulates generating a detailed report (like a list of findings)
def generate_mock_report_data():
    # Generates a mock report list for display.
    return [
        {"severity": "High", "file": "db_utils.py", "line": 42, "description": "Hardcoded AWS secret key found."},
        {"severity": "Medium", "file": "api_client.py", "line": 105, "description": "Use of MD5 hash function."},
        {"severity": "Low", "file": "main.py", "line": 12, "description": "Broad exception handler: except Exception as e."},
        {"severity": "High", "file": "routes.py", "line": 20, "description": "Insecure SQL query concatenation."}
    ]

# This mock function simulates generating a JSON report file content
def generate_mock_json_report(data):
    # Generates a mock JSON string for download.
    report = {
        "summary": {
            "High": len([d for d in data if d['severity'] == 'High']),
            "Medium": len([d for d in data if d['severity'] == 'Medium']),
            "Low": len([d for d in data if d['severity'] == 'Low'])
        },
        "findings": data
    }
    return json.dumps(report, indent=4)

# Path and Setup
# Set up the Python path to allow imports from the 'scanner' directory
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

# We can import placeholders for the logic we will build later
# from scanner.core import scan_file, scan_directory 
# from scanner.models import VulnerabilityReport

# UI Configuration and Setup
st.set_page_config(
    page_title="Source Code Vulnerability Scanner",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Initialize session state for report visibility
if 'report_data' not in st.session_state:
    st.session_state.report_data = None
if 'file_name' not in st.session_state:
    st.session_state.file_name = None
# State variable to track if a scan just finished and toast is needed
if 'scan_just_finished' not in st.session_state:
    st.session_state.scan_just_finished = False

# Main Application Logic

def display_report_section(data, file_name):
    # Displays the vulnerability report summary, detailed findings,
    # and the download button.
    st.markdown("---")
    st.header(f"✅ Scan Complete for: `{file_name}`")
    
    # 1. Summary Metrics
    df = pd.DataFrame(data)
    summary = df.groupby('severity').size().reindex(['High', 'Medium', 'Low'], fill_value=0)
    total_findings = summary.sum()

    st.subheader(f"Summary: {total_findings} Vulnerabilities Found")

    # Display summary using columns/metrics for visual appeal
    col1, col2, col3 = st.columns(3)
    col1.metric("High Severity", summary.get('High', 0), delta_color="inverse")
    col2.metric("Medium Severity", summary.get('Medium', 0), delta_color="off")
    col3.metric("Low Severity", summary.get('Low', 0))

    # 2. Detailed Findings (Preview)
    st.subheader("Detailed Findings Preview")
    
    # Use st.dataframe for an interactive, sortable table
    st.dataframe(
        df,
        column_order=("severity", "file", "line", "description"),
        hide_index=True,
        use_container_width=True,
        # Apply color based on severity for better previsualization
        column_config={
            "severity": st.column_config.Column(
                "Severity",
                help="The potential security impact.",
                width="small",
            ),
        },
    )

    # 3. Download Button
    json_report_content = generate_mock_json_report(data)
    
    st.markdown("### Export Report")
    st.download_button(
        label="⬇️ Download JSON Report",
        data=json_report_content,
        file_name=f"vulnerability_report_{file_name.replace('.', '_')}.json",
        mime="application/json",
        key='download_json'
    )
    
def main_app():
    # The main function for the Streamlit application.
    st.title("🛡️ Python Source Code Vulnerability Scanner")
    st.markdown("---")

    # Sidebar for Options
    st.sidebar.header("Scan Options")
    
    # Placeholder for configuration options (e.g., language, severity filters)
    language = st.sidebar.selectbox("Target Language", ["Python (Default)"], index=0)
    
    # Placeholder for the main action area
    st.header("Upload File or Directory")

    scan_type = st.radio(
        "Select Scan Target", 
        ("Single File", "Project Directory"),
        index=0,
        horizontal=True
    )
    
    # Reset report data when switching scan type
    if st.session_state.report_data is not None and scan_type == "Project Directory":
        # We only reset here if the user switches the main scan_type radio button
        st.session_state.report_data = None
        st.session_state.file_name = None
        st.session_state.scan_just_finished = False


    if scan_type == "Single File":
        uploaded_file = st.file_uploader(
            "Upload a Python file (`.py`) to scan", 
            type=['py']
        )
        
        if uploaded_file is not None:
            # FIX APPLIED HERE
            # If a new file is uploaded (or the user re-uploads the same file), 
            # we reset state and use st.stop() to force a clean re-render
            if st.session_state.file_name != uploaded_file.name or st.session_state.report_data is not None:
                st.session_state.file_name = uploaded_file.name
                st.session_state.report_data = None
                st.session_state.scan_just_finished = False
                # Re-run the script immediately to clear the report and show the clean state
                st.rerun() 
            # END FIX

            st.success(f"File '{uploaded_file.name}' ready for scanning.")
            # st.code(uploaded_file.read().decode('utf-8')) # Use this to preview content
            
            # Check if a scan has already been run for this file
            if st.session_state.report_data is None:
                if st.button("Start Scan", key="start_single_scan"):
                    # 1. ACTUAL SCANNING LOGIC GOES HERE IN THE FUTURE
                    with st.spinner(f"Scanning {uploaded_file.name}..."):
                        # Simulate work
                        import time; time.sleep(2) 
                        
                        # Generate the mock report data and store it in state
                        mock_data = generate_mock_report_data()
                        st.session_state.report_data = mock_data
                        
                        # DEBUG/INSPECTION CODE
                        st.code(
                            f"Report data generated for inspection:\n{json.dumps(mock_data, indent=2)}",
                            language="json"
                        )
                        # END DEBUG/INSPECTION CODE
                        
                        st.session_state.scan_just_finished = True
                    # END
            
    elif scan_type == "Project Directory":
        # Note: Streamlit file_uploader is limited for directories. 
        st.warning("Directory scanning functionality requires a local setup or zip upload for web apps.")
        st.info("Please use the 'Single File' option for this prototype.")
        st.text_input("Simulated Directory Path (e.g., /home/user/my_project)")

    # Report Display Area (Conditional)
    if st.session_state.report_data is not None:
        # Pass the mock data and file name to the display function
        display_report_section(
            st.session_state.report_data, 
            st.session_state.file_name
        )
        
        # Display the toast message ONLY after the rerun has completed and the report is shown
        if st.session_state.scan_just_finished:
            st.toast("Scan complete! Report generated.")
            st.session_state.scan_just_finished = False # Reset the flag


# Run the application
if __name__ == "__main__":
    main_app()
