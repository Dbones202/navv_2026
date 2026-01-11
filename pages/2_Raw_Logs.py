import streamlit as st
import os
import glob
import polars as pl
from zeek_runner import ZeekRunner

st.set_page_config(page_title="Raw Logs", page_icon="📄", layout="wide")
st.title("📄 Analysis: Raw Logs")

zeek = ZeekRunner()
log_files = glob.glob(os.path.join(zeek.logs_dir, "*.log"))

if not log_files:
    st.warning("⚠️ No logs found. Please go to the **Ingest** page and process a PCAP file first.")
    st.stop()

# Sort by modification time
log_files.sort(key=os.path.getmtime, reverse=True)

selected_log = st.selectbox("Select Log File", [os.path.basename(f) for f in log_files])

if selected_log:
    file_path = os.path.join(zeek.logs_dir, selected_log)
    stats = os.stat(file_path)
    st.caption(f"Path: `{file_path}` | Size: `{stats.st_size/1024:.2f} KB`")

    try:
        # Extract Headers from Zeek Log (#fields line)
        headers = None
        with open(file_path, 'r', errors='ignore') as f:
            for _ in range(30):
                line = f.readline()
                if line.startswith("#fields"):
                    # Zeek Format: #fields \t col1 \t col2 ...
                    # Split and strip contents
                    parts = line.strip().split('\t')
                    # Remove the first element '#fields'
                    if len(parts) > 1:
                        headers = parts[1:]
                    break
        
        # Load with Polars
        if headers:
            df = pl.read_csv(file_path, separator='\t', comment_prefix="#", has_header=False, ignore_errors=True, new_columns=headers)
        else:
            df = pl.read_csv(file_path, separator='\t', comment_prefix="#", has_header=False, ignore_errors=True)
            
        # Ensure we didn't just read an empty dataframe
        if df.height == 0:
             st.warning("Log file appears empty or contains only metadata.")
        
        # Simple Filter
        search = st.text_input("Filter Content", placeholder="Search...")
        if search:
            # Very naive filtering logic for now
            # Convert to pandas for easier string search or use polars filtering
            # Polars is faster but scanning all columns as string is verbose to write
            pass 
        
        st.dataframe(df, use_container_width=True)
        
    except Exception as e:
        st.error(f"Error reading log: {e}")
        with open(file_path, "r", encoding="utf-8", errors="replace") as f:
            st.text_area("Raw Content", f.read(), height=400)
