import streamlit as st
import os
import time
import datetime
from zeek_runner import ZeekRunner

import sys
import subprocess



st.set_page_config(page_title="Ingest PCAP", page_icon="📥", layout="wide")
st.title("📥 Ingest: Process PCAP")

zeek = ZeekRunner()

# Main Area
st.subheader("1. Input Source")

if "ingest_file_path" not in st.session_state:
    st.session_state["ingest_file_path"] = ""

def open_file_dialog():
    script = """
import tkinter as tk
from tkinter import filedialog
import sys
import os

# Suppress stderr to keep clean for Streamlit unless we want to capture it
# But we will capture it in the subprocess call
try:
    root = tk.Tk()
    root.withdraw()
    root.wm_attributes('-topmost', 1)
    
    # Check if we can open a window
    # On Linux, this might fail if no X11/Wayland
    
    file_path = filedialog.askopenfilename(
        title="Select PCAP File",
        filetypes=[("PCAP Files", "*.pcap"), ("All Files", "*.*")]
    )
    print(file_path, end="")
    root.destroy()
except Exception as e:
    # Print error to stderr so we can catch it
    sys.stderr.write(str(e))
    sys.exit(1)
"""
    try:
        # Run the script in a separate process
        # Use subprocess.run to capture stderr/stdout
        result = subprocess.run(
            [sys.executable, "-c", script], 
            capture_output=True, 
            text=True,
            check=False # Don't raise immediately, check returncode
        )
        
        if result.returncode == 0:
            file_path = result.stdout.strip()
            if file_path:
                st.session_state["ingest_file_path"] = file_path
        else:
            # Command failed
            err_msg = result.stderr.strip()
            if "no display name" in err_msg.lower():
                st.error("Cannot open file dialog: No display found (Headless environment?). Please enter path manually.")
            else:
                st.error(f"Error opening file dialog: {err_msg}")
                
    except Exception as e:
        st.error(f"System error: {e}")

c_input, c_btn = st.columns([4, 1])

with c_input:
    # Use key to bind directly to session state
    local_path = st.text_input(
        "Local File Path (Absolute Path)", 
        placeholder="/path/to/file.pcap", 
        key="ingest_file_path"
    )

with c_btn:
    # Add vertical spacing to align button with input box text
    st.write("") 
    st.write("")
    st.button("📂 Browse Files", on_click=open_file_dialog)

st.caption("Reads directly from disk. No file size limits.")

active_file = None

if local_path:
    clean_path = local_path.strip().strip('"')
    if os.path.exists(clean_path):
        active_file = clean_path
        st.info(f"📍 Ready to process: `{active_file}`")
    else:
        st.error("❌ File path does not exist.")

st.subheader("2. Run Processing")

if active_file:
    if st.button("Run Zeek Analysis", type="primary"):
        progress_bar = st.progress(0, text="Starting...")
        
        start_time = time.time()
        
        def update_progress(current, total):
            pct = min(current / total, 1.0)
            elapsed = time.time() - start_time
            if elapsed > 0 and current > 0:
                rate = current / elapsed 
                remaining_bytes = total - current
                eta_seconds = remaining_bytes / rate if rate > 0 else 0
                eta_str = str(datetime.timedelta(seconds=int(eta_seconds)))
                progress_text = f"Processing: {int(pct*100)}% ({current//(1024*1024)}MB / {total//(1024*1024)}MB) | ETA: {eta_str}"
            else:
                 progress_text = f"Calculating..."

            progress_bar.progress(pct, text=progress_text)

        try:
            with st.spinner("Running Zeek..."):
                success, output = zeek.process_pcap(active_file, progress_callback=update_progress)
                
                if success:
                    progress_bar.progress(1.0, text="Done!")
                    st.success("✅ Analysis Complete! Logs are ready.")
                    st.balloons()
                else:
                    progress_bar.empty()
                    st.error("❌ Analysis Failed")
                    st.code(output)
                    
        except Exception as e:
             st.warning(f"⚠️ Process interrupted: {e}")

st.subheader("3. Log Quality Status")
if os.path.exists(zeek.logs_dir):
    c1, c2 = st.columns(2)
    
    # Check MACs in conn.log
    conn_log = os.path.join(zeek.logs_dir, "conn.log")
    has_macs = False
    if os.path.exists(conn_log):
        try:
            with open(conn_log, "r", errors="ignore") as f:
                # Read header to find fields
                for line in f:
                    if line.startswith("#fields"):
                        if "orig_l2_addr" in line:
                            has_macs = True
                        break
        except:
            pass
            
    with c1:
        if has_macs:
            st.success("✅ **MAC Addresses Detected**\n\n`conn.log` contains L2 addresses.")
        else:
            st.warning("⚠️ **No MAC Addresses**\n\n`conn.log` missing `orig_l2_addr`. Check Zeek configuration or PCAP L2 headers.")

    # Check Community ID (Flow Hash)
    has_community_id = False
    if os.path.exists(conn_log):
        try:
            with open(conn_log, "r", errors="ignore") as f:
                for line in f:
                    if line.startswith("#fields"):
                        if "community_id" in line:
                            has_community_id = True
                        break
        except:
            pass
             
    with c2:
        if has_community_id:
            st.success("✅ **Community ID Detected**\n\n`conn.log` contains Flow Hash (`community_id`).")
        else:
            st.warning("⚠️ **No Community ID**\n\n`conn.log` missing `community_id`. Ensure `zeek-community-id` package is loaded.")

st.markdown("---")

# --- Maintenance Section ---
with st.expander("🛠️ System Maintenance & Updates", expanded=False):
    st.subheader("External Databases")
    col_m1, col_m2 = st.columns(2)
    
    with col_m1:
        if st.button("🔄 Update MAC OUI Database"):
            from backend.oui_lookup import oui_lookup
            with st.spinner("Downloading Wireshark OUI Database..."):
                if oui_lookup.update_oui_db():
                    st.success("MAC OUI Database Updated!")
                else:
                    st.error("Failed to update OUI Database.")
                    
    with col_m2:
        if st.button("🔄 Update Nmap Services"):
            from backend.service_lookup import service_lookup
            with st.spinner("Downloading Nmap Services..."):
                if service_lookup.update_nmap_db():
                    st.success("Nmap Services Updated!")
                else:
                    st.error("Failed to update Nmap Services.")

    st.markdown("---")
    st.subheader("Service Overrides")
    st.info("Manually define services for specific Proto/Port combinations. These take precedence over Nmap and Zeek.")
    
    overrides_path = os.path.join("backend", "data", "service_overrides.json")
    current_overrides = {}
    
    import json
    if os.path.exists(overrides_path):
        try:
            with open(overrides_path, 'r') as f:
                current_overrides = json.load(f)
        except:
            current_overrides = {}
            
    # Convert to DataFrame for Editor
    # List of {"Protocol/Port": key, "Service Name": value}
    editor_data = [{"Protocol/Port": k, "Service Name": v} for k, v in current_overrides.items()]
    
    edited_df = st.data_editor(editor_data, num_rows="dynamic", use_container_width=True)
    
    if st.button("💾 Save Service Overrides"):
        # Convert back
        new_overrides = {}
        for row in edited_df:
            k = row.get("Protocol/Port", "").strip()
            v = row.get("Service Name", "").strip()
            if k and v:
                new_overrides[k] = v
        
        try:
            with open(overrides_path, 'w') as f:
                json.dump(new_overrides, f, indent=4)
            service_lookup.load_lookups() # Reload in memory
            st.success("Overrides Saved! Restart Analysis to apply.")
        except Exception as e:
            st.error(f"Error saving overrides: {e}")

st.markdown("---")
if st.button("Clear Old Logs"):
    zeek.clear_logs()
    st.success("Logs cleared.")
