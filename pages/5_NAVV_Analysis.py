import streamlit as st
import polars as pl
import pandas as pd
import plotly.graph_objects as go
import os

# Increase Styler limit for large datasets
pd.set_option("styler.render.max_elements", 1_000_000)
from backend.navv_analysis_engine import NavvAnalysisEngine
from backend.inventory_manager import InventoryHarmonizer
from backend.segment_manager import SegmentResolver
from zeek_runner import ZeekRunner
from utils import check_log_prerequisites

st.set_page_config(page_title="NAVV Analysis", page_icon="🕵️", layout="wide")
st.title("🕵️ NAVV Traffic Analysis")

if not check_log_prerequisites():
    st.error("⚠️ No Zeek logs found. Please use the **Ingest** module to process a PCAP file first.")
    st.stop()


# Initialize
zeek = ZeekRunner()
inv = InventoryHarmonizer()
seg = SegmentResolver()

# Load Context (Inventory & Segments)
# In a real app, we'd cache these or load from the saved CSVs
with st.status("Loading Data Environment...", expanded=True) as status:
    dhcp_log = os.path.join(zeek.logs_dir, "dhcp.log")
    dns_log = os.path.join(zeek.logs_dir, "dns.log")
    conn_log_path = os.path.join(zeek.logs_dir, "conn.log")
    
    status.write("Ingesting Activity Logs (DHCP, DNS, Conn)...")
    inv.ingest_model(
        inventory_csv="master_navv_inventory.csv" if os.path.exists("master_navv_inventory.csv") else "inventory.csv",
        conn_log=conn_log_path,
        dhcp_log=dhcp_log,
        dns_log=dns_log
    )
    
    status.write("Loading Network Segments...")
    seg.load_segments("segments.csv")
    
    status.update(label="Environment Ready", state="complete", expanded=False)

engine = NavvAnalysisEngine(inv, seg)
conn_log = os.path.join(zeek.logs_dir, "conn.log")

if not os.path.exists(conn_log):
    st.error("⚠️ No `conn.log` found.")
    st.stop()

if st.button("🚀 Run Analysis", type="primary"):
    with st.spinner("Analyzing Traffic Flows..."):
        try:
            df = engine.run_analysis(conn_log)
            # Save to session for persistency across re-renders (like sorting)
            st.session_state['analysis_df'] = df.to_pandas()
            st.success("Analysis Complete")
        except Exception as e:
            st.error(f"Analysis failed: {e}")

if 'analysis_df' in st.session_state:
    df = st.session_state['analysis_df']
    
    # Metrics
    col1, col2, col3 = st.columns(3)
    col1.metric("Total Flows", len(df))
    
    # Count Risks (Conditional)
    if "risk_alert" in df.columns:
        risks = df[df['risk_alert'] == 'CRITICAL']
        risk_count = len(risks)
        col2.metric(
            "Critical Risks", 
            risk_count, 
            delta=f"{risk_count} Found" if risk_count > 0 else "All Good",
            delta_color="inverse"
        )
    else:
        col2.metric("Critical Risks", "N/A", "Enrichment Disabled")
    
    st.markdown("---")
    
    st.subheader("Traffic Analysis Table")
    
    # Add basic filters
    display_df = df.copy()
    if "risk_alert" in df.columns:
        risk_filter = st.checkbox("Show Only Risks")
        if risk_filter:
                display_df = display_df[display_df['risk_alert'] == 'CRITICAL']

    # Apply Styling
    def highlight_cells(row):
        # Default
        styles = [''] * len(row)
        
        # Map index to column name for easy access
        # source
        src_bg = row.get('src_color', '#ffffff')
        src_font = row.get('src_font', '#000000')
        dst_bg = row.get('dst_color', '#ffffff')
        dst_font = row.get('dst_font', '#000000')
        
        for i, col in enumerate(row.index):
            if col in ['src_ip', 'Src Name']:
                styles[i] = f'background-color: {src_bg}; color: {src_font}'
            elif col in ['dst_ip', 'Dst Name']:
                styles[i] = f'background-color: {dst_bg}; color: {dst_font}'
        return styles

    st.dataframe(
        display_df.style.apply(highlight_cells, axis=1), 
        use_container_width=True,
        column_config={
            "src_color": None, "src_font": None, "src_segment": None, 
            "dst_color": None, "dst_font": None, "dst_segment": None,
            "src_name_conf": st.column_config.NumberColumn("Src Conf", help="Source Name Confidence (1=High, 8=Low)"),
            "dst_name_conf": st.column_config.NumberColumn("Dst Conf", help="Dest Name Confidence (1=High, 8=Low)"),
            "service_confidence": st.column_config.NumberColumn("Svc Conf", help="Service Confidence (1=High, 8=Low)"),
        }
    )

st.divider()
with st.expander("ℹ️ How it Works: Traffic Analysis & Enrichment"):
    st.markdown("""
    ### 1. The Analysis Engine
    This module ingests raw `conn.log` data and enriches it with the context built in the **Ingest** and **Inventory** phases.
    
    ### 2. Data Enrichment Fields
    *   **Source / Destination Names**: Resolved from your Master Asset List (Inventory).
        *   *Confidence Factor*: A score (1-8) indicating how the name was found (1=Manual Override, 8=Unknown).
    *   **Segments & Zones**: Active IPs are mapped to your definitions in the **Segments** page.
        *   *Color Coding*: Cells are colored by their Purdue Level (Blue=OT, Green=IT, Grey=Public).
    *   **Services**: Protocol and Service identification (e.g., `HTTP`, `ENIP`, `S7Comm`) is enhanced using Nmap logic where Zeek falls short.

    ### 3. Visualizations
    *   **Sankey Diagram**: Shows the high-level volume of traffic flowing between **Zones** (e.g., "Site Operations" -> "Internet").
    *   **Traffic Table**: Detailed record of every conversation, with color-coded context for rapid risk assessment.
    """)

# Sidebar Footer
from utils import render_sidebar_stats
render_sidebar_stats()

