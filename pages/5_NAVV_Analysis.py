import streamlit as st
import polars as pl
import pandas as pd
import plotly.graph_objects as go
import os
from backend.navv_analysis_engine import NavvAnalysisEngine
from backend.inventory_manager import InventoryHarmonizer
from backend.segment_manager import SegmentResolver
from zeek_runner import ZeekRunner

st.set_page_config(page_title="NAVV Analysis", page_icon="🕵️", layout="wide")
st.title("🕵️ NAVV Traffic Analysis")

# Initialize
zeek = ZeekRunner()
inv = InventoryHarmonizer()
seg = SegmentResolver()

# Load Context (Inventory & Segments)
# In a real app, we'd cache these or load from the saved CSVs
dhcp_log = os.path.join(zeek.logs_dir, "dhcp.log")
dns_log = os.path.join(zeek.logs_dir, "dns.log")
conn_log_path = os.path.join(zeek.logs_dir, "conn.log")

inv.ingest_model(
    inventory_csv="master_navv_inventory.csv" if os.path.exists("master_navv_inventory.csv") else "inventory.csv",
    conn_log=conn_log_path,
    dhcp_log=dhcp_log,
    dns_log=dns_log
)
seg.load_segments("segments.csv")

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
    
    # Tabs: Visualization | Data
    tab_viz, tab_data = st.tabs(["📊 Visualization", "📋 Detailed Data"])
    
    with tab_viz:
        if "src_zone" in df.columns and "dst_zone" in df.columns:
            st.subheader("Traffic Flow (Sankey)")
            # Aggregate for Sankey: Source Zone -> Dest Zone
            # Group by src_zone, dst_zone
            
            # We need to filter out None zones or fill them
            sankey_data = df.groupby(['src_zone', 'dst_zone']).agg({'count': 'sum'}).reset_index()
            sankey_data = sankey_data.fillna("Unknown")
            
            # Create Node List
            all_nodes = list(pd.concat([sankey_data['src_zone'], sankey_data['dst_zone']]).unique())
            node_map = {name: i for i, name in enumerate(all_nodes)}
            
            # Links
            links = {
                'source': sankey_data['src_zone'].map(node_map),
                'target': sankey_data['dst_zone'].map(node_map),
                'value': sankey_data['count']
            }
            
            import plotly.graph_objects as go
            
            fig = go.Figure(data=[go.Sankey(
                node = dict(
                  pad = 15,
                  thickness = 20,
                  line = dict(color = "black", width = 0.5),
                  label = all_nodes,
                  color = "blue"
                ),
                link = dict(
                  source = links['source'],
                  target = links['target'],
                  value = links['value']
              ))])
            
            fig.update_layout(title_text="Network Traffic Flows (Zone to Zone)", font_size=10)
            st.plotly_chart(fig, use_container_width=True)
        else:
             st.info("Visualizations Disabled: Data not enriched with Zones/Segments.")

    with tab_data:
        st.subheader("Traffic Table")
        
        # Color Risk Rows?
        # Styler is slow for large data. 
        # Just show the dataframe.
        
        # Add basic filters
        display_df = df
        if "risk_alert" in df.columns:
            risk_filter = st.checkbox("Show Only Risks")
            if risk_filter:
                 display_df = df[df['risk_alert'] == 'CRITICAL']
        
        st.dataframe(display_df, use_container_width=True) 
