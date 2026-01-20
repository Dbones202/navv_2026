import streamlit as st
import polars as pl
import pandas as pd
import plotly.graph_objects as go
import os

# Increase Styler limit
pd.set_option("styler.render.max_elements", 1_000_000)

from backend.navv_analysis_engine import NavvAnalysisEngine
from backend.inventory_manager import InventoryHarmonizer
from backend.segment_manager import SegmentResolver
from zeek_runner import ZeekRunner

st.set_page_config(page_title="Sankey Analysis", page_icon="📈", layout="wide")
st.title("📈 Sankey Visualization (Builder)")

# Initialize
zeek = ZeekRunner()
inv = InventoryHarmonizer()
seg = SegmentResolver()

# Load Context
with st.status("Loading Data Environment...", expanded=False) as status:
    dhcp_log = os.path.join(zeek.logs_dir, "dhcp.log")
    dns_log = os.path.join(zeek.logs_dir, "dns.log")
    conn_log_path = os.path.join(zeek.logs_dir, "conn.log")
    
    # Ingest if needed (lightweight check?)
    # For now, just re-run ingest to be safe as per NAVV Analysis page
    inv.ingest_model(
        inventory_csv="master_navv_inventory.csv" if os.path.exists("master_navv_inventory.csv") else "inventory.csv",
        conn_log=conn_log_path,
        dhcp_log=dhcp_log,
        dns_log=dns_log
    )
    seg.load_segments("segments.csv")
    status.update(label="Environment Ready", state="complete")

engine = NavvAnalysisEngine(inv, seg)

if not os.path.exists(conn_log_path):
    st.error("⚠️ No `conn.log` found.")
    st.stop()

# Auto-Run Analysis for this page? Or Button? 
# Button is safer for large logs.
if st.button("🚀 Load Data for Visualization", type="primary"):
    with st.spinner("Processing Traffic..."):
        try:
            df = engine.run_analysis(conn_log_path)
            st.session_state['sankey_df'] = df.to_pandas()
            st.success("Data Loaded")
        except Exception as e:
            st.error(f"Analysis failed: {e}")

if 'sankey_df' in st.session_state:
    df = st.session_state['sankey_df']
    
    st.markdown("### Aggregated Segment Traffic")
    st.info("Validation Table: Aggregated connections grouped by Segment & Level.")
    
    # Aggregation Logic
    # Group by: src_segment, src_level -> dst_segment, dst_level
    # Count: connections
    if "src_segment" in df.columns and "dst_segment" in df.columns:
        agg_table = df.groupby(['src_segment', 'src_level', 'dst_segment', 'dst_level']).agg({'count': 'sum'}).reset_index()
        
        # Sort by Levels (Source then Dest) for logical flow
        agg_table = agg_table.sort_values(by=['src_level', 'dst_level', 'count'], ascending=[True, True, False])
        
        # Display Table
        st.dataframe(
            agg_table, 
            use_container_width=True,
            column_config={
                "src_segment": "Source Segment",
                "src_level": "Src Level",
                "dst_segment": "Dest Segment",
                "dst_level": "Dst Level", 
                "count": st.column_config.NumberColumn("Connections", format="%d"),
            },
            hide_index=True
        )
    else:
        st.warning("Run Analysis to populate segment fields.")

    st.divider()
    st.header("Traffic Flow (Purdue Level Aggregation)")
    
    # Sankey Logic
    # We want to aggregate: Segment Name + Purdue Level -> Segment Name + Purdue Level
    if "src_segment" in df.columns and "src_level" in df.columns:
        
        # 1. Create Label Columns: "SegmentName (Lx)"
        sankey_df = df.copy()
        sankey_df['src_label'] = sankey_df['src_segment'] + " (L" + sankey_df['src_level'].astype(str) + ")"
        sankey_df['dst_label'] = sankey_df['dst_segment'] + " (L" + sankey_df['dst_level'].astype(str) + ")"
        
        # 2. Group & Sum
        agg_df = sankey_df.groupby(['src_label', 'dst_label', 'src_level', 'dst_level']).agg({'count': 'sum'}).reset_index()
        
        # 3. Create Node List & Index Map
        # We need a unified list of all nodes (src + dst) to assign indices
        src_nodes = agg_df[['src_label', 'src_level']].rename(columns={'src_label': 'label', 'src_level': 'level'})
        dst_nodes = agg_df[['dst_label', 'dst_level']].rename(columns={'dst_label': 'label', 'dst_level': 'level'})
        
        all_nodes = pd.concat([src_nodes, dst_nodes]).drop_duplicates(subset='label').reset_index(drop=True)
        node_map = {label: i for i, label in enumerate(all_nodes['label'])}
        
        # 4. Map Colors
        # Use segment resolver colors if possible, or mapping
        # seg.PURDUE_COLORS is {int_level: hex_color}
        all_nodes['color'] = all_nodes['level'].map(seg.PURDUE_COLORS).fillna("blue")
        
        # 5. Build Link Data
        links = {
            'source': agg_df['src_label'].map(node_map),
            'target': agg_df['dst_label'].map(node_map),
            'value': agg_df['count']
        }
        
        # 6. Render
        fig = go.Figure(data=[go.Sankey(
            node = dict(
              pad = 15,
              thickness = 20,
              line = dict(color = "black", width = 0.5),
              label = all_nodes['label'],
              color = all_nodes['color']
            ),
            link = dict(
              source = links['source'],
              target = links['target'],
              value = links['value']
          ))])
        
        fig.update_layout(title_text="Segment-to-Segment Traffic Flow (by Purdue Level)", font_size=12, height=600)
        st.plotly_chart(fig, use_container_width=True)
        
    else:
        st.warning("⚠️ Missing 'src_segment' or 'src_level' columns. Please re-run analysis.")
