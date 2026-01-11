import streamlit as st
import polars as pl
import os
from backend.inventory_manager import InventoryHarmonizer

st.set_page_config(page_title="Inventory Manager", page_icon="📦", layout="wide")
st.title("📦 Inventory Manager")

# Initialize Backend
inv = InventoryHarmonizer()

# Sidebar: Actions
st.sidebar.header("Actions")
uploaded_file = st.sidebar.file_uploader("Upload Manual Inventory (CSV)", type=["csv"])
if st.sidebar.button("⬇️ Download Template"):
    # Generate template
    template = pl.DataFrame({
        "IP": ["192.168.1.10"],
        "Name": ["Workstation-01"],
        "Location": ["Building A"],
        "Description": ["HR PC"]
    })
    st.sidebar.download_button(
        "Download Template",
        template.write_csv(),
        "inventory_template.csv",
        "text/csv"
    )

# Logic
conn_log_path = os.path.join("zeek_logs", "conn.log")
dhcp_log_path = os.path.join("zeek_logs", "dhcp.log")
dns_log_path = os.path.join("zeek_logs", "dns.log")
ntlm_log_path = os.path.join("zeek_logs", "ntlm.log")
enip_log_path = os.path.join("zeek_logs", "enip.log")
inventory_path = None

if uploaded_file:
    # Save temp
    inventory_path = "inventory.csv"
    with open(inventory_path, "wb") as f:
        f.write(uploaded_file.getbuffer())
    st.sidebar.success("Inventory Loaded")
elif os.path.exists("inventory.csv"):
    inventory_path = "inventory.csv"
    st.sidebar.info("Using existing inventory.csv")

# Load Mode
if st.button("🔄 Refresh / Build Master Asset List"):
    with st.spinner("Correlating Manual Inventory with Behavioral Logs..."):
        if os.path.exists(conn_log_path):
            df = inv.ingest_model(
                inventory_csv=inventory_path, 
                conn_log=conn_log_path, 
                dhcp_log=dhcp_log_path,
                dns_log=dns_log_path,
                ntlm_log=ntlm_log_path,
                enip_log=enip_log_path
            )
            # Save to session (or disk - for now disk is easier for statelessness between re-runs if we save result)
            # We'll rely on session state for inter-interaction persistence if needed, but here we just re-run.
            st.session_state['master_asset_list'] = df.to_pandas() # Convert to pandas for st.data_editor support
        else:
            st.error("No `conn.log` found. Please ingest a PCAP first.")

# Display
if 'master_asset_list' in st.session_state:
    st.subheader("Master Asset List")
    
    # NEW: Displaying Asset Profile dimensions
    # Columns expected: 'ip', 'network_scope', 'segment', 'final_classification', 'behavioral_role', 'final_name', 'status'
    
    df = st.session_state['master_asset_list']
    
    # Warning for conflicts (L2 Leak)
    leaks = df[df['final_classification'] == "L2 Leak (Misconfig)"]
    if not leaks.empty:
        st.error(f"🚨 **CRITICAL SECURITY WARNING**: {len(leaks)} Public IPs detected on Local Network (Layer 2 Leak)!")
        st.dataframe(leaks)
    
    # Map Level Int -> Label
    from backend.segment_manager import SegmentResolver
    seg_res = SegmentResolver()
    
    # Convert Pandas -> Polars for robust manipulation
    p_df = pl.from_pandas(df)
    
    # Schema Validation (Backfill new columns if using stale session state)
    required_cols = ["dhcp_host_name", "dhcp_client_fqdn", "dhcp_domain", "broadcast_name", "enip_name", "behavior_level"]
    for col in required_cols:
        if col not in p_df.columns:
            if col == "behavior_level":
                p_df = p_df.with_columns(pl.lit(0).alias(col))
            else:
                p_df = p_df.with_columns(pl.lit(None).cast(pl.String).alias(col))

    def map_lvl(val):
        # Handle cases where level might be NaN or float-converted
        try:
            v_int = int(val)
            return seg_res.PURDUE_LEVELS.get(v_int, "Unknown")
        except:
            return "Unknown"
    
    display_df = p_df.with_columns([
        pl.col("purdue_level").fill_null(0).map_elements(map_lvl, return_dtype=pl.String).alias("Purdue Level"),
        pl.col("behavior_level").fill_null(0).map_elements(map_lvl, return_dtype=pl.String).alias("Behavioral Level")
    ])
    
    # Editor: Hide Colors/Meta, Show only User columns
    visible_cols = ["ip", "is_ipv6", "final_name", "behavioral_role", "segment", "Purdue Level", "Behavioral Level", "final_classification"]
    # Ensure they exist (e.g. final_classification might be missing if no leak logic triggered?) 
    # Actually ingest_model ensures them.
    
    edited_df = st.data_editor(
        display_df.select(visible_cols), 
        column_config={
            "is_ipv6": None,
            "final_classification": st.column_config.TextColumn("Type (Scope/Leak)", help="Private, Public, or Misconfigured Leak"),
            "segment": None,
            "Purdue Level": st.column_config.TextColumn("Purdue Level", help="Inherited from Segment"),
            "Behavioral Level": st.column_config.SelectboxColumn("Behavioral Level", help="Observed Purdue Level based on traffic", options=list(seg_res.PURDUE_LEVELS.values()), width="medium"),
            "behavioral_role": st.column_config.TextColumn("Likely Role", help="Inferred from ports (e.g. PLC, Web Server)"),
            "final_name": st.column_config.TextColumn("Best Identity", help="Coalesced from Manual > DHCP > DNS"),
        },
        num_rows="dynamic", 
        use_container_width=True
    )
    
    if st.button("💾 Save Changes"):
        # Save back to disk as the new 'manual' inventory source?
        # Or save as a 'master_list.csv'?
        # Let's save as master_navv_inventory.csv
        edited_df.to_csv("master_navv_inventory.csv", index=False)
        st.success("Saved to `master_navv_inventory.csv`")
        
    st.divider()
    st.subheader("🎨 Inventory Visualization")
    
    # Visual Preview 
    # Select subset for cleaner view
    # Include new DHCP Meta fields
    pdf_inv = display_df.select([
        "ip", "final_name", "dhcp_host_name", "dhcp_domain", "dhcp_client_fqdn", "broadcast_name", "enip_name", 
        "segment", "Purdue Level", "segment_color", "segment_font_color"
    ]).to_pandas().fillna("").replace("None", "")
    
    def highlight_row_inv(row):
        color = row['segment_color']
        text_color = row['segment_font_color']
        
        if not color or color == "None":
             color = "#ffffff"
        if not text_color or text_color == "None":
             # Fallback
             text_color = 'white' if color in ["#08306b", "#2171b5", "#006d2c", "#444444"] else 'black'

        return [f'background-color: {color}; color: {text_color}'] * len(row)

    # Apply row colors
    st.dataframe(
        pdf_inv.style.apply(highlight_row_inv, axis=1),
        use_container_width=True,
        hide_index=True,
        # column_config={
        #     "segment_color": None,
        #     "segment_font_color": None,
        #     "segment": None,
        #     "dhcp_host_name": st.column_config.TextColumn("DHCP Hostname"),
        #     "dhcp_client_fqdn": st.column_config.TextColumn("DHCP FQDN")
        # }
    )
