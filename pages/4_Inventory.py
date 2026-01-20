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
        "Name": ["Workstation-01"]
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
    try:
        # Validate before saving
        df_val = pl.read_csv(uploaded_file, ignore_errors=True)
        required = {"IP", "Name"}
        missing = required - set(df_val.columns)
        
        if not missing:
            uploaded_file.seek(0)
            inventory_path = "inventory.csv"
            with open(inventory_path, "wb") as f:
                f.write(uploaded_file.getbuffer())
            st.sidebar.success("Inventory Loaded")
        else:
            st.sidebar.error(f"Missing columns: {missing}. Required: IP, Name. Please use the template.")
            
    except Exception as e:
         st.sidebar.error(f"Invalid file: {e}")
elif os.path.exists("inventory.csv"):
    inventory_path = "inventory.csv"
    st.sidebar.info("Using existing inventory.csv")

# Load Mode
if st.button("🔄 Refresh / Build Master Asset List"):
    if os.path.exists(conn_log_path):
        with st.status("Building Master Asset List...", expanded=True) as status:
            status.write("Correlating Activity Logs (Conn/DHCP/DNS/Enip)...")
            
            # We call ingest which does the heavy lifting
            df = inv.ingest_model(
                inventory_csv=inventory_path, 
                conn_log=conn_log_path, 
                dhcp_log=dhcp_log_path,
                dns_log=dns_log_path,
                ntlm_log=ntlm_log_path,
                enip_log=enip_log_path
            )
            
            status.write("Finalizing Asset Profiles...")
            # Save to session (or disk - for now disk is easier for statelessness between re-runs if we save result)
            # We'll rely on session state for inter-interaction persistence if needed, but here we just re-run.
            st.session_state['master_asset_list'] = df.to_pandas() # Convert to pandas for st.data_editor support
            
            status.update(label="Inventory Build Complete", state="complete", expanded=False)
    else:
        st.error("No `conn.log` found. Please ingest a PCAP first.")

# Display
if 'master_asset_list' in st.session_state:
    st.subheader("Master Asset List")
    
    # Filter
    scope_filter = st.radio("Scope Filter", ["All", "Private IP", "Public IP"], horizontal=True)
    
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
    
    # Sort by IP (Mixed IPv4/IPv6) using Pandas (handled better for arbitrary precision ints)
    def ip_sort_key(ip_str):
        import ipaddress
        try:
             return int(ipaddress.ip_address(ip_str))
        except:
             return 0
             
    # Create temp column in Pandas, Sort, Drop
    df['ip_int'] = df['ip'].apply(ip_sort_key)
    df = df.sort_values('ip_int')
    df = df.drop(columns=['ip_int'])

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
            
    # Apply Filters
    if scope_filter == "Private IP":
        # Internet is 8. So < 8.
        p_df = p_df.filter(pl.col("purdue_level") < 8)
    elif scope_filter == "Public IP":
        p_df = p_df.filter(pl.col("purdue_level") >= 8)

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

st.divider()
with st.expander("ℹ️ How it Works: Asset Identification Logic"):
    st.markdown("""
    ### 1. Data Aggregation
    This module correlates multiple Zeek logs to build a unified Asset Profile for every IP:
    *   **Manual Inventory**: User-uploaded CSV (Highest Priority).
    *   **DHCP Logs**: Provides Hostnames, FQDNs, and MAC addresses.
    *   **Name Resolution**: DNS (PTR), NTLM (Hostnames), and ENIP (Industrial Protocol Identities).
    *   **Activity Logs (`conn.log`)**: Determines active presence and roles.

    ### 2. Identity Cascading (Waterfall Fallback)
    The "Final Name" is determined by checking sources in this specific order of reliability:
    1.  **Special IP Types** (e.g., Multicast, Broadcast, Link-Local)
    2.  **Manual Inventory Match** (User Overrides)
    3.  **DHCP Identity** (Computed from Hostname + Domain)
    4.  **Industrial Protocol Name** (EtherNet/IP Identity)
    5.  **Broadcast Name** (NetBIOS / LLMNR / NTLM)
    6.  **DNS Name** (Reverse Lookup)
    7.  **Public Internet** (If IP is Public, labeled "INTERNET")
    8.  **Fallback**: "Unknown Device in [Segment Name]"

    ### 3. Behavioral Enrichment
    *   **Role Detection**: Infers roles (PLC, Web Server, DNS) based on open ports found in traffic.
    *   **Switch Detection**: If multiple IPs are seen sharing the same MAC address, the device is flagged as a "Likely Switch/Router".
    *   **L2 Leak Detection**: If a Public IP is seen with a local MAC address, it is flagged as a misconfiguration.

    ### 4. Data Import Format (CSV)
    When uploading a manual inventory, the CSV must use the following headers:
    *   **IP** (Required): The IP address of the asset.
    *   **Name** (Required): The friendly name for the asset.
    *   **Location** (Optional): Physical or logical location.
    *   **Description** (Optional): Additional notes.

    *Example*:
    ```csv
    IP,Name,Location,Description
    192.168.1.10,HMI-01,Control Room,Main HMI
    ```
    """)
