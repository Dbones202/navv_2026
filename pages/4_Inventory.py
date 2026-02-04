import streamlit as st
import polars as pl
import os
from backend.inventory_manager import InventoryHarmonizer
from utils import check_log_prerequisites, render_sidebar_stats, get_browser_dimensions
from zeek_runner import ZeekRunner

st.set_page_config(page_title="Inventory Manager", page_icon="📦", layout="wide")

# Custom Title in Header (Fixed Position)
st.markdown("""
<div style="
    position: fixed;
    top: 0;
    left: 0;
    right: 0;
    height: 3.75rem; 
    margin-left: 0; 
    z-index: 9999999;
    font-size: 1.5rem;
    font-weight: 700;
    display: flex;
    align-items: center;
    justify-content: center; 
    pointer-events: none; 
    color: inherit;
">
    <span style="pointer-events: auto;">📦 Inventory Manager</span> 
</div>
""", unsafe_allow_html=True)

# Layout Optimizations
st.markdown("""
    <style>
        .block-container {
            padding-top: 2.5rem;
            padding-bottom: 0rem;
            padding-left: 2rem;
            padding-right: 2rem;
        }
        [data-testid="stHeader"] {
            background: rgba(0,0,0,0);
        }
        /* Hide pagination controls if they appear */
        [data-testid="stDataTablePagination"] {
            display: none !important;
        }
        /* Custom Scrollbar Styling for easier grabbing */
        ::-webkit-scrollbar {
            width: 12px;
            height: 12px;
        }
        ::-webkit-scrollbar-track {
            background: rgba(0,0,0,0.05);
        }
        ::-webkit-scrollbar-thumb {
            background: rgba(255,255,255,0.2);
            border-radius: 6px;
            border: 2px solid transparent;
            background-clip: content-box;
        }
        ::-webkit-scrollbar-thumb:hover {
            background: rgba(255,255,255,0.4);
            border: 0px solid transparent;
        }
    </style>
""", unsafe_allow_html=True)

if not check_log_prerequisites():
    st.error("⚠️ No Zeek logs found. Please use the **Ingest** module to process a PCAP file first.")
    st.stop()


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
zeek = ZeekRunner()
conn_log_path = os.path.join(zeek.logs_dir, "conn.log")
dhcp_log_path = os.path.join(zeek.logs_dir, "dhcp.log")
dns_log_path = os.path.join(zeek.logs_dir, "dns.log")
ntlm_log_path = os.path.join(zeek.logs_dir, "ntlm.log")
enip_log_path = os.path.join(zeek.logs_dir, "enip.log")
inventory_path = None

# Parquet Caching
parquet_inventory_cache = os.path.join(zeek.logs_dir, ".navv_master_inventory.parquet")

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


# Create Tabs
tab_entry, tab_viz = st.tabs(["📝 Data Entry", "🎨 Visualization"])

with tab_entry:
    # 2. Type Check & Auto-Load from Cache
    if 'master_asset_list' in st.session_state:
        # If it's Pandas (Legacy), convert to Polars or clear it
        if not isinstance(st.session_state['master_asset_list'], pl.DataFrame):
            try:
                st.session_state['master_asset_list'] = pl.from_pandas(st.session_state['master_asset_list'])
            except:
                del st.session_state['master_asset_list']
                st.sidebar.warning("Resetting Asset List due to format change.")
        
        # One-time cleanup for IP-as-Name in session state
        if 'master_asset_list' in st.session_state:
            df_check = st.session_state['master_asset_list']
            if "manual_name" in df_check.columns:
                has_ip_as_name = df_check.filter(pl.col("manual_name") == pl.col("ip")).height > 0
                if has_ip_as_name:
                    st.session_state['master_asset_list'] = df_check.with_columns(
                        pl.when(pl.col("manual_name") == pl.col("ip"))
                        .then(None)
                        .otherwise(pl.col("manual_name"))
                        .alias("manual_name")
                    )

    if 'master_asset_list' not in st.session_state:
        if os.path.exists(parquet_inventory_cache) and os.path.exists(conn_log_path) and (os.path.getmtime(parquet_inventory_cache) > os.path.getmtime(conn_log_path)):
            try:
                 df_cached = pl.read_parquet(parquet_inventory_cache)
                 st.session_state['master_asset_list'] = df_cached
                 st.toast("Loaded Asset List from cache.")
            except Exception as e:
                 st.sidebar.warning(f"Cache load failed: {e}")

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
                st.session_state['master_asset_list'] = df
                
                # Cache it in Parquet
                try:
                    df.write_parquet(parquet_inventory_cache)
                    st.toast("Master Asset List saved to disk!")
                except Exception as e:
                    st.warning(f"Failed to cache inventory: {e}")
                
                status.update(label="Inventory Build Complete", state="complete", expanded=False)
        else:
            st.error("No `conn.log` found. Please ingest a PCAP first.")

    # Display Entry
    if 'master_asset_list' in st.session_state:
        # Calculate Dynamic Height
        win_h = get_browser_dimensions()
        # We want about 80% of window or at least 400px
        dynamic_height = max(400, int(win_h * 0.75))
        
        # Filter
        scope_filter = st.radio("Scope Filter", ["All", "Private IP", "Public IP"], horizontal=True)
        
        df = st.session_state['master_asset_list']
        
        # Warning for conflicts (L2 Leak)
        leaks = df.filter(pl.col("final_classification") == "L2 Leak (Misconfig)")
        if leaks.height > 0:
            st.error(f"🚨 **CRITICAL SECURITY WARNING**: {leaks.height} Public IPs detected on Local Network (Layer 2 Leak)!")
            st.dataframe(leaks)
        
        # Map Level Int -> Label
        from backend.segment_manager import SegmentResolver
        seg_res = SegmentResolver()
        
        # Sort by IP (Polars implementation)
        import ipaddress
        def safe_ip_sort(ip_str):
            try: return str(ipaddress.ip_address(ip_str).packed.hex())
            except: return "0"
            
        df = df.with_columns(
            pl.col("ip").map_elements(safe_ip_sort, return_dtype=pl.String).alias("_ip_sort")
        ).sort("_ip_sort").drop("_ip_sort")

        # Schema Validation & Backfill
        required_cols = [
            "dhcp_host_name", "dhcp_client_fqdn", "dhcp_domain", "dhcp_computed_name",
            "enip_name", "broadcast_name", "dns_name", "manual_name",
            "name_confidence", "behavior_level", "special_name"
        ]
        for col in required_cols:
            if col not in df.columns:
                if col == "behavior_level" or col == "name_confidence":
                    df = df.with_columns(pl.lit(0).alias(col))
                else:
                    df = df.with_columns(pl.lit(None).cast(pl.String).alias(col))

        def map_lvl(val):
            try: return seg_res.PURDUE_LEVELS.get(int(val or 0), "Unknown")
            except: return "Unknown"

        # 1. Prepare Display Data
        display_df = df.with_columns([
            pl.col("purdue_level").fill_null(0).map_elements(map_lvl, return_dtype=pl.String).alias("Purdue Level"),
            pl.col("behavior_level").fill_null(0).map_elements(map_lvl, return_dtype=pl.String).alias("Behavioral Level"),
            pl.coalesce([
                pl.col("manual_name"), 
                pl.col("dhcp_computed_name"), 
                pl.col("enip_name"),
                pl.col("broadcast_name"),
                pl.col("dns_name"),
                pl.col("segment_fallback_name")
            ]).cast(pl.String).alias("Resolved Identity")
        ])

        # 2. View Logic
        if scope_filter == "All":
            # Show all endpoints EXCEPT special/infrastructure
            all_view = display_df.filter(pl.col("special_name").is_null())
            visible_cols = ["ip", "final_classification", "Resolved Identity"]
            
            st.dataframe(
                all_view.select(visible_cols),
                use_container_width=True,
                height=dynamic_height,
                hide_index=True
            )
            
        elif scope_filter == "Private IP":
            # Show Private IPs only
            private_view = display_df.filter(pl.col("purdue_level") < 8)
            
            # Requested Order: IP, MAC, MAC Vendor, Purdue Level, Role, THEN Resolved Identity, THEN Discovery (Manual first)
            visible_cols = [
                "ip", "mac", "mac_vendor", "Purdue Level", "behavioral_role",
                "Resolved Identity", "manual_name", "dhcp_computed_name", "enip_name", "broadcast_name", "dns_name"
            ]
            
            edited_df = st.data_editor(
                private_view.select(visible_cols),
                column_config={
                    "Resolved Identity": st.column_config.TextColumn("Resolved Identity 🏷️", help="Computed result based on discovery priority.", disabled=True),
                    "manual_name": st.column_config.TextColumn("Manual Override ✏️", help="Update this to manually set asset identity."),
                    "dhcp_computed_name": st.column_config.TextColumn("DHCP Discovery", disabled=True),
                    "enip_name": st.column_config.TextColumn("EtherNet/IP", disabled=True),
                    "broadcast_name": st.column_config.TextColumn("Broadcast/Local", disabled=True),
                    "dns_name": st.column_config.TextColumn("DNS Name", width=350, disabled=True),
                    "behavioral_role": st.column_config.TextColumn("Likely Role", disabled=True),
                },
                num_rows="dynamic",
                use_container_width=True,
                key="private_inventory_editor_v4",
                height=dynamic_height
            )
            
            # Reactivity: Sync manual_name edits back to session state
            if edited_df is not None and len(edited_df) > 0:
                update_map = dict(zip(edited_df['ip'], edited_df['manual_name']))
                # Sync back to session state to trigger reactive update on next rerun
                current_df = st.session_state['master_asset_list']
                if isinstance(current_df, pl.LazyFrame):
                    current_df = current_df.collect()
                
                st.session_state['master_asset_list'] = current_df.with_columns(
                    pl.col("ip").replace(update_map, default=pl.col("manual_name")).alias("manual_name")
                )

            if st.button("💾 Save Private Changes"):
                final_df = st.session_state['master_asset_list']
                if isinstance(final_df, pl.LazyFrame):
                    final_df = final_df.collect()
                final_df.write_parquet(parquet_inventory_cache)
                final_df.write_csv("master_navv_inventory.csv")
                st.success("Changes saved and cached!")

        elif scope_filter == "Public IP":
            # Show Public IPs only (Level 8+)
            public_view = display_df.filter(pl.col("purdue_level") >= 8)
            
            # Requested Order: IP, THEN Resolved Identity, THEN Discovery (Manual first)
            visible_cols = [
                "ip", "Resolved Identity", "manual_name", "dhcp_computed_name", "enip_name", "broadcast_name", "dns_name"
            ]
            
            edited_df = st.data_editor(
                public_view.select(visible_cols),
                column_config={
                    "Resolved Identity": st.column_config.TextColumn("Resolved Identity 🏷️", help="Computed site/device name.", disabled=True),
                    "manual_name": st.column_config.TextColumn("Manual Override ✏️", help="Update this to manually set site/device identity."),
                    "dhcp_computed_name": st.column_config.TextColumn("DHCP Discovery", disabled=True),
                    "enip_name": st.column_config.TextColumn("EtherNet/IP", disabled=True),
                    "broadcast_name": st.column_config.TextColumn("Broadcast/Local", disabled=True),
                    "dns_name": st.column_config.TextColumn("DNS Name", width=350, disabled=True),
                },
                num_rows="dynamic",
                use_container_width=True,
                key="public_inventory_editor_v4",
                height=dynamic_height
            )

            # Reactivity: Sync manual_name edits back to session state
            if edited_df is not None and len(edited_df) > 0:
                update_map = dict(zip(edited_df['ip'], edited_df['manual_name']))
                current_df = st.session_state['master_asset_list']
                if isinstance(current_df, pl.LazyFrame):
                    current_df = current_df.collect()
                
                st.session_state['master_asset_list'] = current_df.with_columns(
                    pl.col("ip").replace(update_map, default=pl.col("manual_name")).alias("manual_name")
                )
            
            if st.button("💾 Save Public Changes"):
                final_df = st.session_state['master_asset_list']
                if isinstance(final_df, pl.LazyFrame):
                    final_df = final_df.collect()
                final_df.write_parquet(parquet_inventory_cache)
                final_df.write_csv("master_navv_inventory.csv")
                st.success("Changes saved and cached!")
        
        if st.sidebar.button("🗑️ Clear Inventory Cache"):
            if os.path.exists(parquet_inventory_cache):
                os.remove(parquet_inventory_cache)
            if 'master_asset_list' in st.session_state:
                del st.session_state['master_asset_list']
            st.sidebar.success("Cache Cleared")
            st.rerun()

with tab_viz:
    if 'master_asset_list' in st.session_state:
        st.subheader("Inventory Visualization")
        
        df_v = st.session_state['master_asset_list']
        
        from backend.segment_manager import SegmentResolver
        seg_res_v = SegmentResolver()
        
        def map_lvl_v(val):
            try: return seg_res_v.PURDUE_LEVELS.get(int(val or 0), "Unknown")
            except: return "Unknown"
            
        display_df_v = df_v.with_columns([
            pl.col("purdue_level").fill_null(0).map_elements(map_lvl_v, return_dtype=pl.String).alias("Purdue Level")
        ])

        # Dynamic height for viz as well
        win_h = get_browser_dimensions()
        dynamic_height_v = max(400, int(win_h * 0.75))

        # Visual Preview 
        pdf_inv = display_df_v.select([
            "ip", "final_name", "dhcp_host_name", "dhcp_domain", "dhcp_client_fqdn", "broadcast_name", "enip_name", 
            "segment", "Purdue Level", "segment_color", "segment_font_color"
        ]).to_pandas().fillna("").replace("None", "")
        
        def highlight_row_inv(row):
            color = row['segment_color']
            text_color = row['segment_font_color']
            if not color or color == "None": color = "#ffffff"
            if not text_color or text_color == "None":
                 text_color = 'white' if color in ["#08306b", "#2171b5", "#006d2c", "#444444"] else 'black'
            return [f'background-color: {color}; color: {text_color}'] * len(row)

        st.dataframe(
            pdf_inv.style.apply(highlight_row_inv, axis=1),
            use_container_width=True,
            hide_index=True,
            height=dynamic_height_v
        )
    else:
        st.info("Build the Master Asset List in the **Data Entry** tab to see visualizations.")

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

# Sidebar Footer
render_sidebar_stats()

