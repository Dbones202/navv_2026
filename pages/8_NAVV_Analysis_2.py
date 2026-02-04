import streamlit as st
import os
import polars as pl
from utils import check_log_prerequisites, render_sidebar_stats, get_browser_dimensions
from backend.navv_analysis_engine import NavvAnalysisEngine
from backend.inventory_manager import InventoryHarmonizer
from backend.segment_manager import SegmentResolver
from zeek_runner import ZeekRunner

st.set_page_config(page_title="NAVV Analysis (2)", page_icon="🕵️", layout="wide")
# Custom Title in Header (Fixed Position)
# Using extremely high z-index to overlay on Streamlit's native header
st.markdown("""
<div style="
    position: fixed;
    top: 0;
    left: 0;
    right: 0;
    height: 3.75rem; /* Standard Streamlit header height */
    margin-left: 0; /* Centered, so no margin needed */
    z-index: 9999999;
    font-size: 1.5rem;
    font-weight: 700;
    display: flex;
    align-items: center;
    justify-content: center; /* Center horizontally */
    pointer-events: none; /* Let clicks pass through to the header buttons behind */
    color: inherit;
">
    <span style="pointer-events: auto;">🕵️ NAVV Analysis (2)</span> 
</div>
""", unsafe_allow_html=True)

# 1. Log Prerequisite Check
if not check_log_prerequisites():
    st.error("⚠️ No Zeek logs found. Please use the **Ingest** module to process a PCAP file first.")
    # Sidebar footer even if locked? Maybe better not to render it if we stop early, 
    # but the user might want to see the "Status: Ready" (or Empty).
    # Let's render it for consistency so the sidebar doesn't jump.
    render_sidebar_stats()
    st.stop()

# 2. Setup Runner and Paths
zeek = ZeekRunner()
conn_file = os.path.join(zeek.logs_dir, "conn.log")
parquet_cache = os.path.join(zeek.logs_dir, ".navv_conn_summary.parquet")

if "df_connection_summary" in st.session_state:
    df = st.session_state["df_connection_summary"]
else:
    if os.path.exists(parquet_cache) and os.path.exists(conn_file) and (os.path.getmtime(parquet_cache) > os.path.getmtime(conn_file)):
        # Cache exists and is newer than the log file
        with st.spinner("Loading Analyzed Data (Cached)..."):
            try:
                df = pl.read_parquet(parquet_cache)
                st.session_state["df_connection_summary"] = df
            except Exception as e:
                st.warning(f"Failed to load cache, re-analyzing: {e}")
                
    if df is None and os.path.exists(conn_file):
        # Not found in state or cache, start analysis
        with st.spinner("Analyzing Network Traffic (Initial Load)..."):
            try:
                # Initialize Managers
                inv = InventoryHarmonizer()
                inv.ingest_model(
                    inventory_csv="master_navv_inventory.csv" if os.path.exists("master_navv_inventory.csv") else "inventory.csv",
                    conn_log=conn_file,
                    dhcp_log=os.path.join(zeek.logs_dir, "dhcp.log"),
                    dns_log=os.path.join(zeek.logs_dir, "dns.log")
                )
                
                seg = SegmentResolver()
                seg.load_segments("segments.csv")
                
                engine = NavvAnalysisEngine(inv, seg)
                
                # Run Analysis
                df = engine.run_analysis(conn_file)
                
                # Cache it in State
                st.session_state["df_connection_summary"] = df
                # Cache it on Disk
                df.write_parquet(parquet_cache)
                st.toast("Analysis complete. Saved to disk for fast reloads!")
                
            except Exception as e:
                st.error(f"Failed to load analysis data: {e}")
                st.stop()

# 2.5 Layout Optimizations
# Reduce whitespace to maximize data view
st.markdown("""
    <style>
        /* Move content up to fill space left by missing st.title */
        .block-container {
            padding-top: 2.5rem; /* Just enough to clear the header bar we invaded */
            padding-bottom: 0rem;
            padding-left: 2rem;
            padding-right: 2rem;
        }
        /* Hide the anchor links for clean view */
        .st-emotion-cache-16k1qpw { display: none; }
    </style>
""", unsafe_allow_html=True)

# 2. Endpoints Analysis
df_endpoints = None
ep_cache = os.path.join(zeek.logs_dir, ".navv_endpoints.parquet")

if "df_endpoints" in st.session_state:
    df_endpoints = st.session_state["df_endpoints"]
elif os.path.exists(ep_cache) and os.path.exists(conn_file) and (os.path.getmtime(ep_cache) > os.path.getmtime(conn_file)):
    try:
        df_endpoints = pl.read_parquet(ep_cache)
        st.session_state["df_endpoints"] = df_endpoints
    except:
        pass
        
if df_endpoints is None and os.path.exists(conn_file):
    with st.spinner("Analyzing Endpoints..."):
        try:
            # We already have engine initialized up in section 1 if it ran
            # Note: engine is likely not in locals if we loaded from cache
            inv = InventoryHarmonizer()
            inv.ingest_model(
                inventory_csv="master_navv_inventory.csv" if os.path.exists("master_navv_inventory.csv") else "inventory.csv",
                conn_log=conn_file,
                dhcp_log=os.path.join(zeek.logs_dir, "dhcp.log"),
                dns_log=os.path.join(zeek.logs_dir, "dns.log")
            )
            seg = SegmentResolver()
            seg.load_segments("segments.csv")
            engine = NavvAnalysisEngine(inv, seg)
            
            df_endpoints = engine.generate_endpoints_view(conn_file)
            df_endpoints.write_parquet(ep_cache)
            st.session_state["df_endpoints"] = df_endpoints
        except Exception as e:
            st.warning(f"Endpoint analysis failed: {e}")

# Discovery Stats Bar
# Only show if we have endpoints, and either ingest is complete or no hosts are in sidebar
if df_endpoints is not None:
    # User requirement: Internal Assets, External Hosts, Total Unique (excluding Special)
    df_internal = df_endpoints.filter(pl.col("Category") == "Internal")
    df_external = df_endpoints.filter(pl.col("Category") == "External")
    
    count_internal = df_internal.height
    count_external = df_external.height
    count_total = count_internal + count_external
    
    # Store sub-dfs in state for other views (internal/external tables)
    st.session_state["df_endpoints_internal"] = df_internal
    st.session_state["df_endpoints_external"] = df_external
    
    # Discovery Stats bar removed as requested. Data now feeds sidebar footer.

# 3. Filtering Controls & Display
if df is not None:
    with st.expander("🌪️ Filter Data", expanded=False):
        st.caption("Select columns to filter by. Supports partial text matching.")
        
        # 0. Prebuilt Filters (Presets)
        presets = st.multiselect(
            "⚡ Quick Filters", 
            ["Failed Connections (S0/REJ)", "Management Traffic (SSH/RDP)", "High Frequency (>100 Flows)"],
            placeholder="Select filters to combine (AND logic)..."
        )
        
        for p in presets:
            if p == "Failed Connections (S0/REJ)":
                # Zeek States: S0 (Attempt seen, no reply), REJ (Rejected), RSTO/RSTR (Reset)
                fail_states = ["S0", "REJ", "RSTO", "RSTR"]
                if "conn_state" in df.columns:
                    df = df.filter(pl.col("conn_state").is_in(fail_states))
                    
            elif p == "Management Traffic (SSH/RDP)":
                # Ports: 22 (SSH), 23 (Telnet), 3389 (RDP)
                mgmt_ports = [22, 23, 3389]
                # Services text match
                mgmt_svcs = ["ssh", "rdp", "telnet", "vnc"]
                
                # Build logic: Port OR Service
                f_port = pl.lit(False)
                if "dst_port" in df.columns:
                    f_port = pl.col("dst_port").cast(pl.Int64).is_in(mgmt_ports)
                    
                f_svc = pl.lit(False)
                if "service" in df.columns:
                     f_svc = pl.col("service").str.to_lowercase().str.contains("|".join(mgmt_svcs))
                     
                df = df.filter(f_port | f_svc)
                
            elif p == "High Frequency (>100 Flows)":
                if "count" in df.columns:
                    df = df.filter(pl.col("count") > 100)
                    
        if presets:
            st.toast(f"Applied {len(presets)} Quick Filters")

        st.divider()
        
        # 1. Select Columns to Filter
        # Get all column names from the dataframe
        all_cols = df.columns
        # Default to common usage ones if possible, else empty
        filter_cols = st.multiselect("Custom Column Filters", all_cols, placeholder="Choose columns to filter...")
        
        # 2. Generate Inputs
        # We use a dictionary to store the filter values
        filters = {}
        
        if filter_cols:
            cols = st.columns(len(filter_cols))
            for i, col_name in enumerate(filter_cols):
                with cols[i]:
                    # Check dtype
                    dtype = df.schema[col_name]
                    
                    if dtype in [pl.Utf8, pl.Object, pl.String]:
                        val = st.text_input(f"{col_name}", placeholder=f"Contains...")
                        if val:
                            filters[col_name] = ("str", val)
                    elif dtype in [pl.Int64, pl.Int32, pl.Float64]:
                        # For numbers, maybe a min/max or exact? 
                        # Let's simple text for exact or ">10" syntax later? 
                        # For now, simple textual match or exact number is easier for user quickness
                        # But text_input returns str.
                        val = st.text_input(f"{col_name}", placeholder="Exact match")
                        if val:
                            filters[col_name] = ("num", val)
        
        # 3. Apply Filters
        if filters:
            for col_name, (ftype, val) in filters.items():
                if ftype == "str":
                    # Case insensitive contains
                    df = df.filter(pl.col(col_name).str.to_lowercase().str.contains(val.lower()))
                elif ftype == "num":
                    # Try to cast input to number
                    try:
                        num_val = float(val)
                        df = df.filter(pl.col(col_name) == num_val)
                    except:
                        st.warning(f"Invalid number for {col_name}: {val}")

    # 3.5 Pagination Logic
    total_rows = df.height
    
    # Initialize Page Size in Session State if not present
    if "navv_page_size" not in st.session_state:
        st.session_state.navv_page_size = 250
        
    # Initialize Page Number
    if "navv2_page" not in st.session_state:
        st.session_state.navv2_page = 1

    # Get current values
    raw_page_size = st.session_state.get("navv_page_size", 250)
    if raw_page_size == "All":
        page_size = total_rows
        total_pages = 1
    else:
        page_size = int(raw_page_size)
        total_pages = max(1, (total_rows + page_size - 1) // page_size)
        
    # Bounds Check
    if st.session_state.navv2_page > total_pages:
        st.session_state.navv2_page = 1
        
    # Slice Data
    offset = (st.session_state.navv2_page - 1) * page_size
    display_df = df.slice(offset, page_size)
    
    # Calculate Dynamic Height
    browser_height = get_browser_dimensions()
    # Safety check: ensure browser_height is valid for multiplication
    h_val = 800 if browser_height is None else browser_height
    # Target approx 80% of height, with a minimum of 400px
    target_height = max(400, int(h_val * 0.8))

    # Display using Streamlit's native dataframe (supports Polars)
    # Scaled dynamically based on browser height
    st.dataframe(display_df, use_container_width=True, height=target_height)

    # 4. Pagination Controls (Bottom)
    st.markdown("""
    <style>
        /* Compact Buttons */
        div[data-testid="stButton"] button {
            padding: 0px 8px !important;
            min-height: 2rem !important;
            height: 2rem !important;
        }
        /* Compact Number Input */
        div[data-testid="stNumberInput"] {
            width: 100px !important;
        }
        div[data-testid="stNumberInput"] input {
            padding: 2px 8px !important;
        }
        /* Align label for Rows per Page */
        .rows-label {
            padding-top: 5px;
            font-size: 0.9rem;
            text-align: right;
        }
    </style>
    """, unsafe_allow_html=True)
    
    st.divider()
    
    # Navigation Actions
    def set_page(p):
        st.session_state.navv2_page = p

    # Footer Layout
    # Increased buffers (cols[2] and cols[8]) to push the middle 5 closer together
    # Ratios: [RowsL, RowsS, Buffer, <<, <, Jump, >, >>, Buffer, Export]
    f_cols = st.columns([1, 1.2, 2.5, 0.4, 0.4, 0.8, 0.4, 0.4, 2.5, 1.5], gap="small")
    
    with f_cols[0]:
        st.markdown('<p class="rows-label">Rows:</p>', unsafe_allow_html=True)
        
    with f_cols[1]:
        st.selectbox(
            "Rows per page", 
            [25, 50, 100, 250, 500, 1000, "All"], 
            key="navv_page_size",
            label_visibility="collapsed"
        )
        
    with f_cols[3]:
        st.button("⏮️", disabled=st.session_state.navv2_page <= 1, on_click=set_page, args=(1,), use_container_width=True)
        
    with f_cols[4]:
        st.button("⬅️", disabled=st.session_state.navv2_page <= 1, on_click=set_page, args=(st.session_state.navv2_page - 1,), use_container_width=True)
        
    with f_cols[5]:
        # Direct Page Jump
        p_input = st.number_input(
            "Page", 
            min_value=1, 
            max_value=total_pages, 
            value=st.session_state.navv2_page, 
            label_visibility="collapsed"
        )
        if p_input != st.session_state.navv2_page:
            st.session_state.navv2_page = p_input
            st.rerun()
            
    with f_cols[6]:
        st.button("➡️", disabled=st.session_state.navv2_page >= total_pages, on_click=set_page, args=(st.session_state.navv2_page + 1,), use_container_width=True)
        
    with f_cols[7]:
        st.button("⏭️", disabled=st.session_state.navv2_page >= total_pages, on_click=set_page, args=(total_pages,), use_container_width=True)
        
    with f_cols[9]:
        st.button("📥 Export", use_container_width=True, help="Placeholder for Excel Export")

    # Status Line
    st.caption(f"Showing page **{st.session_state.navv2_page}** of **{total_pages}** • Total Flows: **{total_rows}**")

# 4. Sidebar Stats
render_sidebar_stats()
