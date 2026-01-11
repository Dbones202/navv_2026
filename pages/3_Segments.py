import streamlit as st
import polars as pl
import os
from backend.segment_manager import SegmentResolver
from zeek_runner import ZeekRunner

st.set_page_config(page_title="Segment Manager", page_icon="🌐", layout="wide")
st.title("🌐 Network Segmentation")

seg = SegmentResolver()
zeek = ZeekRunner()

# Sidebar
st.sidebar.header("Segment Actions")
uploaded_segments = st.sidebar.file_uploader("Upload Segments (CSV)", type=["csv"])

segments_path = "segments.csv"

if uploaded_segments:
    with open(segments_path, "wb") as f:
        f.write(uploaded_segments.getbuffer())
    st.sidebar.success("Segments Loaded")

# Current Segments
current_df = seg.load_segments(segments_path)

col1, col2 = st.columns([2, 1])

with col1:
    st.subheader("Defined Segments")
    
    # Filter
    scope_filter = st.radio("Scope Filter", ["All", "Private/Internal", "Public/Internet"], horizontal=True)
    
    # 1. Map Integer Level to String Label for Display/Editing
    # We leverage the mapping in SegmentResolver
    
    # Helper to map Int -> Str
    def map_level_to_label(val):
        return seg.PURDUE_LEVELS.get(val, "Unknown")
        
    # Helper to map Str -> Int
    def map_label_to_level(label):
        return seg.LEVEL_TO_INT.get(label, 0) # Default to 0
        
    # Helper for Color
    def map_level_to_hex(val):
        return seg.PURDUE_COLORS.get(val, "#ffffff")
        
    # Helper for Font
    def map_color_to_font(hex_color):
         if hex_color in ["#c6dbef", "#ffffff", "#a1d99b"]: # Light Blue, White, Light Green
              return "#000000"
         return "#ffffff"

    # Add Label & Color Columns
    display_df = current_df.with_columns(
        pl.col("Level").cast(pl.Int32, strict=False).fill_null(0).alias("Level_Int")
    ).with_columns([
        pl.col("Level_Int").map_elements(map_level_to_label, return_dtype=pl.String).alias("Purdue Level"),
        pl.col("Level_Int").map_elements(map_level_to_hex, return_dtype=pl.String).alias("Color")
    ]).with_columns(
        pl.col("Color").map_elements(map_color_to_font, return_dtype=pl.String).alias("FontColor")
    )

    # Filter Logic (using Integer)
    if scope_filter == "Private/Internal":
        # Internet is 8. So < 8.
        display_df = display_df.filter(pl.col("Level_Int") < 8)
    elif scope_filter == "Public/Internet":
        display_df = display_df.filter(pl.col("Level_Int") >= 8)
        
    # Editor
    # We hide 'Level' and 'Level_Int', showing 'Name', 'CIDR', 'Purdue Level', 'Color', 'FontColor'
    
    edited_df = st.data_editor(
        display_df.select(["Name", "CIDR", "Purdue Level", "Color", "FontColor"]).to_pandas(), 
        num_rows="dynamic", 
        use_container_width=True,
        column_config={
            "Purdue Level": st.column_config.SelectboxColumn(
                "Purdue Level",
                help="Select the implementation zone",
                width="medium",
                options=list(seg.PURDUE_LEVELS.values()),
                required=True
            ),
            "CIDR": st.column_config.TextColumn("Network CIDR", help="e.g. 192.168.1.0/24", required=True),
            "Name": st.column_config.TextColumn("Segment Name", required=True),
            "Color": st.column_config.TextColumn("Zone Color", help="Auto-assigned based on Level", disabled=True),
            "FontColor": st.column_config.TextColumn("Font Color", help="Auto-contrast", disabled=True)
        }
    )
    
    if st.button("💾 Save Segments"):
        if scope_filter != "All":
             st.warning("⚠️ Switch to 'All' filter to save changes safely.")
        else:
             # Convert Pandas -> Polars
             p_edited = pl.from_pandas(edited_df)
             
             # Map 'Purdue Level' (Str) back to 'Level' (Int)
             # Re-Calculate Color/Font to ensure consistency (in case user found a way to edit it or rows changed)
             
             final_df = p_edited.with_columns(
                 pl.col("Purdue Level").map_elements(map_label_to_level, return_dtype=pl.Int32).alias("Level")
             ).with_columns(
                 pl.col("Level").map_elements(map_level_to_hex, return_dtype=pl.String).alias("Color")
             ).with_columns(
                 pl.col("Color").map_elements(map_color_to_font, return_dtype=pl.String).alias("FontColor")
             ).select(["Name", "CIDR", "Level", "Color", "FontColor"])
             
             final_df.write_csv(segments_path)
             st.success("Segments saved.")

    st.divider()
    st.subheader("🎨 Color-Coded Preview")
    
    # Visual Preview using Pandas Styler (Row Highlighting)
    # We use the display_df which has the 'Color' column computed
    pdf = display_df.select(["Name", "CIDR", "Purdue Level", "Color", "FontColor"]).to_pandas()
    
    def highlight_row(row):
        color = row['Color']
        text_color = row['FontColor']
        return [f'background-color: {color}; color: {text_color}'] * len(row)

    st.dataframe(
        pdf.style.apply(highlight_row, axis=1), 
        use_container_width=True,
        hide_index=True
    )

with col2:
    st.subheader("Auto-Discovery")
    st.write("Analyze `conn.log` to find active subnets and append them to your list.")
    
    conn_log = os.path.join(zeek.logs_dir, "conn.log")
    
    if st.button("🔍 Run & Merge Auto-Discovery"):
        if os.path.exists(conn_log):
            try:
                # 1. Calculate Proposed
                q = pl.scan_csv(conn_log, separator='\t', comment_prefix="#", has_header=False, ignore_errors=True)
                ips = q.select([
                    pl.col("column_3").alias("ip"),
                    pl.col("column_5").alias("dst_ip")
                ]).collect()
                unique_ips = pl.concat([ips.select("ip"), ips.select(pl.col("dst_ip").alias("ip"))]).unique()
                proposed = seg.auto_discover(unique_ips)
                
                # 2. Load Existing (to check duplicates)
                if os.path.exists(segments_path):
                    # Schema enforcement
                    existing = pl.read_csv(segments_path, schema_overrides={"Name": pl.String, "CIDR": pl.String, "Level": pl.Int32})
                else:
                    existing = pl.DataFrame({"Name": [], "CIDR": [], "Level": []}, schema={"Name": pl.String, "CIDR": pl.String, "Level": pl.Int32})
                
                # Ensure types for join/filter
                # existing CIDR vs proposed CIDR
                
                # Filter proposed where CIDR is not in existing["CIDR"]
                # Polars anti-join or filter is_in
                new_segs = proposed.filter(~pl.col("CIDR").is_in(existing["CIDR"]))
                
                if new_segs.height > 0:
                    # Concat
                    updated = pl.concat([existing, new_segs])
                    updated.write_csv(segments_path)
                    st.success(f"Added {new_segs.height} new segments! Reloading...")
                    st.rerun()
                else:
                    st.info("No new unique segments found.")
                    
            except Exception as e:
                st.error(f"Discovery failed: {e}")
        else:
            st.error("No `conn.log` found.")
