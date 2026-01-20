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

# Template Download
template_csv = "Name,CIDR,Level\nExample Segment,192.168.10.0/24,4"
st.sidebar.download_button(
    label="Download Template CSV",
    data=template_csv,
    file_name="segment_template.csv",
    mime="text/csv"
)

uploaded_segments = st.sidebar.file_uploader("Upload Segments (CSV)", type=["csv"])

segments_path = "segments.csv"

if uploaded_segments:
    try:
        # Validate before saving
        # Polars read_csv might read bytes directly
        # We need to make sure we don't consume it such that we can't save it, or we save from the dataframe
        
        # Read to validate
        df_val = pl.read_csv(uploaded_segments, ignore_errors=True)
        required = {"Name", "CIDR", "Level"}
        missing = required - set(df_val.columns)
        
        if not missing:
            # Valid, allow save
            # Reset pointer if read_csv moved it? Polars usually reads from bytes so it might not affect the UploadedFile stream position if it treats it as bytes, 
            # but streamlit UploadedFile acts like a file. safer to seek(0) if needed or just write the bytes we have.
            # actually we can just use `uploaded_segments.getbuffer()` as before, assuming it's still available.
            uploaded_segments.seek(0)
            with open(segments_path, "wb") as f:
                f.write(uploaded_segments.getbuffer())
            st.sidebar.success("Segments Loaded")
        else:
            st.sidebar.error(f"Missing columns: {missing}. Please use the template.")
            
    except Exception as e:
        st.sidebar.error(f"Invalid file: {e}")

st.sidebar.divider()
st.sidebar.header("🎨 Color Picker")
st.sidebar.caption("Pick a color to copy its HEX code.")
picked_color = st.sidebar.color_picker("Picker", "#00f900", key="sidebar_color_picker")
st.sidebar.code(picked_color, language="text")


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
                st.info(f"Scanning {unique_ips.height} unique IPs...")
                proposed = seg.auto_discover(unique_ips)
                
                # 2. Load Existing (to check duplicates)
                if os.path.exists(segments_path):
                    # Schema enforcement
                    existing = pl.read_csv(segments_path, schema_overrides={"Name": pl.String, "CIDR": pl.String, "Level": pl.Int32})
                else:
                    existing = pl.DataFrame({"Name": [], "CIDR": [], "Level": []}, schema={"Name": pl.String, "CIDR": pl.String, "Level": pl.Int32})
                
                # Check Overlap
                st.info(f"Proposed: {proposed.height} segments. Existing: {existing.height} segments.")

                # Filter proposed where CIDR is not in existing["CIDR"]
                # Use Anti-Join for robustness and performance
                new_segs = proposed.join(existing, on="CIDR", how="anti")
                
                if new_segs.height > 0:
                    # Concat
                    updated = pl.concat([existing, new_segs])
                    updated.write_csv(segments_path)
                    st.success(f"Added {new_segs.height} new segments! Reloading...")
                    st.rerun()
                else:
                    st.warning("No new unique segments found (All proposed segments already verify against existing list).")
                    
            except Exception as e:
                st.error(f"Discovery failed: {e}")
        else:
            st.error("No `conn.log` found.")

st.divider()
with st.expander("ℹ️ How it Works: Segmentation & Autodiscovery"):
    st.markdown("""
    ### 1. Segmentation Logic
    Segments are defined by **CIDR** blocks (e.g., `192.168.10.0/24`) and assigned a **Purdue Level** (0-8) for risk classification.
    *   **Matching**: IPs are matched to the specific subnet they belong to.
    *   **Visualization**: Colors are auto-assigned based on the Purdue Level (Blue=OT, Green/Orange=IT/DMZ, Grey=Internet).

    ### 2. Autodiscovery Process
    When you run "Auto-Discovery", the system performs the following:
    1.  **Scan**: Reads `conn.log` to find all unique IP addresses involved in traffic.
    2.  **Group**: Aggregates these IPs into `/24` subnets (Standard Class C).
    3.  **Propose**: Creates a proposed segment for every `/24` block containing active IPs.
        *   *Private IPs*: Default to Level 4 (Site Operations).
        *   *Public IPs*: Default to Level 8 (Internet).
    4.  **Filter**: Removes any proposed segments that conflict with or duplicate your existing definitions using an **Anti-Join**.

    ### 3. Usage
    *   **Manual Override**: You can upload a `segments.csv` to enforce your own strict network boundaries.
    *   **Hybrid**: You can start with Auto-Discovery to find active networks, then manually refine the Names and Levels in the editor.

    ### 4. Data Import Format (CSV)
    *   **Name** (Required): Segment label.
    *   **CIDR** (Required): Network range (e.g., `10.0.0.0/24`).
    *   **Level** (Required): Integer (1-8) representing the Purdue Level.

    ### 5. Purdue Level Reference
    Use these integer codes in your CSV `Level` column:
    *   **8**: Internet (Public)
    *   **7**: IT DMZ
    *   **6**: IT Enterprise
    *   **5**: OT DMZ
    *   **4**: Site Operations / Logistics
    *   **3**: Supervisory Control
    *   **2**: Basic Control
    *   **1**: Physical Process
    """)
