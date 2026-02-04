import streamlit as st
import pandas as pd
import polars as pl
import sys

st.set_page_config(page_title="Debug Console", page_icon="🐞", layout="wide")
st.title("🐞 Debug Console")

st.markdown("""
This tool inspects the current `st.session_state` and allows you to visualize any DataFrames currently in memory.
""")

# 1. State Inspection
st.subheader("Session State Inventory")

# Filter keys that are likely DataFrames
all_keys = sorted(st.session_state.keys())
df_keys = []
other_keys = []

for k in all_keys:
    val = st.session_state[k]
    if isinstance(val, (pd.DataFrame, pl.DataFrame)):
        df_keys.append(k)
    else:
        other_keys.append(k)

c1, c2 = st.columns(2)
with c1:
    st.info(f"**DataFrames in Memory**: {len(df_keys)}")
    st.code("\n".join(df_keys) if df_keys else "None")

with c2:
    st.info(f"**Other Variables**: {len(other_keys)}")
    with st.expander("Show Variable Names"):
        st.code("\n".join(other_keys) if other_keys else "None")

st.divider()

# 2. DataFrame Inspector
st.subheader("DataFrame Inspector")

if not df_keys:
    st.warning("No DataFrames found in memory. Run 'Ingest' or 'Analysis' to generate data.")
else:
    selected_key = st.selectbox("Select DataFrame to View", df_keys)
    
    if selected_key:
        df_obj = st.session_state[selected_key]
        
        # Meta Info
        is_polars = isinstance(df_obj, pl.DataFrame)
        df_type = "Polars 🐻‍❄️" if is_polars else "Pandas 🐼"
        
        if is_polars:
            row_count = df_obj.height
            col_count = df_obj.width
            memory_usage = df_obj.estimated_size() / (1024 * 1024)
        else:
            row_count = len(df_obj)
            col_count = len(df_obj.columns)
            try:
                memory_usage = df_obj.memory_usage(deep=True).sum() / (1024 * 1024)
            except:
                memory_usage = 0

        # Metrics
        m1, m2, m3, m4 = st.columns(4)
        m1.metric("Type", df_type)
        m2.metric("Rows", f"{row_count:,}")
        m3.metric("Columns", f"{col_count}")
        m4.metric("Est. Memory", f"{memory_usage:.2f} MB")
        
        # View
        st.caption("Head (Top 100)")
        
        if is_polars:
            # Convert to Pandas for visualization if complex types exist, or use st.dataframe directly (Streamlit supports Polars now)
            st.dataframe(df_obj.head(100), use_container_width=True)
            
            with st.expander("Schema / Dtypes"):
                st.json(str(df_obj.schema))
        else:
            st.dataframe(df_obj.head(100), use_container_width=True)
            
            with st.expander("Dtypes"):
                st.code(df_obj.dtypes)

st.divider()
if st.button("🗑️ Clear Session State"):
    for k in list(st.session_state.keys()):
        del st.session_state[k]
    st.success("Session state cleared. Please refresh page.")
