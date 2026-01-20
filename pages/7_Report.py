import streamlit as st
import pandas as pd
import io
import os

st.set_page_config(page_title="Report Export", page_icon="📑", layout="wide")
st.title("📑 Report Generation")

if 'analysis_df' not in st.session_state:
    st.warning("⚠️ No Analysis data found. Please run the **NAVV Analysis** first.")
    st.stop()

df = st.session_state['analysis_df']

st.write("Ready to export the updated analysis.")

# Summary Stats
stats = {
    "Total Flows": len(df),
    "Critical Risks": len(df[df['risk_alert'] == 'CRITICAL']),
    "Unique Source Assets": df['src_name'].nunique(),
    "Generated At": str(pd.Timestamp.now())
}
stats_df = pd.DataFrame([stats])

# Excel Buffer
output = io.BytesIO()

if st.button("Generate Excel Report"):
    with pd.ExcelWriter(output, engine='xlsxwriter') as writer:
        stats_df.to_excel(writer, sheet_name='Summary', index=False)
        df.to_excel(writer, sheet_name='Traffic_Analysis', index=False)
        
        # Add Inventory Sheet if available
        if os.path.exists("master_navv_inventory.csv"):
            try:
                inv_df = pd.read_csv("master_navv_inventory.csv")
                inv_df.to_excel(writer, sheet_name='Inventory_Master', index=False)
            except:
                pass
        
        # Add Segments Sheet if available
        if os.path.exists("segments.csv"):
             try:
                seg_df = pd.read_csv("segments.csv")
                seg_df.to_excel(writer, sheet_name='Segments', index=False)
             except:
                 pass
                 
    output.seek(0)
    
    st.download_button(
        label="Download Full Report (.xlsx)",
        data=output,
        file_name="NAVV_Report.xlsx",
        mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
    )
    st.success("Report Generated!")
