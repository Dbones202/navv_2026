import streamlit as st
from utils import check_zeek_availability

st.set_page_config(
    page_title="NAVV - Network Analysis",
    page_icon="🛡️",
    layout="wide"
)

st.title("🛡️ NAVV: Network Architecture Verification")
st.markdown("---")

col1, col2 = st.columns(2)

with col1:
    st.header("Welcome")
    st.write("""
    This tool provides advanced network analysis using Zeek and Purdue Model segmentation.
    
    **Workflow:**
    1.  **Ingest**: Process PCAP files using Zeek.
    2.  **Inventory**: Upload assets and resolve role conflicts.
    3.  **Segments**: Define network zones and auto-discover subnets.
    4.  **Analysis**: Visualize traffic flows and detect critical risks.
    """)

with col2:
    st.header("System Status")
    if check_zeek_availability():
        st.success("✅ Zeek Detected")
        st.caption("Ready to process PCAPS.")
    else:
        st.error("❌ Zeek Not Found")
        st.info("Please install Zeek (WSL) to use the Ingest feature.")

st.info("👈 Select a module from the sidebar to begin.")
