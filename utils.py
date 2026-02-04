import os
import platform
import subprocess
import shutil
import polars as pl

def is_wsl_mode():
    """
    Detect if we are running in a context where we need to use WSL.
    This is true if we are on Windows.
    """
    return platform.system() == "Windows"

def convert_to_wsl_path(win_path):
    """
    Convert a Windows path to a WSL path.
    Example: 'C:\\Users\\User\\file.pcap' -> '/mnt/c/Users/User/file.pcap'
    """
    if not is_wsl_mode():
        return win_path
    
    # Simple conversion for C: drive essentially
    # A more robust way asks wsl itself, but this is faster for common cases
    # wslpath -u 'C:\Users\foo'
    
    try:
        # Use wslpath utility which is standard in WSL envs (accessible from Win via wsl command)
        result = subprocess.run(['wsl', 'wslpath', '-u', win_path], capture_output=True, text=True)
        if result.returncode == 0:
            return result.stdout.strip()
    except Exception as e:
        print(f"Error converting path via wslpath: {e}")
        
    # Fallback manual conversion if wslpath fails or isn't accessible (e.g. partial setup)
    # This is a bit naive but works for standard drive letters
    drive, tail = os.path.splitdrive(win_path)
    drive_letter = drive.replace(':', '').lower()
    wsl_path = f"/mnt/{drive_letter}{tail.replace('\\', '/')}"
    return wsl_path

def get_zeek_command():
    """
    Return the command list to invoke Zeek. 
    Handles WSL and common install locations.
    """
    # Common locations to check if not in PATH
    common_locations = ["/opt/zeek/bin/zeek"]
    
    base_cmd = []
    check_cmd = []
    
    if is_wsl_mode():
        base_cmd = ['wsl']
        # Try 'zeek' first
        try:
            subprocess.run(['wsl', 'zeek', '--version'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True)
            return ['wsl', 'zeek']
        except (subprocess.CalledProcessError, FileNotFoundError):
            # Try explicit paths
            for loc in common_locations:
                try:
                    subprocess.run(['wsl', loc, '--version'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True)
                    return ['wsl', loc]
                except (subprocess.CalledProcessError, FileNotFoundError):
                    continue
        return None
    else:
        # Native Linux
        if shutil.which("zeek"):
            return ["zeek"]
        for loc in common_locations:
            if os.path.exists(loc) and os.access(loc, os.X_OK):
                return [loc]
        return None

def check_zeek_availability():
    """
    Check if 'zeek' command is available.
    """
    return get_zeek_command() is not None


def check_log_prerequisites():
    """
    Check if the necessary Zeek logs exist to run analysis.
    Checks for: conn.log
    """
    # Assuming logs are in 'zeek_logs' relative to CWD, which is how ZeekRunner defaults
    log_path = os.path.join(os.getcwd(), "zeek_logs", "conn.log")
    return os.path.exists(log_path)


def render_sidebar_stats():
    """
    Render global analysis statistics in the sidebar footer.
    """
    import streamlit as st
    import textwrap
    
    # Custom CSS Container for footer stats
    # Using HTML/Markdown allows precise control over font size and spacing
    # Flexbox logic pushes this container to the bottom of the sidebar
    
    # Define metrics
    
    # 1. Hosts (Endpoints)
    host_count = "0"
    internal_count = 0
    external_count = 0
    
    if "df_endpoints" in st.session_state:
        df_ep = st.session_state["df_endpoints"]
        
        # Breakdown if Categorized
        if "Category" in df_ep.columns:
            internal_count = df_ep.filter(pl.col("Category") == "Internal").height
            external_count = df_ep.filter(pl.col("Category") == "External").height
            
        # Overall Count (Sum of categorized devices, excluding 'Special')
        host_count = f"{(internal_count + external_count):,}"
    
    # 2. Segments
    seg_count = "0"
    if "df_endpoints" in st.session_state:
        try:
             df = st.session_state['df_endpoints']
             if "Name" in df.columns:
                 # Count unique non-null segment names
                 unique_segs = df.select(pl.col("Name")).filter(pl.col("Name").is_not_null()).unique()
                 seg_count = str(unique_segs.height)
        except:
             pass
        
    # 3. Status
    status = "Ready"
    if "df_connection_summary" in st.session_state:
        status = "Analyzed"
        
    metrics = [
        ("Hosts", f"{host_count} ({internal_count} Int / {external_count} Ext)"),
        ("Segments", seg_count),
        ("Duration", "TBD"),
        ("Status", status)
    ]
    
    # Generate HTML
    # Use textwrap.dedent to prevent Markdown from interpreting indented HTML as code blocks
    html_header = textwrap.dedent("""
        <div id="sidebar-stats-footer">
            <hr style="margin-top: 0; margin-bottom: 1rem;">
            <h3 style="font-size: 1rem; margin-bottom: 1rem;">Analysis Statistics</h3>
    """)
    
    html_rows = ""
    for label, value in metrics:
        html_rows += textwrap.dedent(f"""
            <div style="margin-bottom: 8px;">
                <div style="font-size: 14px; color: #a0a0a0; margin-bottom: 2px;">{label}</div>
                <div style="font-size: 14px; color: #28a745; font-weight: 500;">{value}</div>
            </div>
        """)
    
    html_footer = "</div>"
    
    full_html = html_header + html_rows + html_footer

    # Inject CSS
    # 1. Make sidebar a flex container
    # 2. Target the footer to push it down
    # 3. Reduce Sidebar Width (User requested ~25% reduction. Default is ~21rem/336px. Target ~16rem/250px)
    st.sidebar.markdown(
        """
        <style>
        /* Force sidebar width */
        [data-testid="stSidebar"] {
            min-width: 250px !important;
            max-width: 250px !important;
        }
        
        [data-testid="stSidebar"] > div:nth-child(1) {
            height: 100vh;
            display: flex;
            flex-direction: column;
        }
        /* Push the last element (our footer) to the bottom */
        [data-testid="stSidebar"] > div:nth-child(1) > div:last-child {
            margin-top: auto;
        }
        </style>
        """,
        unsafe_allow_html=True
    )
        
    st.sidebar.markdown(full_html, unsafe_allow_html=True)

def get_browser_dimensions():
    """
    Inject a JS bridge to detect the browser window height.
    Stores the value in st.session_state["browser_height"].
    Provides a default fallback to ensure the app never stops rendering.
    """
    import streamlit as st
    import streamlit.components.v1 as components

    DEFAULT_HEIGHT = 800

    # 1. Initialize session state
    if st.session_state.get("browser_height") is None:
        st.session_state.browser_height = DEFAULT_HEIGHT

    # 2. Check query params (passed back from JS)
    q_params = st.query_params
    if "win_h" in q_params:
        try:
            st.session_state.browser_height = int(q_params["win_h"])
        except:
            pass

    # 3. Inject JS to detect and update URL for future loads
    # We do this without st.stop() so the page continues to render with the fallback/previous value
    components.html(
        """
        <script>
            const height = window.innerHeight;
            const url = new URL(window.parent.location.href);
            // Only redirect if the current win_h in URL is missing or different
            if (url.searchParams.get("win_h") != height) {
                url.searchParams.set("win_h", height);
                window.parent.location.href = url.href;
            }
        </script>
        """,
        height=0,
        width=0
    )

    return st.session_state.browser_height

