import os
import platform
import subprocess
import shutil

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

