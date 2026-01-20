import os
import subprocess
import shutil
from utils import is_wsl_mode, convert_to_wsl_path, check_zeek_availability, get_zeek_command

class ZeekRunner:
    def __init__(self, logs_dir="zeek_logs"):
        self.logs_dir = os.path.abspath(logs_dir)
        if not os.path.exists(self.logs_dir):
            os.makedirs(self.logs_dir)

    def clear_logs(self):
        """
        Remove all files in the logs directory.
        """
        if os.path.exists(self.logs_dir):
            for f in os.listdir(self.logs_dir):
                file_path = os.path.join(self.logs_dir, f)
                try:
                    if os.path.isfile(file_path):
                        os.unlink(file_path)
                except Exception as e:
                    print(f"Error deleting {file_path}: {e}")
            
    def process_pcap(self, pcap_path, progress_callback=None):
        """
        Run Zeek on the provided pcap file.
        Streams file content to Zeek via stdin to enable progress tracking.
        Exceptions (like aborts) will trigger graceful termination of the Zeek subprocess.
        """
        zeek_cmd = get_zeek_command()
        if not zeek_cmd:
            return False, "Zeek is not installed or not found in PATH (check WSL if on Windows)."

        pcap_abs_path = os.path.abspath(pcap_path)
        if not os.path.exists(pcap_abs_path):
             return False, "File not found."

        file_size = os.path.getsize(pcap_abs_path)
        
        # We need to run the command such that output goes to logs_dir
        # Approach: cd to logs_dir then run zeek -r -
        # '-' tells zeek to read from stdin
        
        cmd = []
        if is_wsl_mode():
            wsl_logs_dir = convert_to_wsl_path(self.logs_dir)
            binary = zeek_cmd[-1]
            # Use streaming mode: -r - 
            # We run via bash to handle directory change
            # Added 'local' to enable local site policy (captures MACs etc.)
            cmd = ['wsl', 'bash', '-c', f'cd "{wsl_logs_dir}" && {binary} -C -r - local'] 
        else:
            # Native Linux
            cmd = zeek_cmd + ['-C', '-r', '-', 'local']

        process = None
        try:
            cwd = None if is_wsl_mode() else self.logs_dir 
            
            # Start process with stdin pipe
            process = subprocess.Popen(
                cmd,
                cwd=cwd,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=False # Binary mode for stdin
            )
            
            # Stream the file
            bytes_sent = 0
            chunk_size = 1024 * 1024 * 5 # 5MB chunks
            
            with open(pcap_abs_path, 'rb') as f:
                while True:
                    chunk = f.read(chunk_size)
                    if not chunk:
                        break
                    
                    try:
                        process.stdin.write(chunk)
                        process.stdin.flush()
                        bytes_sent += len(chunk)
                        
                        if progress_callback and file_size > 0:
                            progress_callback(bytes_sent, file_size)
                            
                    except BrokenPipeError:
                        # Process died early (e.g. error in args)
                        break
                        
            # Close stdin to signal EOF to Zeek
            process.stdin.close()
            process.stdin = None # Prevent communicate from flushing closed stdin
            
            # Wait for completion
            stdout, stderr = process.communicate()
            
            if process.returncode == 0:
                return True, (stdout.decode('utf-8', errors='replace') + "\n" + stderr.decode('utf-8', errors='replace'))
            else:
                return False, f"Zeek failed (Code {process.returncode}):\n{stderr.decode('utf-8', errors='replace')}"

        except Exception as e:
            # Handle aborts or errors
            if process:
                process.kill()
            raise e

