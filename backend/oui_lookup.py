import os
import json
import time
import datetime
import urllib.request
import re

DATA_DIR = os.path.dirname(os.path.abspath(__file__)) + "/data"
MANUF_URLS = [
    "https://gitlab.com/wireshark/wireshark/-/raw/master/manuf",
    "https://gitlab.com/wireshark/wireshark/-/raw/main/manuf",
    "https://raw.githubusercontent.com/wireshark/wireshark/master/manuf",
    "https://www.wireshark.org/download/automated/data/manuf"
]
DB_PATH = os.path.join(DATA_DIR, "mac_oui.json")

class OUILookup:
    def __init__(self):
        self.oui_db = {}
        self.metadata = {"last_updated": None, "count": 0}
        self.load_db()

    def load_db(self):
        """Loads the local JSON database if it exists."""
        if os.path.exists(DB_PATH):
            try:
                with open(DB_PATH, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                    self.oui_db = data.get("vendors", {})
                    self.metadata = data.get("metadata", {})
            except Exception as e:
                print(f"Error loading OUI DB: {e}")

    def update_oui_db(self):
        """Downloads the latest manuf file from Wireshark mirrors and updates the local DB."""
        content = None
        source_used = None
        
        for url in MANUF_URLS:
            print(f"Attempting download from {url}...")
            try:
                # Add headers to avoid 403s on some sites
                req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
                with urllib.request.urlopen(req) as response:
                    content = response.read().decode('utf-8', errors='ignore')
                    source_used = url
                    print(f"Success: Downloaded from {url}")
                    break
            except Exception as e:
                print(f"Failed {url}: {e}")
                
        if not content:
            print("All download sources failed.")
            return False
        
        try:
            new_db = {}
            for line in content.splitlines():
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                
                # Format: OUI<tab>ShortName<tab>LongName
                # Example: 00:00:00	Xerox	Xerox Corporation
                # Some have masks: 00:00:00/24
                
                parts = re.split(r'\s+', line, maxsplit=2)
                if len(parts) >= 2:
                    oui_raw = parts[0]
                    short_name = parts[1]
                    # long_name = parts[2] if len(parts) > 2 else short_name
                    
                    # Normalize OUI: 00:00:00 -> 000000
                    # Handle masks? For now, we only care about standard /24 OUIs (XX:XX:XX)
                    # If it has /24 or no mask, it's a standard OUI.
                    # If it's /36 or something, it's specific, but we usually index by top 3 bytes.
                    
                    if '/' in oui_raw:
                        oui, mask = oui_raw.split('/')
                        if mask != '24':
                            continue # Skip non-standard block sizes for simplicity in this version
                    else:
                        oui = oui_raw

                    # Normalize: Remove colons, dashes to get clean hex
                    clean_oui = oui.replace(":", "").replace("-", "").upper()
                    
                    if len(clean_oui) == 6:
                        new_db[clean_oui] = short_name
            
            # Save
            save_data = {
                "metadata": {
                    "last_updated": datetime.datetime.now().isoformat(),
                    "source": source_used,
                    "count": len(new_db)
                },
                "vendors": new_db
            }
            
            if not os.path.exists(DATA_DIR):
                os.makedirs(DATA_DIR)
                
            with open(DB_PATH, 'w', encoding='utf-8') as f:
                json.dump(save_data, f, indent=2)
                
            self.oui_db = new_db
            self.metadata = save_data["metadata"]
            print(f"OUI Database updated. Loaded {len(new_db)} vendors.")
            return True
            
        except Exception as e:
            print(f"Failed to update OUI DB: {e}")
            return False

    def get_vendor(self, mac_address):
        """
        Returns the vendor name for a given MAC address.
        Expects MAC in format XX:XX:XX:XX:XX:XX or XXXXXXXXXXXX.
        """
        if not mac_address or len(mac_address) < 6:
            return "Unknown"
            
        # Normalize
        clean_mac = mac_address.replace(":", "").replace("-", "").replace(".", "").upper()
        
        # Take first 6 chars (OUI)
        if len(clean_mac) >= 6:
            oui = clean_mac[:6]
            return self.oui_db.get(oui, "Unknown")
            
        return "Unknown"

# Singleton instance
oui_lookup = OUILookup()
