import os
import json
import urllib.request
import re
import datetime

DATA_DIR = os.path.dirname(os.path.abspath(__file__)) + "/data"
NMAP_SERVICES_URL = "https://raw.githubusercontent.com/nmap/nmap/master/nmap-services"
NMAP_DB_PATH = os.path.join(DATA_DIR, "nmap_services.json")
OVERRIDES_PATH = os.path.join(DATA_DIR, "service_overrides.json")

class ServiceLookup:
    def __init__(self):
        self.nmap_db = {}
        self.overrides = {}
        self.metadata = {"last_updated": None}
        self.load_lookups()

    def load_lookups(self):
        """Loads local overrides and Nmap DB."""
        # 1. Load Overrides
        if os.path.exists(OVERRIDES_PATH):
            try:
                with open(OVERRIDES_PATH, 'r', encoding='utf-8') as f:
                    self.overrides = json.load(f)
            except Exception as e:
                print(f"Error loading Service Overrides: {e}")
                self.overrides = {}
        
        # 2. Load Nmap DB
        if os.path.exists(NMAP_DB_PATH):
            try:
                with open(NMAP_DB_PATH, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                    self.nmap_db = data.get("services", {})
                    self.metadata = data.get("metadata", {})
            except Exception as e:
                print(f"Error loading Nmap DB: {e}")
                self.nmap_db = {}

    def update_nmap_db(self):
        """Downloads nmap-services and updates local DB."""
        print(f"Downloading Nmap Services from {NMAP_SERVICES_URL}...")
        try:
            req = urllib.request.Request(NMAP_SERVICES_URL, headers={'User-Agent': 'Mozilla/5.0'})
            
            # Bypass SSL check for MacOS
            import ssl
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            
            with urllib.request.urlopen(req, context=ctx) as response:
                content = response.read().decode('utf-8', errors='ignore')
            
            new_db = {}
            # Format: ServiceName<tab>Port/Proto<tab>Frequency<tab>Comments
            # Example: http	80/tcp	0.484143	# World Wide Web HTTP
            
            for line in content.splitlines():
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                
                parts = line.split('\t')
                if len(parts) >= 2:
                    service_name = parts[0]
                    port_proto = parts[1] # "80/tcp"
                    
                    # We index by "proto/port" usually? Or just use their "port/proto" format?
                    # The overrides file uses "tcp/44818". Nmap uses "44818/tcp".
                    # Let's standardize on "tcp/44818" (proto/port) internally for consistency with user request description?
                    # User request: "tcp/44818".
                    # Nmap: "44818/tcp".
                    
                    if '/' in port_proto:
                        p_val, proto = port_proto.split('/')
                        key = f"{proto.lower()}/{p_val}"
                        
                        # Store. Note: Nmap lists are ordered by frequency essentially, but here we just map Key -> Name.
                        # Nmap has duplicates? (Same port, different service name?)
                        # Usually no, but "http" and "www" might alias?
                        # Nmap file structure is unique on port/proto usually.
                        new_db[key] = service_name

            save_data = {
                "metadata": {
                    "last_updated": datetime.datetime.now().isoformat(),
                    "source": NMAP_SERVICES_URL,
                    "count": len(new_db)
                },
                "services": new_db
            }
            
            if not os.path.exists(DATA_DIR):
                os.makedirs(DATA_DIR)

            with open(NMAP_DB_PATH, 'w', encoding='utf-8') as f:
                json.dump(save_data, f, indent=2)
                
            self.nmap_db = new_db
            self.metadata = save_data["metadata"]
            print(f"Nmap Services Database updated. Loaded {len(new_db)} services.")
            return True

        except Exception as e:
            print(f"Failed to update Nmap DB: {e}")
            return False

    def resolve_service(self, port, proto, zeek_service=None):
        """
        Resolves the service name using Multi-Tier logic:
        1. Manual Override
        2. Zeek Service (if provided and valid)
        3. Nmap DB
        4. Fallback (Proto/Port)
        
        Returns: Tuple (service_name, source_tier)
        """
        try:
            port_val = str(port)
            proto_val = str(proto).lower()
            key = f"{proto_val}/{port_val}"
            
            # Tier 1: Override -> 0
            if key in self.overrides:
                return (str(self.overrides[key]), 0)
            
            # Tier 2: Zeek -> 1
            if zeek_service and isinstance(zeek_service, str):
                z = zeek_service.strip()
                if z and z != "-" and z.lower() != "unknown" and z != "(empty)":
                    return (z, 1)
            
            # Tier 3: Nmap -> 2
            if key in self.nmap_db:
                svc = str(self.nmap_db[key])
                if svc.lower() != "unknown":
                    return (svc, 2)
                
            # Tier 4: Fallback -> 3
            return (f"{proto_val.upper()}/{port_val}", 3)
            
        except Exception:
            return (f"{str(proto).upper()}/{str(port)}", 3)

service_lookup = ServiceLookup()
