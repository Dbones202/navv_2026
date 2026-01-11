import polars as pl
import ipaddress
import os

class SegmentResolver:
    PURDUE_LEVELS = {
        8: "6 - Internet",
        7: "5 - IT DMZ",
        6: "4 - IT",
        5: "3.5 - OT DMZ",
        4: "3 - Site Operations",
        3: "2 - Supervisory Control",
        2: "1 - Basic Control",
        1: "0 - Physical Process"
    }
    # Reverse mapping for lookups
    LEVEL_TO_INT = {v: k for k, v in PURDUE_LEVELS.items()}
    
    # Colors for Visualization
    # 0-3 Blues (Dark to Light), 3.5 Orange, 4-5 Greens (Light to Dark), 6 Grey
    PURDUE_COLORS = {
        1: "#08306b", # 0 - Darkest Blue
        2: "#2171b5", # 1 - Dark Blue
        3: "#6baed6", # 2 - Medium Blue
        4: "#c6dbef", # 3 - Light Blue
        5: "#ff7f00", # 3.5 - Orange
        6: "#a1d99b", # 4 - Light Green
        7: "#006d2c", # 5 - Dark Green
        8: "#444444"  # 6 - Dark Grey
    }

    def __init__(self):
        self.segments_df = None

    def load_segments(self, segments_csv=None):
        """
        Load segments from CSV. Scehma: Name, CIDR, Level.
        """
        if segments_csv and os.path.exists(segments_csv):
            try:
                # Enforce schema to prevent Type Errors (e.g. Name being inferred as Int)
                self.segments_df = pl.read_csv(segments_csv, schema_overrides={"Name": pl.String, "CIDR": pl.String, "Level": pl.Int32})
            except:
                self.segments_df = pl.DataFrame(schema={"Name": pl.String, "CIDR": pl.String, "Level": pl.Int32})
        else:
             self.segments_df = pl.DataFrame(schema={"Name": pl.String, "CIDR": pl.String, "Level": pl.Int32})
        return self.segments_df
        
    def resolve_ip(self, ip_series):
        """
        Given a Polars Series of IPs, return Series of Segment Names and Levels.
        Note: This is computationally intensive if done row-by-row in Python.
        Optimization: 
        1. If small number of segments, check each segment against all IPs.
        2. If /24 based, use string manipulation.
        
        For reliability, we will use a plython-map approach since segment count is usually < 100.
        """
        if self.segments_df is None or self.segments_df.height == 0:
             return pl.Series([("Unknown", 0)] * len(ip_series), dtype=pl.Object)

        # Convert DF to list of dicts for faster iteration
        segments = self.segments_df.to_dicts()
        # Pre-compile networks
        for s in segments:
            try:
                s['net'] = ipaddress.ip_network(s['CIDR'], strict=False)
            except:
                s['net'] = None

        def match_ip(ip_str):
            try:
                ip = ipaddress.ip_address(ip_str)
                for s in segments:
                    if s['net'] and ip in s['net']:
                        return (str(s['Name']), s['Level'])
            except:
                pass
            return ("Unknown", 0)

        # Apply
        # Polars map_elements returns a single Series of tuples/structs? 
        # Easier to return Struct and split.
        
        # map_elements is slow for millions of rows. 
        # Fast path: Group by raw IP, map unique IPs, then join back? 
        # Yes, caller should handle unique deduplicaton if needed. 
        # Here we assume ip_series is the column.
        
        # NOTE: For massive logs, we should optimize this lookup (RangeJoin or similar in DBs).
        # In memory python:
        
        return ip_series.map_elements(lambda x: match_ip(x), return_dtype=pl.Object)

    def resolve_ip_single(self, ip_str):
        """
        Helper for single IP string resolution (used by Inventory Manager).
        Priorities:
        1. Defined Segment (User Overrides)
        2. Special Ranges (Multicast, Broadcast, APIPA, Loopback)
        3. Public -> "Internet" (Level 6)
        4. Private -> "Unknown" (Level 0)
        """
        import ipaddress
        
        if not ip_str:
            return ("Unknown", 0, "#ffffff", "#000000")

        ip = None
        try:
            ip = ipaddress.ip_address(ip_str)
        except:
            return ("Invalid IP", 0, "#ffffff", "#000000")

        # Initial Defaults
        seg_name = "Unknown"
        level = 0
        bg = "#ffffff"
        font = "#000000"
        found_segment = False

        # Helper for Font Contrast
        def get_font_contrast(hex_color):
            if hex_color in ["#c6dbef", "#ffffff", "#a1d99b"]: 
                 return "#000000"
            return "#ffffff"

        # 1. Look for Defined Segment
        if self.segments_df is not None and self.segments_df.height > 0:
            segments = self.segments_df.to_dicts()
            for s in segments:
                try:
                    if 'net' not in s or s['net'] is None:
                        s['net'] = ipaddress.ip_network(s['CIDR'], strict=False)
                    
                    if s['net'] and ip in s['net']:
                        seg_name = str(s['Name'])
                        level = s['Level']
                        bg = self.PURDUE_COLORS.get(level, "#ffffff")
                        font = get_font_contrast(bg)
                        found_segment = True
                        break # First match wins
                except:
                    pass

        # 2. Check Special Types (Override Visuals, Default Level if unknown)
        is_special = False
        special_label = ""
        
        if ip.is_multicast:
            is_special = True
            special_label = "Multicast Range"
        elif str(ip).endswith(".255") or str(ip) == "255.255.255.255":
            is_special = True
            special_label = "Broadcast"
        elif ip.is_link_local:
            is_special = True
            special_label = "Link-Local"
        elif ip.is_loopback:
            is_special = True
            special_label = "Loopback"
        elif ip.version == 6:
            is_special = True
            special_label = "IPv6"

        if is_special:
            # Override Visuals
            bg = "#ffffff"
            font = "#ff0000"
            
            # If we didn't find a parent segment, assign default properties
            if not found_segment:
                level = 4 # Default to Site Operations (Level 3)
                seg_name = special_label

        # 3. Public vs Private (If nothing else matches)
        if not found_segment and not is_special and not ip.is_private:
            seg_name = "Internet"
            level = 8
            bg = self.PURDUE_COLORS.get(8, "#444444")
            font = "#ffffff"
            
        return (seg_name, level, bg, font)

    def auto_discover(self, unique_ips_df):
        """
        Group IPs into /24 subnets and propose segments.
        unique_ips_df: Polars DF with 'ip' column.
        """
        import ipaddress

        if unique_ips_df is None or unique_ips_df.height == 0:
            return pl.DataFrame({"Name": [], "CIDR": [], "Level": []})

        # Ensure IPs are strings
        w_ips = unique_ips_df.with_columns(pl.col("ip").cast(pl.String))

        # We need to filter out Special IPs first to avoid proposing "224.0.0.0/24"
        def get_subnet(ip_str):
            if not ip_str: 
                return None
            try:
                ip = ipaddress.ip_address(ip_str)
                if ip.is_multicast or ip.is_loopback or ip.is_link_local or str(ip) == "255.255.255.255":
                    return None
                
                # Create /24
                if ip.version == 4:
                    # Strict=False allows host bits to be set, but we want the NETWORK address for the CIDR
                    # ip_interface gives us network, ip_network gives us network object
                    # ipaddress.ip_network("192.168.1.5/24", strict=False) -> 192.168.1.0/24
                    net = ipaddress.ip_network(f"{ip}/24", strict=False)
                    return str(net)
            except:
                pass
            return None

        # Apply using map_elements
        # Note: map_elements can be slow.
        proposed_series = w_ips["ip"].map_elements(get_subnet, return_dtype=pl.String)
        
        # Create DF, filter nulls
        subnets_df = pl.DataFrame({"subnet": proposed_series}).filter(pl.col("subnet").is_not_null())
        
        if subnets_df.height == 0:
             return pl.DataFrame({"Name": [], "CIDR": [], "Level": []})

        # Count
        counts = subnets_df.group_by("subnet").len().sort("len", descending=True)
        
        # Format
        # subnet string is like "192.168.1.0/24"
        # We want Name to be "Auto-Seg-192.168.1"
        # Slice off .0/24? length is 5 chars? 
        # Safer: split by '.' and join 3 parts.
        
        # Polars string extract? or just slice if we trust format. 
        # "192.168.1.0/24" -> slice(0, -5) -> "192.168.1"
        
        # Prepare DataFrame
        proposed_base = counts.select([
             (pl.lit("Auto-Seg-") + pl.col("subnet").str.replace(r"\.0/24$", "")).alias("Name"), 
             pl.col("subnet").alias("CIDR")
        ])

        # Helper to determine default level
        def get_default_level(cidr):
            try:
                net = ipaddress.ip_network(cidr, strict=False)
                # Private -> "3 - Site Operations" (4). Public -> "6 - Internet" (8)
                if net.is_private:
                    return 4
                return 8
            except:
                return 0

        # Apply Level
        proposed = proposed_base.with_columns(
            pl.col("CIDR").map_elements(get_default_level, return_dtype=pl.Int32).alias("Level")
        )
        
        return proposed
