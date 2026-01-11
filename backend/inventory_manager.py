import polars as pl
import os
from backend.oui_lookup import oui_lookup

class InventoryHarmonizer:
    def __init__(self):
        self.master_df = None

    def ingest_model(self, inventory_csv=None, conn_log=None, dhcp_log=None, dns_log=None, ntlm_log=None, enip_log=None, segments_csv="Segments.csv"):
        """
        Build the Master Asset List using the "Asset Profile" logic:
        1. Network Scope (Private/Public/User-Defined)
        2. Physical Presence (Active/Passive/L2 Leak)
        3. Human Identity (Manual > DHCP > ENIP > NetBIOS > DNS > TLS)
        """
        # --- 1. Load Sources ---
        
        # Manual Inventory
        if inventory_csv and os.path.exists(inventory_csv):
            try:
                manual_df = pl.scan_csv(inventory_csv).select([
                    pl.col("IP").alias("ip"),
                    pl.col("Name").alias("manual_name"),
                    pl.col("Location").alias("location"),
                    pl.col("Description").alias("description")
                ])
                # Ensure IP is string
                manual_df = manual_df.with_columns(pl.col("ip").cast(pl.String))
            except Exception as e:
                # print(f"Error loading inventory: {e}")
                manual_df = pl.DataFrame(schema={"ip": pl.String, "manual_name": pl.String, "location": pl.String, "description": pl.String}).lazy()
        else:
            manual_df = pl.DataFrame(schema={"ip": pl.String, "manual_name": pl.String, "location": pl.String, "description": pl.String}).lazy()

        # Conn Log (Activity & L2 Presence)
        conn_df = pl.DataFrame(schema={"ip": pl.String, "has_mac": pl.Boolean, "mac": pl.String}).lazy()
        if conn_log and os.path.exists(conn_log):
            try:
                # Check headers for macs
                has_mac_headers = False
                with open(conn_log, 'r', errors='ignore') as f:
                    for _ in range(20):
                        line = f.readline()
                        if line.startswith("#fields") and "orig_l2_addr" in line:
                            has_mac_headers = True
                            break
                            
                q = pl.scan_csv(conn_log, separator='\t', comment_prefix="#", has_header=False, ignore_errors=True, null_values=["-", "(empty)"])
                
                # Active Lists
                active_ips = q.select([
                    pl.col("column_3").alias("ip"), # id.orig_h
                    pl.col("column_5").alias("dst_ip") # id.resp_h
                ])
                
                ips_1 = active_ips.select("ip")
                ips_2 = active_ips.select(pl.col("dst_ip").alias("ip"))
                
                # Basic active list
                if has_mac_headers:
                    # Attempt to find MAC columns
                    # We need to re-read headers or assume standard mapped columns if we found the header? 
                    # If we found #fields, we can try to guess indices?
                    # For simplicity, if we detected l2_addr, we'll try to extract specific columns if known.
                    # But scanning CSV without headers is hard if we don't know the index.
                    # Let's rely on DHCP for MACs mostly, or try to extract if we can map it.
                    pass 
                
                conn_df = pl.concat([ips_1, ips_2]).unique().with_columns([
                    pl.lit(False).alias("has_mac"),
                    pl.lit(None).cast(pl.String).alias("mac")
                ])
                
            except Exception:
                pass

        conn_df = conn_df.with_columns(pl.col("ip").cast(pl.String))

        # DHCP Log (Identity)
        dhcp_df = pl.DataFrame(schema={"ip": pl.String, "dhcp_host_name": pl.String, "dhcp_client_fqdn": pl.String, "dhcp_domain": pl.String, "dhcp_computed_name": pl.String, "mac": pl.String}).lazy()
        if dhcp_log and os.path.exists(dhcp_log):
            try:
                # Zeek dhcp.log columns usually: ts, uids, client_addr (2), server_addr (3), mac (1?)... 
                # Let's verify headers generally. usually #fields ts uid id.orig_h ...
                # Wait, dhcp.log has: ts, uid, id.orig_h, id.orig_p, id.resp_h, id.resp_p, mac, assigned_ip, lease_time, trans_id
                # Actually standard Zeek dhcp.log:
                # client_addr (IP), mac, host_name, client_fqdn
                # Let's try to read generic TSV and map by index if headers missing, or use header parsing?
                # Best effort: use 'has_header=False' and guess indices for standard Zeek?
                # Standard Zeek 6.0: 
                # fields ts uid id.orig_h id.orig_p id.resp_h id.resp_p mac assigned_ip lease_time trans_id
                # Only some scripts add host_name (dhcp-hostname.zeek).
                # User linked to https://docs.zeek.org/en/master/logs/dhcp.html
                # Fields: client_addr, server_addr, mac, host_name, client_fqdn, domain...
                # Note: 'client_addr' is often the assigned IP? Or 'assigned_ip'?
                # Docs say: `assigned_ip`: IP address assigned to client.
                # `host_name`: Name given by client.
                # `client_fqdn`: FQDN given by client.
                
                # We need to find column indices dynamically or assume standard.
                # Let's Assume Standard:
                # Index 0: ts, 1: uid, 2: id.orig_h, ...
                # Actually user's logs might differ. 
                # Safest: Use Polars to read first few lines, find #fields, map columns.
                
                # FAST PATH: Read with Polars as CSV treating '#' as comment? 
                # Zeek logs header is complex (#fields ...). Polars doesn't parse that natively as header.
                # We'll use the same hack: read generic, but we need exact column indices.
                
                # Better: Read header line manually to find indices.
                cols = {}
                with open(dhcp_log, 'r', errors='ignore') as f:
                    for _ in range(20):
                        line = f.readline()
                        if line.startswith("#fields"):
                            parts = line.strip().split('\t')
                            # parts[0] is #fields
                            for idx, field in enumerate(parts):
                                if idx == 0: continue
                                # Zeek columns are 0-indexed in relevant data? 
                                # e.g. #fields ts uid...
                                # Data: 1234.5 Ckb...
                                # So 'ts' is col 0. 'uid' is col 1.
                                # parts has ['#fields', 'ts', 'uid'...]
                                # So field 'ts' is at index 0 of data. 
                                # So dict: field -> idx - 1.
                                cols[field] = idx - 1
                            break
                
                # Required: assigned_ip OR client_addr (depending on log version)
                ip_col_idx = cols.get("assigned_ip", cols.get("client_addr", -1))
                host_col_idx = cols.get("host_name", -1)
                fqdn_col_idx = cols.get("client_fqdn", -1)
                dom_col_idx = cols.get("domain", -1)
                
                if ip_col_idx >= 0:
                    # Select columns by index
                    # Treat "-" as Null
                    q_dhcp = pl.scan_csv(dhcp_log, separator='\t', comment_prefix="#", has_header=False, ignore_errors=True, null_values=["-", "(empty)"])
                    
                    # Construct selection
                    selects = [pl.col(f"column_{ip_col_idx+1}").alias("ip")]
                    
                    if host_col_idx >= 0:
                        selects.append(pl.col(f"column_{host_col_idx+1}").alias("dhcp_host_name"))
                    else:
                        selects.append(pl.lit(None).alias("dhcp_host_name"))
                        
                    if fqdn_col_idx >= 0:
                        selects.append(pl.col(f"column_{fqdn_col_idx+1}").alias("dhcp_client_fqdn"))
                    else:
                        selects.append(pl.lit(None).alias("dhcp_client_fqdn"))
                        
                    if dom_col_idx >= 0:
                        selects.append(pl.col(f"column_{dom_col_idx+1}").alias("dhcp_domain"))
                    else:
                        selects.append(pl.lit(None).alias("dhcp_domain"))

                    # MAC Address
                    mac_col_idx = cols.get("mac", cols.get("client_mac", -1))
                    if mac_col_idx >= 0:
                        selects.append(pl.col(f"column_{mac_col_idx+1}").alias("mac"))
                    else:
                        selects.append(pl.lit(None).alias("mac"))
                    
                    # Aggregate by IP to find any non-null names (handling multiple log entries)
                    # Filter for non-empty strings (length > 0) to avoid capturing empty fields that escaped null parsing
                    # STRICT FILTER: Remove entries with no IP address (e.g. DHCPDISCOVER handshake before assignment)
                    dhcp_df = q_dhcp.select(selects).filter(
                        pl.col("ip").is_not_null() & (pl.col("ip").str.len_chars() > 0)
                    ).group_by("ip").agg([
                        pl.col("dhcp_host_name").filter(pl.col("dhcp_host_name").str.len_chars() > 0).first(),
                        pl.col("dhcp_client_fqdn").filter(pl.col("dhcp_client_fqdn").str.len_chars() > 0).first(),
                        pl.col("dhcp_domain").filter(pl.col("dhcp_domain").str.len_chars() > 0).first(),
                        pl.col("mac").filter(pl.col("mac").str.len_chars() > 0).first()
                    ])
                    
                    # Compute Best DHCP Name Strategy
                    dhcp_df = dhcp_df.with_columns(
                        pl.when(pl.col("dhcp_client_fqdn").str.len_chars() > 1)
                          .then(pl.col("dhcp_client_fqdn"))
                          .when((pl.col("dhcp_host_name").str.len_chars() > 0) & (pl.col("dhcp_domain").str.len_chars() > 0))
                          .then(pl.col("dhcp_host_name") + "." + pl.col("dhcp_domain"))
                          .otherwise(pl.col("dhcp_host_name"))
                          .cast(pl.String)
                          .alias("dhcp_computed_name")
                    )

                    # Debug
                    print(f"DHCP Records Found: {dhcp_df.collect().height}")
                    
            except Exception as e:
                # print(f"DHCP Load Error: {e}")
                pass
                
        dhcp_df = dhcp_df.with_columns(pl.col("ip").cast(pl.String))
        
        # --- NetBIOS & ENIP & DNS ---
        
        def get_zeek_cols(fpath):
            cols = {}
            with open(fpath, 'r', errors='ignore') as f:
                for _ in range(20):
                    line = f.readline()
                    if line.startswith("#fields"):
                        parts = line.strip().split('\t')
                        for idx, field in enumerate(parts):
                            if idx == 0: continue
                            cols[field] = idx - 1
                        break
            return cols

        # 1. DNS Log (NetBIOS:137, LLMNR:5355, mDNS:5353)
        broadcast_from_dns = pl.DataFrame(schema={"ip": pl.String, "broadcast_name": pl.String}).lazy()
        dns_ptr_df = pl.DataFrame(schema={"ip": pl.String, "dns_name": pl.String}).lazy()

        if dns_log and os.path.exists(dns_log):
            try:
                cols = get_zeek_cols(dns_log)
                ip_idx = cols.get("id.orig_h", -1)
                port_idx = cols.get("id.resp_p", -1)
                qtype_idx = cols.get("qtype_name", -1)
                query_idx = cols.get("query", -1)
                
                if ip_idx >= 0 and query_idx >= 0:
                    q_dns = pl.scan_csv(dns_log, separator='\t', comment_prefix="#", has_header=False, ignore_errors=True, null_values=["-", "(empty)"])
                    
                    # Broadcast Extraction
                    if port_idx >= 0:
                        # NetBIOS (137 + NB/NBSTAT) OR LLMNR (5355) OR mDNS (5353)
                        port_col = pl.col(f"column_{port_idx+1}")
                        qtype_col = pl.col(f"column_{qtype_idx+1}") if qtype_idx >= 0 else pl.lit("UNKNOWN")
                        
                        broadcast_from_dns = q_dns.filter(
                            (port_col.is_in([5353, 5355])) |
                            ((port_col == 137) & (qtype_col.is_in(["NB", "NBSTAT"])))
                        ).select([
                            pl.col(f"column_{ip_idx+1}").alias("ip"),
                            pl.col(f"column_{query_idx+1}").alias("broadcast_name")
                        ]).filter(pl.col("broadcast_name").str.len_chars() > 0)

                    # Standard DNS (Fallback)
                    dns_ptr_df = q_dns.select([
                        pl.col(f"column_{ip_idx+1}").alias("ip"),
                        pl.col(f"column_{query_idx+1}").alias("dns_name")
                    ]).filter(pl.col("dns_name").str.len_chars() > 0).unique("ip")
            except: pass

        # 2. NTLM (Treat as Broadcast/Local Identity)
        broadcast_from_ntlm = pl.DataFrame(schema={"ip": pl.String, "broadcast_name": pl.String}).lazy()
        if ntlm_log and os.path.exists(ntlm_log):
            try:
                cols = get_zeek_cols(ntlm_log)
                ip_idx = cols.get("id.orig_h", -1)
                host_idx = cols.get("hostname", -1)
                if ip_idx >= 0 and host_idx >= 0:
                    q_ntlm = pl.scan_csv(ntlm_log, separator='\t', comment_prefix="#", has_header=False, ignore_errors=True, null_values=["-", "(empty)"])
                    broadcast_from_ntlm = q_ntlm.select([
                        pl.col(f"column_{ip_idx+1}").alias("ip"),
                        pl.col(f"column_{host_idx+1}").alias("broadcast_name")
                    ]).filter(pl.col("broadcast_name").str.len_chars() > 0)
            except: pass
            
        # Merge Broadcast
        broadcast_df = pl.concat([broadcast_from_dns, broadcast_from_ntlm]).unique("ip").with_columns(pl.col("ip").cast(pl.String))
        dns_df = dns_ptr_df.with_columns(pl.col("ip").cast(pl.String))

        # 3. ENIP (EtherNet/IP)
        enip_df = pl.DataFrame(schema={"ip": pl.String, "enip_name": pl.String}).lazy()
        if enip_log and os.path.exists(enip_log):
             try:
                cols = get_zeek_cols(enip_log)
                ip_idx = cols.get("id.orig_h", -1)
                prod_idx = cols.get("product_name", -1)
                
                if ip_idx >= 0 and prod_idx >= 0:
                    q_enip = pl.scan_csv(enip_log, separator='\t', comment_prefix="#", has_header=False, ignore_errors=True, null_values=["-", "(empty)"])
                    enip_df = q_enip.select([
                        pl.col(f"column_{ip_idx+1}").alias("ip"),
                        pl.col(f"column_{prod_idx+1}").alias("enip_name")
                    ]).filter(pl.col("enip_name").str.len_chars() > 0).unique("ip")
             except: pass
        
        enip_df = enip_df.with_columns(pl.col("ip").cast(pl.String))

        # --- 2. Merge & Identify ---
        
        # Start with all known IPs (Union of Manual and Conn)
        # Start with all known IPs (Union of Manual, Conn, DHCP)
        # Start with all known IPs (Union of Manual, Conn, DHCP, NetBIOS, ENIP, DNS)
        # Start with all known IPs (Union of Manual, Conn, DHCP, Broadcast, ENIP, DNS)
        all_ips = pl.concat([
            manual_df.select("ip"),
            conn_df.select("ip"),
            dhcp_df.select("ip"),
            broadcast_df.select("ip"),
            enip_df.select("ip"),
            dns_df.select("ip")
        ]).drop_nulls().filter(pl.col("ip").str.len_chars() > 0).unique()
        
        # Join details
        combined = all_ips.join(manual_df, on="ip", how="left") \
                          .join(conn_df, on="ip", how="left") \
                          .join(dhcp_df, on="ip", how="left") \
                          .join(broadcast_df, on="ip", how="left") \
                          .join(enip_df, on="ip", how="left") \
                          .join(dns_df, on="ip", how="left")
                          
        # Consolidate MAC Address (for Switch Detection & Vendor Lookup)
        # Handle potential duplicates from joins (mac, mac_right)
        cols = combined.collect_schema().names()
        if "mac" in cols and "mac_right" in cols:
             combined = combined.with_columns(
                 pl.coalesce(["mac", "mac_right"]).alias("mac")
             ).drop("mac_right")
        elif "mac" not in cols and "mac_right" in cols:
             combined = combined.rename({"mac_right": "mac"})
        elif "mac" not in cols:
             combined = combined.with_columns(pl.lit(None).cast(pl.String).alias("mac"))
                          
        # Identity Cascading Logic
        # Manual > DNS (others missing for now)
        # Helper for Special Names
        def get_special_name(ip_str):
             import ipaddress
             try:
                 ip = ipaddress.ip_address(ip_str)
                 
                 # IPv6 Specific Handling
                 if ip.version == 6:
                     if ip.is_multicast: return "IPv6 Multicast"
                     if ip.is_link_local: return "IPv6 Link-Local"
                     if ip.is_loopback: return "IPv6 Loopback"
                     return "IPv6 Address"

                 # IPv4 Handling
                 if ip.is_multicast: return "Multicast Address"
                 if str(ip).endswith(".255") or str(ip) == "255.255.255.255": return "Broadcast Address"
                 if ip.is_link_local: return "Link-Local Device"
                 if ip.is_loopback: return "Loopback"
             except:
                 pass
             return None

        # Helper for IPv6 Boolean
        def check_ipv6(ip_str):
             import ipaddress
             try:
                 return ipaddress.ip_address(ip_str).version == 6
             except:
                 return False

        combined = combined.with_columns([
            pl.col("ip").map_elements(get_special_name, return_dtype=pl.String).alias("special_name"),
            pl.col("ip").map_elements(check_ipv6, return_dtype=pl.Boolean).alias("is_ipv6")
        ])

        # --- 3. Classification (MOVED UP) ---
        
        # A. Network Scope (Private vs Public) & Segments
        from backend.segment_manager import SegmentResolver
        seg_resolver = SegmentResolver()
        seg_resolver.load_segments(segments_csv)
        
        def classify_scope_and_segment(ip_val):
            import ipaddress
            scope = "Unknown"
            segment_name = "Unassigned"
            p_level = 0
            p_color = "#ffffff"
            p_font = "#000000"
            
            # 1. Check Segments (Rule B - Override)
            resolved_seg, level, bg, font = seg_resolver.resolve_ip_single(ip_val)
            if resolved_seg != "Unknown":
                scope = "Internal (User-Defined)"
                segment_name = resolved_seg
                p_level = level
                p_color = bg
                p_font = font
            else:
                # 2. Check RFC1918 (Rule A)
                try:
                    ip = ipaddress.ip_address(ip_val)
                    if ip.is_private:
                        scope = "Private"
                    else:
                        scope = "Public"
                        # Public -> Level 8/Internet
                        p_level = 8
                        p_color = seg_resolver.PURDUE_COLORS.get(8, "#444444")
                        p_font = "#ffffff"
                except:
                    pass
            
            return (str(scope), str(segment_name), p_level, str(p_color), str(p_font))

        # Apply Scope (Rule A & B)
        combined = combined.with_columns([
            pl.col("ip").map_elements(lambda x: classify_scope_and_segment(x)[0], return_dtype=pl.String).alias("network_scope"),
            pl.col("ip").map_elements(lambda x: classify_scope_and_segment(x)[1], return_dtype=pl.String).alias("segment"),
            pl.col("ip").map_elements(lambda x: classify_scope_and_segment(x)[2], return_dtype=pl.Int32).alias("purdue_level"),
            pl.col("ip").map_elements(lambda x: classify_scope_and_segment(x)[3], return_dtype=pl.String).alias("segment_color"),
            pl.col("ip").map_elements(lambda x: classify_scope_and_segment(x)[4], return_dtype=pl.String).alias("segment_font_color")
        ])

        # Feature: Segment-based Fallback Name
        # "Unknown device in {Segment} network" or "Unknown device in Unknown Internal Network"
        combined = combined.with_columns([
            pl.when((pl.col("segment") != "Unassigned") & (pl.col("segment").is_not_null()) & (pl.col("segment") != "Unknown"))
            .then(pl.concat_str([pl.lit("Unknown device in "), pl.col("segment"), pl.lit(" network")]))
            .otherwise(pl.lit("Unknown device in Unknown Internal Network"))
            .alias("segment_fallback_name")
        ])

        # Identity Cascading Logic
        # Special Name > Manual > DHCP > ENIP > Broadcast > DNS > Public(INTERNET) > Segment Fallback
        combined = combined.with_columns([
            pl.coalesce([
                pl.col("special_name"), 
                pl.col("manual_name"), 
                pl.col("dhcp_computed_name"), 
                pl.col("enip_name"),
                pl.col("broadcast_name"),
                pl.col("dns_name"),
                # Add Public Internet Name Logic
                pl.when(pl.col("network_scope") == "Public").then(pl.lit("INTERNET")).otherwise(None),
                # Fallback to Segment Name
                pl.col("segment_fallback_name")
            ]).cast(pl.String).alias("final_name"),
            pl.col("has_mac").fill_null(False),
            pl.lit(0).cast(pl.Int32).alias("behavior_level") # Default to 0 (Unknown)
        ])
        
        # --- Switch Detection (Multi-IP on Same MAC) ---
        # 1. Filter IPs that have a MAC
        # 2. Group by MAC -> Count IPs
        # 3. Join back to flag
        
        # Schema check for MAC column presence
        if "mac" in combined.collect_schema().names():
            # Calculate IP counts per MAC
            mac_counts = combined.filter(
                pl.col("mac").is_not_null() & (pl.col("mac").str.len_chars() > 0)
            ).group_by("mac").agg([
                pl.count("ip").alias("mac_ip_count")
            ])
            
            # Join back
            combined = combined.join(mac_counts, on="mac", how="left")
            combined = combined.with_columns(pl.col("mac_ip_count").fill_null(0))
            
            # OUI Vendor Lookup
            combined = combined.with_columns(
                pl.col("mac").map_elements(lambda m: oui_lookup.get_vendor(m), return_dtype=pl.String).alias("mac_vendor")
            )
            
        else:
             combined = combined.with_columns([
                 pl.lit(0).alias("mac_ip_count"),
                 pl.lit("Unknown").alias("mac_vendor")
             ])

        # Scope classification moved up.

        
        # Rule C: L2 Leak
        # If Scope is Public BUT has_mac is True -> "L2 Leak (Misconfig)"
        combined = combined.with_columns(
            pl.when((pl.col("network_scope") == "Public") & (pl.col("has_mac") == True))
            .then(pl.lit("L2 Leak (Misconfig)"))
            .otherwise(pl.col("network_scope"))
            .alias("final_classification")
        )

        # 4. Behavioral Role (Ports)
        roles_df = self.heuristic_enrichment(conn_log)
        combined = combined.with_columns(pl.col("ip").cast(pl.String)) # Ensure type again
        
        if roles_df is not None:
             # roles_df ip is string?
             roles_df = roles_df.with_columns(pl.col("ip").cast(pl.String))
             combined = combined.join(roles_df, on="ip", how="left")
             combined = combined.with_columns(pl.col("behavioral_role").fill_null("Unknown"))
        else:
             combined = combined.with_columns(pl.lit("Unknown").alias("behavioral_role"))

        # Switch/Router Overrides
        combined = combined.with_columns(
            pl.when(pl.col("mac_ip_count") > 1)
            .then(pl.lit("Likely Switch/Router"))
            .otherwise(pl.col("behavioral_role"))
            .alias("behavioral_role")
        )

        # Final Cleanup
        self.master_df = combined.collect()
        return self.master_df

    def get_master_list(self):
        """
        Returns the cached Master Asset List DataFrame.
        If not processed, attempting temporary processing or returning None.
        """
        if self.master_df is not None:
            return self.master_df
        else:
            # Try to load default
            print("Master List not resident. attempting default ingest.")
            try:
                # We can't easily guess paths here without Arguments, 
                # so we rely on the caller having run ingest_model, 
                # OR we return an empty structure to prevent crashes.
                # Attempting a safe ingest with what we have (defaults)
                return self.ingest_model()
            except Exception as e:
                print(f"Auto-ingest failed: {e}")
                return None

    def heuristic_enrichment(self, conn_log):
        """
        Scan conn.log for server ports to determine role.
        """
        if not conn_log or not os.path.exists(conn_log):
            return None
            
        try:
            # resp_h is the server. resp_p is the port.
            q = pl.scan_csv(conn_log, separator='\t', comment_prefix="#", has_header=False, ignore_errors=True)
            
            # Group by dest_ip, aggregate unique ports
            server_traffic = q.select([
                pl.col("column_5").alias("ip"),    # id.resp_h
                pl.col("column_6").cast(pl.Int32, strict=False).alias("port"),  # id.resp_p
                pl.col("column_7").alias("proto")  # proto
            ])
            
            # Group by IP -> list of ports
            grouped = server_traffic.group_by("ip").agg(pl.col("port").unique().alias("ports"))
            
            enriched = grouped.with_columns(
                pl.col("ports").map_elements(lambda p_list: 
                    "Likely PLC" if any(p in [502, 44818, 102] for p in p_list if p is not None)
                    else "Likely Web Server" if any(p in [80, 443] for p in p_list if p is not None)
                    else "Likely DNS" if 53 in p_list
                    else "Workstation/Unknown"
                , return_dtype=pl.String).alias("behavioral_role")
            )
            
            return enriched.select(["ip", "behavioral_role"])
            
        except Exception as e:
            print(f"Heuristics Error: {e}")
            return None
