import polars as pl
import os
from backend.inventory_manager import InventoryHarmonizer
from backend.segment_manager import SegmentResolver
from backend.service_lookup import service_lookup

class NavvAnalysisEngine:
    def __init__(self, inventory_mgr: InventoryHarmonizer, segment_mgr: SegmentResolver):
        self.inv = inventory_mgr
        self.seg = segment_mgr

    def run_analysis(self, conn_log_path):
        """
        Process conn.log and return the enriched Analysis DataFrame.
        """
        if not os.path.exists(conn_log_path):
            raise FileNotFoundError("conn.log not found")

        # 1. Parse Headers to find column indices
        field_map = {}
        try:
            with open(conn_log_path, 'r', errors='ignore') as f:
                for _ in range(30): # check first 30 lines
                    line = f.readline()
                    if line.startswith("#fields"):
                        parts = line.strip().split('\t')
                        # format: #fields ts uid ...
                        for i, field in enumerate(parts):
                            if i == 0: continue # skip #fields tag
                            # Field 'ts' is at index 1 in the split list...
                            # In the data TSV, 'ts' is the 0th column.
                            # Polars 'column_1' is the 0th column (if has_header=False) ?? 
                            # Wait, Polars scan_csv with has_header=False names columns "column_1", "column_2"... 
                            # where column_1 is the FIRST column.
                            # So if 'ts' is the first field, it corresponds to column_1.
                            field_map[field] = f"column_{i}" 
                        break
        except Exception as e:
            # print(f"Naming Calculation Failed: {e}")
            pass

        # 2. Define Targets and Aliases
        # Requested: Src_ip, dst_ip, src_port, dst_port, proto, service, conn_state
        # Optional: orig_l2_addr, resp_l2_addr
        target_mapping = {
            "id.orig_h": "src_ip",
            "id.resp_h": "dst_ip", 
            "id.orig_p": "src_port",
            "id.resp_p": "dst_port",
            "proto": "proto",
            "service": "service",
            "conn_state": "conn_state",
            "orig_l2_addr": "src_mac",
            "resp_l2_addr": "dst_mac",
            "vlan": "vlan"
        }

        # 3. Build Selection
        selection = []
        
        # We need to distinguish between base grouping cols and potential mac cols
        base_group_aliases = ["src_ip", "dst_ip", "src_port", "dst_port", "proto", "service", "conn_state"]
        mac_group_aliases = ["src_mac", "dst_mac"]
        
        for zeek_field, alias in target_mapping.items():
            if zeek_field in field_map:
                col_name = field_map[zeek_field]
                # Cleaning
                expr = pl.col(col_name).fill_null("-").replace("-", "Unknown")
                
                # IP/MAC Types
                if alias in ["src_ip", "dst_ip", "src_mac", "dst_mac"]:
                    expr = expr.cast(pl.String)
                
                selection.append(expr.alias(alias))
            else:
                selection.append(pl.lit("-").alias(alias))
            
        # 4. Scan
        q = pl.scan_csv(conn_log_path, separator='\t', comment_prefix="#", has_header=False, ignore_errors=True)
        raw = q.select(selection)

        # 5. Single Pass Aggregation
        # We include MAC addresses by default in the group_by. 
        # If they are missing in the log, they were replaced with lit("-") in step 3,
        # so they will aggregate correctly as a single group for that IP/Port set.
        group_cols = base_group_aliases + mac_group_aliases
        
        # Aggregate and Collect once
        df = raw.group_by(group_cols).agg(pl.len().alias("count")).collect()
            
        # 5.1 Service Resolution
        
        # 5.5 Lookup Names (RESTORED with STRICT TYPES)
        assets = self.inv.get_master_list()
        
        # Handle empty/missing inventory
        if assets is None:
             assets = pl.DataFrame(schema={"ip": pl.String, "final_name": pl.String})
        
        # Ensure schema for join
        if "final_name" not in assets.columns:
            assets = assets.with_columns([
                pl.lit("Unknown").alias("final_name"),
                pl.lit(8).cast(pl.Int32).alias("name_confidence") # Default low confidence
            ])
            
        # THE FIX: Force final_name to String to prevent Int64 mismatch
        assets = assets.with_columns(pl.col("final_name").cast(pl.String))
        
        # Select columns for join
        assets_lookup = assets.select([
            pl.col("ip").cast(pl.String), 
            pl.col("final_name"),
            pl.col("name_confidence")
        ])

        # Join Src Name
        df = df.join(assets_lookup, left_on="src_ip", right_on="ip", how="left") \
               .rename({"final_name": "Src Name Raw", "name_confidence": "src_name_conf"})
        
        # Join Dst Name
        df = df.join(assets_lookup, left_on="dst_ip", right_on="ip", how="left") \
               .rename({"final_name": "Dst Name Raw", "name_confidence": "dst_name_conf"})
        
        # 5.6 Resolve Segments
        # Create lookup of unique IPs to minimize python loop overhead
        unique_ips = pl.concat([
            df.select(pl.col("src_ip").alias("ip")), 
            df.select(pl.col("dst_ip").alias("ip"))
        ]).unique()
        
        # Resolve (returns Struct column)
        resolved_struct = self.seg.resolve_ip(unique_ips["ip"])
        
        # Unpack into DataFrame
        val_df = unique_ips.with_columns(resolved_struct.alias("seg_data")).unnest("seg_data")
        
        # Join Src Segments
        # Rename columns to avoid collision
        src_lookup = val_df.select([
             pl.col("ip"),
             pl.col("Name").alias("src_segment"),
             pl.col("Level").alias("src_level"),
             pl.col("Color").alias("src_color"),
             pl.col("FontColor").alias("src_font")
        ])
        df = df.join(src_lookup, left_on="src_ip", right_on="ip", how="left")
        
        # Join Dst Segments
        dst_lookup = val_df.select([
             pl.col("ip"),
             pl.col("Name").alias("dst_segment"),
             pl.col("Level").alias("dst_level"),
             pl.col("Color").alias("dst_color"),
             pl.col("FontColor").alias("dst_font")
        ])
        df = df.join(dst_lookup, left_on="dst_ip", right_on="ip", how="left")

        # 5.7 Finalize Names
        # Use Inventory Name if found, else "Unknown Device" - Set confidence to 8 (lowest) if null
        df = df.with_columns([
            pl.col("Src Name Raw").fill_null("Unknown Device").alias("Src Name"),
            pl.col("Dst Name Raw").fill_null("Unknown Device").alias("Dst Name"),
            pl.col("src_name_conf").fill_null(8).alias("src_name_conf"),
            pl.col("dst_name_conf").fill_null(8).alias("dst_name_conf"),
            # Fill null segments? (Shouldn't be null due to resolve_ip logic, but for safety)
            pl.col("src_segment").fill_null("Unknown"),
            pl.col("dst_segment").fill_null("Unknown"),
            pl.col("src_level").fill_null(0),
            pl.col("dst_level").fill_null(0),
            pl.col("src_color").fill_null("#ffffff"),
            pl.col("src_font").fill_null("#000000"),
            pl.col("dst_color").fill_null("#ffffff"),
            pl.col("dst_font").fill_null("#000000"),
        ])

        # 6. Reorder and Sort
        # Requested: count, src_ip, src_name, dst_ip, dst_name, others...
        
        ordered_cols = ["count"]
        if "src_ip" in group_cols:
             ordered_cols.extend(["src_ip", "Src Name", "src_segment", "src_color", "src_font", "src_name_conf"])
        if "dst_ip" in group_cols:
             ordered_cols.extend(["dst_ip", "Dst Name", "dst_segment", "dst_color", "dst_font", "dst_name_conf"])
             
        # Add the rest
        for col in group_cols:
            if col not in ["src_ip", "dst_ip"]:
                ordered_cols.append(col)
                # Add confidence next to service
                if col == "service":
                    ordered_cols.append("service_confidence")
                
        # Select existing cols only
        final_cols = [c for c in ordered_cols if c in df.columns]
        
        df = df.select(final_cols).sort("count", descending=True)

        return df
    
    def generate_endpoints_view(self, conn_log_path):
        """
        Generate a summary of all unique endpoints (IPs) found in the logs.
        Aggregates usage statistics (bytes sent/received, connection counts).
        
        Returns a Polars DataFrame.
        """
        if not os.path.exists(conn_log_path):
             return pl.DataFrame()
             
        # Lazy Scan
        q = pl.scan_csv(conn_log_path, separator='\t', comment_prefix="#", has_header=False, ignore_errors=True)

        # Field Mapping (Naive but consistent with current run_analysis)
        # We need orig_bytes, resp_bytes for volume analysis
        # id.orig_h (col 2), id.resp_h (col 4), orig_bytes (col 9), resp_bytes (col 10) likely
        # Better to check fields again or trust schema stability... 
        # But wait, run_analysis does a dynamic header check. We should factor that out?
        # For now, let's reuse the dynamic check (duplication, but safer than hardcoding)
        
        field_map = {}
        try:
            with open(conn_log_path, 'r', errors='ignore') as f:
                 for _ in range(30):
                    line = f.readline()
                    if line.startswith("#fields"):
                        parts = line.strip().split('\t')
                        for i, field in enumerate(parts):
                            if i == 0: continue
                            field_map[field] = f"column_{i}" 
                        break
        except:
             return pl.DataFrame()
             
        # Extract Cols
        def get_expr(field, alias, cast_type=pl.String, fill_val=None):
             if field in field_map:
                 e = pl.col(field_map[field])
                 if cast_type == pl.Int64:
                     # Zeek uses '-' for null. Replace with '0' before casting.
                     e = e.replace("-", "0")
                 if fill_val is not None:
                      e = e.fill_null(fill_val)
                 return e.cast(cast_type).alias(alias)
             else:
                 return pl.lit(fill_val if fill_val is not None else 0).cast(cast_type).alias(alias)

        # We need src, dst, bytes
        df_base = q.select([
             get_expr("id.orig_h", "src_ip"),
             get_expr("id.resp_h", "dst_ip"),
             get_expr("orig_bytes", "bytes_sent", pl.Int64, 0),
             get_expr("resp_bytes", "bytes_recv", pl.Int64, 0)
        ]).collect()
        
        # Aggregate as Source
        # How many times was this IP the Originator? And bytes sent?
        as_src = df_base.group_by("src_ip").agg([
             pl.len().alias("count_as_src"),
             pl.col("bytes_sent").sum().alias("total_sent")
        ]).rename({"src_ip": "ip"})
        
        # Aggregate as Dest
        as_dst = df_base.group_by("dst_ip").agg([
             pl.len().alias("count_as_dst"),
             pl.col("bytes_recv").sum().alias("total_recv")
        ]).rename({"dst_ip": "ip"})
        
        # Outer Join (Full List of IPs)
        df_full = as_src.join(as_dst, on="ip", how="full")
        
        # Fill Nulls (0 activity)
        df_full = df_full.fill_null(0)
        
        # Total Activity
        df_full = df_full.with_columns([
             (pl.col("count_as_src") + pl.col("count_as_dst")).alias("total_conns"),
             (pl.col("total_sent") + pl.col("total_recv")).alias("total_bytes")
        ]).sort("total_bytes", descending=True)
        
        
        # 6. Categorization Logic
        def categorize_ip(ip_str):
            import ipaddress
            try:
                ip = ipaddress.ip_address(ip_str)
                if ip.is_multicast or ip.is_loopback or ip.is_link_local or str(ip) == "255.255.255.255" or str(ip).endswith(".255"):
                    return "Special"
                if ip.is_private:
                    return "Internal"
                return "External"
            except:
                return "Special"

        df_full = df_full.with_columns(
            pl.col("ip").map_elements(categorize_ip, return_dtype=pl.String).alias("Category")
        )
        
        # Enrich with Inventory Name
        assets = self.inv.get_master_list()
        if assets is not None:
             # Ensure types
             assets = assets.with_columns(pl.col("final_name").cast(pl.String))
             lookup = assets.select(["ip", "final_name"])
             df_full = df_full.join(lookup, on="ip", how="left") \
                              .rename({"final_name": "Hostname"}) \
                              .with_columns(pl.col("Hostname").fill_null("Unknown Device"))
        else:
             df_full = df_full.with_columns(pl.lit("Unknown Device").alias("Hostname"))
             
        # Enrich with Segment
        resolved_struct = self.seg.resolve_ip(df_full["ip"])
        val_df = df_full.with_columns(resolved_struct.alias("seg_data")).unnest("seg_data")
        
        # Select Final
        cols_final = [
             "ip", "Hostname", "Category", "count_as_src", "count_as_dst", "total_conns", "total_sent", "total_recv", "total_bytes",
             "Name", "Level" # Segment info
        ]
        
        return val_df.select([c for c in cols_final if c in val_df.columns])
