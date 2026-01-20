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
        # Requested: Src_ip, dst_ip, src_port, dst_port, proto, service, vlan
        target_mapping = {
            "id.orig_h": "src_ip",
            "id.resp_h": "dst_ip", 
            "id.orig_p": "src_port",
            "id.resp_p": "dst_port",
            "proto": "proto",
            "service": "service",
            "vlan": "vlan"
        }

        # 3. Build Selection
        selection = []
        group_cols = []
        
        for zeek_field, alias in target_mapping.items():
            if zeek_field in field_map:
                col_name = field_map[zeek_field]
                # Cast ports to Int? Strings are safer for aggregation if mixed. 
                # User didn't specify types, but Ports/Vlan benefit from Int? 
                # For safety against schema errors, keep as String or explicit Cast.
                # Let's clean nulls (Zeek uses '-')
                
                # Special handling for ports to look nice? default to string for grouping.
                expr = pl.col(col_name).fill_null("-").replace("-", "Unknown")
                
                # Force IP columns to String
                if alias in ["src_ip", "dst_ip"]:
                    expr = expr.cast(pl.String)
                    
                selection.append(expr.alias(alias))
            else:
                # Missing column (e.g. VLAN) -> Literal
                selection.append(pl.lit("-").alias(alias))
            
            group_cols.append(alias)

        # 4. Scan and Select
        q = pl.scan_csv(conn_log_path, separator='\t', comment_prefix="#", has_header=False, ignore_errors=True)
        raw = q.select(selection)

        # 5. Aggregate
        # "Put the counts as the first column and sort largest to smallest"
        df_lazy = raw.group_by(group_cols).agg(pl.len().alias("count"))
        
        df = df_lazy.collect()

        # 5.1 Service Resolution (Nmap 2nd Tier)
        # Apply Nmap/Fallback lookup to fill in missing Zeek services
        def resolve_svc_struct(s):
            name, conf = service_lookup.resolve_service(
                s["dst_port"],
                s["proto"],
                s["service"]
            )
            return {"service": name, "service_confidence": conf}

        if "dst_port" in df.columns and "proto" in df.columns and "service" in df.columns:
            svc_schema = pl.Struct({"service": pl.String, "service_confidence": pl.Int32})
            df = df.with_columns(
                pl.struct(["dst_port", "proto", "service"])
                  .map_elements(resolve_svc_struct, return_dtype=svc_schema)
                  .alias("svc_struct")
            ).drop("service").unnest("svc_struct")
        
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
