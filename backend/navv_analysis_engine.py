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
        
        # Collect for Joining with Inventory (which is Eager)
        df = df_lazy.collect()
        
        # 5.5 Lookup Names (RESTORED with STRICT TYPES)
        assets = self.inv.get_master_list()
        
        # Handle empty/missing inventory
        if assets is None:
             assets = pl.DataFrame(schema={"ip": pl.String, "final_name": pl.String})
        
        # Ensure schema for join
        if "final_name" not in assets.columns:
            assets = assets.with_columns(pl.lit("Unknown").alias("final_name"))
            
        # THE FIX: Force final_name to String to prevent Int64 mismatch
        assets = assets.with_columns(pl.col("final_name").cast(pl.String))
        assets_lookup = assets.select([pl.col("ip").cast(pl.String), pl.col("final_name")])

        # Join Src Name
        df = df.join(assets_lookup, left_on="src_ip", right_on="ip", how="left").rename({"final_name": "Src Name Raw"})
        
        # Join Dst Name
        df = df.join(assets_lookup, left_on="dst_ip", right_on="ip", how="left").rename({"final_name": "Dst Name Raw"})
        
        # 5.6 Resolve Segments (REMOVED - SIMPLIFIED)
        # User requested to undo "Unknown device in segment X" convention.
        
        # 5.7 Finalize Names
        # Use Inventory Name if found, else "Unknown Device"
        df = df.with_columns([
            pl.col("Src Name Raw").fill_null("Unknown Device").alias("Src Name"),
            pl.col("Dst Name Raw").fill_null("Unknown Device").alias("Dst Name")
        ])

        # 6. Reorder and Sort
        # Requested: count, src_ip, src_name, dst_ip, dst_name, others...
        
        ordered_cols = ["count"]
        if "src_ip" in group_cols:
             ordered_cols.extend(["src_ip", "Src Name"])
        if "dst_ip" in group_cols:
             ordered_cols.extend(["dst_ip", "Dst Name"])
             
        # Add the rest
        for col in group_cols:
            if col not in ["src_ip", "dst_ip"]:
                ordered_cols.append(col)
                
        # Select existing cols only
        final_cols = [c for c in ordered_cols if c in df.columns]
        
        df = df.select(final_cols).sort("count", descending=True)

        return df
