import os
import json
import hashlib
import time
import pandas as pd
from pathlib import Path
from unittest.mock import patch

from process_duplicates import process_and_publish

def calculate_sha256(filepath):
    if not os.path.exists(filepath): return "NONE"
    sha256_hash = hashlib.sha256()
    with open(filepath, "rb") as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
    return sha256_hash.hexdigest()

def run_simulation(scenario_name, eval_hashes, records_to_write, expected_success, corrupt_readback=False):
    root = Path(__file__).resolve().parent
    run_id = f"test_{scenario_name}_{int(time.time())}"
    
    in_file = root / f'test_in_{run_id}.jsonl'
    tmp_out_file = root / f'test_out_{run_id}.tmp'
    final_out_file = root / f'test_final_out_{scenario_name}.jsonl'
    
    # Write mock input data
    with open(in_file, 'w', encoding='utf-8') as f:
        for record in records_to_write:
            if isinstance(record, str):
                f.write(record + '\n')
            else:
                f.write(json.dumps(record) + '\n')
                
    # Initialize fake final file to test preservation
    with open(final_out_file, 'w') as f:
        f.write("OLD_DATA")
    
    initial_final_sha = calculate_sha256(final_out_file)
    
    # Mock dataframe
    df = pd.DataFrame([{'sha256': h, 'route': 'HIGH_RISK_UNCERTAIN'} for h in eval_hashes])
    deferred_hashes = eval_hashes
    
    print(f"\n--- Scenario: {scenario_name} ---")
    
    if corrupt_readback:
        # Patch json.loads to fail on readback
        original_loads = json.loads
        call_count = [0]
        def side_effect(s, *args, **kwargs):
            call_count[0] += 1
            if call_count[0] > len(records_to_write): # This means we are at read-back phase
                res = original_loads(s, *args, **kwargs)
                if 'caps' in res: del res['caps']
                return res
            return original_loads(s, *args, **kwargs)
            
        with patch('json.loads', side_effect=side_effect):
            is_passed = process_and_publish(in_file, tmp_out_file, final_out_file, run_id, eval_hashes, deferred_hashes, df, report_prefix=f'test_{scenario_name}_')
    else:
        is_passed = process_and_publish(in_file, tmp_out_file, final_out_file, run_id, eval_hashes, deferred_hashes, df, report_prefix=f'test_{scenario_name}_')
        
    final_sha = calculate_sha256(final_out_file)
    
    assert is_passed == expected_success, f"Expected {expected_success} but got {is_passed}"
    
    if is_passed:
        print(f"[{scenario_name}] OK: Passed and published.")
        assert initial_final_sha != final_sha, "Final file should be replaced on success!"
    else:
        print(f"[{scenario_name}] FAIL: Verification caught the issue.")
        assert initial_final_sha == final_sha, "Final file must NOT be replaced on failure!"
        
    if in_file.exists(): os.remove(in_file)

if __name__ == '__main__':
    eval_hashes = {"hash1", "hash2"}
    
    # 1. Normal Input
    run_simulation('normal_success', eval_hashes, [
        {"sha256": "hash1", "caps": ["a"], "ttps": [], "mbc": []},
        {"sha256": "hash2", "caps": [], "ttps": [], "mbc": []}
    ], expected_success=True)
    
    # 2. Hash Missing (hash2 is missing from input entirely)
    run_simulation('hash_missing', eval_hashes, [
        {"sha256": "hash1", "caps": ["a"], "ttps": [], "mbc": []}
    ], expected_success=False)
    
    # 3. Parsing Error (Broken JSON string in input)
    run_simulation('parsing_error', eval_hashes, [
        {"sha256": "hash1", "caps": ["a"], "ttps": [], "mbc": []},
        {"sha256": "hash2", "caps": [], "ttps": [], "mbc": []},
        "{broken_json: true"
    ], expected_success=False)
    
    # 4. Read-back Mismatch (simulate corruption during re-reading)
    run_simulation('readback_mismatch', eval_hashes, [
        {"sha256": "hash1", "caps": ["a"], "ttps": [], "mbc": []},
        {"sha256": "hash2", "caps": [], "ttps": [], "mbc": []}
    ], expected_success=False, corrupt_readback=True)
    
    print("\nAll assertions passed! The actual function handles conditions strictly.")
