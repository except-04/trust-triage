import urllib.request
import json
import zipfile
import io
import pandas as pd
import numpy as np
import time
import os
import uuid
from pathlib import Path
from collections import defaultdict
import uuid
import shutil
import hashlib

def calculate_sha256(filepath):
    sha256_hash = hashlib.sha256()
    with open(filepath, "rb") as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
    return sha256_hash.hexdigest()
def main():
    root = Path(__file__).resolve().parent
    mapping_path = root / 'data' / 'ember2024' / 'mapping' / 'eval_row_to_sha256.csv'
    routes_path = root / 'data' / 'jrr_routes_eval.npy'
    
    if not mapping_path.exists():
        print(f"Mapping not found at {mapping_path}", flush=True)
        return
        
    df = pd.read_csv(mapping_path)
    eval_hashes = set(df['sha256'].values)
    
    routes = np.load(routes_path)
    df['route'] = routes
    deferred_hashes = set(df[df['route'] == 'HIGH_RISK_UNCERTAIN']['sha256'].values)
    
    print("Fetching EMBER2024 MAIN dataset file list...", flush=True)
    url = "https://huggingface.co/api/datasets/joyce8/EMBER2024"
    req = urllib.request.Request(url)
    res = urllib.request.urlopen(req).read()
    files = [x['rfilename'] for x in json.loads(res)['siblings'] if x['rfilename'].endswith('.zip')]
    
    # eval is from 'train' subset (weeks 46-51), which corresponds to Win32_train.zip and Win64_train.zip
    target_files = [f for f in files if f == 'Win32_train.zip' or f == 'Win64_train.zip']
    
    failed_downloads = []
    processed_files = []
    parsing_errors = 0
    
    run_id = str(uuid.uuid4())[:8]
    print(f"Run ID: {run_id}", flush=True)
    
    tmp_out_file = root / 'data' / 'ember2024' / 'mapping' / f'eval_capa_results_{run_id}.jsonl.tmp'
    final_out_file = root / 'data' / 'ember2024' / 'mapping' / 'eval_capa_results.jsonl'
    
    hash_status = {}  # 0=missing, 1=empty, 2=valid, -1=error
    matched_records_count = 0
    
    with open(tmp_out_file, 'w', encoding='utf-8') as f_out:
        for filename in target_files:
            dl_url = f"https://huggingface.co/datasets/joyce8/EMBER2024/resolve/main/{filename}"
            print(f"Downloading {filename} ...", flush=True)
            
            tmp_zip_path = root / 'data' / 'ember2024' / 'mapping' / f'tmp_{filename}'
            try:
                # Download in chunks to disk
                req = urllib.request.Request(dl_url, headers={'User-Agent': 'Mozilla/5.0'})
                with urllib.request.urlopen(req, timeout=60) as response, open(tmp_zip_path, 'wb') as f_zip:
                    while True:
                        chunk = response.read(8192 * 1024)
                        if not chunk: break
                        f_zip.write(chunk)
                        
                print(f"  Downloaded to tmp. Extracting...", flush=True)
                with zipfile.ZipFile(tmp_zip_path) as z:
                    for zinfo in z.infolist():
                        if zinfo.filename.endswith('.jsonl') or zinfo.filename.endswith('.json'):
                            # Weeks 46-51 are what we want, but since eval_hashes is specific, we can just match hashes.
                            with z.open(zinfo) as f:
                                for line in f:
                                    try:
                                        record = json.loads(line)
                                        sha256 = record.get('sha256')
                                        if sha256 in eval_hashes:
                                            f_out.write(json.dumps(record) + '\n')
                                            matched_records_count += 1
                                            
                                            if sha256 not in hash_status: hash_status[sha256] = {}
                                            for field in ['caps', 'ttps', 'mbc']:
                                                has_field = field in record
                                                field_val = record.get(field)
                                                
                                                is_valid = isinstance(field_val, list) and len(field_val) > 0
                                                is_empty = isinstance(field_val, list) and len(field_val) == 0
                                                
                                                current_stat = hash_status[sha256].get(field, -1)
                                                if is_valid: hash_status[sha256][field] = 2
                                                elif is_empty and current_stat < 2: hash_status[sha256][field] = 1
                                                elif not has_field and current_stat < 1: hash_status[sha256][field] = 0
                                    except json.JSONDecodeError:
                                        parsing_errors += 1
                                    except Exception as e:
                                        parsing_errors += 1
                                        if sha256 in eval_hashes: 
                                            if sha256 not in hash_status: hash_status[sha256] = {}
                                            for field in ['caps', 'ttps', 'mbc']: hash_status[sha256][field] = -1
                                        
                processed_files.append(filename)
                print(f"  Current unique matched hashes: {len(hash_status)}", flush=True)
            except Exception as e:
                print(f"  Failed to process {filename}: {e}", flush=True)
                failed_downloads.append(filename)
            finally:
                if tmp_zip_path.exists():
                    os.remove(tmp_zip_path)
                
    # Read back to verify
    verified_hashes = set()
    verified_records_count = 0
    verified_status = {}
    
    with open(tmp_out_file, 'r', encoding='utf-8') as f:
        for line in f:
            verified_records_count += 1
            record = json.loads(line)
            h = record['sha256']
            verified_hashes.add(h)
            
            if h not in verified_status: verified_status[h] = {}
            for field in ['caps', 'ttps', 'mbc']:
                has_field = field in record
                field_val = record.get(field)
                is_valid = isinstance(field_val, list) and len(field_val) > 0
                is_empty = isinstance(field_val, list) and len(field_val) == 0
                
                current_stat = verified_status[h].get(field, -1)
                if is_valid: verified_status[h][field] = 2
                elif is_empty and current_stat < 2: verified_status[h][field] = 1
                elif not has_field and current_stat < 1: verified_status[h][field] = 0
            
    # Strict Verification Conditions
    expected_files = ['Win32_train.zip', 'Win64_train.zip']
    is_files_processed = len(processed_files) == 2 and all(x in processed_files for x in expected_files)
    is_no_failures = len(failed_downloads) == 0
    is_no_parsing_errors = parsing_errors == 0
    is_hash_set_match = verified_hashes == eval_hashes
    is_record_count_match = verified_records_count == matched_records_count
    is_stats_match = verified_status == hash_status
    
    is_all_passed = (is_files_processed and is_no_failures and is_no_parsing_errors and 
                     is_hash_set_match and is_record_count_match and is_stats_match)
                     
    if is_all_passed:
        # Finalize atomically
        os.replace(tmp_out_file, final_out_file)
        print(f"Verification passed. Saved matched records to {final_out_file}", flush=True)
        final_data_sha256 = calculate_sha256(final_out_file)
    else:
        print(f"Verification failed! Keeping tmp file at {tmp_out_file}", flush=True)
        print(f"  Files processed match: {is_files_processed}")
        print(f"  No download failures: {is_no_failures}")
        print(f"  No parsing errors: {is_no_parsing_errors}")
        print(f"  Hash set match: {is_hash_set_match} (Expected {len(eval_hashes)}, Got {len(verified_hashes)})")
        print(f"  Record count match: {is_record_count_match} (Expected {matched_records_count}, Got {verified_records_count})")
        print(f"  Stats match: {is_stats_match}")
        final_data_sha256 = "VERIFICATION_FAILED"
            
    report = f"=== EMBER2024 파일 단위 CAPA 연결 품질 보고서 ===\n"
    report += f"Run ID: {run_id}\n"
    report += f"데이터 버전: joyce8/EMBER2024 (공식 원본 JSONL)\n"
    report += f"처리 파일 목록:\n"
    for pf in processed_files: report += f"  - {pf}\n"
    if failed_downloads:
        report += f"다운로드 실패:\n"
        for fd in failed_downloads: report += f"  - {fd}\n"
    else:
        report += f"다운로드 실패: 없음\n"
        
    report += f"\n파싱 에러: {parsing_errors}\n"
    
    report += "\n1. 고유 해시 기준 통계 (Unique Hashes)\n"
    report += f"전체 고유 해시 (eval): {len(eval_hashes):,}\n"
    report += f"전체 고유 해시 (JRR 보류): {len(deferred_hashes):,}\n"
    
    def calc_hash_stats(target_hashes, field='caps'):
        matched = 0; valid = 0; empty = 0; missing = 0; err = 0
        for h in target_hashes:
            if h in hash_status:
                matched += 1
                stat = hash_status[h].get(field, -1)
                if stat == 2: valid += 1
                elif stat == 1: empty += 1
                elif stat == 0: missing += 1
                else: err += 1
        return matched, valid, empty, missing, err

    def add_field_report(target_hashes, label):
        rep = f"  [{label}]\n"
        for field in ['caps', 'ttps', 'mbc']:
            m, v, emp, mis, e = calc_hash_stats(target_hashes, field)
            rep += f"  - {field.upper()} 매칭 성공: {m:,} / 미매칭: {len(target_hashes) - m:,}\n"
            rep += f"    * 유효한 결과(valid): {v:,}\n"
            rep += f"    * 빈 결과 목록(empty): {emp:,}\n"
            rep += f"    * 필드 누락(missing): {mis:,}\n"
            rep += f"    * 처리 에러(error): {e:,}\n"
        return rep

    report += add_field_report(eval_hashes, 'Eval 전체')
    report += add_field_report(deferred_hashes, 'JRR 보류')
    
    report += f"\n2. 행 기준 통계 (Rows - duplicates included)\n"
    total_eval_rows = len(df)
    total_def_rows = len(df[df['route'] == 'HIGH_RISK_UNCERTAIN'])
    
    def calc_row_stats(sub_df, field='caps'):
        matched = 0; valid = 0; empty = 0; missing = 0; err = 0
        for h in sub_df['sha256']:
            if h in hash_status:
                matched += 1
                stat = hash_status[h].get(field, -1)
                if stat == 2: valid += 1
                elif stat == 1: empty += 1
                elif stat == 0: missing += 1
                else: err += 1
        return matched, valid, empty, missing, err
        
    def add_field_row_report(sub_df, label, total):
        rep = f"  [{label}]\n"
        for field in ['caps', 'ttps', 'mbc']:
            rm, rv, re, rmis, rerr = calc_row_stats(sub_df, field)
            rep += f"  - {field.upper()} 매칭 행 수: {rm:,} (유효: {rv:,}, 빈목록: {re:,}, 누락: {rmis:,}, 에러: {rerr:,})\n"
        return rep

    report += f"전체 행 (eval): {total_eval_rows:,}\n"
    report += add_field_row_report(df, 'Eval 전체 행', total_eval_rows)
    report += f"전체 행 (JRR 보류): {total_def_rows:,}\n"
    report += add_field_row_report(df[df['route'] == 'HIGH_RISK_UNCERTAIN'], 'JRR 보류 행', total_def_rows)

    
    report += "\n3. 완료 검증 (Verification)\n"
    report += f"- 추출된 레코드 수(matched_records_count): {matched_records_count}\n"
    report += f"- 재입력 검증 레코드 수(verified_records_count): {verified_records_count}\n"
    report += f"- 기대 해시(eval_hashes) 수: {len(eval_hashes)}\n"
    report += f"- 재입력 검증 고유 해시 수: {len(verified_hashes)}\n"
    if is_all_passed:
        report += "- [OK] 결과 파일과 내부 통계가 모두 일치하며, 엄격한 게시 조건을 통과했습니다.\n"
    else:
        report += "- [ERROR] 엄격한 게시 조건을 통과하지 못했습니다! (로그 확인 요망)\n"

    print(report, flush=True)
    
    report_file = root / 'data' / 'ember2024' / 'mapping' / f'capa_connection_report_{run_id}.txt'
    if is_all_passed:
        report_file = root / 'data' / 'ember2024' / 'mapping' / 'capa_connection_report.txt'
        
    with open(report_file, 'w', encoding='utf-8') as f:
        f.write(report)
        
    # Write Manifest
    manifest = {
        'run_id': run_id,
        'timestamp': time.time(),
        'success': is_all_passed,
        'files': {
            'report': report_file.name,
            'report_sha256': calculate_sha256(report_file)
        }
    }
    if is_all_passed:
        manifest['files']['data'] = final_out_file.name
        manifest['files']['data_sha256'] = final_data_sha256
        
    manifest_file = root / 'data' / 'ember2024' / 'mapping' / f'manifest_{run_id}.json'
    with open(manifest_file, 'w', encoding='utf-8') as f:
        json.dump(manifest, f, indent=2)

if __name__ == '__main__':
    main()
