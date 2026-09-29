import json
import pandas as pd
import numpy as np
from pathlib import Path

import uuid
import os
import hashlib
import time

def calculate_sha256(filepath):
    sha256_hash = hashlib.sha256()
    with open(filepath, "rb") as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
    return sha256_hash.hexdigest()

def process_and_publish(in_file, tmp_out_file, final_out_file, run_id, eval_hashes, deferred_hashes, df, report_prefix=''):
    merged_records = {}
    parsing_errors = 0

    # 1. Load and select the richest record inline
    total_records = 0
    with open(in_file, 'r', encoding='utf-8') as f:
        for line in f:
            total_records += 1
            try:
                record = json.loads(line)
            except:
                parsing_errors += 1
                continue
            h = record.get('sha256')
            if not h: continue
            caps_len = len(record.get('caps', []))
            
            if h not in merged_records:
                merged_records[h] = (caps_len, record)
            else:
                if caps_len > merged_records[h][0]:
                    merged_records[h] = (caps_len, record)

    # 2. Write deduped file to tmp
    unique_records_count = 0
    hash_status = {}

    with open(tmp_out_file, 'w', encoding='utf-8') as f:
        for sha256, (caps_len, record) in merged_records.items():
            f.write(json.dumps(record) + '\n')
            unique_records_count += 1
            
            hash_status[sha256] = {}
            for field in ['caps', 'ttps', 'mbc']:
                has_field = field in record
                field_val = record.get(field)
                if isinstance(field_val, list) and len(field_val) > 0:
                    hash_status[sha256][field] = 2
                elif isinstance(field_val, list) and len(field_val) == 0:
                    hash_status[sha256][field] = 1
                else:
                    hash_status[sha256][field] = 0

    # 3. Read back to verify
    verified_hashes = set()
    verified_records_count = 0
    verified_status = {}

    with open(tmp_out_file, 'r', encoding='utf-8') as f:
        for line in f:
            verified_records_count += 1
            try:
                record = json.loads(line)
                h = record['sha256']
                verified_hashes.add(h)
                verified_status[h] = {}
                for field in ['caps', 'ttps', 'mbc']:
                    has_field = field in record
                    field_val = record.get(field)
                    if isinstance(field_val, list) and len(field_val) > 0:
                        verified_status[h][field] = 2
                    elif isinstance(field_val, list) and len(field_val) == 0:
                        verified_status[h][field] = 1
                    else:
                        verified_status[h][field] = 0
            except:
                parsing_errors += 1

    expected_hashes = eval_hashes
    is_hash_set_match = (verified_hashes == expected_hashes)
    is_record_count_match = (verified_records_count == unique_records_count)
    is_stats_match = (verified_status == hash_status)
    is_no_parsing_errors = (parsing_errors == 0)

    is_all_passed = is_hash_set_match and is_record_count_match and is_stats_match and is_no_parsing_errors

    if is_all_passed:
        os.replace(tmp_out_file, final_out_file)
        print(f"Verification passed. Saved unique records to {final_out_file}", flush=True)
        final_data_sha256 = calculate_sha256(final_out_file)
    else:
        print(f"Verification failed! Keeping tmp file at {tmp_out_file}", flush=True)
        print(f"  Hash set match: {is_hash_set_match}")
        print(f"  Record count match: {is_record_count_match}")
        print(f"  Stats match: {is_stats_match}")
        print(f"  No parsing errors: {is_no_parsing_errors}")
        final_data_sha256 = "VERIFICATION_FAILED"

    # 4. Generate report
    report = f"=== EMBER2024 통합 CAPA 연결 품질 보고서 (고유 파일 통합본) ===\n"
    report += f"Run ID: {run_id}\n"
    report += f"1. 고유 해시 기준 통계 (Unique Hashes)\n"
    report += f"전체 고유 해시 (eval): {len(eval_hashes):,}\n"
    report += f"전체 고유 해시 (JRR 보류): {len(deferred_hashes):,}\n"

    def calc_hash_stats(target_hashes, field='caps'):
        matched = 0; valid = 0; empty = 0; missing = 0
        for h in target_hashes:
            if h in hash_status:
                matched += 1
                stat = hash_status[h][field]
                if stat == 2: valid += 1
                elif stat == 1: empty += 1
                else: missing += 1
        return matched, valid, empty, missing

    def add_field_report(target_hashes, label):
        rep = f"  [{label}]\n"
        for field in ['caps', 'ttps', 'mbc']:
            m, v, emp, mis = calc_hash_stats(target_hashes, field)
            rep += f"  - {field.upper()} 매칭 성공: {m:,} / 미매칭: {len(target_hashes) - m:,}\n"
            rep += f"    * 유효한 결과(valid): {v:,}\n"
            rep += f"    * 빈 결과 목록(empty): {emp:,}\n"
            rep += f"    * 필드 누락(missing): {mis:,}\n"
        return rep

    report += add_field_report(eval_hashes, 'Eval 전체')
    report += add_field_report(deferred_hashes, 'JRR 보류')

    report += f"\n2. 행 기준 통계 (eval 행 기반)\n"
    total_eval_rows = len(df)
    total_def_rows = len(df[df['route'] == 'HIGH_RISK_UNCERTAIN'])

    def calc_row_stats(sub_df, field='caps'):
        matched = 0; valid = 0; empty = 0; missing = 0
        for h in sub_df['sha256']:
            if h in hash_status:
                matched += 1
                stat = hash_status[h][field]
                if stat == 2: valid += 1
                elif stat == 1: empty += 1
                else: missing += 1
        return matched, valid, empty, missing

    def add_field_row_report(sub_df, label, total):
        rep = f"  [{label}]\n"
        for field in ['caps', 'ttps', 'mbc']:
            rm, rv, re, rmis = calc_row_stats(sub_df, field)
            rep += f"  - {field.upper()} 해시 미매칭: {total - rm:,}\n"
            rep += f"  - {field.upper()} 연결을 적용한 행 수: {rm:,} (유효: {rv:,}, 빈목록: {re:,}, 누락: {rmis:,})\n"
        return rep

    report += f"전체 행 (eval): {total_eval_rows:,}\n"
    report += f"전체 행 (JRR 보류): {total_def_rows:,}\n"
    report += add_field_row_report(df, 'Eval 전체 행', total_eval_rows)
    report += add_field_row_report(df[df['route'] == 'HIGH_RISK_UNCERTAIN'], 'JRR 보류 행', total_def_rows)

    report += "\n3. 원본 및 통합 검증\n"
    report += f"- 추출된 원본 레코드 수: {total_records:,} (중복 포함)\n"
    report += f"- 통합된 고유 파일 수: {unique_records_count:,}\n"
    report += f"- 데이터 중복 원인(가설): 주 데이터셋 ZIP 내부(`Win32_train.zip`, `Win64_train.zip`)에서 동일 해시가 2회씩 등장했습니다. 한쪽은 빈 배열, 다른 쪽은 정상 추출된 배열을 가지는 것으로 보아, 데이터셋 구축 시 특징 추출 단계의 병합 과정에서 중복 누적되었을 것으로 추정됩니다.\n"
    report += f"- 통합 정책: (Union이 아님) 동일 해시를 가진 여러 레코드들 중 caps 길이가 가장 긴(즉, 가장 많은 분석 내용이 담긴) 단일 레코드를 최종적으로 선택하는 정책을 적용했습니다.\n"
    if is_all_passed:
        report += "- [OK] 결과 파일과 내부 통계가 모두 일치하며, 엄격한 게시 조건을 통과했습니다.\n"
    else:
        report += "- [ERROR] 엄격한 게시 조건을 통과하지 못했습니다! (로그 확인 요망)\n"

    print(report, flush=True)

    report_file_name = f'{report_prefix}capa_connection_report_final_{run_id}.txt'
    if is_all_passed:
        report_file_name = f'{report_prefix}capa_connection_report_final.txt'
        
    report_file = final_out_file.parent / report_file_name
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
        
    manifest_file_name = f'{report_prefix}manifest_process_{run_id}.json'
    manifest_file = final_out_file.parent / manifest_file_name
    with open(manifest_file, 'w', encoding='utf-8') as f:
        json.dump(manifest, f, indent=2)
        
    return is_all_passed

def main():
    root = Path(__file__).resolve().parent
    in_file = root / 'data' / 'ember2024' / 'mapping' / 'eval_capa_results.jsonl'
    run_id = str(uuid.uuid4())[:8]
    tmp_out_file = root / 'data' / 'ember2024' / 'mapping' / f'eval_capa_results_unique_{run_id}.jsonl.tmp'
    final_out_file = root / 'data' / 'ember2024' / 'mapping' / 'eval_capa_results_unique.jsonl'
    
    mapping_path = root / 'data' / 'ember2024' / 'mapping' / 'eval_row_to_sha256.csv'
    routes_path = root / 'data' / 'jrr_routes_eval.npy'
    
    df = pd.read_csv(mapping_path)
    eval_hashes = set(df['sha256'].values)
    routes = np.load(routes_path)
    df['route'] = routes
    deferred_hashes = set(df[df['route'] == 'HIGH_RISK_UNCERTAIN']['sha256'].values)
    
    process_and_publish(in_file, tmp_out_file, final_out_file, run_id, eval_hashes, deferred_hashes, df)

if __name__ == '__main__':
    main()
