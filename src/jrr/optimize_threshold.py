# src/jrr/optimize_threshold.py
import numpy as np
import mlflow
import joblib
import os
import sys
import json
import hashlib

# jrr_router 모듈 경로 추가
sys.path.append(os.path.abspath(os.path.dirname(__file__)))
from jrr_router import JointRiskRouter
from _jrr_eval_core import calculate_review_yield

def get_file_hash(filepath, chunk_size=1048576):
    """Calculate MD5 hash of a file for exact cache invalidation."""
    hasher = hashlib.md5()
    try:
        with open(filepath, 'rb') as f:
            for chunk in iter(lambda: f.read(chunk_size), b''):
                hasher.update(chunk)
        return hasher.hexdigest()
    except Exception:
        return ""

def calculate_or_load_signals(X_calib_path, y_calib_path):
    print("[데이터 로딩] Calibration 세트 다중 위험 신호 계산 (최초 실행 시 시간 소요)")
    y_true = np.load(y_calib_path)

    # 캐시 파일 및 메타데이터 경로
    p_calib_cache = "data/cache_p_calib.npy"
    disagreement_cache = "data/cache_disagreement_calib.npy"
    ood_cache = "data/cache_ood_calib.npy"
    diff_cache = "data/cache_diff_calib.npy"
    meta_cache = "data/cache_meta.json"

    input_files = [
        X_calib_path, y_calib_path,
        "data/baseline_model_lightgbm_tuned_500_4way.pkl",
        "data/baseline_model_xgb_500_4way_1000cap.pkl",
        "data/jrr_calibrator_4way.pkl",
        "data/jrr_risk_signals.pkl",
        "data/top_feature_indices_500.npy"
    ]
    cache_files = [p_calib_cache, disagreement_cache, ood_cache, diff_cache, meta_cache]

    cache_valid = True
    if not all(os.path.exists(f) for f in cache_files):
        cache_valid = False
    elif not all(os.path.exists(f) for f in input_files):
        cache_valid = False
    else:
        # Load meta
        try:
            with open(meta_cache, "r", encoding="utf-8") as f:
                meta = json.load(f)
            # Check meta against current state
            for f in input_files:
                current_mtime = os.path.getmtime(f)
                current_size = os.path.getsize(f)
                if (meta.get(f, {}).get("mtime") != current_mtime or
                    meta.get(f, {}).get("size") != current_size or
                    meta.get(f, {}).get("hash") != get_file_hash(f)):
                    cache_valid = False
                    break
        except Exception:
            cache_valid = False

    if not getattr(sys.flags, 'force', False) and '--force' not in sys.argv and cache_valid:
        print("  -> 캐시된 신호 파일(cache_*.npy) 및 메타데이터(cache_meta.json)를 불러옵니다.")
        return y_true, np.load(p_calib_cache), np.load(disagreement_cache), np.load(ood_cache), np.load(diff_cache)

    print("  -> 캐시를 새로 생성합니다. Calibration 데이터로 새로 계산합니다.")
    X_calib = np.load(X_calib_path, mmap_mode="r")
    top_500_idx = np.load("data/top_feature_indices_500.npy")
    X_calib_500 = X_calib[:, top_500_idx]

    # 1. Probability
    if not os.path.exists("data/baseline_model_lightgbm_tuned_500_4way.pkl"):
        raise FileNotFoundError("공식 4-way 모델(baseline_model_lightgbm_tuned_500_4way.pkl)을 찾을 수 없습니다. 모델을 훈련하거나 추출하세요.")
    model_lgb = joblib.load("data/baseline_model_lightgbm_tuned_500_4way.pkl")
    print("  -> [1] LGBM 예측 중...")
    p_lgb_raw = model_lgb.predict_proba(X_calib_500)[:, 1]

    if not os.path.exists("data/jrr_calibrator_4way.pkl"):
        raise FileNotFoundError("4-way 전용 보정기(jrr_calibrator_4way.pkl)를 찾을 수 없습니다.")
    calibrator_pack = joblib.load("data/jrr_calibrator_4way.pkl")
    calibrator = calibrator_pack['model']
    p_calib = calibrator.predict(p_lgb_raw)

    # 2. Disagreement
    print("  -> [2] XGB 예측 중 (Disagreement 계산)...")
    model_xgb = joblib.load("data/baseline_model_xgb_500_4way_1000cap.pkl")
    p_xgb_raw = model_xgb.predict_proba(X_calib_500)[:, 1]
    disagreement = np.abs(p_lgb_raw - p_xgb_raw)

    # 3. OOD & Difficulty
    print("  -> [3,4] OOD & Difficulty 계산 중...")
    risk_signals = joblib.load("data/jrr_risk_signals.pkl")
    ood_model = risk_signals['ood_model']
    difficulty_indices = risk_signals['difficulty_indices']

    ood_scores = ood_model.decision_function(X_calib_500)
    difficulty_scores = np.sum(X_calib_500[:, difficulty_indices], axis=1)

    # 캐시 저장
    np.save(p_calib_cache, p_calib)
    np.save(disagreement_cache, disagreement)
    np.save(ood_cache, ood_scores)
    np.save(diff_cache, difficulty_scores)

    # Save metadata
    meta = {}
    for f in input_files:
        meta[f] = {
            "mtime": os.path.getmtime(f),
            "size": os.path.getsize(f),
            "hash": get_file_hash(f)
        }
    with open(meta_cache, "w", encoding="utf-8") as f:
        json.dump(meta, f, indent=4)
    print("  -> 캐시 저장 완료!")

    return y_true, p_calib, disagreement, ood_scores, difficulty_scores


def simulate_full_routing(p_calib, disagreement, ood_scores, difficulty_scores, tau_low, tau_high, tau_disagree, tau_ood, tau_difficulty):
    router = JointRiskRouter(tau_low, tau_high, tau_disagree, tau_ood, tau_difficulty)
    routed = router.route_batch(p_calib, disagreement, ood_scores, difficulty_scores)
    return np.array([r["initial_verdict"] for r in routed])


def optimize_grid_search(y_true, p_calib, disagreement, ood_scores, difficulty_scores, tau_high):
    total_malware = np.sum(y_true == 1)

    # 2D 탐색 공간 정의 (의미 있는 구간으로 압축하여 속도 확보)
    tl_bounds = np.array([0.50, 0.55, 0.60, 0.65, 0.70, 0.75, 0.80])
    td_bounds = np.arange(1.0, 11.0, 1.0)

    best_utility = -1
    best_params = {}
    best_stats = {}

    print("=========================================================================================")
    print(" [Grid Search] tau_low & tau_difficulty 2차원 동시 최적화")
    print(f" - 목적: 변수 간 순환 논리 배제 및 (타율 극대화 & 악성 누출 최소화) 탐색")
    print("=========================================================================================")
    print(f"{'Rank':^4} | {'tau_low':^8} | {'tau_diff':^8} | {'심층비율':^10} | {'Review Yield':^12} | {'악성 누출':^10}")
    print(f"{'-'*4}-+-{'-'*8}-+-{'-'*8}-+-{'-'*10}-+-{'-'*12}-+-{'-'*10}")

    results = []

    # 그리드 서치 수행
    print("  -> (모든 조합 시뮬레이션 계산 중... 약 30~60초 소요)")
    for tl in tl_bounds:
        for td in td_bounds:
            routes = simulate_full_routing(p_calib, disagreement, ood_scores, difficulty_scores,
                                           tau_low=tl, tau_high=tau_high, tau_disagree=0.3, tau_ood=0.0, tau_difficulty=td)

            n_total = len(routes)
            n_uncertain = np.sum(routes == "HIGH_RISK_UNCERTAIN")
            pct_uncertain = n_uncertain / n_total * 100

            auto_benign_mask = (routes == "AUTO_BENIGN")
            leaked_malware = np.sum((y_true == 1) & auto_benign_mask)

            yield_score = calculate_review_yield(y_true, routes)
            leakage_rate = leaked_malware / total_malware if total_malware > 0 else 0
            utility_score = yield_score * (1 - leakage_rate)

            results.append({
                'tl': tl, 'td': td, 'pct_uncertain': pct_uncertain, 'n_uncertain': n_uncertain,
                'yield_score': yield_score, 'leaked_malware': leaked_malware, 'leakage_rate': leakage_rate,
                'utility_score': utility_score
            })

            if utility_score > best_utility:
                best_utility = utility_score
                best_params = {'tau_low': tl, 'tau_diff': td}
                best_stats = {'pct_uncertain': pct_uncertain, 'n_uncertain': n_uncertain,
                              'yield_score': yield_score, 'leaked_malware': leaked_malware, 'leakage_rate': leakage_rate}

    # Utility Score 기준 내림차순 정렬하여 Top 15만 출력
    results = sorted(results, key=lambda x: x['utility_score'], reverse=True)

    for idx, r in enumerate(results[:15]):
        mark = "->" if idx == 0 else "  "
        print(f" {mark} {idx+1:2d} |  {r['tl']:^6.2f} |   {r['td']:^6.1f} | {r['pct_uncertain']:>9.2f}% | {r['yield_score']:>10.2f}% | {r['leaked_malware']:>6,}건")

    print("=========================================================================================\n")
    return best_params, best_stats


def main():
    print("[Threshold Optimization] Data Leakage 없는 순수 Grid Search 튜닝 시작!\n")

    if True:
        calibrator_pack = joblib.load("data/jrr_calibrator_4way.pkl")
        fixed_upper_bound = float(calibrator_pack.get('threshold', 0.983645))

        y_true, p_calib, disagreement, ood_scores, diff_scores = calculate_or_load_signals(
            "data/X_calib.npy", "data/y_calib.npy"
        )

        # 전수조사(Grid Search) 실행으로 단 한 번의 시뮬레이션으로 가장 완벽한 조합 추출
        best_params, best_stats = optimize_grid_search(y_true, p_calib, disagreement, ood_scores, diff_scores, fixed_upper_bound)

        print("==================================================")
        print("[완료] Grid Search 기반 글로벌 최적 라우팅 임계값 확정")
        print(f" - [확정] 자동 차단 상한선(Upper Bound): {fixed_upper_bound:.6f} (FPR 0.1% 기준 고정)")
        print(f" - [확정] 심층 분석 하한선(Lower Bound): {best_params['tau_low']:.2f}")
        print(f" - [확정] 분석 난이도 임계값(Difficulty): {best_params['tau_diff']:.1f}")
        print(f" - [확인] Calibration 심층분석 비율: {best_stats['pct_uncertain']:.2f}% ({best_stats['n_uncertain']:,}건)")
        print(f" - [확인] Calibration 분석가 가성비(Yield): {best_stats['yield_score']:.2f}%")
        print(f" - [확인] Calibration 악성 누락: {best_stats['leaked_malware']:,}건 ({best_stats['leakage_rate']*100:.2f}%)")
        print("==================================================")
        print(f"[안내] 위 산출된 최적 하한선(tau_low={best_params['tau_low']:.2f}, tau_difficulty={best_params['tau_diff']:.1f})을 확인하시고, jrr_router.py로 Eval 최종 라우팅을 실행하세요.")

if __name__ == "__main__":
    main()
