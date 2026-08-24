#!/usr/bin/env python3
"""
4단계 — 전처리와 시간 기반 분할. 단, 이 단계는 X를 복사하지 않는다.

핵심 설계
---------
X(21GB)는 건드리지 않고 y, week_id, 인덱스 배열만 가지고 작업한다.
y_train은 208만 x int32 = 8MB, 메타데이터도 수십 MB라 RAM에 올려도 무해하다.
따라서 이 단계의 산출물은 수 MB짜리 인덱스 파일과 JSON 리포트뿐이다.
분할 기준을 바꾸고 싶으면 이 단계만 다시 돌리면 되고, 21GB 복사(5단계)를
다시 할 필요가 없다.

왜 무작위 분할이 아니라 시간 분할인가
------------------------------------
EMBER2024는 IID가 아니라 시간축 설계다. 무작위/층화 분할은 미래 정보를 과거
학습에 흘려 성능을 낙관적으로 부풀린다. 그래서 `week_id` 기준으로만 나눈다:
  idx_tr    : weeks  0–33   (약 65%, 적합 전용)
  idx_val   : weeks 34–39   (약 12%, 모델 선택 전용, 6주)
  idx_calib : weeks 40–45   (약 12%, 임계값 추정용, 6주)
  idx_eval  : weeks 46–51   (약 12%, 시간 이동 후 성능 확인용, 6주)

validation을 왜 따로 두는가
  이전 설계는 train(0–39)/calib/eval의 3분할이라 validation이 없었다. 그러면
  하이퍼파라미터 탐색과 early stopping을 할 곳이 없어 calib나 eval이 그 역할을
  겸하게 되고, 임계값이 자기가 고른 모델 위에서 추정되거나(낙관 편향) eval이
  더 이상 시간 이동 성능의 정직한 추정치가 아니게 된다. train의 뒤쪽 6주를
  떼어 val로 만들면 각 조각이 역할을 하나씩만 갖는다. 계약은
  common.split_contract()에 있고 06단계가 manifest.json에 기록한다.

설계 원칙:
  * 주차 경계를 먼저 정하고 비율은 결과로 받아들인다. 비율을 억지로 맞추려고
    주차를 쪼개면 시간 분할의 의미가 사라진다.
  * val / calibration / eval의 시간 폭을 각 6주로 동일하게 유지한다. 이 대칭성이
    비율보다 중요하다 — 폭이 같아야 val→calib, calib→eval 구간의 성능 저하를
    서로 비교할 수 있고, eval의 저하가 test에서 겪을 저하의 대리 지표가 된다.
  * family 기반 제약을 걸지 않는다. 주요 family는 52주 내내 등장하므로 경계
    걸침을 제거하면 데이터 대부분이 소실된다. 정상 파일은 family가 null이라
    그룹 정의도 불가능하다. 신종 family 일반화는 분할이 아니라 리포팅에서 본다.

리샘플링 / SMOTE / class_weight는 쓰지 않는다. 데이터가 대략 균형이고,
SMOTE는 PE 특징 공간에서 실재 불가능한 벡터를 만든다.

수행 내용
---------
1. train에서 라벨 -1(미분류)을 마스크로 제외 (행 삭제 아님 — 인덱스 유지).
2. .NET 등 비PE(file_type ∉ {Win32,Win64})가 섞여 있으면 함께 제외.
3. 남은 train을 week_id로 시간 4분할 (tr / val / calib / eval).
4. test / challenge는 절대 필터링하지 않는다. valid_mask(-1 아님)만 별도 저장.
   Lockbox 원본은 무손상으로 두고, 최종 평가 시점에 마스크만 적용한다.
5. non-finite(NaN/±inf) 검사: 청크로 돌며 컬럼별 개수를 누적한다.
6. 주차별 악성 비율 추이 — 드리프트 감지용으로 리포트에 남긴다.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parent))
from common import (  # noqa: E402
    ARCH_NAMES, DEFAULT_CHUNK, DEV_SPLITS, LABEL_UNKNOWN, PE_FILE_TYPES,
    SPLIT_WEEKS, WEEK_CALIB_END, WEEK_CALIB_START, WEEK_EVAL_START, WEEK_MAX,
    WEEK_TRAIN_END, WEEK_VAL_END, WEEK_VAL_START,
    Layout, Timer, add_root_arg, get_dim, iter_chunks, label_stats, load_meta,
    load_y, open_dat, setup_logging, split_contract, write_json,
)


def scan_nonfinite(X, n: int, dim: int, chunk: int, log) -> dict:
    """
    청크 단위로 non-finite(NaN/±inf) 값을 센다.

    2568컬럼 x 208만 행을 한 번에 검사하면 메모리가 터지므로 청크로 돌면서
    컬럼별 카운트를 누적한다. '있다/없다'가 아니라 '어느 컬럼에 몇 개'가
    나와야 대응 방침을 정할 수 있다.

    EMBER 특징의 NaN/inf는 랜덤 결측이 아니라 '해당 파일에서 값이 정의되지
    않음'(빈 파일의 히스토그램 정규화, 0으로 나누기 등)을 뜻한다. 결측 자체가
    예측 신호이므로 평균 대치로 뭉개지 않는다. LightGBM은 NaN을 네이티브로
    처리하므로 보통 그대로 둔다.
    """
    col_nan = np.zeros(dim, dtype=np.int64)
    col_posinf = np.zeros(dim, dtype=np.int64)
    col_neginf = np.zeros(dim, dtype=np.int64)
    n_bad_rows = 0

    for s, e in iter_chunks(n, chunk):
        block = np.asarray(X[s:e])
        nan = np.isnan(block)
        pinf = np.isposinf(block)
        ninf = np.isneginf(block)
        col_nan += nan.sum(axis=0, dtype=np.int64)
        col_posinf += pinf.sum(axis=0, dtype=np.int64)
        col_neginf += ninf.sum(axis=0, dtype=np.int64)
        n_bad_rows += int((nan | pinf | ninf).any(axis=1).sum())
        if (s // chunk) % 20 == 0:
            log.info("    ...%d / %d 행 (%.1f%%)", e, n, 100.0 * e / n)

    total = col_nan + col_posinf + col_neginf
    bad_cols = np.flatnonzero(total)
    top = sorted(bad_cols.tolist(), key=lambda c: -int(total[c]))[:30]

    return {
        "n_rows_scanned": int(n),
        "n_rows_with_nonfinite": n_bad_rows,
        "n_columns_with_nonfinite": int(bad_cols.size),
        "total_nan": int(col_nan.sum()),
        "total_posinf": int(col_posinf.sum()),
        "total_neginf": int(col_neginf.sum()),
        "top_columns": [
            {
                "col": int(c),
                "nan": int(col_nan[c]),
                "posinf": int(col_posinf[c]),
                "neginf": int(col_neginf[c]),
            }
            for c in top
        ],
    }


def time_split(week: np.ndarray, keep: np.ndarray) -> dict:
    """
    week_id로 시간 4분할. keep(불리언 마스크)에 걸린 행만 대상으로 한다.
    경계는 common.py의 SPLIT_WEEKS(= WEEK_* 상수). 행 삭제 없이 인덱스만 만든다.

    {"tr": idx, "val": idx, "calib": idx, "eval": idx}를 DEV_SPLITS 순서로
    돌려준다. 구간을 [lo, hi] 양끝 포함으로 통일해 두면 경계가 한 군데에만
    적히므로, 나중에 주차를 옮길 때 조건식을 손댈 필요가 없다.
    """
    out = {}
    for name in DEV_SPLITS:
        lo, hi = SPLIT_WEEKS[name]
        out[name] = np.where(keep & (week >= lo) & (week <= hi))[0]
    return out


def main() -> int:
    ap = argparse.ArgumentParser(description="전처리 / 시간 분할(week_id) / QC")
    add_root_arg(ap)
    ap.add_argument("--chunk", type=int, default=DEFAULT_CHUNK)
    ap.add_argument("--force", action="store_true")
    ap.add_argument("--qc-subsets", default="train,test,challenge",
                    help="non-finite 검사를 수행할 subset (쉼표 구분). "
                         "'none'이면 건너뜀")
    args = ap.parse_args()

    layout = Layout(args.root)
    layout.mkdirs()
    log = setup_logging("04_split_qc", layout.logs)

    if layout.is_done("split_qc") and not args.force:
        log.info("이미 완료되었습니다 (--force로 재실행).")
        return 0

    dim = get_dim()
    week_boundaries = {
        "idx_tr": f"week <= {WEEK_TRAIN_END}",
        "idx_val": f"{WEEK_VAL_START} <= week <= {WEEK_VAL_END}",
        "idx_calib": f"{WEEK_CALIB_START} <= week <= {WEEK_CALIB_END}",
        "idx_eval": f"week >= {WEEK_EVAL_START}",
    }
    report: dict = {
        "split_method": "time (week_id)",
        "week_boundaries": week_boundaries,
        "feature_dim": dim,
        # 분할의 용도/허용/금지 계약. 06단계가 manifest에도 그대로 옮겨 적는다.
        "split_contract": split_contract(),
    }

    # ------------------------------------------------------------------
    # 1) train: 메타데이터 로드 + 마스크 + 시간 분할
    # ------------------------------------------------------------------
    try:
        meta = load_meta(layout, "train")
    except FileNotFoundError as exc:
        log.error("%s", exc)
        return 1

    y_train = load_y(layout, "train")
    arch_train = np.load(layout.arch_path("train"))
    if not (len(meta) == y_train.size == arch_train.size):
        log.error("행 수 불일치: meta=%d, y=%d, arch=%d — 03단계를 재실행하세요.",
                  len(meta), y_train.size, arch_train.size)
        return 1

    # 메타 label과 y의 정합성 재확인 (03에서 이미 검증했지만 저비용이라 재확인).
    if not (meta["label"].to_numpy(dtype=np.int64)
            == y_train.astype(np.int64)).all():
        log.error("meta.label과 y_train이 불일치합니다 — 03단계를 재실행하세요.")
        return 1

    week = meta["week_id"].to_numpy(dtype=np.int64)
    file_type = meta["file_type"].to_numpy()

    log.info("train 원본: %d행", y_train.size)
    report["train_raw"] = label_stats(y_train, arch_train)
    log.info("  라벨 분포: %s", report["train_raw"])

    # --- 마스크: -1 제외 + 비PE(.NET 등) 제외 --------------------------
    keep = (y_train != LABEL_UNKNOWN)
    n_unknown = int((~keep).sum())
    log.info("라벨 -1(미분류): %d행 → 마스크로 제외 (행 삭제 아님)", n_unknown)

    is_pe = np.isin(file_type, np.asarray(PE_FILE_TYPES))
    n_nonpe = int((keep & ~is_pe).sum())
    if n_nonpe:
        import collections
        excluded_types = collections.Counter(
            file_type[keep & ~is_pe].tolist()
        )
        log.warning(".NET/비PE 혼입 감지: file_type ∉ %s 인 %d행을 함께 제외합니다. "
                    "제외 분포: %s", list(PE_FILE_TYPES), n_nonpe, dict(excluded_types))
        keep &= is_pe
        report["nonpe_excluded"] = {
            "n_excluded": n_nonpe,
            "by_type": {str(k): int(v) for k, v in excluded_types.items()},
        }
    else:
        log.info(".NET/비PE 혼입 없음 (전부 Win32/Win64)")
        report["nonpe_excluded"] = {"n_excluded": 0, "by_type": {}}

    # week_id가 0–51 밖(예: 메타 추출 시 누락되어 -1로 채워진 행)이면 제외한다.
    # 이 방어가 없으면 week_id=-1인 행이 `week <= 39` 조건에 걸려 train으로
    # 조용히 새어 들어간다.
    in_range = (week >= 0) & (week <= WEEK_MAX)
    n_oob = int((keep & ~in_range).sum())
    if n_oob:
        log.warning("week_id가 0–%d 밖인 %d행을 제외합니다 (누락/이상치). "
                    "정상이라면 0이어야 합니다.", WEEK_MAX, n_oob)
        keep &= in_range
    report["week_out_of_range_excluded"] = n_oob

    n_keep = int(keep.sum())
    log.info("분할 대상(유효 PE): %d행 (%.2f%%)",
             n_keep, 100.0 * n_keep / y_train.size)

    # --- 시간 분할 ------------------------------------------------------
    span = " / ".join(
        f"{SPLIT_WEEKS[n][0]}–{SPLIT_WEEKS[n][1]}" for n in DEV_SPLITS
    )
    with Timer(log, f"시간 {len(DEV_SPLITS)}분할 (weeks {span})"):
        splits = time_split(week, keep)

    for name, idx in splits.items():
        np.save(layout.split_idx_path(name), idx)
        st = label_stats(y_train[idx], arch_train[idx])
        report[f"split_{name}"] = st
        report[f"split_{name}"]["n_indices"] = int(idx.size)
        w = week[idx]
        report[f"split_{name}"]["week_range"] = (
            [int(w.min()), int(w.max())] if idx.size else None
        )
        log.info(
            "%-6s %8d행 (%.1f%%)  악성비율=%s  주차=%s  arch=%s",
            name, idx.size, 100.0 * idx.size / max(n_keep, 1),
            None if st["malicious_ratio"] is None else f"{st['malicious_ratio']:.4f}",
            report[f"split_{name}"]["week_range"],
            {k: v["n_total"] for k, v in st.get("per_arch", {}).items()},
        )

    # --- 무결성: 중복 없음 + 커버리지 확인 ------------------------------
    # 분할 쌍을 하드코딩하지 않고 조합으로 전부 돈다. 분할이 하나 늘어나도
    # (3분할 → 4분할처럼) 검사에서 빠지는 쌍이 생기지 않는다.
    import itertools
    overlap = sum(
        len(np.intersect1d(splits[a], splits[b]))
        for a, b in itertools.combinations(DEV_SPLITS, 2)
    )
    if overlap:
        log.error("분할 간 중복 인덱스 %d개 발견 — 중단합니다.", overlap)
        return 1

    # 네 버킷(0–33 / 34–39 / 40–45 / 46–51)은 정수 주차를 빠짐없이 덮으므로,
    # week를 0–51로 제한한 keep 집합은 정확히 분할된다. 어긋나면 상류 버그다.
    total = sum(int(idx.size) for idx in splits.values())
    if total != n_keep:
        log.error("분할 합계(%d)가 유효 행 수(%d)와 다릅니다 — 경계 로직 오류.",
                  total, n_keep)
        return 1
    log.info("분할 무결성 확인: 중복 0건, 커버리지 일치")

    # 주차 구간이 연속인지(빈틈/겹침 없이 0–WEEK_MAX를 덮는지) 직접 확인한다.
    # 상수만 고치고 한 분할의 경계를 잘못 적으면 합계 검사는 통과하면서도
    # 특정 주차가 통째로 사라질 수 있다.
    covered = sorted(SPLIT_WEEKS[n] for n in DEV_SPLITS)
    expect = 0
    for lo, hi in covered:
        if lo != expect:
            log.error("주차 구간이 연속적이지 않습니다: %d주차에서 끊김 "
                      "(구간=%s) — WEEK_* 상수를 확인하세요.", expect, covered)
            return 1
        expect = hi + 1
    if expect != WEEK_MAX + 1:
        log.error("주차 구간이 0–%d를 덮지 않습니다 (마지막=%d) — "
                  "WEEK_* 상수를 확인하세요.", WEEK_MAX, expect - 1)
        return 1
    log.info("주차 구간 연속성 확인: %s → 0–%d 빈틈 없음", covered, WEEK_MAX)

    # --- 주차별 악성 비율 추이 (드리프트 감지) --------------------------
    kept_meta = meta.loc[keep]
    wk = kept_meta.groupby("week_id")["label"].agg(["mean", "size"])
    report["weekly_malicious_ratio"] = {
        "per_week": {int(k): {"mean": float(v["mean"]), "size": int(v["size"])}
                     for k, v in wk.to_dict("index").items()},
        "describe": {k: float(v) for k, v in wk["mean"].describe().to_dict().items()},
    }
    log.info("주차별 악성 비율 describe(mean): %s",
             {k: round(v, 4) for k, v in
              report["weekly_malicious_ratio"]["describe"].items()})
    log.info("  주차별 mean이 뒤로 갈수록 뚜렷이 움직이면 base rate 드리프트 신호 — "
             "calibration 임계값이 test에서 그대로 통하지 않을 수 있습니다.")

    # ------------------------------------------------------------------
    # 2) lockbox: 필터링하지 않고 valid 마스크만 저장
    # ------------------------------------------------------------------
    for subset in ("test", "challenge"):
        try:
            y = load_y(layout, subset)
        except FileNotFoundError:
            log.warning("%s 없음 — 건너뜀", subset)
            continue
        arch_path = layout.arch_path(subset)
        arch = np.load(arch_path) if arch_path.is_file() else None

        mask = (y != LABEL_UNKNOWN)
        np.save(layout.valid_mask_path(subset), mask)
        st = label_stats(y, arch)
        report[f"lockbox_{subset}"] = st
        log.info("%s (원본 보존): %d행, 유효 %d행, 악성비율=%s",
                 subset, y.size, int(mask.sum()), st["malicious_ratio"])
        log.info("  → 원본은 필터링하지 않고 valid_mask_%s.npy만 저장했습니다.", subset)

        if subset == "challenge" and arch is not None:
            dist = {ARCH_NAMES.get(int(a), str(a)): int((arch == a).sum())
                    for a in np.unique(arch)}
            log.info("  challenge arch 분포: %s", dist)
            n_pe = int(((arch == 0) | (arch == 1)).sum())
            report["challenge_win_count"] = n_pe
            log.warning(
                "  challenge의 Win32/Win64는 %d건뿐입니다. 표본이 작아 탐지율 "
                "비교 시 신뢰구간을 반드시 함께 보고하세요.", n_pe,
            )

    # ------------------------------------------------------------------
    # 3) non-finite 검사
    # ------------------------------------------------------------------
    qc_targets = [] if args.qc_subsets.strip().lower() == "none" else [
        s.strip() for s in args.qc_subsets.split(",") if s.strip()
    ]
    report["nonfinite"] = {}
    for subset in qc_targets:
        try:
            X, _, n = open_dat(layout, subset, dim)
        except FileNotFoundError:
            continue
        with Timer(log, f"non-finite 검사 ({subset}, {n}행)"):
            res = scan_nonfinite(X, n, dim, args.chunk, log)
        report["nonfinite"][subset] = res
        del X
        if res["n_rows_with_nonfinite"]:
            log.warning(
                "%s: non-finite를 포함한 행 %d개 / 영향 컬럼 %d개 "
                "(NaN %d, +inf %d, -inf %d)",
                subset, res["n_rows_with_nonfinite"], res["n_columns_with_nonfinite"],
                res["total_nan"], res["total_posinf"], res["total_neginf"],
            )
            log.warning(
                "  LightGBM은 NaN을 네이티브로 처리하므로 보통 그대로 두는 것이 "
                "가장 낫습니다(inf→NaN 통합은 순수 데이터 위생, 누수 아님). "
                "sklearn/신경망을 쓸 때만 train median으로 대치하고 결측 지시자 "
                "컬럼을 추가하세요. 상세는 리포트의 top_columns를 확인하세요."
            )
        else:
            log.info("%s: non-finite 없음", subset)

    write_json(layout.reports / "qc_report.json", report)
    log.info("QC 리포트: %s", layout.reports / "qc_report.json")

    layout.mark_done("split_qc", {
        "split_method": "time",
        "week_boundaries": week_boundaries,
        "n_per_split": {n: int(idx.size) for n, idx in splits.items()},
    })
    log.info("다음 단계: python 05_materialize.py --root %s", args.root)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
