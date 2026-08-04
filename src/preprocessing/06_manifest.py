#!/usr/bin/env python3
"""
6단계 — manifest 생성, lockbox 봉인, README 작성.

manifest에 기록하는 것
----------------------
* 모든 산출물의 shape / dtype / sha256
* 클래스 비율, arch 비율, 시간 분할 주차 경계, 주차별 악성 비율 추이
* pefile / numpy / thrember 버전과 thrember 커밋 해시
  → 나중에 X를 공유하지 않고 인덱스만 공유하기로 바꿀 경우, 받는 쪽이
    직접 벡터화한 결과가 내 것과 같은지 X_train.dat의 sha256으로 대조할 수
    있어야 한다. 버전이 다르면 pefile 파싱 결과가 달라져 특징 값이 바뀔 수
    있으므로 반드시 기록해 둔다.

lockbox 봉인
------------
test/challenge 파일을 0o444(읽기 전용)로 바꾸고 해시를 남긴다.
나중에 "혹시 실수로 열어보거나 수정했나"를 해시로 검증할 수 있다.
"""

from __future__ import annotations

import argparse
import os
import stat
import sys
import time
from pathlib import Path

import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parent))
from common import (  # noqa: E402
    Layout, Timer, add_root_arg, env_versions, fmt_bytes, get_dim,
    read_json, setup_logging, sha256_file, thrember_commit, write_json,
)

README_TEMPLATE = """# EMBER2024 Win32/Win64 데이터셋 (전처리 완료본)

생성 일시: {created}
분할 방식: {split_method}
주차 경계: idx_tr={b_tr} / idx_calib={b_calib} / idx_eval={b_eval}
특징 차원: {dim} (thrember / EMBER feature version 3)

## 디렉터리

```
out/
  dev/       개발용. 자유롭게 사용.
  lockbox/   최종 검증 전용. 열지 말 것.
  index/     분할 인덱스 + arch 인덱스 + valid 마스크 + 메타데이터 (수십 MB)
  reports/   QC 리포트, manifest
```

## 개발용 (out/dev/)

| 파일 | 행 수 | 설명 |
|---|---|---|
| X_tr.npy / y_tr.npy / arch_tr.npy | {n_tr} | 학습 (weeks 0–39) |
| X_calib.npy / y_calib.npy / arch_calib.npy | {n_calib} | 임계값 보정 (weeks 40–45) |
| X_eval.npy / y_eval.npy / arch_eval.npy | {n_eval} | 시간 이동 평가 (weeks 46–51) |

* **시간 기반 분할**입니다. 원본 train(week 0–51)을 `week_id`로 나눴습니다.
  EMBER2024는 IID가 아니라 시간축 설계이므로 무작위/층화 분할을 쓰지 않았고,
  리샘플링·SMOTE·class_weight도 적용하지 않았습니다.
* 라벨 -1(미분류)과 비PE(.NET 등, file_type ∉ {{Win32,Win64}})는 제외했습니다.
* `arch_*.npy`: 0 = Win32, 1 = Win64, 2 = 기타
* 임계값은 **calibration(40–45)에서 목표 FPR로 산출 → eval(46–51)에서 시간
  이동 후 유지되는지 확인 → test/challenge에 한 번만 적용**하세요.
* 지표는 arch별로 분해해서 보세요. Win32:Win64가 약 3:1이라 집계 지표는
  사실상 Win32 성능만 반영합니다. 평가는 accuracy/F1이 아니라 ROC-AUC와
  고정 FPR에서의 TPR을 씁니다(50:50 비율은 운영 환경과 다름).
* 행 순서와 동일한 `index/meta_train.pkl`(sha256/week_id/file_type/
  family/label, pandas pickle)로 신종 family 일반화 등은 분할이 아니라
  리포팅에서 집계하세요: `pd.read_pickle("out/index/meta_train.pkl")`.

## Lockbox (out/lockbox/) — 열지 마세요

| 파일 | 행 수 |
|---|---|
| X_test.npy / y_test.npy / arch_test.npy / valid_mask_test.npy | {n_test} |
| X_challenge.npy / y_challenge.npy / arch_challenge.npy / valid_mask_challenge.npy | {n_challenge} |

* **필터링하지 않은 원본 그대로**입니다. 라벨 -1은 제거하지 않고
  `valid_mask_*.npy`(-1이 아닌 행 = True)만 별도로 넣어두었습니다.
  최종 평가 시점에 마스크를 적용하세요.
* 파일은 읽기 전용(0o444)이며 sha256이 manifest.json에 기록되어 있습니다.
* challenge는 **전부 악성**입니다. 정확도나 AUC는 의미가 없고, eval에서 정한
  임계값에서의 탐지율(recall)로만 봐야 합니다.
* challenge에는 APK/ELF/PDF도 섞여 있습니다. Win32/Win64만 보려면
  `arch_challenge.npy`로 필터링하세요. 필터 후 표본이 작으므로 신뢰구간을
  함께 보고하세요.

## 로딩 방법

32GB RAM에서는 통째로 올리지 말고 memmap으로 여세요.

```python
import numpy as np
X_tr = np.load("out/dev/X_tr.npy", mmap_mode="r")   # lazy
y_tr = np.load("out/dev/y_tr.npy")                  # 작으므로 그대로
```

## 재현

`out/index/idx_*.npy`가 원본이고 `X_*.npy`는 그 파생물입니다.
`X_train.dat`과 인덱스만 있으면 개발용 3분할을 언제든 복원할 수 있습니다.
버전 정보와 `X_train.dat`의 sha256은 manifest.json에 있습니다.
"""


def main() -> int:
    ap = argparse.ArgumentParser(description="manifest 생성 및 lockbox 봉인")
    add_root_arg(ap)
    ap.add_argument("--thrember-repo", default=None,
                    help="thrember git 저장소 경로 (커밋 해시 기록용)")
    ap.add_argument("--no-seal", action="store_true",
                    help="lockbox 파일을 읽기 전용으로 만들지 않음")
    ap.add_argument("--hash-dat", action="store_true",
                    help="dataset/*.dat도 해시 (26GB 읽기, 인덱스 공유 시 필요)")
    args = ap.parse_args()

    layout = Layout(args.root)
    layout.mkdirs()
    log = setup_logging("06_manifest", layout.logs)

    qc_path = layout.reports / "qc_report.json"
    qc = read_json(qc_path) if qc_path.is_file() else {}

    manifest: dict = {
        "created_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        "feature_dim": get_dim(),
        "split_method": qc.get("split_method", "time (week_id)"),
        "week_boundaries": qc.get("week_boundaries"),
        "nonpe_excluded": qc.get("nonpe_excluded"),
        "environment": env_versions(),
        "thrember_commit": thrember_commit(args.thrember_repo),
        "files": {},
        "class_distribution": {
            k: v for k, v in qc.items()
            if k.startswith(("split_", "lockbox_", "train_raw"))
        },
        "weekly_malicious_ratio": qc.get("weekly_malicious_ratio"),
    }

    # --- 산출물 해시 ----------------------------------------------------
    # 인덱스 dir의 메타데이터(.pkl)도 해시 대상에 포함한다. 인덱스만 공유해
    # X를 재생성하는 경우, 받는 쪽이 동일한 메타데이터로 시간 분할을 복원할 수
    # 있어야 하기 때문이다.
    targets: list[Path] = []
    for d in (layout.dev, layout.lockbox, layout.index):
        targets.extend(sorted(d.glob("*.npy")))
    targets.extend(sorted(layout.index.glob("*.pkl")))
    if args.hash_dat:
        targets.extend(sorted(layout.dataset.glob("*.dat")))

    with Timer(log, f"sha256 계산 ({len(targets)}개 파일)"):
        for p in targets:
            size = p.stat().st_size
            log.info("  %-30s %10s ...", p.name, fmt_bytes(size))
            entry = {
                "path": str(p.relative_to(layout.root)),
                "bytes": size,
                "sha256": sha256_file(p),
            }
            if p.suffix == ".npy":
                arr = np.load(p, mmap_mode="r")
                entry["shape"] = list(arr.shape)
                entry["dtype"] = str(arr.dtype)
                del arr
            manifest["files"][p.name] = entry

    # --- lockbox 봉인 ---------------------------------------------------
    if not args.no_seal:
        sealed = []
        for p in sorted(layout.lockbox.glob("*.npy")):
            os.chmod(p, stat.S_IRUSR | stat.S_IRGRP | stat.S_IROTH)  # 0o444
            sealed.append(p.name)
        manifest["lockbox_sealed"] = sealed
        log.info("lockbox %d개 파일을 읽기 전용(0o444)으로 봉인했습니다.", len(sealed))
        log.info("  수정이 필요하면: chmod u+w <파일>")

    write_json(layout.reports / "manifest.json", manifest)
    log.info("manifest: %s", layout.reports / "manifest.json")

    # --- README ---------------------------------------------------------
    def nrows(key: str, default: str = "?") -> str:
        info = manifest["files"].get(key)
        return f"{info['shape'][0]:,}" if info and "shape" in info else default

    wb = manifest.get("week_boundaries") or {}
    readme = README_TEMPLATE.format(
        created=manifest["created_at"],
        split_method=manifest.get("split_method"),
        b_tr=wb.get("idx_tr", "week <= 39"),
        b_calib=wb.get("idx_calib", "40 <= week <= 45"),
        b_eval=wb.get("idx_eval", "week >= 46"),
        dim=manifest["feature_dim"],
        n_tr=nrows("X_tr.npy"),
        n_calib=nrows("X_calib.npy"),
        n_eval=nrows("X_eval.npy"),
        n_test=nrows("X_test.npy"),
        n_challenge=nrows("X_challenge.npy"),
    )
    readme_path = layout.out / "README.md"
    readme_path.write_text(readme, encoding="utf-8")
    log.info("README: %s", readme_path)

    total = sum(e["bytes"] for e in manifest["files"].values())
    log.info("")
    log.info("총 산출물 용량: %s", fmt_bytes(total))
    log.info("공유할 디렉터리: %s", layout.out)
    log.info("  (업로드는 직접 하시면 됩니다 — dev/ 와 lockbox/ 를 함께 올리세요)")

    layout.mark_done("manifest")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
