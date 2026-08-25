# EMBER2024 Win32/Win64 데이터 준비 파이프라인

원본 EMBER2024에서 **Win32/Win64 PE만** 골라 내려받고, 특징 벡터로 만들고,
**시간(week_id) 기준 4분할**로 나눠 재현 가능한 학습용 데이터셋을 만드는
6단계 스크립트입니다. 모델 학습은 포함하지 않습니다 — 여기까지가 데이터 준비고,
산출물을 받아서 학습하는 건 별도입니다.

32GB RAM을 가정하므로 **X 행렬(21GB)을 통째로 RAM에 올리는 코드는 없습니다.**
전부 memmap + 청크 처리입니다.

## 코드와 데이터는 분리되어 있습니다

이 폴더에는 **코드만** 있습니다. 데이터는 `--root`로 지정한 곳에 쌓입니다.

```
k\                       ← 지금 이 폴더 (코드)
  01~06_*.py, common.py

<root>\                  ← --root 로 지정 (데이터, 약 50GB + 원본 44GB)
  dataset\               원본 .jsonl + .dat
  out\dev\               X_tr / X_val / X_calib / X_eval
  out\lockbox\           X_test / X_challenge  (봉인)
  out\index\             idx_*, arch_*, meta_*.pkl
  out\reports\           qc_report.json, manifest.json
  out\README.md          ← 데이터셋 설명서 (06이 자동 생성, 손으로 고치지 말 것)
  .state\                단계별 완료 마커
  logs\                  단계별 실행 로그
```

현재 이 머신의 root는 **`C:\EMBER\result`** 입니다. (thrember 원본 저장소는
`C:\EMBER\src\EMBER2024`)

`out\README.md`와 이 파일은 다릅니다. 저건 데이터를 받는 사람용 설명서라
[06_manifest.py](06_manifest.py)의 `README_TEMPLATE`이 매번 새로 씁니다.
이 파일은 파이프라인을 돌리는 사람용입니다.

## 요구 환경

Python 3.11+ (검증: 3.14.5 / Windows 11), `thrember`, `numpy`, `pandas`,
`pefile`. 학습까지 하려면 `lightgbm`. thrember는 EMBER2024 공식 패키지고,
특징 차원(2568)은 하드코딩하지 않고 `PEFeatureExtractor().dim`에서 가져옵니다.

디스크는 원본 44GB + 벡터 26GB + 산출물 50GB = **약 120GB** 필요합니다
(HuggingFace 캐시가 심볼릭 링크 대신 복사로 동작하면 더).

## 전체 실행

```bash
python 01_download.py --root C:\EMBER\result
```
```bash
python 02_vectorize.py --root C:\EMBER\result
```
```bash
python 03_build_index.py --root C:\EMBER\result
```
```bash
python 04_split_qc.py --root C:\EMBER\result
```
```bash
python 05_materialize.py --root C:\EMBER\result --verify
```
```bash
python 06_manifest.py --root C:\EMBER\result --thrember-repo C:\EMBER\src\EMBER2024
```

각 단계는 끝날 때 다음 단계 명령을 로그에 찍습니다. 이미 끝난 단계는
`.state\*.done` 마커를 보고 알아서 스킵하므로, 중간에 죽었으면 그냥 같은
명령을 다시 실행하면 됩니다.

## 단계별

| 단계 | 하는 일 | 소요(이 머신) |
|---|---|---|
| [01_download.py](01_download.py) | Win32/Win64 train·test + challenge 다운로드, challenge의 arch 인덱스 생성 | 33분 |
| [02_vectorize.py](02_vectorize.py) | `.jsonl` → `X_*.dat` / `y_*.dat` (2568차원 float32) + 0행 검사 | 39분 |
| [03_build_index.py](03_build_index.py) | 벡터 행 순서 그대로 메타데이터(sha256/week_id/file_type/family/label) 추출, arch 파생 | 3분 |
| [04_split_qc.py](04_split_qc.py) | 마스킹 + **시간 4분할 인덱스 생성** + non-finite QC + 주차별 드리프트 리포트 | 4분 |
| [05_materialize.py](05_materialize.py) | 인덱스를 적용해 최종 `.npy` 산출 (X는 여기서만 복사됨) | 4분 |
| [06_manifest.py](06_manifest.py) | 전체 sha256, manifest.json, **분할 계약** 기록, lockbox 봉인, README 생성 | 1분 |

[common.py](common.py)는 CLI가 없는 공유 모듈입니다. 경로 레이아웃, memmap
헬퍼, 로깅, **주차 경계 상수와 분할 계약**이 전부 여기 있습니다.

### 주요 인자

모든 단계 공통: `--root <경로>` (기본 `./ember2024_work`), `--force`(완료 마커
무시하고 재실행).

- **01**: `--min-free-gb 60` 여유 공간 하한 / `--skip-preflight` 환경 점검 생략 /
  `--strict-preflight` 경고도 실패 처리 / `--retries 3` / `--skip-challenge`(비권장)
- **02**: `--chunk 20000` 청크 행 수 / `--skip-zero-check` 0행 검사 생략(비권장 —
  벡터화 중단은 파일 크기로는 안 잡힙니다)
- **03**: `--subsets train,test,challenge`
- **04**: `--qc-subsets train,test,challenge` (`none`이면 non-finite 검사 생략,
  4분 → 30초) / `--chunk`
- **05**: `--verify` 표본 행을 원본 `.dat`과 바이트 대조(거의 공짜, 권장) /
  `--verify-n 200` / `--skip-lockbox` test·challenge 재복사 생략
- **06**: `--thrember-repo <경로>` 커밋 해시 기록 / `--no-seal` 봉인 생략 /
  `--hash-dat` 26GB `.dat`까지 해시(인덱스만 공유할 때 필요)

## 분할 계약 — 조각마다 역할은 하나씩

`week_id`로만 나눕니다. EMBER2024는 IID가 아니라 시간축 설계라 무작위/층화
분할은 미래 정보를 과거 학습에 흘립니다. 리샘플링·SMOTE·class_weight도 쓰지
않습니다.

| 조각 | 주차 | 행 수 | 해도 되는 것 | 하면 안 되는 것 |
|---|---|---:|---|---|
| **tr** | 0–33 | 2,720,000 | fit, 전처리 통계 산출 | 성능 보고 |
| **val** | 34–39 | 480,000 | 하이퍼파라미터, early stopping, 모델 선택 | 임계값 산출, 최종 성능 보고, 학습에 포함 |
| **calib** | 40–45 | 480,000 | 확정된 모델의 목표 FPR 임계값, 확률 보정 | 모델 선택, 학습에 포함 |
| **eval** | 46–51 | 480,000 | 6주 이동 후 성능 확인 | 결과 보고 되돌려 바꾸기 |
| **lockbox** | — | test 960,000 / challenge 6,315 | 최종 1회 평가 | 개발 중 열람 |

순서: **tr에서 학습 → val에서 모델 확정 → calib에서 임계값 → eval에서 유지
확인 → lockbox 단 한 번.**

validation은 원래 없었습니다(train이 0–39 통짜). 그 상태면 모델 선택할 곳이
없어 calib나 eval이 그 역할을 겸하게 되고, 임계값이 자기가 고른 모델 위에서
추정되거나(FPR 낙관 편향) eval이 시간 이동 성능의 정직한 추정치가 아니게
됩니다. 그래서 train 뒤쪽 6주를 떼어 val로 만들었습니다. val/calib/eval의 폭이
모두 6주로 같아 구간별 성능 저하를 서로 비교할 수 있습니다.

경계는 [common.py](common.py)의 `WEEK_*` 상수와 `SPLIT_WEEKS` 한 곳에만
있습니다. 계약 전문은 `split_contract()`에 있고 04가 `qc_report.json`에,
06이 `manifest.json`의 `split_contract`에 그대로 기록합니다.

## 무엇을 바꾸면 어디부터 다시 돌리나

| 바꾼 것 | 다시 돌릴 단계 |
|---|---|
| 주차 경계(`WEEK_*`) | `04 --force` → `05 --skip-lockbox` → `06` |
| 라벨 마스크 / `PE_FILE_TYPES` | `04 --force` → `05 --skip-lockbox` → `06` |
| 계약·README 문구만 | `06` |
| thrember/pefile 버전, 특징 추출기 | `02 --force` → `03 --force` → `04 --force` → `05 --force` → `06` |
| 데이터 추가 다운로드 | `01` → 이하 전부 `--force` |

- **04는 X를 복사하지 않습니다.** 그래서 분할 기준을 바꿔도 21GB 재복사가
  아니라 수 MB짜리 인덱스만 다시 만들면 됩니다. 이 구조 덕에 분할 실험이 쌉니다.
- **05는 낡은 산출물을 자동으로 감지합니다.** 기존 `X_*.npy`의 shape가 현재
  인덱스와 다르면 `--force` 없이도 경고 후 재생성하고, 일치하면 스킵합니다.
  경계를 바꾼 뒤 `--force`를 깜빡해 X와 인덱스가 어긋난 채 남는 사고를 막습니다.
- **06을 다시 돌리면 manifest의 모든 해시가 갱신됩니다.** 이전 해시는 무효가
  되니, 데이터를 이미 공유했다면 새 manifest도 같이 넘기세요.

진행 상태는 마커로 확인합니다:

```bash
dir C:\EMBER\result\.state
```

## 이 파이프라인이 일부러 하지 않는 것

- **무작위/층화 분할** — 시간축 설계라 금지. `week_id`로만 나눕니다.
- **family 기반 분할 제약** — 주요 family가 52주 내내 나와서 경계 걸침을
  제거하면 데이터 대부분이 날아갑니다. 정상 파일은 family가 null이라 그룹
  정의도 불가능합니다. 신종 family 일반화는 분할이 아니라 리포팅에서 봅니다
  (`meta_train.pkl` 사용).
- **원본 .jsonl 필터링** — 물리적으로 잘라내면 `gather_feature_paths()`가
  원본과 필터본을 모두 집어 행이 중복됩니다. 대신 마스크와 인덱스만 만듭니다.
- **lockbox 필터링** — test/challenge는 라벨 -1도 지우지 않고 그대로 둡니다.
  `valid_mask_*.npy`를 최종 평가 시점에 적용하세요.
- **NaN 대치** — EMBER의 NaN은 랜덤 결측이 아니라 "값이 정의되지 않음"이라
  그 자체가 신호입니다. LightGBM은 네이티브로 처리합니다.
- **float16** — 최대 표현값이 65504라 파일 크기·섹션 크기 같은 원시 정수
  특징이 대량으로 inf가 됩니다.
- **parquet** — 2568개 dense float 컬럼은 최악의 입력이고, 읽을 때 전체
  materialize가 강제돼 32GB에서 터집니다. `.npy` + `mmap_mode='r'`을 씁니다.
- **`thrember.read_vectorized_features()`** — 내부에서 21GB를 통째로 RAM에
  복사합니다. `common.open_dat()`의 memmap을 쓰세요.
- **`thrember.read_metadata()`** — challenge 자리에 test 레코드를 넣는 버그가
  있고 RAM도 감당이 안 됩니다. 03단계가 직접 뽑습니다.

## 산출물 쓰는 법

```python
import numpy as np, pandas as pd
X_tr  = np.load(r"C:\EMBER\result\out\dev\X_tr.npy",  mmap_mode="r")  # lazy
y_tr  = np.load(r"C:\EMBER\result\out\dev\y_tr.npy")                  # 작음
X_val = np.load(r"C:\EMBER\result\out\dev\X_val.npy", mmap_mode="r")
y_val = np.load(r"C:\EMBER\result\out\dev\y_val.npy")
arch  = np.load(r"C:\EMBER\result\out\dev\arch_tr.npy")   # 0=Win32, 1=Win64, 2=기타
meta  = pd.read_pickle(r"C:\EMBER\result\out\index\meta_train.pkl")
```

지표는 **arch별로 분해**해서 보세요. Win32:Win64가 약 3:1이라 집계 지표는
사실상 Win32 성능만 반영합니다. 클래스가 50:50이라 운영 환경과 다르므로
accuracy/F1이 아니라 **ROC-AUC와 고정 FPR에서의 TPR**을 씁니다.

## 트러블슈팅

- **로그에 `--- Logging error ---`** — 콘솔이 cp949일 때 ▶/■ 기호 때문입니다.
  `common.enable_utf8_console()`이 처리하지만, 직접 만든 스크립트라면 호출하세요.
- **`UnicodeDecodeError`로 .jsonl 읽기 실패** — Windows 기본 인코딩이 cp949라
  그렇습니다. `encoding="utf-8"` 명시.
- **"이미 완료되었습니다"만 찍고 끝남** — `.state` 마커 때문입니다. `--force`.
- **05가 X_tr을 스킵함** — 정상입니다. shape가 인덱스와 일치한다는 뜻입니다.
  강제로 다시 만들려면 `--force`.
- **lockbox 파일 쓰기 실패** — 06이 0o444로 봉인해서 그렇습니다. 05가
  `ensure_writable()`로 자동으로 풉니다. 수동이면 `attrib -r <파일>`.
- **디스크 부족** — 01의 `--min-free-gb`가 미리 잡아줍니다. HF 캐시가 별도
  드라이브에 쌓일 수 있으니 두 드라이브를 모두 보세요.

## 현재 상태 (2026-08-24)

`C:\EMBER\result`는 01~06을 완주한 상태지만 **3분할(train 0–39) 기준**입니다.
코드는 4분할로 갱신되었으므로 `out\dev`는 지금 코드와 어긋나 있습니다.
`X_tr.npy`가 옛 기준(3,200,000행)이고 `idx_val.npy`가 없습니다. 아래를 돌리면
정합해집니다 (약 8분):

```bash
python 04_split_qc.py --root C:\EMBER\result --force
```
```bash
python 05_materialize.py --root C:\EMBER\result --skip-lockbox --verify
```
```bash
python 06_manifest.py --root C:\EMBER\result --thrember-repo C:\EMBER\src\EMBER2024
```
