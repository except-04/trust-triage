# EMBER2024 Win32/Win64 데이터 준비 파이프라인

32GB RAM 노트북에서 EMBER2024의 Win32/Win64 부분을 내려받아 벡터화하고,
**시간 기반(week_id) 3분할**(train/calibration/eval)과 봉인된
lockbox(test/challenge)를 만드는 스크립트 모음입니다.

EMBER2024는 IID가 아니라 시간축 설계입니다. 그래서 이 파이프라인은 다음을
**하지 않습니다**:

* 무작위/층화 분할 — `week_id` 기준 시간 분할만 씁니다 (앞 주차=train, 뒤
  주차=calibration/eval). 미래 정보가 과거 학습으로 새는 것을 막습니다.
* 리샘플링 / SMOTE / class_weight — 데이터가 대략 균형이고, SMOTE는 PE 특징
  공간에서 실재 불가능한 벡터를 만듭니다.
* lockbox(test/challenge)에서 행 삭제 — 어려운 샘플을 지우고 점수를 매기는
  꼴입니다. -1도 지우지 않고 마스크만 별도로 둡니다.

## 사전 준비

```bash
git clone https://github.com/FutureComputing4AI/EMBER2024.git
cd EMBER2024 && pip install .
pip install pandas   # 3단계 메타데이터 추출에 필요 (parquet/pyarrow 불필요)
```

디스크 여유 공간을 먼저 확인하세요. 피크 사용량은 약 **100GB**입니다.

| 항목 | 용량 |
|---|---|
| 원본 .jsonl | 44 GB |
| 벡터화 .dat | 26 GB |
| 최종 .npy 산출물 | 최대 26 GB |

## 실행

**Windows (PowerShell) — 권장:**

```powershell
.\run_all.ps1 D:\ember2024_work C:\src\EMBER2024
```

실행 정책 때문에 막히면 `powershell -ExecutionPolicy Bypass -File .\run_all.ps1 D:\ember2024_work`.

**Linux / macOS / Git Bash:**

```bash
chmod +x run_all.sh
./run_all.sh ~/ember2024_work /path/to/EMBER2024
```

또는 단계별로 (OS 공통):

```bash
python 01_download.py    --root ~/ember2024_work
python 02_vectorize.py   --root ~/ember2024_work
python 03_build_index.py --root ~/ember2024_work
python 04_split_qc.py    --root ~/ember2024_work
python 05_materialize.py --root ~/ember2024_work --verify
python 06_manifest.py    --root ~/ember2024_work --thrember-repo /path/to/EMBER2024
```

각 단계는 `.state/`에 완료 마커를 남깁니다. 중간에 끊겨도 다시 실행하면
끝난 단계는 건너뜁니다. 강제 재실행은 `--force`.

## 단계별 요약

| 단계 | 하는 일 | 대략 소요 |
|---|---|---|
| 01 | Win32/Win64 × train/test + challenge 다운로드 (5회 호출) | 네트워크 의존 |
| 02 | 벡터화 + 무결성 검증(전부 0인 행 탐지) | 수 시간 |
| 03 | 메타데이터(sha256/week_id/file_type/family/label) 추출 → meta_*.pkl, arch 인덱스, 정합성 assert | 수십 분 |
| 04 | -1·비PE 마스크, week_id 시간 3분할, non-finite·클래스 비율·주차별 드리프트 QC | 수 분 |
| 05 | 인덱스 적용해 최종 .npy 생성 (청크 복사) | 1~2시간 |
| 06 | sha256 봉인, manifest, README 생성 | 수 분 |

## 설계상 중요한 선택

**`read_vectorized_features()`를 쓰지 않습니다.** 이 함수는 내부에서
`np.array(X)`를 호출해 21GB를 통째로 RAM에 복사합니다. 대신 파일 크기에서
행 수를 역산해 읽기 전용 memmap을 직접 엽니다.

**3단계에서 메타데이터를 벡터 행 순서 그대로 추출합니다.**
`read_vectorized_features()`는 X, y만 줄 뿐 `week_id`와 `file_type`을 주지
않습니다. 시간 분할과 challenge 필터를 하려면 이 둘이 반드시 필요하므로,
원본 jsonl에서 `sha256/week_id/file_type/family/label`을 **벡터화와 동일한
행 순서로** 뽑아 `index/meta_*.pkl`(pandas pickle)에 저장합니다. 이때
`len(meta)==행 수`와
`meta.label==y`를 assert로 검증하고, 통과하지 못하면 즉시 중단합니다. 이
정합성이 깨진 채 넘어가면 이후 시간 분할이 통째로 무의미해지기 때문입니다.

**4단계는 X를 건드리지 않습니다.** -1·비PE 마스킹, 시간 분할, 클래스 비율
확인을 전부 y·week_id·인덱스 배열만으로 처리합니다. 산출물은 수 MB짜리
인덱스와 JSON 리포트뿐이라, 분할 경계를 바꾸고 싶으면 21GB 복사를 다시 하지
않아도 됩니다.

**분할은 주차 경계를 먼저 정하고 비율은 결과로 받아들입니다.**
weeks 0–39=train, 40–45=calibration, 46–51=eval (대략 77:12:12). 6:2:2를
억지로 맞추려고 주차를 쪼개면 시간 분할의 의미가 사라집니다. calibration과
eval의 폭을 각 6주로 **동일하게** 두는 대칭성이 비율보다 중요합니다 —
eval에서 관측한 성능 저하가 test에서 겪을 저하의 대리 지표가 되려면 폭이
같아야 합니다.

**인덱스가 원본, .npy가 파생물입니다.** `X_train.dat` + `out/index/idx_*.npy`만
있으면 개발용 3분할을 언제든 복원할 수 있습니다. 나중에 용량 문제로 X를
공유하지 않기로 바꾸면 큰 파일만 지우면 됩니다. `05_materialize.py --verify`가
이 복원 가능성을 실제 표본으로 검증합니다.

**분할 인덱스는 오름차순입니다.** `np.where`가 주차 마스크를 오름차순으로
돌려주므로 21GB memmap 청크 복사가 거의 순차 읽기가 됩니다. 무작위 순서면
랜덤 I/O가 되어 훨씬 느립니다.

**family로 분할을 제약하지 않습니다.** 주요 family는 52주 내내 등장하므로
경계 걸침을 제거하면 데이터 대부분이 소실되고 분포가 왜곡됩니다. 정상 파일은
`family`가 null이라 그룹 정의도 불가능합니다. 신종 family 일반화가 궁금하면
분할이 아니라 **리포팅에서** `meta_train.pkl`로 따로 집계하세요.

**dtype은 float32를 유지합니다.** float16은 표현 가능 최대값이 65,504라
`general.size`(원시 파일 크기), `SectionInfo`의 size/vsize,
`AddressOfEntryPoint` 같은 원시 정수 특징이 대량으로 `inf`가 됩니다.
용량 절감보다 손실이 훨씬 큽니다.

**특징 행렬은 .npy, 메타데이터는 pandas pickle(.pkl)입니다.** 2568개 dense
float 컬럼은 읽을 때 전체 materialize가 강제되어 32GB에서 다시 터지므로, X는
`np.load(..., mmap_mode='r')`로 lazy 로딩되는 `.npy`로 둡니다. 메타데이터는
스칼라 5컬럼뿐이라 작지만, parquet(pyarrow/fastparquet)은 네이티브 DLL을
요구해 스마트 앱 제어 등 애플리케이션 제어 정책이 걸린 Windows에서 로딩이
차단될 수 있습니다. 그래서 pandas만 있으면 되는 pickle로 저장합니다 (분할
로직이 X를 전혀 열지 않고 week_id만 읽으면 됩니다).

**NaN/inf는 대치하지 않고 보존합니다.** EMBER 특징의 결측은 랜덤 결측이 아니라
'해당 파일에서 값이 정의되지 않음'(빈 파일 히스토그램, 0으로 나누기 등)을
뜻하므로 결측 자체가 예측 신호입니다. 4단계는 컬럼별 non-finite 개수와 결측
행의 악성 비율을 리포트에만 남기고 값은 건드리지 않습니다. LightGBM은 NaN을
네이티브로 처리합니다. sklearn/신경망을 쓸 때만 **train에서 산출한 median**으로
대치하고 **결측 지시자 컬럼을 추가**하세요 (대치값을 전체 데이터에서 뽑으면
누수). inf→NaN 통합은 학습 파라미터가 아닌 순수 데이터 위생이라 누수가
아닙니다.

**`thrember.read_metadata()`는 쓰지 않습니다.** challenge 부분에 버그가 있어
challenge 자리에 test 레코드를 반환하며, 전체 레코드를 RAM에 올려 32GB로는
돌지 않습니다. 메타데이터와 arch 인덱스는 03단계에서 원본 jsonl을 직접 스캔해
만듭니다.

## Lockbox 취급

`out/lockbox/`의 test/challenge는 **필터링하지 않은 원본**입니다.
라벨 -1을 제거하지 않고 `valid_mask_*.npy`만 따로 넣어두었으니, 최종 평가
시점에 마스크를 적용하세요. 파일은 0o444로 봉인되고 sha256이 manifest에
기록됩니다.

challenge는 전부 악성이고 APK/ELF/PDF가 섞여 있습니다. 전부 `label=1`이라
ROC-AUC·accuracy·F1은 계산 불가하거나 무의미하며, eval에서 목표 FPR로 정한
**고정 임계값에서의 탐지율(recall)만** 유효합니다. `arch_challenge.npy`로
Win32/Win64만 필터링하되(6,315개 중 수백~수천으로 줄 수 있음), 필터 후 표본이
작으니 점추정치만 보고하지 말고 신뢰구간을 함께 보고하세요.

## 평가 지표 (이 파이프라인 범위 밖, 참고)

* **ROC-AUC**와 **고정 FPR에서의 TPR**(예: FPR 0.1%)을 씁니다. accuracy/F1은
  쓰지 않습니다 — 이 데이터의 50:50 비율은 실제 운영 환경의 악성 비율과 전혀
  다르므로 배포 성능을 예측하지 못합니다.
* 임계값은 **calibration(40–45)에서 목표 FPR로 산출 → eval(46–51)에서 시간
  이동 후 유지되는지 확인 → test/challenge에 한 번만 적용**합니다.
* eval에서 FPR이 목표치보다 크게 벌어지면 이는 클래스 비율 문제가 아니라
  **분포 변화 신호**입니다. 대응은 리샘플링이 아니라 임계값 재조정 또는 주기적
  재학습입니다. 4단계 리포트의 주차별 악성 비율 추이로 조짐을 미리 봅니다.

## 산출물 로딩

```python
import numpy as np

X_tr = np.load("out/dev/X_tr.npy", mmap_mode="r")   # lazy, RAM 안 씀
y_tr = np.load("out/dev/y_tr.npy")                  # 작으므로 그대로
arch = np.load("out/dev/arch_tr.npy")               # 0=Win32, 1=Win64

win64 = arch == 1                                   # arch별 지표 분해용
```
