"""Read-only audit of previously generated Lockbox signals; no fitting/inference.

Usage: python src/jrr/audit_lockbox.py --output docs/validation/RUN_ID
Only the new output directory is written. Requires NumPy, not model runtimes.
"""

import argparse
import csv
import hashlib
import itertools
import json
import platform
import subprocess
from datetime import datetime, timedelta, timezone
from pathlib import Path

import numpy as np
from jrr_router import JointRiskRouter

VERSION = "1.0.0"
ROOT = Path(__file__).resolve().parents[2]
THRESHOLDS = dict(
    tau_low=0.65, tau_high=0.983645, tau_disagree=0.30, tau_ood=0.0, tau_difficulty=6.0
)
MODELS = dict(
    lgbm="baseline_model_lightgbm_tuned_500_4way.pkl",
    xgb="baseline_model_xgb_500_4way_1000cap.pkl",
    calibrator="jrr_calibrator_4way.pkl",
    risk_signals="jrr_risk_signals.pkl",
    top_500_idx="top_feature_indices_500.npy",
)
SIGNALS = ["SYSTEM_ERROR", "OOD", "DISAGREEMENT", "DIFFICULTY", "GRAY_ZONE"]
DEFINITIONS = {
    "scope": "Previously opened Lockbox test/challenge; saved predictions only",
    "two_way": "p >= 0.983645 -> malicious; otherwise benign",
    "three_way": "0.65 < p < 0.983645 -> review; remaining as two_way",
    "jrr": "SYSTEM_ERROR > OOD < 0 > disagreement >= .30 > difficulty >= 6 > gray; otherwise two_way",
    "automatic_error": "FP + FN among automatic decisions",
    "malicious_leakage": "FN count; FN / all labeled malicious; FN / AUTO_BENIGN also reported separately",
    "review_yield": "labeled malicious in review / all labeled review (existing project definition); not errors recovered",
    "rates": "fractions 0..1; absent denominator -> null; labeled metrics exclude labels other than 0/1",
    "ece": "10 equal-width bins, left closed/right open; final bin includes 1 (evaluate_jrr_final convention)",
    "auc": "pairwise rank AUC with ties worth 0.5; single class -> null",
    "kill_test": "AUTO_MALICIOUS among benign OOD / benign OOD; structural routing check, not external safety validation",
    "ci": "Wilson 95% interval, z=1.959963984540054; binomial independence assumption",
}


def sha(path):
    h = hashlib.sha256()
    with path.open("rb") as f:
        for block in iter(lambda: f.read(8 * 1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


def dump(path, obj):
    path.write_text(
        json.dumps(obj, indent=2, ensure_ascii=False, allow_nan=False) + "\n",
        encoding="utf-8",
    )


def ratio(a, b):
    return float(a / b) if b else None


def wilson(k, n):
    if not n:
        return None
    z = 1.959963984540054
    p = k / n
    center = (p + z * z / (2 * n)) / (1 + z * z / n)
    radius = z * np.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / (1 + z * z / n)
    return [float(max(0, center - radius)), float(min(1, center + radius))]


def auc(y, p):
    nb, nm = np.sum(y == 0), np.sum(y == 1)
    if not nb or not nm:
        return None
    order = np.argsort(p, kind="stable")
    scores, labels = p[order], y[order]
    starts = np.r_[0, np.flatnonzero(np.diff(scores)) + 1]
    sizes = np.diff(np.r_[starts, len(scores)])
    pos = np.add.reduceat((labels == 1).astype(np.int64), starts)
    neg = sizes - pos
    return float(np.sum(pos * (np.cumsum(neg) - neg + 0.5 * neg)) / (nb * nm))


def signal_masks(p, d, o, f):
    invalid = (
        ~(np.isfinite(p) & np.isfinite(d) & np.isfinite(o) & np.isfinite(f))
        | (p < 0)
        | (p > 1)
    )
    # Production fail-closed returns before collecting any other signals.
    return [
        invalid,
        ~invalid & (o < 0),
        ~invalid & (d >= 0.30),
        ~invalid & (f >= 6),
        ~invalid & (p > 0.65) & (p < 0.983645),
    ]


def routes(p, masks):
    return np.where(
        np.logical_or.reduce(masks),
        "HIGH_RISK_UNCERTAIN",
        np.where(p >= 0.983645, "AUTO_MALICIOUS", "AUTO_BENIGN"),
    )


def policy_metrics(y, r):
    valid = np.isin(y, [0, 1])
    benign, malicious, review = (
        r == "AUTO_BENIGN",
        r == "AUTO_MALICIOUS",
        r == "HIGH_RISK_UNCERTAIN",
    )
    fn, fp = int(np.sum(benign & (y == 1))), int(np.sum(malicious & (y == 0)))
    auto = int(np.sum(~review))
    nb, nm = int(np.sum(y == 0)), int(np.sum(y == 1))
    nr, nrl = int(review.sum()), int(np.sum(review & valid))
    nrm = int(np.sum(review & (y == 1)))
    tp = int(np.sum(malicious & (y == 1)))
    return dict(
        total=len(y),
        labeled=int(valid.sum()),
        auto_benign=int(benign.sum()),
        auto_malicious=int(malicious.sum()),
        automatic_count=auto,
        automatic_rate=ratio(auto, len(y)),
        automatic_errors=fn + fp,
        automatic_labeled_count=int(np.sum(~review & valid)),
        automatic_error_rate=ratio(fn + fp, int(np.sum(~review & valid))),
        fp=fp,
        fn=fn,
        malicious_leakage_count=fn,
        malicious_leakage_rate=ratio(fn, nm),
        auto_benign_malicious_fraction=ratio(fn, int(np.sum(benign & valid))),
        review_count=nr,
        review_rate=ratio(nr, len(y)),
        review_labeled_count=nrl,
        review_malicious=nrm,
        review_benign=int(np.sum(review & (y == 0))),
        review_yield=ratio(nrm, nrl),
        review_malicious_fraction=ratio(nrm, nrl),
        tpr=ratio(tp, nm),
        observed_fpr=ratio(fp, nb),
        tpr_wilson95=wilson(tp, nm),
        observed_fpr_wilson95=wilson(fp, nb),
    )


def breakdown(y, mask, n_review):
    return dict(
        count=int(mask.sum()),
        fraction_total=ratio(int(mask.sum()), len(y)),
        fraction_review=ratio(int(mask.sum()), n_review),
        malicious=int(np.sum(mask & (y == 1))),
        benign=int(np.sum(mask & (y == 0))),
        unknown=int(np.sum(mask & ~np.isin(y, [0, 1]))),
    )


def contract_tests():
    router = JointRiskRouter()
    count = 0
    for values in itertools.product(
        [
            0.0,
            0.65,
            np.nextafter(0.65, 1),
            np.nextafter(0.983645, 0),
            0.983645,
            1.0,
            np.nan,
            np.inf,
            -1.0,
        ],
        [0.0, 0.30, np.nan],
        [-0.1, 0.0, np.inf],
        [0.0, 6.0, np.nan],
    ):
        p, d, o, f = [np.array([x]) for x in values]
        masks = signal_masks(p, d, o, f)
        actual = router.route_sample(*values)
        assert actual["initial_verdict"] == routes(p, masks)[0]
        expected_signals = [name for name, m in zip(SIGNALS[1:], masks[1:]) if m[0]]
        expected_signals = [
            "UNCERTAIN_PROBABILITY" if s == "GRAY_ZONE" else s for s in expected_signals
        ]
        assert actual["triggered_signals"] == expected_signals
        count += 1
    assert auc(np.array([0, 1]), np.array([0.5, 0.5])) == 0.5
    assert auc(np.array([0, 1]), np.array([0.0, 1.0])) == 1.0
    assert auc(np.array([0, 1]), np.array([1.0, 0.0])) == 0.0
    assert auc(np.array([1]), np.array([0.5])) is None
    assert ratio(0, 0) is None and wilson(0, 0) is None
    m = policy_metrics(
        np.array([0, 1, 1, -1]),
        np.array(
            [
                "AUTO_MALICIOUS",
                "AUTO_BENIGN",
                "HIGH_RISK_UNCERTAIN",
                "HIGH_RISK_UNCERTAIN",
            ]
        ),
    )
    assert (
        m["fp"] == m["fn"] == 1
        and m["review_yield"] == 1
        and m["automatic_errors"] == 2
    )
    return count


def evaluate(split, output):
    data = ROOT / "data"
    metadata = json.loads((data / f"jrr_inference_metadata_{split}.json").read_text())
    checks = []

    def verify(path, expected):
        actual = sha(path)
        checks.append(
            dict(
                path=str(path.relative_to(ROOT)),
                sha256=actual,
                expected=expected,
                match=actual == expected,
            )
        )
        if actual != expected:
            raise ValueError(f"Historical hash mismatch: {path}")

    for key, name in MODELS.items():
        verify(data / name, metadata["hashes"]["models"][key])
    for key in ["X", "mask"]:
        name = f"X_{split}.npy" if key == "X" else f"valid_mask_{split}.npy"
        verify(data / name, metadata["hashes"]["inputs"][key])
    verify(data / f"selected_rows_{split}.npy", metadata["hashes"]["selected_rows"])
    for key, value in metadata["hashes"]["outputs"].items():
        verify(data / f"{key}_{split}.npy", value)
    load = lambda name: np.load(
        data / f"{name}_{split}.npy", mmap_mode="r", allow_pickle=False
    )
    yraw, mask, rows, X = (
        load("y"),
        load("valid_mask"),
        load("selected_rows"),
        load("X"),
    )
    assert mask.dtype == np.bool_ and mask.shape == yraw.shape
    assert np.array_equal(rows, np.flatnonzero(mask)), (
        "selected row alignment differs from mask"
    )
    assert len(yraw) == metadata["n_raw"] == X.shape[0]
    y = yraw[rows]
    p, d, o, f = [
        load(k)
        for k in [
            "jrr_calibrated_proba",
            "model_disagreement",
            "jrr_ood_scores",
            "jrr_difficulty_scores",
        ]
    ]
    assert (
        all(a.shape == (len(y),) for a in [p, d, o, f])
        and len(y) == metadata["n_valid"]
    )
    masks = signal_masks(p, d, o, f)
    # Invalid probabilities have no meaningful all-automatic baseline; stop rather than silently drop them.
    assert np.all(np.isfinite(p) & (p >= 0) & (p <= 1)), (
        "Invalid probabilities; baseline not defined"
    )
    r = routes(p, masks)
    stored = data / f"jrr_routes_{split}.npy"
    match = (
        bool(np.array_equal(np.load(stored, allow_pickle=False), r))
        if stored.exists()
        else None
    )
    if match is False:
        raise ValueError(f"Stored routes mismatch: {split}")
    # Compare every selected row against production, not just vectorized reimplementation.
    router = JointRiskRouter(**THRESHOLDS)
    for i, values in enumerate(zip(p, d, o, f)):
        actual = router.route_sample(*values)
        if actual["initial_verdict"] != r[i]:
            raise ValueError(f"Production mismatch at {split}:{i}")
    policies = {
        "2-way": np.where(p >= 0.983645, "AUTO_MALICIOUS", "AUTO_BENIGN"),
        "3-way": routes(p, [masks[-1]]),
        "JRR": r,
    }
    valid = np.isin(y, [0, 1])
    yy, pp = y[valid], p[valid]
    bins = np.clip(np.digitize(pp, np.linspace(0, 1, 11)) - 1, 0, 9)
    ece = (
        sum(
            float(np.sum(bins == i))
            / len(yy)
            * abs(float(pp[bins == i].mean() - yy[bins == i].mean()))
            for i in range(10)
            if np.any(bins == i)
        )
        if len(yy)
        else None
    )
    nr = int(np.sum(r == "HIGH_RISK_UNCERTAIN"))
    bits = sum(m.astype(np.uint8) * (1 << i) for i, m in enumerate(masks))
    combinations = {
        " + ".join(
            name for i, name in enumerate(SIGNALS) if value & (1 << i)
        ): breakdown(y, bits == value, nr)
        for value in range(1, 32)
        if np.any(bits == value)
    }
    assert sum(v["count"] for v in combinations.values()) == nr
    primary = np.full(len(y), "NONE", dtype="U20")
    for name, m in reversed(list(zip(SIGNALS, masks))):
        primary[m] = name
    kill_mask = (o < 0) & (y == 0)
    result = dict(
        split=split,
        role="Final Lockbox",
        historical_metadata=metadata,
        historical_hash_checks=checks,
        current_label_sha256=sha(data / f"y_{split}.npy"),
        label_historical_hash_available=False,
        n_raw=len(yraw),
        n_selected=len(y),
        excluded_by_mask=int((~mask).sum()),
        labels={str(int(v)): int(np.sum(y == v)) for v in np.unique(y)},
        stored_routes_match=match,
        stored_routes_sha256=sha(stored) if stored.exists() else None,
        production_routes_match=True,
        policies={k: policy_metrics(y, v) for k, v in policies.items()},
        model=dict(
            roc_auc=auc(yy, pp),
            brier=float(np.mean((pp - yy) ** 2)) if len(yy) else None,
            ece=ece,
        ),
        kill_test=dict(
            benign_ood_count=int(kill_mask.sum()),
            fp=int(np.sum(kill_mask & (r == "AUTO_MALICIOUS"))),
            fpr=ratio(
                int(np.sum(kill_mask & (r == "AUTO_MALICIOUS"))), int(kill_mask.sum())
            ),
        ),
        signals={name: breakdown(y, m, nr) for name, m in zip(SIGNALS, masks)},
        combinations=combinations,
        primary_reasons={name: breakdown(y, primary == name, nr) for name in SIGNALS},
    )
    dump(output / f"{split}_metrics.json", result)
    with (output / f"{split}_signal_combinations.csv").open(
        "w", encoding="utf-8-sig", newline=""
    ) as stream:
        writer = csv.DictWriter(
            stream,
            fieldnames=[
                "combination",
                "count",
                "fraction_total",
                "fraction_review",
                "malicious",
                "benign",
                "unknown",
            ],
        )
        writer.writeheader()
        writer.writerows(dict(combination=k, **v) for k, v in combinations.items())
    print(
        f"{split}: {len(y):,} rows; historical hashes match; production routing exact",
        flush=True,
    )
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    frozen_paths = [ROOT / "data" / v for v in MODELS.values()] + [
        Path(__file__),
        ROOT / "src/jrr/jrr_router.py",
        ROOT / "docs/feature-extraction/ember-v3-schema.json",
        ROOT / "docs/feature-extraction/feature-selection-ember-v3-top500.json",
    ]
    frozen = {p.relative_to(ROOT).as_posix(): sha(p) for p in frozen_paths}
    git = lambda *a: subprocess.check_output(["git", *a], cwd=ROOT, text=True).strip()
    freeze = dict(
        audit_started=datetime.now(timezone(timedelta(hours=9))).isoformat(),
        script_version=VERSION,
        git_commit=git("rev-parse", "HEAD"),
        git_status=git("status", "--short"),
        runtime=dict(python=platform.python_version(), numpy=np.__version__),
        thresholds=THRESHOLDS,
        definitions=DEFINITIONS,
        hashes=frozen,
        note="Current audit freeze; does not retroactively prove pre-opening freeze",
        output=str(output),
    )
    dump(
        output / "audit_freeze.json", freeze
    )  # Definitions saved before label/performance inspection.
    ntests = contract_tests()
    selection = json.loads(
        (
            ROOT / "docs/feature-extraction/feature-selection-ember-v3-top500.json"
        ).read_text()
    )
    schema = json.loads(
        (ROOT / "docs/feature-extraction/ember-v3-schema.json").read_text()
    )
    assert selection["source_schema_version"] == schema["schema_version"]
    assert (
        selection["source_artifact_sha256"].lower()
        == frozen["data/top_feature_indices_500.npy"]
    )
    assert np.array_equal(
        selection["source_indices"],
        np.load(ROOT / "data/top_feature_indices_500.npy", allow_pickle=False),
    )
    results = [evaluate(split, output) for split in ["test", "challenge"]]
    after = {p.relative_to(ROOT).as_posix(): sha(p) for p in frozen_paths}
    assert frozen == after, "Frozen files changed during audit"
    dump(
        output / "audit_verification.json",
        dict(
            boundary_cases=ntests,
            frozen_files_unchanged=True,
            feature_contract_match=True,
            completed=datetime.now(timezone(timedelta(hours=9))).isoformat(),
        ),
    )
    lines = [
        "# TRUST-Triage Lockbox 검증 보고서",
        "",
        f"검증 시각: {freeze['audit_started']} / commit `{freeze['git_commit']}`",
        "",
        "기존 test/challenge 추론 산출물을 읽어 수행한 검증이다. 모델·Calibration·Threshold·Risk Signal·Routing Policy는 변경하지 않았다.",
        "최초 개방 후 미조정이라는 사용자 제공 가이드라인의 진술을 전제로 하며, 최초 개방 전 freeze 기록 자체를 소급 증명하지는 않는다.",
        "",
        "## 검증 결과",
        "",
        f"경계값·NaN/Inf 등 {ntests}개 합성 입력의 운영 라우터 비교 통과. 전체 선택 행의 운영 라우터 판정 일치. 현재 Top500 contract 일치. 검증 전후 freeze 파일 해시 동일.",
        "기존 추론 메타데이터의 모델 5종·입력 X/mask·selected_rows·출력 신호 4종 SHA-256을 대조했다.",
        "",
        "## 정책 비교",
        "",
        "비율 분모는 선택된 전체 행이다. FP/FN은 알려진 라벨의 자동 판정 오류이며, Review Yield는 라벨이 알려진 검토 대상 중 악성 비율이다.",
        "",
        "| 세트 | 정책 | 자동 정상 | 자동 악성 | 자동 비율 | FP | FN | 오류 합계 | 검토 대상 | 검토 비율 | Review Yield |",
        "|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|",
    ]
    pct = lambda x: "N/A" if x is None else f"{x * 100:.4f}%"
    for result in results:
        for name, m in result["policies"].items():
            lines.append(
                f"| {result['split']} | {name} | {m['auto_benign']:,} | {m['auto_malicious']:,} | {pct(m['automatic_rate'])} | {m['fp']:,} | {m['fn']:,} | {m['automatic_errors']:,} | {m['review_count']:,} | {pct(m['review_rate'])} | {pct(m['review_yield'])} |"
            )
    for result in results:
        m = result["policies"]["2-way"]
        lines += [
            "",
            f"## {result['split']} 세부 결과",
            "",
            f"원본 {result['n_raw']:,}행 / 선택 {result['n_selected']:,}행 / 라벨 분포 {result['labels']}.",
            f"ROC-AUC: {result['model']['roc_auc']}; Brier: {result['model']['brier']}; ECE(10 bins): {result['model']['ece']}.",
            f"고정 threshold TPR: {pct(m['tpr'])}, Wilson 95% CI: {m['tpr_wilson95']}; 관측 FPR: {pct(m['observed_fpr'])}.",
            f"JRR Malicious Leakage(FN/전체 악성): {pct(result['policies']['JRR']['malicious_leakage_rate'])}.",
            f"OOD 정상 대상 Kill Test: {result['kill_test']} (구조상 OOD 전량 보류 검증).",
            "",
            "| 신호 조합 (상호 배타적) | 건수 | 전체 비율 | 검토 중 비율 | 악성 | 정상 | 미지 라벨 |",
            "|---|---:|---:|---:|---:|---:|---:|",
        ]
        for name, b in result["combinations"].items():
            lines.append(
                f"| {name} | {b['count']:,} | {pct(b['fraction_total'])} | {pct(b['fraction_review'])} | {b['malicious']:,} | {b['benign']:,} | {b['unknown']:,} |"
            )
    lines += [
        "",
        "## 해석 및 한계",
        "",
        "- Review Yield는 Deep Analysis 실제 실행/오판 회수 성공률이 아니다. 같은 모델 출력 위의 판정 정책 비교다.",
        "- Challenge는 단일 클래스일 경우 ROC-AUC/FPR을 산출하지 않는다. TPR 신뢰구간은 독립 이항 표본 가정이며 계열 상관을 반영하지 않는다.",
        "- 목표 FPR과 관측 FPR은 다르며 관측 결과에 맞춰 임계값을 수정하지 않는다.",
        "- 원본 label 파일의 과거 해시, 최초 실행 Git commit/스크립트 버전/사전 지표 정의 및 당시 Feature Schema 해시가 추론 메타데이터에 없다. 현재 해시만으로 과거 독립성을 확정할 수 없다.",
        "- test 저장 route 일치는 검증했으며 challenge는 저장 route가 없으면 현재 고정 정책으로만 재구성한다. 개별 상태는 JSON에 기록했다.",
        "- 현재 작업 트리는 기존 사용자 변경을 포함한다. commit만으로 현재 전체 서비스 상태를 재현할 수 없으며 audit_freeze.json에 상태와 평가 파일 해시를 기록했다.",
        "- Engineering Eval은 별도 기존 src/jrr/jrr_final_report.md를 참고한다. 이번 Lockbox 수치와 합산하지 않았다.",
        "- Raw PE에서 CAPA/FLOSS/Speakeasy/MITRE/LLM의 실제 E2E 및 UI 표시는 이 feature-vector 평가로 검증할 수 없다. 별도 evidence_review.json 및 검증 메모를 참고한다.",
        "- Known-Benign FP는 정상 출처·파일명·해시가 검증된 사례로만 확정한다. 기존 AUTO_MALICIOUS 산출물만으로 정상 FP라고 추정하지 않는다.",
        "- 향후 개선은 새 버전과 새 독립 평가셋으로 분리한다. 이번 결과로 모델/정책/신호를 조정하지 않는다.",
        "",
        "재현: `python src/jrr/audit_lockbox.py --output docs/validation/<새 실행 폴더>` (NumPy 필요). 기존 폴더에는 덮어쓰지 않는다.",
    ]
    (output / "report.md").write_text("\n".join(lines) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
