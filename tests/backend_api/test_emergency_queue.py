from tests.backend_api.fake_repository import MemoryAnalysisRepository
from trust_triage.backend_api.repository import AnalysisRecord


def test_emergency_queue_logic():
    repo = MemoryAnalysisRepository()

    # 1. 일반 Impact만 있는 경우 (Not Emergency) -> DEEP
    repo.rows["test-impact-only"] = AnalysisRecord(
        analysis_id="test-impact-only",
        sha256="1111",
        file_location="loc1",
        filename="test1",
        size_bytes=100,
        initial_result={
            "prediction": {"calibrated_probability": 0.8},
            "initial_verdict": "HIGH_RISK_UNCERTAIN",
        },
        deep_result={
            "evidence": [
                {
                    "source": "capa",
                    "status": "OBSERVED",
                    "attack_techniques": [
                        {
                            "technique_id": "T0000",
                            "technique_name": "General Impact",
                            "tactics": ["Impact"],
                        }
                    ],
                }
            ]
        },
        created_at="2026-10-04T00:00:00+00:00",
    )

    # 2. 데이터 파괴 (정적 기능 확인 - obs_level 2, level 1)
    repo.rows["test-data-dest-static"] = AnalysisRecord(
        analysis_id="test-data-dest-static",
        sha256="2222",
        file_location="loc1",
        filename="test2",
        size_bytes=100,
        initial_result={
            "prediction": {"calibrated_probability": 0.8},
            "initial_verdict": "HIGH_RISK_UNCERTAIN",
        },
        deep_result={
            "evidence": [
                {
                    "source": "capa",
                    "status": "OBSERVED",
                    "attack_techniques": [
                        {"technique_id": "T1485", "technique_name": "Data Destruction"}
                    ],
                }
            ]
        },
        created_at="2026-10-04T01:00:00+00:00",
    )

    # 3. 랜섬웨어 암호화 (동적 행동 관측 - obs_level 1, level 1)
    repo.rows["test-ransom-dyn"] = AnalysisRecord(
        analysis_id="test-ransom-dyn",
        sha256="3333",
        file_location="loc1",
        filename="test3",
        size_bytes=100,
        initial_result={
            "prediction": {"calibrated_probability": 0.8},
            "initial_verdict": "HIGH_RISK_UNCERTAIN",
        },
        deep_result={
            "evidence": [
                {
                    "source": "speakeasy",
                    "status": "OBSERVED",
                    "attack_techniques": [
                        {
                            "technique_id": "T1486",
                            "technique_name": "Data Encrypted for Impact",
                        }
                    ],
                }
            ]
        },
        created_at="2026-10-04T02:00:00+00:00",
    )

    # 4. 복구 방해 ATTEMPTED - Not OBSERVED, should be ignored -> DEEP
    repo.rows["test-inhibit-attempt"] = AnalysisRecord(
        analysis_id="test-inhibit-attempt",
        sha256="4444",
        file_location="loc1",
        filename="test4",
        size_bytes=100,
        initial_result={
            "prediction": {"calibrated_probability": 0.9},
            "initial_verdict": "HIGH_RISK_UNCERTAIN",
        },
        deep_result={
            "evidence": [
                {
                    "source": "speakeasy",
                    "status": "ATTEMPTED",
                    "attack_techniques": [
                        {
                            "technique_id": "T1490",
                            "technique_name": "Inhibit System Recovery",
                        }
                    ],
                }
            ]
        },
        created_at="2026-10-04T03:00:00+00:00",
    )

    # 5. 정적·동적 증거 함께 있는 경우 (중복 증거) -> 동적이 우선 (obs_level 1)
    repo.rows["test-both"] = AnalysisRecord(
        analysis_id="test-both",
        sha256="5555",
        file_location="loc1",
        filename="test5",
        size_bytes=100,
        initial_result={
            "prediction": {"calibrated_probability": 0.95},
            "initial_verdict": "HIGH_RISK_UNCERTAIN",
        },
        deep_result={
            "evidence": [
                {
                    "source": "capa",
                    "status": "OBSERVED",
                    "attack_techniques": [
                        {"technique_id": "T1485", "technique_name": "Data Destruction"}
                    ],
                },
                {
                    "source": "speakeasy",
                    "status": "OBSERVED",
                    "attack_techniques": [
                        {"technique_id": "T1485", "technique_name": "Data Destruction"}
                    ],
                },
            ]
        },
        created_at="2026-10-04T04:00:00+00:00",
    )

    # 6. 동률 정렬 테스트
    repo.rows["test-tie-1"] = AnalysisRecord(
        analysis_id="test-tie-1",
        sha256="6666",
        file_location="loc1",
        filename="test6",
        size_bytes=100,
        initial_result={
            "prediction": {"calibrated_probability": 0.90},
            "initial_verdict": "HIGH_RISK_UNCERTAIN",
        },
        deep_result={
            "evidence": [
                {
                    "source": "speakeasy",
                    "status": "OBSERVED",
                    "attack_techniques": [{"technique_id": "T1486"}],
                }
            ]
        },
        created_at="2026-10-04T05:00:00+00:00",
    )
    repo.rows["test-tie-2"] = AnalysisRecord(
        analysis_id="test-tie-2",
        sha256="7777",
        file_location="loc1",
        filename="test7",
        size_bytes=100,
        initial_result={
            "prediction": {"calibrated_probability": 0.95},
            "initial_verdict": "HIGH_RISK_UNCERTAIN",
        },
        deep_result={
            "evidence": [
                {
                    "source": "speakeasy",
                    "status": "OBSERVED",
                    "attack_techniques": [{"technique_id": "T1486"}],
                }
            ]
        },
        created_at="2026-10-04T06:00:00+00:00",
    )

    # 7. CANDIDATE 증거 무시, 빈 technique_id 무시 (AttributeError 방지), 단순 encrypt data 무시
    repo.rows["test-candidate-encrypt"] = AnalysisRecord(
        analysis_id="test-candidate-encrypt",
        sha256="8888",
        file_location="loc1",
        filename="test8",
        size_bytes=100,
        initial_result={
            "prediction": {"calibrated_probability": 0.95},
            "initial_verdict": "HIGH_RISK_UNCERTAIN",
        },
        deep_result={
            "evidence": [
                {
                    "source": "capa",
                    "status": "CANDIDATE",
                    "attack_techniques": [
                        {"technique_id": "T1485", "technique_name": "Data Destruction"}
                    ],
                },
                {
                    "source": "speakeasy",
                    "status": "OBSERVED",
                    "attack_techniques": [
                        {"technique_id": None, "technique_name": "encrypt data"}
                    ],  # 단순 암호화는 무시됨
                },
            ]
        },
        created_at="2026-10-04T07:00:00+00:00",
    )

    recs = repo.get_priority_recommendations()

    emergency = [r for r in recs if r["queue_name"] == "EMERGENCY"]
    deep = [r for r in recs if r["queue_name"] == "DEEP"]

    # emergency: test-both, test-tie-2, test-tie-1, test-ransom-dyn, test-data-dest-static
    assert len(emergency) == 5
    # deep: test-impact-only, test-inhibit-attempt, test-candidate-encrypt
    assert len(deep) == 3

    assert emergency[0]["analysis_id"] == "test-both"
    assert emergency[1]["analysis_id"] == "test-tie-2"
    assert emergency[2]["analysis_id"] == "test-tie-1"
    assert emergency[3]["analysis_id"] == "test-ransom-dyn"
    assert emergency[4]["analysis_id"] == "test-data-dest-static"

    # Check priority reasons
    assert emergency[4]["priority_reason"] == "데이터 파괴"
    assert emergency[4]["queue_reason"] == "CAPA: 데이터 파괴 (정적 규칙 일치)"

    assert emergency[3]["priority_reason"] == "랜섬웨어 암호화"
    assert (
        emergency[3]["queue_reason"]
        == "SPEAKEASY: 랜섬웨어 암호화 (동적 관측—결과 미확인)"
    )

    assert emergency[3]["score_policy"] == "emergency-v1"


def test_real_normalized_result_format():
    repo = MemoryAnalysisRepository()

    # 실제 수집 파이프라인에서 만들어지는 정규화 구조 예시 (실제 speakeasy JSON 형태와 유사)
    real_like_deep_result = {
        "analysis_id": "real-test-1",
        "sha256": "aaaa",
        "version": "1.0",
        "evidence": [
            {
                "source": "speakeasy",
                "status": "OBSERVED",
                "malware_family": "wannacry",
                "attack_techniques": [
                    {
                        "technique_id": "T1486",
                        "technique_name": "Data Encrypted for Impact",
                        "tactics": ["Impact"],
                        "description": "Observed encrypting multiple files and appending .wncry",
                    }
                ],
                "signatures_matched": ["ransomware_wannacry"],
            },
            {
                "source": "capa",
                "status": "OBSERVED",
                "attack_techniques": [
                    {
                        "technique_id": "T1485",
                        "technique_name": "Data Destruction",
                        "tactics": ["Impact"],
                    }
                ],
            },
        ],
        "metadata": {"sandbox_version": "2.0", "capa_version": "7.0.1"},
    }

    repo.rows["real-test-1"] = AnalysisRecord(
        analysis_id="real-test-1",
        sha256="aaaa",
        file_location="loc1",
        filename="real-malware.exe",
        size_bytes=512000,
        initial_result={
            "prediction": {"calibrated_probability": 0.99},
            "initial_verdict": "HIGH_RISK",
        },
        deep_result=real_like_deep_result,
        created_at="2026-10-04T08:00:00+00:00",
    )

    recs = repo.get_priority_recommendations()
    emergency = [r for r in recs if r["queue_name"] == "EMERGENCY"]
    assert len(emergency) == 1

    # 랜섬웨어가 동적(1순위)이고, 데이터 파괴가 정적(2순위)이므로, 랜섬웨어가 우선 판정됨
    # Risk level = 1 (T1486), obs_level = 1 (Speakeasy OBSERVED) -> 랜섬웨어 암호화
    assert emergency[0]["priority_reason"] == "랜섬웨어 암호화"
    assert (
        emergency[0]["queue_reason"]
        == "SPEAKEASY: 랜섬웨어 암호화 (동적 관측—결과 미확인)"
    )
