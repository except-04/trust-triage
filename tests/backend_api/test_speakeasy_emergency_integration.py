"""Exercise real report/Worker/normalizer functions, with detached persistence.

No sample is executed and no AWS or production database is contacted.
The positive routing case deliberately supplies a technique label that the
current raw-report summarizer does not itself produce.
"""

from fastapi.testclient import TestClient

from trust_triage.backend_api.app import create_app
from trust_triage.backend_api.config import BackendConfig
from trust_triage.backend_api.repository import (
    AnalysisRecord,
    PostgresAnalysisRepository,
)
from trust_triage.backend_api.schemas import PriorityRecommendationResponse
from trust_triage.backend_api.service import BackendService
from trust_triage.backend_api.storage import LocalSampleStorage
from trust_triage.deep_analysis.normalizer import normalize_speakeasy_result
from trust_triage.deep_analysis.service_models import DeepAnalysisRequest
from trust_triage.deep_analysis.worker_results import (
    analysis_from_worker,
    validate_worker_record,
)
from trust_triage.dynamic_analysis.models import (
    DynamicAnalysisResult,
    DynamicAnalysisStatus,
)
from trust_triage.dynamic_analysis.speakeasy_analyzer import _summarize_report
from trust_triage.speakeasy_worker.models import (
    JobRecord,
    JobStatus,
    result_from_analysis,
)

from .fake_repository import MemoryAnalysisRepository


def _worker_evidence(
    report, *, extra_behaviors=(), status=DynamicAnalysisStatus.SUCCESS
):
    request = DeepAnalysisRequest(
        analysis_id="speakeasy-integration-001",
        sha256="a" * 64,
        file_location="s3://integration-fixture/raw/sample.bin",
        initial_route="DEEP_ANALYSIS",
        requested_at="2026-10-07T00:00:00Z",
    )
    summary = _summarize_report(report)
    analysis = DynamicAnalysisResult(
        evidence_id="speakeasy-integration-evidence",
        sha256=request.sha256,
        source="SPEAKEASY",
        category="BEHAVIOR",
        status=status,
        summary="Inert report fixture; no executable sample",
        observed_apis=summary.observed_apis,
        api_call_counts=summary.api_call_counts,
        behaviors=summary.behaviors + tuple(extra_behaviors),
        events=summary.events,
        errors=() if status is DynamicAnalysisStatus.SUCCESS else ("fixture timeout",),
    )
    envelope = result_from_analysis(request.worker_job, analysis)
    record = JobRecord(
        request.worker_job,
        JobStatus.COMPLETED
        if status is DynamicAnalysisStatus.SUCCESS
        else JobStatus.FAILED,
        result=envelope,
    )
    validated = validate_worker_record(request, record)
    converted = analysis_from_worker(request, validated)
    evidence = [item.to_dict() for item in normalize_speakeasy_result(converted)]
    return request, summary, evidence


def _saved_recommendations(tmp_path, request, evidence):
    repository = MemoryAnalysisRepository()
    initial = {
        "prediction": {"calibrated_probability": 0.8},
        "initial_verdict": "HIGH_RISK_UNCERTAIN",
        "triggered_signals": ["UNCERTAIN_PROBABILITY"],
        "risk_signals": {},
    }
    repository.rows[request.analysis_id] = AnalysisRecord(
        analysis_id=request.analysis_id,
        sha256=request.sha256,
        file_location=request.file_location,
        filename="inert-report.exe",
        size_bytes=100,
        phase="WAITING_DEEP",
        initial_result=initial,
        created_at="2026-10-07T00:00:00+00:00",
    )
    repository.set_daily_budget(10, em=5, deep=5)
    before = repository.get_priority_recommendations()[0]
    assert before["queue_name"] == "DEEP"
    claim = repository.claim(request.analysis_id, 600)
    snapshot = {
        "analysis_id": request.analysis_id,
        "sha256": request.sha256,
        "evidence": evidence,
    }
    assert repository.save_deep(
        request.analysis_id,
        claim.token,
        snapshot,
        finished=True,
        current_stage="SPEAKEASY",
    )
    assert repository.get(request.analysis_id).deep_result == snapshot
    # Use the production classifier as well as the in-memory recommendation path.
    production = PostgresAnalysisRepository.__new__(PostgresAnalysisRepository)
    decision = production._determine_queue(
        0.8,
        initial["initial_verdict"],
        initial["triggered_signals"],
        {},
        snapshot,
    )
    config = BackendConfig(storage_root=tmp_path / "samples")
    service = BackendService(
        repository, LocalSampleStorage(config.storage_root), config
    )
    # Expose response-contract failures before middleware replaces them with 500.
    PriorityRecommendationResponse.model_validate(
        service.get_priority_recommendations()
    )
    with TestClient(create_app(service)) as client:
        response = client.get("/analyst/recommendations")
        assert response.status_code == 200, response.text
        body = response.json()
    items = body["emergency_recommendations"] + body["deep_recommendations"]
    assert len(items) == 1
    assert items[0]["queue_name"] == decision["queue_name"]
    return body, items[0]


def test_raw_file_crypto_report_currently_has_no_emergency_mapping(tmp_path):
    report = {
        "entry_points": [
            {
                "apis": [
                    {"api_name": "advapi32.CryptEncrypt", "ret_val": "0x1"},
                    {"api_name": "kernel32.DeleteFileW", "ret_val": "0x1"},
                ],
                "file_access": [{"path": "C:/fixture/document.bin", "event": "write"}],
            }
        ]
    }
    request, summary, evidence = _worker_evidence(report)
    assert summary.behaviors == ("file_access",)
    assert all(not item["attack_techniques"] for item in evidence)
    body, item = _saved_recommendations(tmp_path, request, evidence)
    assert body["emergency_recommendations"] == []
    assert item["queue_name"] == "DEEP"


def test_explicit_technique_label_reaches_emergency_api_and_reclassifies(tmp_path):
    # Contract test only: this label is injected, not inferred from a raw report.
    request, _, evidence = _worker_evidence(
        {"entry_points": []},
        extra_behaviors=("T1486: Data Encrypted for Impact",),
    )
    assert evidence[0]["attack_techniques"][0]["technique_id"] == "T1486"
    body, item = _saved_recommendations(tmp_path, request, evidence)
    assert len(body["emergency_recommendations"]) == 1
    assert item["score_policy"] == "emergency-v1"
    assert item["priority_reason"] == "랜섬웨어 암호화"
    assert "결과 미확인" in item["queue_reason"]


def test_failed_worker_does_not_create_emergency_evidence(tmp_path):
    request, _, evidence = _worker_evidence(
        {"entry_points": []},
        extra_behaviors=("T1486: Data Encrypted for Impact",),
        status=DynamicAnalysisStatus.TIMEOUT,
    )
    assert evidence == []
    body, item = _saved_recommendations(tmp_path, request, evidence)
    assert body["emergency_recommendations"] == []
    assert item["queue_name"] == "DEEP"


def test_other_dynamic_technique_stays_in_deep_queue(tmp_path):
    request, _, evidence = _worker_evidence(
        {
            "entry_points": [
                {
                    "apis": [
                        {"api_name": "kernel32.CreateRemoteThread", "ret_val": "0x1234"}
                    ],
                }
            ]
        }
    )
    assert evidence[0]["attack_techniques"][0]["technique_id"] == "T1055"
    body, item = _saved_recommendations(tmp_path, request, evidence)
    assert body["emergency_recommendations"] == []
    assert item["queue_name"] == "DEEP"


def test_dynamic_ransomware_evidence_routes_to_emergency(tmp_path):
    report = {
        "entry_points": [
            {
                "apis": [
                    {"api_name": "advapi32.CryptEncrypt", "ret_val": "0x1"},
                ],
                "file_access": [
                    {
                        "path": "C:/Users/Public/Desktop/HOW_TO_DECRYPT.txt",
                        "event": "write",
                    }
                ],
            }
        ]
    }
    request, summary, evidence = _worker_evidence(report)
    assert any(
        tech["technique_id"] == "T1486"
        for item in evidence
        for tech in item.get("attack_techniques", [])
    )

    body, item = _saved_recommendations(tmp_path, request, evidence)
    assert len(body["emergency_recommendations"]) == 1
    assert item["score_policy"] == "emergency-v1"
    assert item["priority_reason"] == "랜섬웨어 암호화"
    assert item["queue_name"] == "EMERGENCY"


def test_dynamic_data_destruction_routes_to_emergency(tmp_path):
    report = {
        "entry_points": [
            {
                "file_access": [{"path": "\\\\.\\PhysicalDrive0", "event": "write"}],
            }
        ]
    }
    request, summary, evidence = _worker_evidence(report)
    assert any(
        tech["technique_id"] == "T1485"
        for item in evidence
        for tech in item.get("attack_techniques", [])
    )

    body, item = _saved_recommendations(tmp_path, request, evidence)
    assert len(body["emergency_recommendations"]) == 1
    assert item["score_policy"] == "emergency-v1"
    assert item["priority_reason"] == "데이터 파괴"
    assert item["queue_name"] == "EMERGENCY"


def test_dynamic_ransomware_read_only_ignored(tmp_path):
    report = {
        "entry_points": [
            {
                "apis": [{"api_name": "kernel32.ReadFile", "ret_val": "0x1"}],
                "file_access": [
                    {
                        "path": "C:/Users/Public/Desktop/HOW_TO_DECRYPT.txt",
                        "event": "read",
                    }
                ],
            }
        ]
    }
    request, summary, evidence = _worker_evidence(report)
    assert not any(
        tech["technique_id"] == "T1486"
        for item in evidence
        for tech in item.get("attack_techniques", [])
    )
    body, item = _saved_recommendations(tmp_path, request, evidence)
    assert item["queue_name"] == "DEEP"


def test_dynamic_data_destruction_read_only_ignored(tmp_path):
    report = {
        "entry_points": [
            {
                "apis": [{"api_name": "kernel32.CreateFileA", "ret_val": "0x1"}],
                "file_access": [{"path": "\\\\.\\PhysicalDrive0", "event": "read"}],
            }
        ]
    }
    request, summary, evidence = _worker_evidence(report)
    assert not any(
        tech["technique_id"] == "T1485"
        for item in evidence
        for tech in item.get("attack_techniques", [])
    )
    body, item = _saved_recommendations(tmp_path, request, evidence)
    assert item["queue_name"] == "DEEP"


def test_dynamic_innocent_readme_ignored(tmp_path):
    report = {
        "entry_points": [
            {
                "apis": [{"api_name": "kernel32.WriteFile", "ret_val": "0x1"}],
                "file_access": [
                    {"path": "C:/Program Files/App/README.txt", "event": "write"}
                ],
            }
        ]
    }
    request, summary, evidence = _worker_evidence(report)
    assert not any(
        tech["technique_id"] == "T1486"
        for item in evidence
        for tech in item.get("attack_techniques", [])
    )
    body, item = _saved_recommendations(tmp_path, request, evidence)
    assert item["queue_name"] == "DEEP"


def test_dynamic_ransomware_extension_only_ignored(tmp_path):
    report = {
        "entry_points": [
            {
                "apis": [{"api_name": "kernel32.WriteFile", "ret_val": "0x1"}],
                "file_access": [
                    {
                        "path": "C:/Users/User/Desktop/document.wannacry",
                        "event": "write",
                    }
                ],
            }
        ]
    }
    request, summary, evidence = _worker_evidence(report)
    assert not any(
        tech["technique_id"] == "T1486"
        for item in evidence
        for tech in item.get("attack_techniques", [])
    )
    body, item = _saved_recommendations(tmp_path, request, evidence)
    assert item["queue_name"] == "DEEP"


def test_dynamic_ransomware_failed_crypto_ignored(tmp_path):
    report = {
        "entry_points": [
            {
                "apis": [{"api_name": "advapi32.CryptEncrypt", "ret_val": "0x0"}],
                "file_access": [
                    {
                        "path": "C:/Users/User/Desktop/document.wannacry",
                        "event": "write",
                    }
                ],
            }
        ]
    }
    request, summary, evidence = _worker_evidence(report)
    assert not any(
        tech["technique_id"] == "T1486"
        for item in evidence
        for tech in item.get("attack_techniques", [])
    )
    body, item = _saved_recommendations(tmp_path, request, evidence)
    assert item["queue_name"] == "DEEP"


def test_dynamic_ransomware_bcrypt_success_emergency(tmp_path):
    report = {
        "entry_points": [
            {
                # BCryptEncrypt success is 0x0
                "apis": [
                    {"api_name": "bcrypt.BCryptEncrypt", "ret_val": "0x0", "pid": 1234}
                ],
                "file_access": [
                    {
                        "path": "C:/Users/User/Desktop/document.wannacry",
                        "event": "write",
                        "pid": 1234,
                    }
                ],
            }
        ]
    }
    request, summary, evidence = _worker_evidence(report)
    assert any(
        tech["technique_id"] == "T1486"
        for item in evidence
        for tech in item.get("attack_techniques", [])
    )
    body, item = _saved_recommendations(tmp_path, request, evidence)
    assert item["queue_name"] == "EMERGENCY"


def test_dynamic_ransomware_bcrypt_failure_ignored(tmp_path):
    report = {
        "entry_points": [
            {
                # BCryptEncrypt failure is non-zero (e.g. 0xC0000001)
                "apis": [
                    {
                        "api_name": "bcrypt.BCryptEncrypt",
                        "ret_val": "0xC0000001",
                        "pid": 1234,
                    }
                ],
                "file_access": [
                    {
                        "path": "C:/Users/User/Desktop/document.wannacry",
                        "event": "write",
                        "pid": 1234,
                    }
                ],
            }
        ]
    }
    request, summary, evidence = _worker_evidence(report)
    assert not any(
        tech["technique_id"] == "T1486"
        for item in evidence
        for tech in item.get("attack_techniques", [])
    )
    body, item = _saved_recommendations(tmp_path, request, evidence)
    assert item["queue_name"] == "DEEP"


def test_dynamic_ransomware_unconfirmed_crypto_ignored(tmp_path):
    report = {
        "entry_points": [
            {
                # Unconfirmed crypto call (no ret_val)
                "apis": [{"api_name": "advapi32.CryptEncrypt"}],
                "file_access": [
                    {
                        "path": "C:/Users/User/Desktop/document.wannacry",
                        "event": "write",
                    }
                ],
            }
        ]
    }
    request, summary, evidence = _worker_evidence(report)
    assert not any(
        tech["technique_id"] == "T1486"
        for item in evidence
        for tech in item.get("attack_techniques", [])
    )
    body, item = _saved_recommendations(tmp_path, request, evidence)
    assert item["queue_name"] == "DEEP"


def test_dynamic_ransomware_unrelated_pid_ignored(tmp_path):
    report = {
        "entry_points": [
            {
                # Successful crypto call but in PID 1000
                "apis": [
                    {"api_name": "advapi32.CryptEncrypt", "ret_val": "0x1", "pid": 1000}
                ],
                # Ransomware file write in PID 2000
                "file_access": [
                    {
                        "path": "C:/Users/User/Desktop/document.wannacry",
                        "event": "write",
                        "pid": 2000,
                    }
                ],
            }
        ]
    }
    request, summary, evidence = _worker_evidence(report)
    assert not any(
        tech["technique_id"] == "T1486"
        for item in evidence
        for tech in item.get("attack_techniques", [])
    )
    body, item = _saved_recommendations(tmp_path, request, evidence)
    assert item["queue_name"] == "DEEP"


def test_dynamic_ransomware_missing_pid_different_entry_point_ignored(tmp_path):
    report = {
        "entry_points": [
            {
                # Successful crypto call in entry point 0, no PID
                "apis": [{"api_name": "advapi32.CryptEncrypt", "ret_val": "0x1"}],
            },
            {
                # Ransomware file write in entry point 1, no PID
                "file_access": [
                    {
                        "path": "C:/Users/User/Desktop/document.wannacry",
                        "event": "write",
                    }
                ],
            },
        ]
    }
    request, summary, evidence = _worker_evidence(report)
    assert not any(
        tech["technique_id"] == "T1486"
        for item in evidence
        for tech in item.get("attack_techniques", [])
    )
    body, item = _saved_recommendations(tmp_path, request, evidence)
    assert item["queue_name"] == "DEEP"
