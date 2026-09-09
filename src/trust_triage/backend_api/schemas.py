"""외부 API의 공통 언어. 이 모델에서 입력 검증과 OpenAPI 명세가 함께 나온다."""

from __future__ import annotations

from enum import Enum
from typing import Annotated, Any, Literal

from pydantic import AwareDatetime, BaseModel, ConfigDict, Field, model_validator

AnalysisId = Annotated[str, Field(pattern=r"^[A-Za-z0-9_-]{1,128}$")]
Sha256 = Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]
Probability = Annotated[float, Field(ge=0, le=1, allow_inf_nan=False)]


class APIModel(BaseModel):
    model_config = ConfigDict(extra="forbid", allow_inf_nan=False)


class AnalysisStatus(str, Enum):
    """QUEUED: 대기, RUNNING: 진행, COMPLETED: 완료, FAILED: 실패, NOT_REQUIRED: 해당 단계 생략."""

    QUEUED = "QUEUED"
    RUNNING = "RUNNING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    NOT_REQUIRED = "NOT_REQUIRED"


class CurrentStage(str, Enum):
    """UPLOAD: 접수, INITIAL_ANALYSIS: 초기 분석, JRR: 경로 선택, CAPA_FLOSS/SPEAKEASY: 추가 분석, LLM: 증거 설명, FINAL_ASSESSMENT: 최종 처리."""

    UPLOAD = "UPLOAD"
    INITIAL_ANALYSIS = "INITIAL_ANALYSIS"
    JRR = "JRR"
    CAPA_FLOSS = "CAPA_FLOSS"
    SPEAKEASY = "SPEAKEASY"
    LLM = "LLM"
    FINAL_ASSESSMENT = "FINAL_ASSESSMENT"


class InitialVerdict(str, Enum):
    """JRR 초기 판정. AUTO_BENIGN: 정상 경로, AUTO_MALICIOUS: 악성 경보 경로, HIGH_RISK_UNCERTAIN: 심층 분석 필요."""

    AUTO_BENIGN = "AUTO_BENIGN"
    AUTO_MALICIOUS = "AUTO_MALICIOUS"
    HIGH_RISK_UNCERTAIN = "HIGH_RISK_UNCERTAIN"


class FinalVerdict(str, Enum):
    """시스템 최종 판정. BENIGN: 정상, MALICIOUS: 악성, UNCERTAIN: 확정하기 어려워 검토 필요."""

    BENIGN = "BENIGN"
    MALICIOUS = "MALICIOUS"
    UNCERTAIN = "UNCERTAIN"


class ErrorDetail(APIModel):
    code: str = Field(
        description="오류 유형을 식별하는 안정적인 코드입니다. 로그 상관관계 분석과 장애 지원에 사용합니다."
    )
    message: str = Field(description="무엇이 잘못됐는지 설명하는 메시지입니다.")
    stage: str | None = Field(
        default=None,
        description="오류가 발생한 단계입니다. 특정 단계와 관련 없으면 null입니다.",
    )
    retryable: bool = Field(
        default=False,
        description="서버가 일시적 오류로 분류했는지 나타냅니다. true여도 즉시 성공을 보장하지 않습니다.",
    )


class ErrorResponse(APIModel):
    error: ErrorDetail


class AnalysisIdentity(APIModel):
    analysis_id: AnalysisId = Field(
        description="접수한 파일 분석 1건의 번호입니다. 상태·결과·검토 조회에 사용합니다."
    )
    batch_id: AnalysisId | None = Field(
        default=None,
        description="일괄 접수한 묶음의 번호입니다. 파일을 단독 접수했다면 null입니다.",
    )
    sha256: Sha256 = Field(
        description="파일 내용으로 계산한 64자리 해시입니다. analysis_id와 달리 같은 내용의 파일이면 같습니다."
    )
    created_at: AwareDatetime = Field(
        description="접수 시각입니다. Z는 UTC를 뜻하며 한국 시각은 UTC보다 9시간 빠릅니다."
    )


class AnalysisAccepted(AnalysisIdentity):
    """분석 식별자와 접수 시점의 작업 상태를 제공하는 파일 접수 응답입니다."""

    status: AnalysisStatus = Field(
        description="접수 시점의 진행 상태입니다. 접수 직후에는 보통 QUEUED입니다."
    )
    duplicate_of: AnalysisId | None = Field(
        default=None,
        description="같은 SHA-256의 이전 분석 번호. 이번 요청은 독립된 작업입니다.",
    )


class AnalysisProgress(AnalysisIdentity):
    """HTTP 요청 결과와 독립적으로 관리되는 전체 분석 수명주기 상태입니다."""

    status: AnalysisStatus = Field(
        description="전체 분석의 대기·진행·완료·실패 상태입니다. 분석 완료 여부는 이 값으로 판단합니다."
    )
    current_stage: CurrentStage = Field(
        description="현재 수행 중이거나 마지막으로 기록한 분석 단계입니다."
    )
    updated_at: AwareDatetime = Field(
        description="분석 상태가 마지막으로 갱신된 시각입니다."
    )
    completed_at: AwareDatetime | None = Field(
        default=None,
        description="완료 또는 실패로 종료된 시각입니다. 진행 중이면 null입니다.",
    )
    error: ErrorDetail | None = Field(
        default=None,
        description="분석 실패 정보입니다. code는 오류 유형을, message는 세부 원인을 나타냅니다.",
    )


class Prediction(APIModel):
    """악성 확률은 0~1 범위입니다. 예를 들어 0.72는 72%입니다."""

    lgbm_raw_probability: Probability = Field(
        description="LightGBM 모델이 산출한 보정 전 악성 확률입니다."
    )
    xgb_raw_probability: Probability = Field(
        description="비교용 XGBoost 모델이 계산한 악성 확률입니다."
    )
    calibrated_probability: Probability = Field(
        description="LightGBM의 확률을 Calibration으로 보정한 값입니다."
    )


class RiskSignals(APIModel):
    """추가 분석 필요성을 판단하는 신호입니다. 각 점수가 모두 악성 확률인 것은 아닙니다."""

    disagreement: Probability = Field(
        description="두 모델의 악성 확률 차이입니다. 클수록 두 모델의 의견 차이가 큽니다."
    )
    ood_score: float = Field(
        allow_inf_nan=False,
        description="Isolation Forest decision_function 원값. 음수도 정상적인 값입니다.",
    )
    difficulty_score: float = Field(
        ge=0,
        allow_inf_nan=False,
        description="정적 Feature에서 계산한 분석 난이도 신호입니다. 악성 확률이 아닙니다.",
    )


class TopFeature(APIModel):
    """한 Feature가 LightGBM 원출력에 미친 SHAP 영향입니다."""

    feature_name: str = Field(description="모델 입력 Schema에 정의된 특성 이름입니다.")
    feature_value: float | None = Field(
        default=None,
        allow_inf_nan=False,
        description="원본 결측값은 null로 표시합니다.",
    )
    shap_value: float = Field(
        allow_inf_nan=False,
        description="이 특성이 모델 원출력에 미친 영향입니다. 확률이나 백분율이 아닙니다.",
    )
    direction: Literal["MALICIOUS", "BENIGN", "NEUTRAL"] = Field(
        description="영향 방향입니다. MALICIOUS는 악성 쪽, BENIGN은 정상 쪽, NEUTRAL은 중립입니다."
    )


class InitialResult(APIModel):
    prediction: Prediction
    risk_signals: RiskSignals
    initial_verdict: InitialVerdict
    route: Literal["FINAL", "DEEP_ANALYSIS"]
    reason: str
    top_features: list[TopFeature] = Field(default_factory=list, max_length=50)
    feature_metadata: dict[str, Any] = Field(default_factory=dict)
    xai_status: Literal["SUCCESS", "FAILED", "NOT_REQUIRED"] = "NOT_REQUIRED"
    xai_error: dict[str, Any] | None = None


class TriageResponse(AnalysisIdentity):
    """초기 모델·위험 신호·JRR 결과입니다. 초기 분석 전의 결과는 null입니다."""

    status: AnalysisStatus = Field(
        description="초기 분석 단계의 상태입니다. 전체 분석 상태는 /status에서 확인합니다."
    )
    prediction: Prediction | None = Field(
        default=None, description="모델별 악성 확률과 보정 확률입니다."
    )
    risk_signals: RiskSignals | None = Field(
        default=None, description="모델 불일치, OOD, 분석 난이도입니다."
    )
    initial_verdict: InitialVerdict | None = Field(
        default=None,
        description="JRR의 초기 판정입니다. 전문가 최종 의견과 별도로 보존합니다.",
    )
    route: Literal["FINAL", "DEEP_ANALYSIS"] | None = Field(
        default=None,
        description="다음 경로입니다. FINAL은 최종 처리, DEEP_ANALYSIS는 심층 분석입니다.",
    )
    reason: str | None = Field(
        default=None, description="JRR이 이 경로를 선택한 이유입니다."
    )
    feature_metadata: dict[str, Any] | None = None


class XAIResponse(AnalysisIdentity):
    """LightGBM 원출력에 대한 SHAP 기반 특성 기여도입니다."""

    status: AnalysisStatus = Field(
        description="SHAP 설명 단계의 상태입니다. 실패했으면 error를 함께 확인합니다."
    )
    explained_output: Literal["LIGHTGBM_RAW_OUTPUT"] = Field(
        default="LIGHTGBM_RAW_OUTPUT",
        description="SHAP이 설명하는 대상입니다. 보정 확률이 아닌 LightGBM 원출력을 설명합니다.",
    )
    top_features: list[TopFeature] = Field(
        default_factory=list,
        description="영향이 큰 특성 목록입니다. 기본 최대 5개이며 서버 설정에 따라 달라집니다.",
    )
    error: ErrorDetail | None = None


class TechniqueEvidence(APIModel):
    technique_id: str
    technique_name: str
    sources: list[str]
    summary: str
    evidence_ids: list[str] = Field(default_factory=list)


class LLMSummary(APIModel):
    summary: str
    suspicious_behaviors: list[str] = Field(default_factory=list)
    analyst_notes: str = ""


class DeepAnalysisResponse(AnalysisIdentity):
    """선택적으로 수행한 도구 분석 결과입니다. 필요한 단계의 결과만 채워집니다."""

    status: AnalysisStatus = Field(
        description="심층 분석의 종합 상태입니다. 전체 파일 분석 상태와 구분합니다."
    )
    deep_analysis_status: dict[str, AnalysisStatus] = Field(
        description="capa, floss, speakeasy, cape의 개별 상태입니다. 현재 cape는 NOT_REQUIRED입니다."
    )
    tool_details: dict[str, Any] = Field(
        default_factory=dict,
        description="원래 도구 상태와 버전. TIMEOUT 등을 완료 상태와 구분합니다.",
    )
    capa: dict[str, Any] | None = None
    floss: dict[str, Any] | None = None
    speakeasy: dict[str, Any] | None = None
    evidence: list[TechniqueEvidence] = Field(
        default_factory=list,
        description="ATT&CK 기법별로 묶은 분석 증거입니다. SHAP 특성과는 별개입니다.",
    )
    evidence_details: list[dict[str, Any]] = Field(
        default_factory=list,
        description="증거별 식별자, 출처, 신뢰도 등을 담은 상세 목록입니다.",
    )
    llm_summary: LLMSummary | None = Field(
        default=None,
        description="증거에 대한 LLM 참고 설명입니다. 아직 없거나 생성되지 않았다면 null입니다.",
    )
    llm_status: str | None = None
    error: ErrorDetail | None = None


class FinalAssessment(APIModel):
    """시스템이 제안한 최종 판정과 처리 방식입니다."""

    final_verdict: FinalVerdict = Field(
        description="시스템이 제안한 정상·악성·불확실 판정입니다."
    )
    disposition: Literal[
        "AUTO_ALLOW_RECOMMENDED",
        "ALERT_RECOMMENDED",
        "MANUAL_REVIEW",
        "ANALYSIS_FAILED",
    ] = Field(
        description="AUTO_ALLOW_RECOMMENDED: 정상 처리 제안, ALERT_RECOMMENDED: 악성 경보 제안, MANUAL_REVIEW: 전문가 검토, ANALYSIS_FAILED: 분석 실패."
    )
    requires_human_review: bool = Field(
        description="true이면 전문가의 검토가 필요합니다."
    )
    reason: str = Field(description="이 판정과 처리 방식을 제안한 이유입니다.")
    policy_version: str = "backend-review-first-v1"


class ReviewRequest(APIModel):
    """전문가 판정 또는 보류 의견을 등록하는 요청입니다."""

    analyst_final_verdict: Literal["BENIGN", "MALICIOUS"] | None = Field(
        description="null은 검토 보류이며 시스템 판정을 변경하지 않습니다."
    )
    analyst_notes: str = Field(
        default="",
        max_length=4000,
        description="판정 또는 보류의 근거입니다. 허용 길이는 최대 4,000자입니다.",
    )
    reviewer_id: str = Field(
        min_length=1,
        max_length=128,
        pattern=r"^[A-Za-z0-9_.@-]+$",
        description="감사 이력에 기록되는 검토자 식별자입니다. 영문, 숫자 및 _ . @ - 문자를 허용하며 인증 키와는 별개입니다.",
    )
    expected_revision: int = Field(
        ge=0,
        description="종합 결과에서 조회한 review_revision입니다. 서버의 최신 값과 다르면 409가 반환되며 저장되지 않습니다.",
    )


class ReviewResponse(APIModel):
    """저장된 전문가 의견입니다. revision은 저장 후 새로 발급한 수정 번호입니다."""

    analysis_id: AnalysisId
    revision: int
    analyst_final_verdict: Literal["BENIGN", "MALICIOUS"] | None
    analyst_notes: str
    reviewer_id: str
    reviewed_at: AwareDatetime


class ReviewHistoryResponse(APIModel):
    """검토 이력입니다. items가 비어 있으면 아직 저장한 의견이 없습니다."""

    analysis_id: AnalysisId
    items: list[ReviewResponse]


class AnalysisResponse(AnalysisProgress):
    """파일 한 건의 종합 결과입니다. 초기·시스템·전문가 판정을 별도 필드로 보존합니다."""

    filename: str = Field(description="접수한 파일 이름입니다.")
    size_bytes: int = Field(description="원본 파일 크기입니다. 단위는 bytes입니다.")
    duplicate_of: AnalysisId | None = None
    prediction: Prediction | None = None
    risk_signals: RiskSignals | None = None
    initial_verdict: InitialVerdict | None = None
    route: Literal["FINAL", "DEEP_ANALYSIS"] | None = None
    reason: str | None = None
    top_features: list[TopFeature] = Field(default_factory=list)
    deep_analysis_status: dict[str, AnalysisStatus]
    evidence: list[TechniqueEvidence] = Field(default_factory=list)
    llm_summary: LLMSummary | None = None
    final_verdict: FinalVerdict | None = Field(
        default=None,
        description="시스템의 최종 판정입니다. 아직 최종 처리 전이면 null입니다.",
    )
    final_assessment: FinalAssessment | None = Field(
        default=None,
        description="시스템 판정의 이유, 처리 제안, 전문가 검토 필요 여부입니다.",
    )
    analyst_final_verdict: Literal["BENIGN", "MALICIOUS"] | None = Field(
        default=None,
        description="전문가가 확정한 판정입니다. 검토 전이거나 보류 중이면 null입니다.",
    )
    approval_status: Literal["AUTO_POLICY", "PENDING", "APPROVED", "MODIFIED"] = Field(
        description="AUTO_POLICY: 자동 처리, PENDING: 검토 대기·보류, APPROVED: 시스템 판정과 일치, MODIFIED: 전문가가 다른 판정으로 수정."
    )
    review_revision: int = Field(
        default=0,
        description="현재 검토 수정 번호입니다. 검토 저장 시 expected_revision에 그대로 넣습니다.",
    )


class AnalysisListResponse(APIModel):
    total_count: int = Field(description="검색 조건에 맞는 전체 분석 개수입니다.")
    limit: int = Field(description="한 페이지에 요청한 개수입니다.")
    offset: int = Field(description="앞에서 건너뛴 개수입니다.")
    analyses: list[AnalysisResponse] = Field(
        description="이번 페이지의 분석 목록입니다."
    )


class BatchAnalysisListResponse(AnalysisListResponse):
    batch_id: AnalysisId


class BatchStatus(str, Enum):
    QUEUED = "QUEUED"
    RUNNING = "RUNNING"
    PARTIALLY_COMPLETED = "PARTIALLY_COMPLETED"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"


class BatchSummary(APIModel):
    """상태 개수와 초기 판정 개수는 서로 독립된 집계다."""

    total: int = 0
    queued: int = 0
    running: int = 0
    completed: int = 0
    failed: int = 0
    auto_benign: int = 0
    auto_malicious: int = 0
    high_risk_uncertain: int = 0
    unclassified: int = 0


class BatchInputEntry(APIModel):
    input_index: int = Field(
        ge=0, description="입력 순서. 이름이 같은 파일도 구분합니다."
    )
    filename: str = Field(min_length=1, max_length=512)
    status: Literal["ACCEPTED", "SKIPPED"]
    analysis_id: AnalysisId | None = None
    sha256: Sha256 | None = None
    size_bytes: int | None = Field(default=None, ge=0)
    reason_code: str | None = Field(default=None, max_length=64)
    reason: str | None = Field(default=None, max_length=512)

    @model_validator(mode="after")
    def consistent_outcome(self):
        if self.status == "ACCEPTED":
            if (
                self.analysis_id is None
                or self.sha256 is None
                or self.size_bytes is None
            ):
                raise ValueError("accepted entries require analysis identity and size")
            if self.reason_code is not None or self.reason is not None:
                raise ValueError("accepted entries cannot have a skip reason")
        elif self.analysis_id is not None or not self.reason_code or not self.reason:
            raise ValueError("skipped entries require a reason and no analysis_id")
        return self


class BatchInputReport(APIModel):
    source_type: Literal["MULTIPLE_FILES", "ZIP"]
    archive_filename: str | None = Field(default=None, min_length=1, max_length=512)
    archive_sha256: Sha256 | None = None
    archive_size_bytes: int | None = Field(default=None, ge=0)
    entries: list[BatchInputEntry] = Field(default_factory=list, max_length=1000)

    @model_validator(mode="after")
    def consistent_source(self):
        archive_fields = (
            self.archive_filename,
            self.archive_sha256,
            self.archive_size_bytes,
        )
        if self.source_type == "ZIP" and any(value is None for value in archive_fields):
            raise ValueError("ZIP requests require archive identity")
        if self.source_type != "ZIP" and any(
            value is not None for value in archive_fields
        ):
            raise ValueError("non-archive requests cannot contain archive identity")
        indexes = [entry.input_index for entry in self.entries]
        if indexes != sorted(set(indexes)):
            raise ValueError("input indexes must be ordered and unique")
        return self


class BatchInputReceipt(APIModel):
    input_count: int = Field(
        default=0, description="접수 전에 검사한 파일 수입니다. 폴더는 제외합니다."
    )
    accepted_count: int = Field(
        default=0, description="독립 분석 작업을 등록한 파일 수입니다."
    )
    skipped_count: int = Field(
        default=0, description="분석 작업을 만들지 않은 파일 수입니다."
    )
    archive_file_count: int | None = Field(
        default=None, description="ZIP 내부 파일 수. 일반 다중 입력이면 null입니다."
    )
    entries: list[BatchInputEntry] = Field(default_factory=list)


class BatchAccepted(BatchInputReceipt):
    batch_id: AnalysisId = Field(
        description="묶음 전체를 조회할 때 사용하는 번호입니다."
    )
    total_count: int = Field(
        description="이번 묶음으로 등록한 분석 수입니다. accepted_count와 같으며 SKIPPED는 제외합니다."
    )
    analyses: list[AnalysisAccepted] = Field(
        description="파일별 접수 결과입니다. 각 항목에 고유한 analysis_id가 있습니다."
    )


class BatchResponse(BatchInputReceipt):
    batch_id: AnalysisId = Field(description="조회한 묶음의 번호입니다.")
    total_count: int = Field(
        description="묶음에 등록된 분석 수입니다. accepted_count와 같으며 SKIPPED는 제외합니다."
    )
    finished_count: int = Field(
        description="COMPLETED와 FAILED를 합한 종료 파일 수입니다. 성공한 파일 수와는 다를 수 있습니다."
    )
    status_counts: dict[str, int] = Field(
        description="QUEUED, RUNNING, COMPLETED, FAILED에 해당하는 파일 수입니다."
    )
    analyses: list[AnalysisResponse] = Field(
        description="묶음 안의 파일별 종합 결과입니다."
    )
    status: BatchStatus = Field(
        default=BatchStatus.QUEUED,
        description="배치 진행 상태입니다. COMPLETED는 처리가 모두 종료됐다는 의미이며 일부 실패 또는 전체 SKIPPED를 포함할 수 있습니다.",
    )
    summary: BatchSummary = Field(default_factory=BatchSummary)
