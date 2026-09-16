# TRUST-TRIAGE

악성코드 정적 분석 결과와 AI 모델의 신뢰도 정보를 결합하여 자동 판정, 심층 분석 및 분석가 검토 대상을 분류하는 신뢰도 기반 악성코드 Triage 시스템입니다.

## Backend API

파일 접수·진행 상태·분석 결과·전문가 검토를 제공하는 FastAPI 백엔드는 `src/trust_triage/backend_api`에 있습니다. [소스코드 구조와 처리 흐름](docs/backend-api/backend-structure.md), [API 종류와 설명](docs/backend-api/api-reference.md)을 참고하세요. [생성된 OpenAPI 명세](docs/backend-api/openapi.json)도 함께 제공합니다.

HTTP 서버와 분석 처리기는 별도 프로세스로 실행합니다. 실제 모델 파일과 심층 분석 서비스는 해당 모듈의 준비가 필요하며, 미설정 상태에서 가짜 분석 결과를 반환하지 않습니다.

DB·S3 등의 설정 예시는 루트의 [.env.backend.example](.env.backend.example)에 있습니다. 처음 설정할 때 이 파일을 `.env`로 복사해 실제 값을 채우고, 백엔드 실행 명령에 `--env-file .env`를 지정합니다.

## Speakeasy Worker

SQS 요청 수신, S3 원본 확인, 기존 Speakeasy 분석기 호출, PostgreSQL 상태·결과 저장을 담당하는 별도 프로세스입니다. 중복 수신 방지, 작업 점유 갱신, 재시도·DLQ 처리와 SHA-256 경로의 정규화 리포트 보관을 제공합니다.

[실행 방법](docs/worker/speakeasy-worker.md), [Backend 연결·실행 절차](docs/worker/backend-integration.md), [요청·결과 계약](docs/worker/contracts.md), [환경변수 예시](.env.worker.example)를 참고하세요. Backend 처리기가 CAPA/FLOSS 결과를 저장하고 필요한 작업을 SQS에 전달하며, Worker 결과를 수신하면 저장된 단계에서 증거 반영·선택적 LLM 요약·전체 상태 갱신을 이어간다. Worker 완료는 Speakeasy 단계의 완료를 뜻한다. 실제 AWS 환경과 승인된 PE를 통한 검증은 배포 환경에서 수행해야 한다.

## 개발 환경 설정

아래 과정은 Windows 환경을 기준으로 작성되었습니다.

### 1. GitHub 저장소 Clone

프로젝트를 저장할 경로에서 CMD, PowerShell 또는 Git Bash를 실행합니다.

```bash
git clone https://github.com/<GitHub-사용자명-or-Organization>/trust-triage.git
cd trust-triage
```

저장소 주소는 GitHub 저장소의 **Code → HTTPS**에서 확인할 수 있습니다.

Clone이 정상적으로 완료되었는지 확인합니다.

```bash
git status
```

다음과 비슷하게 출력되면 정상입니다.

```text
On branch main
Your branch is up to date with 'origin/main'.
nothing to commit, working tree clean
```

---

### 2. Python 버전 확인

Python이 설치되어 있는지 확인합니다.

```bash
python --version
```

Python 명령어가 인식되지 않는 경우 다음 명령어도 확인합니다.

```bash
py --version
```

---

### 3. Python 가상환경 생성

프로젝트 루트 디렉터리에서 다음 명령어를 실행합니다.

```bash
python -m venv trust-triage-env
```

`python` 명령어가 작동하지 않고 `py`만 작동하는 경우에는 다음과 같이 실행합니다.

```bash
py -m venv trust-triage-env
```

가상환경을 생성하면 프로젝트 폴더 내부에 `trust-triage-env` 디렉터리가 생성됩니다.

`trust-triage-env`는 개인별 로컬 개발 환경이므로 GitHub 저장소에는 업로드하지 않습니다.

---

### 4. 가상환경 활성화

#### Windows CMD

```cmd
trust-triage-env\Scripts\activate
```

#### Windows PowerShell

```powershell
.\trust-triage-env\Scripts\Activate.ps1
```

#### Git Bash

```bash
source trust-triage-env/Scripts/activate
```

가상환경이 정상적으로 활성화되면 터미널 경로 앞에 `(trust-triage-env)`가 표시됩니다.

```text
(trust-triage-env) C:\Users\사용자명\trust-triage>
```

---

### 5. pip 업그레이드

가상환경을 활성화한 상태에서 pip를 업그레이드합니다.

```bash
python -m pip install --upgrade pip
```

---

### 6. 프로젝트 라이브러리 설치

프로젝트에 필요한 라이브러리를 `requirements.txt`를 통해 설치합니다.

```bash
python -m pip install -r requirements.txt
```

설치된 라이브러리를 확인하려면 다음 명령어를 사용합니다.

```bash
python -m pip list
```

MLflow가 정상적으로 설치되었는지 확인합니다.

```bash
mlflow --version
```

---

### 7. MLflow 서버 실행

가상환경이 활성화된 상태에서 다음 명령어를 실행합니다.

```bash
mlflow server --port 5000
```

서버가 실행되면 웹 브라우저에서 다음 주소로 접속합니다.

```text
http://localhost:5000
```

MLflow 서버가 실행 중인 터미널은 실험 기록을 확인하는 동안 종료하지 않습니다.

> MLflow 실행 과정에서 생성되는 `mlflow.db`, `mlruns/`, `mlartifacts/` 등의 로컬 파일은 GitHub에 업로드하지 않습니다.

---

### 8. MLflow 서버 종료

MLflow가 실행 중인 터미널에서 다음 키를 입력합니다.

```text
Ctrl + C
```

서버가 종료된 후 명령어를 다시 입력할 수 있습니다.

---

### 9. 가상환경 종료

작업을 마친 뒤 다음 명령어를 실행합니다.

```bash
deactivate
```

터미널 경로 앞에 표시되던 `(trust-triage-env)`가 사라지면 가상환경이 정상적으로 종료된 것입니다.

---

## 이후 프로젝트 실행 순서

저장소를 이미 Clone했고 가상환경까지 생성한 경우에는 매번 가상환경을 다시 만들 필요가 없습니다.

프로젝트 작업을 시작할 때는 다음 순서로 실행합니다.

```bash
cd trust-triage
trust-triage-env\Scripts\activate
git pull origin main
python -m pip install -r requirements.txt
mlflow server --port 5000
```

작업을 종료할 때는 다음 순서로 진행합니다.

```text
1. MLflow 터미널에서 Ctrl + C
2. deactivate
```

---

## 최신 코드 받기

작업을 시작하기 전에 `main` 브랜치의 최신 변경 사항을 가져옵니다.

```bash
git switch main
git pull origin main
```

담당 기능을 개발할 때는 `main` 브랜치에서 직접 작업하지 않고 별도의 브랜치를 생성합니다.

```bash
git switch -c feature/<기능명>
```

예시는 다음과 같습니다.

```bash
git switch -c feature/baseline-model
git switch -c feature/feature-extraction
git switch -c feature/calibration
```

## Feature extraction MVP

PE Feature 추출 방법은
[`docs/feature-extraction/feature-extraction.md`](docs/feature-extraction/feature-extraction.md)에 정리되어 있습니다.
공식 EMBER2024 Feature Version 3만 사용하며, `.exe`와 `.dll`을 실행하지 않고
정적으로 읽어 고정 벡터를 반환합니다.

## Backend API

파일 접수·분석 결과·전문가 검토 API는 [API 안내](docs/backend-api/api-reference.md),
실행 프로세스와 소스 구조는 [백엔드 구조](docs/backend-api/backend-structure.md)를 참고합니다.
원본은 SHA-256 기준으로 공유하고 실행별 리포트를 함께 보관합니다.
기존 DB 전환과 Worker용 저장 인터페이스는 [저장 구조 안내](docs/backend-api/storage.md)에 정리되어 있습니다.
