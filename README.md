# TRUST-TRIAGE

악성코드 정적 분석 결과와 AI 모델의 신뢰도 정보를 결합하여 자동 판정, 심층 분석 및 분석가 검토 대상을 분류하는 신뢰도 기반 악성코드 Triage 시스템입니다.

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
python -m venv .venv
```

`python` 명령어가 작동하지 않고 `py`만 작동하는 경우에는 다음과 같이 실행합니다.

```bash
py -m venv .venv
```

가상환경을 생성하면 프로젝트 폴더 내부에 `.venv` 디렉터리가 생성됩니다.

`.venv`는 개인별 로컬 개발 환경이므로 GitHub 저장소에는 업로드하지 않습니다.

---

### 4. 가상환경 활성화

#### Windows CMD

```cmd
.venv\Scripts\activate
```

#### Windows PowerShell

```powershell
.\.venv\Scripts\Activate.ps1
```

#### Git Bash

```bash
source .venv/Scripts/activate
```

가상환경이 정상적으로 활성화되면 터미널 경로 앞에 `(.venv)`가 표시됩니다.

```text
(.venv) C:\Users\사용자명\trust-triage>
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

터미널 경로 앞에 표시되던 `(.venv)`가 사라지면 가상환경이 정상적으로 종료된 것입니다.

---

## 이후 프로젝트 실행 순서

저장소를 이미 Clone했고 가상환경까지 생성한 경우에는 매번 가상환경을 다시 만들 필요가 없습니다.

프로젝트 작업을 시작할 때는 다음 순서로 실행합니다.

```bash
cd trust-triage
.venv\Scripts\activate
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
