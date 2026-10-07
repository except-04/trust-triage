from pathlib import Path
import subprocess

path = Path('output/pr/analyst-priority-budget-pr.md')
text = path.read_text(encoding='utf-8')
files = subprocess.check_output(['git', 'diff', '--name-only', 'origin/main...HEAD'], encoding='utf-8').splitlines()
head = subprocess.check_output(['git', 'rev-parse', '--short', 'HEAD'], encoding='utf-8').strip()
base = subprocess.check_output(['git', 'rev-parse', '--short', 'origin/main'], encoding='utf-8').strip()
assert len(files) == 90

text = text.replace('当前', '현재')
text = text.replace('현재 변경된 84개 추적 파일 전체에 대한 회귀 검증 완료를 뜻하지 않습니다.', '이번 PR의 90개 변경 파일 전체에 대한 회귀 검증 완료를 뜻하지 않습니다. 이번 문서 갱신에서는 테스트를 재실행하지 않았습니다.')
text = text.replace('별도 Lockbox 감사 스크립트와 보고서는 저장된 예측 결과를 재검산하는 자료이며 모델 재학습이나 정책 재최적화를 수행하지 않습니다.', 'Lockbox 감사 스크립트는 저장된 예측 결과를 재검산하며 모델 재학습이나 정책 재최적화를 수행하지 않습니다. 검증 보고서·PDF는 이번 커밋에 포함하지 않습니다.')
text = text.replace('## 파일별 변경 상세\n\n', f'## 파일별 변경 상세\n\n`origin/main...HEAD` 기준 총 **90개 파일**입니다. 기능·내용 변경 16개, 경미한 조건식 수정·테스트 환경 보완 3개, 형식 정리 71개로 나누어 설명합니다.\n\n', 1)
text = text.replace('### 신규 소스·테스트', '### 이번 커밋에 추가된 소스·테스트 (6개)')

start = text.index('### 신규 검증 자료·PDF')
end = text.index('## 리뷰 시 확인할 사항', start)
text = text[:start] + text[end:]
text = text.replace('- 광범위한 서식 변경과 Lockbox 자료를 함께 포함할 경우 핵심 기능 변경과 구분해 리뷰합니다.', '- 광범위한 형식 정리와 Lockbox 감사 스크립트는 업무 큐의 기능 변경과 구분해 리뷰합니다.')

start = text.index('작성 기준:')
text = text[:start] + f'''작성 기준: 2026-10-07, `feature/analyst-priority-budget`의 커밋 `{head}`와 로컬에 저장된 `origin/main` (`{base}`)의 PR 비교(`origin/main...HEAD`). 현재 로컬 브랜치와 원격 추적 브랜치가 같은 커밋을 가리킵니다. 이번 작성 중 fetch·commit·push·병합은 수행하지 않았습니다. `output/`, `tmp/`의 로컬 산출물은 PR 변경 목록에 포함하지 않습니다.
'''

# All committed files must be described, individually or in the format-only list.
for filename in files:
    assert ('`' + filename + '`') in text or filename.rsplit('/', 1)[-1] in text, filename
path.write_text(text, encoding='utf-8')
print(f'Refreshed PR message for {head}: {len(files)} committed files')
