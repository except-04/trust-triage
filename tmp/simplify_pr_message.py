from pathlib import Path
import re
from collections import defaultdict

path = Path('output/pr/analyst-priority-budget-pr.md')
text = path.read_text(encoding='utf-8')
start = text.index('## 파일별 변경 상세')
end = text.index('### 신규 소스·테스트', start)
rows = re.findall(r'^\| `([^`]+)` \| (.+) \|$', text[start:end], re.MULTILINE)
assert len(rows) == 84, len(rows)
functional = {
    'dashboard/api_client.py', 'dashboard/app.py',
    'src/trust_triage/backend_api/app.py',
    'src/trust_triage/backend_api/repository.py',
    'src/trust_triage/backend_api/schema.sql',
    'src/trust_triage/backend_api/schemas.py',
    'src/trust_triage/backend_api/service.py',
    'src/trust_triage/deep_analysis/normalizer.py',
    'tests/backend_api/fake_repository.py',
    'docs/jrr_summary.md',
}
small = {
    'src/jrr/optimize_threshold.py',
    'src/preprocessing/build_index.py',
    'tests/backend_api/test_service_processor.py',
}
section = '''## 파일별 변경 상세

### 기능 및 문서 내용 변경

| 파일 | 변경 내용 |
| --- | --- |
'''
for filename, desc in rows:
    if filename in functional:
        section += f'| `{filename}` | {desc} |\n'
section += '''
### 조건식 단순화 및 테스트 환경 보완

| 파일 | 변경 내용 |
| --- | --- |
'''
for filename, desc in rows:
    if filename in small:
        section += f'| `{filename}` | {desc} |\n'

format_files = [f for f, _ in rows if f not in functional | small]
section += f'''
### 코드·문서 형식 정리 ({len(format_files)}개 파일)

아래 파일은 줄바꿈·공백·import 순서 및 미사용 import, 타입 표기, 공개 이름 나열 순서, 설명 들여쓰기를 정리했습니다. 보간이 없는 f-string도 일반 문자열로 정리했습니다. 알고리즘·판정 정책·테스트 조건을 새로 추가한 변경은 없습니다.

대상 파일은 다음과 같습니다.

```text
'''
grouped = defaultdict(list)
for filename in format_files:
    group = 'tests' if filename.startswith('tests/') else ('docs' if filename.startswith('docs/') else str(Path(filename).parent).replace('\\', '/'))
    grouped[group].append(filename)
section += '\n\n'.join('\n'.join(names) for names in grouped.values())
section += '\n```\n\n'

updated = text[:start] + section + text[end:]
assert all(updated.count('`' + f + '`') >= 1 or f in format_files for f, _ in rows)
assert len(format_files) + len(functional) + len(small) == 84
path.write_text(updated, encoding='utf-8')
print(f'Grouped formatting files: {len(format_files)}; individual descriptions: {len(functional) + len(small)}')
