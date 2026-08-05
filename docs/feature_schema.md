# feature_schema.md — TRUST-EDR 특징 스키마 (전면 개편)

> 특징 추출 모듈(이상욱) → 이 스키마로 출력 / 모델·Calibration·JRR(전원) → 이 스키마로 입력받음.
> 여기 없는 이름은 코드에 쓰지 않습니다. 변경 시 반드시 팀 전체 공지 후 이 파일부터 수정.

## 0. 개요

EMBER2024(thrember) 2568차원 전체 특징으로 Baseline을 학습시킨 뒤, Feature
Importance 상위 **500개**를 채택했습니다 (근거: `500개_특징_선택_근거.md`).
이 500개를 thrember 소스(`thrember/features.py`)의 `PEFeatureExtractor` 구조를
직접 확인해 정확한 블록 경계값으로 전수 분류했고, 그 결과를 아래 스키마에
그대로 반영했습니다.

- **해싱 안 됨: 303개(60.6%)** → 정확한 계산식으로 재현 가능, 아래 스키마 확정
- **해싱됨: 197개(39.4%)** → 정확한 값 재현 불가, "이 카테고리가 중요하다"는
  참고 힌트로만 사용하고 실제 API 그룹은 도메인 지식으로 독립 설계

---

## 1. 전체 블록 구조 (thrember 소스 기준, 검증됨: 합계 2568)

| 블록 | 인덱스 범위 | 차원 | 해싱 | 500개 중 개수 |
|---|---|---|---|---|
| GeneralFileInfo | 0–7 | 7 | ❌ | 2 |
| ByteHistogram | 7–263 | 256 | ❌ | 62 |
| ByteEntropyHistogram | 263–519 | 256 | ❌ | 43 |
| StringExtractor | 519–696 | 177 | ❌ | **95 (최다)** |
| HeaderFileInfo | 696–770 | 74 | ❌ | 39 |
| SectionInfo_general | 770–781 | 11 | ❌ | 7 |
| SectionInfo_sizes_hashed | 781–831 | 50 | ⭕ | 8 |
| SectionInfo_vsize_hashed | 831–881 | 50 | ⭕ | 17 |
| SectionInfo_entropy_hashed | 881–931 | 50 | ⭕ | 13 |
| SectionInfo_characteristics_hashed | 931–981 | 50 | ⭕ | 15 |
| SectionInfo_entry_name_hashed | 981–991 | 10 | ⭕ | 0 |
| SectionInfo_overlay | 991–994 | 3 | ❌ | 3 |
| ImportsInfo_lengths | 994–996 | 2 | ❌ | 2 |
| ImportsInfo_libraries_hashed | 996–1252 | 256 | ⭕ | 27 |
| ImportsInfo_imports_hashed | 1252–2276 | 1024 | ⭕ | 89 |
| ExportsInfo_length | 2276–2277 | 1 | ❌ | 1 |
| ExportsInfo_hashed | 2277–2405 | 128 | ⭕ | 2 |
| DataDirectories | 2405–2439 | 34 | ❌ | 25 |
| RichHeader_count | 2439–2440 | 1 | ❌ | 1 |
| RichHeader_hashed | 2440–2472 | 32 | ⭕ | 26 |
| AuthenticodeSignature | 2472–2480 | 8 | ❌ | 6 |
| PEFormatWarnings | 2480–2568 | 88 | ❌ | 17 |

---

## 2. PE Header

`HeaderFileInfo` 블록(696–770). 전부 pefile로 직접 계산 가능, 해싱 없음.

| 특징명 | 타입 | 설명 | 계산 방식 |
|---|---|---|---|
| `timestamp` | int | 컴파일 타임스탬프 | `pe.FILE_HEADER.TimeDateStamp` |
| `timestamp_is_future` | binary | 타임스탬프가 미래 시점인지 | 파생: 현재 시각과 비교 |
| `timestamp_is_zero` | binary | 타임스탬프 조작/제거 의심 | 파생: `timestamp == 0` |
| `number_of_sections` | int | Section 개수 | `pe.FILE_HEADER.NumberOfSections` |
| `number_of_symbols` | int | 심볼 개수 | `pe.FILE_HEADER.NumberOfSymbols` |
| `machine_type` | categorical | CPU 아키텍처 | `pe.FILE_HEADER.Machine` |
| `subsystem` | categorical | 실행 서브시스템 | `pe.OPTIONAL_HEADER.Subsystem` |
| `image_characteristics` | binary×16 | 파일 특성 플래그(16종) | `pe.FILE_HEADER` characteristics 비트 |
| `dll_characteristics` | binary×11 | DLL 특성 플래그(11종, ASLR/DEP 등) | `pe.OPTIONAL_HEADER` dll_characteristics 비트 |
| `sizeof_code` / `sizeof_headers` / `sizeof_image` | int | 코드/헤더/이미지 크기 | `pe.OPTIONAL_HEADER` |
| **`address_of_entrypoint`** | int | **Entry Point 주소** | `pe.OPTIONAL_HEADER.AddressOfEntryPoint` |
| `image_base` / `section_alignment` / `checksum` | int | 로드 주소/정렬/체크섬 | `pe.OPTIONAL_HEADER` |
| `dos_header_fields` | int×17 | DOS 헤더 17개 필드 | `pe.DOS_HEADER.dump_dict()` |

> **Entry Point 위치 판단**(어느 section에 있는지, `.text`인지 등)은
> `SectionInfo`와 결합해서 파생 특징으로 별도 계산 (2.4절 참고).

---

## 3. Entropy 관련 (세 군데에 분산되어 있음)

| 특징명 | 위치 | 타입 | 설명 |
|---|---|---|---|
| `file_entropy` | GeneralFileInfo | float | 파일 전체 Shannon Entropy |
| `byte_entropy_histogram` | ByteEntropyHistogram | 256차원 | 바이트값×지역 entropy 2D 분포(16×16), 해싱 아님 |
| `section_entropy_max` / `section_entropy_min` | SectionInfo_general | float | Section별 entropy 중 최댓값/최솟값 |
| `overlay_entropy` | SectionInfo_overlay | float | 파일 끝 overlay 영역 entropy |

`packing_suspected` 파생 특징: `section_entropy_max >= 7.0` (임계값은 회의에서 재검토)

---

## 4. Section 정보

`SectionInfo` 블록(770–994). **일부만 해싱** — 통계는 그대로, 이름별 세부 정보만 해싱.

### 해싱 안 됨 — 정확히 재현
| 특징명 | 설명 |
|---|---|
| `n_sections` | Section 개수 |
| `n_zero_size_sections` | 크기 0인 section 개수 |
| `n_empty_name_sections` | 이름 없는 section 개수 |
| `n_rx_sections` | 읽기+실행 가능 section 개수 (코드 삽입 의심 신호) |
| `n_w_sections` | 쓰기 가능 section 개수 |
| `size_ratio_max/min`, `vsize_ratio_max/min` | 실제크기/가상크기 비율 극값 |
| `overlay_size`, `overlay_size_ratio` | 파일 끝 추가 데이터(overlay) 크기·비율 |

### 해싱됨 — 카테고리 힌트로만
Section 이름별 크기/가상크기/entropy/특성/Entry Point가 속한 section 이름 — 전부
`(section이름, 값)` 쌍을 해시 트릭으로 압축. 어느 section이 위험한지 특정은 불가.

---

## 5. API/DLL

`ImportsInfo`(994–2276) + `ExportsInfo`(2276–2405). **대부분 해싱**, 500개 중 116개
(Imports만) 차지해 두 번째로 큰 카테고리지만 정확한 API 이름 재현 불가.

| 특징명 | 해싱 여부 | 설명 |
|---|---|---|
| `import_count` | ❌ | import된 함수 총 개수 |
| `dll_count` | ❌ | import된 고유 DLL 개수 |
| `export_count` | ❌ | export하는 함수 개수 |
| `libraries_hashed` (256차원) | ⭕ | DLL 이름 해시 |
| `imports_hashed` (1024차원) | ⭕ | `dll:함수명` 해시 |
| `exports_hashed` (128차원) | ⭕ | export 함수명 해시 |

> **실제 API 그룹(레지스트리/인젝션/네트워크 등)은 위 해싱 때문에 EMBER에서
> 역추적 불가.** pefile로 직접 열어 API 이름을 텍스트로 뽑고, 아래
> `api_group_definitions.json`(별도 파일)에 정의한 그룹과 매칭하는 방식으로
> 독립적으로 설계합니다.

```
api_registry_group   — 레지스트리 조작 API 포함 여부
api_injection_group  — 프로세스 인젝션 API 포함 여부
api_network_group    — 네트워크 통신 API 포함 여부
api_crypto_group     — 암호화 API 포함 여부
```

---

## 6. 문자열 기반 특징 (StringExtractor) — 신규 카테고리

`StringExtractor` 블록(519–696). **500개 중 95개로 가장 많이 뽑힌 카테고리인데
** 전부 해싱 안 됨 — 특정 정규식 패턴 매칭 여부를 직접 카운트.

### 기본 통계 (해싱 아님)
| 특징명 | 설명 |
|---|---|
| `numstrings` | 추출된 문자열(5자 이상 연속 출력가능문자) 개수 |
| `avlength` | 평균 문자열 길이 |
| `printables` | 전체 출력가능문자 개수 |
| `string_entropy` | 문자열 집합의 entropy |
| `printable_char_dist` (96차원) | 문자별(0x20–0x7f) 분포 |

### 패턴 매칭 카운트 (76개, 보안 관점으로 그룹핑 추천)

| 그룹 | 포함 패턴 |
|---|---|
| **네트워크/C2 의심** | url, ipv4_addr, ipv6_addr, http, https, ftp, download, connect, useragent, cookie, internet, get, post |
| **지속성/시스템 조작** | registry_key, hostname, service, install, hidden, mutex, token, privilege |
| **스크립트 실행** | powershell, Invoke-Expression, Invoke-Command, Start-process |
| **난독화/인코딩 의심** | base64, base64string, crypt, encode, decode, btc_wallet |
| **분석 방해/환경 탐지** | debug, environment, enum |
| **파일/경로** | file_path(C:/), /dev/, /proc/, /bin/, /usr/, /tmp/ |
| **기타 일반** | process, remote, resource, security, thread, window, memory, module, desktop, clipboard, keyboard, snapshot, disk, directory, exit, create, delete, command, cache, certificate 등 |

> 이 그룹핑은 EMBER 정규식 목록을 그대로 재현 가능(해싱 안 됨)하므로, 상욱님
> 모듈에서 정규식 그대로 이식하면 EMBER 결과와 100% 동일한 값을 낼 수 있습니다.

---

## 7. 기타 확정 카테고리 (신규)

| 카테고리 | 위치 | 해싱 | 설명 |
|---|---|---|---|
| `byte_histogram` (256차원) | ByteHistogram | ❌ | 파일 전체 바이트값(0–255) 분포 |
| `data_directories` | DataDirectories(2405–2439) | ❌ | EXPORT/IMPORT/RESOURCE 등 16개 명명된 디렉토리의 크기·가상주소, `has_relocs`, `has_dynamic_relocs` |
| `authenticode_signature` | AuthenticodeSignature(2472–2480) | ❌ | `num_certs`, `self_signed`, `empty_program_name`, `no_countersigner`, `parse_error`, `chain_max_depth`, `signing_time_diff` — 디지털 서명 여부·자체서명 의심 |
| `pe_format_warnings` | PEFormatWarnings(2480–2568) | ❌ | pefile 파싱 시 발생한 경고 87종 + 총 경고 개수. **분석 난이도(파싱 실패·구조 이상) 신호로 활용 검토** |
| `rich_header_pair_count` | RichHeader(2439–2440) | ❌ | Rich Header 내 값 쌍 개수 (나머지 32차원은 해싱) |

---

## 8. 파일명 기반 특징 (thrember에 없음, 자체 추가 — 멘토 피드백 반영)

| 특징명 | 타입 | 설명 | 계산 방식 |
|---|---|---|---|
| `filename_typo_similarity` | float(0~1) | 알려진 정상 시스템 파일명과의 최대 문자열 유사도 | `SequenceMatcher` 등, 시스템 파일 목록과 비교 |
| `filename_exact_match_system` | binary | 시스템 파일명과 완전 일치 여부 | 정확 일치 |

---

## 9. 파생 위험 신호 (특징 추출 모듈 책임 아님 — 참고용)

Calibration/JRR 담당(김건우·이가영)이 아래 단계에서 계산. 특징 추출 모듈은
1~8번까지만 책임집니다.

| 특징명 | 계산 위치 |
|---|---|
| `calibrated_probability` | Calibration 단계 |
| `model_disagreement` | JRR 단계 |
| `ood_score` | JRR 단계 |
| `risk_score` | JRR 단계 |

---

## 10. 담당 매핑

| 섹션 | 담당 |
|---|---|
| 1~8번 (원본 특징) | 이상욱 (특징 추출 모듈) |
| 9번 (파생 위험 신호) | 김건우·이가영 (Calibration/JRR) |

---

## 확정 필요 항목 (다음 회의 안건)

- [x] ~~특징 개수~~ → **500개 확정**
- [x] ~~블록 분류~~ → **완료** (해싱 안 됨 303개/60.6%, 해싱됨 197개/39.4%)
- [x] ~~StringExtractor 존재 확인~~ → **본 문서에 6번 카테고리로 반영 완료**
- [ ] StringExtractor 76개 패턴을 전부 이식할지, 보안 관련성 높은 일부만 추릴지
- [ ] `pe_format_warnings`를 분석 난이도 신호로 정식 채택할지
- [ ] `packing_suspected` 임계값 7.0 유지 여부
- [ ] `api_group_definitions.json` 실제 API 함수명 목록
