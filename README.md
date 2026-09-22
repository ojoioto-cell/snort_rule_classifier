# Snort Rule Classifier

**Snort 형식의 보안 룰을 URL·IP·시그니처로 분류하고, 판정 근거와 함께 Excel 파일로 정리하는 도구입니다.**

| 항목 | 내용 |
| --- | --- |
| 배포 버전 | `1.0.0` |
| 실행 환경 | Python 3.10 이상 |
| 실행 의존성 | Python 표준 라이브러리만 사용 |
| 입력 | 한 줄에 룰 하나를 저장한 텍스트 파일 |
| 출력 | `.xlsx` — 전체 결과 및 URL / IP / 시그니처 시트 |
| 처리 방식 | 로컬 파일 처리, 외부 API·DNS 조회 없음 |

기존 내부 개선판 v3.5를 기반으로 첫 GitHub 배포 버전을 `v1.0.0`으로 정리했습니다.
분류 결과는 룰 정리와 검토를 위한 휴리스틱입니다. 룰의 악성 여부, 탐지 정확도 또는 차단 가능 여부를 보장하지 않습니다.

## 빠른 시작

압축을 해제하고 `snort-rule-classifier` 폴더에서 실행합니다. 별도의 `pip install` 없이 사용할 수 있습니다.

```bash
python snort_rule_classifier.py --version
python snort_rule_classifier.py examples/sample.rules -o output/sample.xlsx
```

Windows에서 `python` 명령을 사용할 수 없다면 `py -3`으로, Linux/macOS에서는 환경에 따라 `python3`으로 바꾸세요.

포함된 가상 예제 16건의 예상 결과:

| 분류 | 건수 |
| --- | ---: |
| 단일 URL | 5 |
| 하위 디렉터리 | 2 |
| IP | 3 |
| 시그니처 | 6 |

실제 입력은 로컬 `data/` 폴더에 두고 실행할 수 있습니다. `data/`와 `output/`은 Git 추적 제외 대상입니다.

```bash
python snort_rule_classifier.py data/input.rules -o output/result.xlsx
```

## 입력 형식

일반 룰과 `넘버|설명|룰` 형식을 지원합니다.

```text
alert tcp any any -> any 80 (msg:"Example domain"; content:"example.test"; sid:1000001;)
10|분리 Host 예제|alert tcp any any -> any 80 (content:"Host|3a 20|"; content:"example.test"; sid:1000002;)
```

- 빈 줄과 첫 비공백 문자가 `#`인 주석 행은 제외합니다.
- 넘버가 없으면 주석·빈 줄을 제외한 순번을 부여합니다.
- 외부 설명이 없으면 룰의 `msg`를 사용합니다.
- 룰 시작 위치 앞에서만 구분자 `|`를 해석합니다. `content`의 HEX 블록 및 PCRE의 `|`, `;`를 보존합니다.
- 지원하지 않는 행이나 미완성 따옴표·괄호는 물리적 행 번호와 함께 오류를 표시합니다. 여러 줄 룰, `include`, 행 끝 주석은 지원하지 않습니다.

## 분류 기준 요약

| 분류 | 대표 조건 | 예 |
| --- | --- | --- |
| 단일 URL | 도메인/URL 형태의 content, 하위 경로 없음 | `content:"example.test";` |
| 하위 디렉터리 | 도메인 뒤 경로 또는 별도의 `/...` content | `content:"example.test"; content:"/download";` |
| IP | 제한된 헤더 조건의 단일 IPv4/CIDR 또는 범용 헤더의 단일 IP content | `alert tcp 192.0.2.1 any -> any any (...)` |
| 시그니처 | 부정 content, 예외 정책, 추가 IP 탐지 조건, 일반 공격 문자열 등 | `content:!"example.test";` |

`Host|3A 20|`, `Host|3a 20|`, Host와 도메인이 분리된 content, 제한적인 파이프 유실 형태를 처리합니다. 원본의 단축 URL·서비스 예외 정책도 유지합니다.

IP 분류는 `msg`, `sid`, `flags`만 허용하며 content IP 분류에서만 `content`를 추가 허용합니다. **`rev`, `classtype`, `metadata`도 현재 정책에서는 IP 분류를 제외**합니다. URL 분류에는 같은 옵션 제한을 적용하지 않습니다.

자세한 우선순위와 의도적 제약은 [분류 정책](docs/CLASSIFICATION.md)을 참고하세요.

## 실행 옵션

```bash
python snort_rule_classifier.py input.rules
python snort_rule_classifier.py input.rules -o output/result.xlsx
python snort_rule_classifier.py input.rules --encoding cp949 -o output/result.xlsx
python snort_rule_classifier.py input.rules -o output/result.xlsx --force
python snort_rule_classifier.py --help
```

| 옵션 | 설명 |
| --- | --- |
| `input` | 입력 텍스트 파일 경로 |
| `-o`, `--output` | 출력 경로. 생략 시 `입력파일명_분류결과.xlsx` |
| `--encoding` | 입력 인코딩 지정. 생략 시 UTF-8 / CP949 / EUC-KR 순으로 시도 |
| `--force` | 기존 출력 파일의 덮어쓰기를 명시적으로 허용 |
| `--version` | 버전 출력 |

출력 확장자가 `.xlsx`가 아니면 `.xlsx`로 바꿉니다. 입력과 출력이 같은 파일이면 `--force`가 있어도 중단합니다. 자동 디코딩이 실패하면 latin-1로 읽고 경고합니다. EUC-KR 파일은 호환되는 CP949로 표시될 수 있습니다.

| 종료 코드 | 의미 |
| --- | --- |
| `0` | 완료 |
| `1` | 기타 처리·저장 오류 |
| `2` | 잘못된 인자, 입력 파일·형식·인코딩·크기 오류 |
| `3` | 파일 접근 권한 오류 |
| `4` | 기존 출력 파일 존재, 덮어쓰기 미허용 |

## Excel 출력

`분류결과`, `URL`, `IP`, `시그니처`의 4개 시트에 같은 6개 열을 제공합니다. URL 시트는 단일 URL과 하위 디렉터리를 함께 포함합니다.

| 열 | 내용 |
| --- | --- |
| 넘버 | 입력 식별자 또는 순번 |
| msg | 외부 설명 또는 룰의 msg |
| snort 룰 | 분류에 사용한 룰 텍스트 |
| 분류결과 | 단일 URL / 하위 디렉터리 / IP / 시그니처 |
| 근거 | 분류 이유 |
| 근거 내용 | URL: 호스트 / IP: IPv4·CIDR / 시그니처: 룰 텍스트 |

첫 행 고정, 필터, 줄바꿈을 적용합니다. 모든 셀을 텍스트로 저장하므로 `=`로 시작하는 입력도 Excel 수식으로 기록하지 않습니다.

룰의 content와 PCRE는 정규화된 값으로 덮어쓰지 않습니다. 다만 룰 앞뒤 공백·행 끝 문자는 정리하며, XML에 넣을 수 없는 제어문자는 `\x00` 같은 표시 문자열로 바꿉니다. URL 근거 내용에는 경로가 아니라 호스트가 들어가며, 경로는 룰 열에서 확인할 수 있습니다.

## 선택 사항: 명령어로 설치

가상환경 등 원하는 Python 환경에서 프로젝트 폴더를 로컬 설치할 수 있습니다.

```bash
python -m pip install .
snort-rule-classifier --version
snort-rule-classifier examples/sample.rules -o output/installed_sample.xlsx
```

프로그램 실행 의존성은 없습니다. 위 설치 방식은 빌드 도구인 setuptools/wheel을 내려받을 수 있으므로, 오프라인에서는 `.py` 직접 실행 방식을 사용하세요. PyPI에 게시된 패키지라는 의미는 아닙니다.

## 테스트

```bash
python -m unittest discover -s tests -v
```

표준 라이브러리 `unittest`로 분류 정책, 원문 보존, 한글 인코딩, XLSX 구조, 파일 보호와 오류 처리를 검증합니다. 저장소의 GitHub Actions에는 Linux·Windows·macOS 테스트 구성을 포함했습니다. 실제 로컬 검증 범위는 [검증 기록](docs/VALIDATION.md)을 참고하세요.

## 제약

- Snort/Suricata 엔진의 전체 문법 검사기나 룰 실행기가 아닙니다. 탐지 버퍼, PCRE 및 옵션의 의미를 완전히 평가하지 않습니다.
- IPv6, IP 목록·변수·부정 주소는 전용 IP 분류 대상이 아닙니다.
- 실제 TLD, DNS 존재 여부, URL 접속 가능 여부는 확인하지 않습니다.
- 입력과 결과를 메모리에 보관하므로 대규모 파일은 나누어 처리하세요. 대용량 부하 시험은 수행하지 않았습니다.
- Excel 한계는 셀 32,767자, 전체 결과 시트의 데이터 1,048,575건입니다. 이 수치는 처리 성능을 보장하는 수치가 아닙니다.

## 문서 및 배포

- [분류 정책](docs/CLASSIFICATION.md)
- [GitHub 업로드 및 v1.0.0 릴리스 등록](docs/GITHUB_UPLOAD.md)
- [검증 기록](docs/VALIDATION.md)
- [변경 내역](CHANGELOG.md) · [릴리스 설명](RELEASE_NOTES.md)
- [기여 안내](CONTRIBUTING.md) · [보안 안내](SECURITY.md)

## 라이선스

현재 라이선스는 지정하지 않았습니다. 저장소 소유자가 배포 조건을 선택한 뒤 루트에 `LICENSE`를 추가하고 이 항목을 갱신하세요. 공개 저장소 게시만으로 오픈소스 라이선스가 부여되지는 않습니다. [GitHub 라이선스 안내](https://docs.github.com/en/repositories/managing-your-repositorys-settings-and-features/customizing-your-repository/licensing-a-repository)
