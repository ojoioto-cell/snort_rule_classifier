#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Snort Rule Classifier — GitHub 배포용 v1.0.0.

한 줄씩 저장된 룰을 단일 URL / 하위 디렉터리 / IP / 시그니처로 분류하고
Python 표준 라이브러리만으로 XLSX 파일을 생성합니다.

사용법:
    python snort_rule_classifier.py examples/sample.rules
    python snort_rule_classifier.py input.rules -o output/result.xlsx
    python snort_rule_classifier.py --version

기존 내부 v3.5 분류 정책을 기반으로 합니다. 판정용 정규화는 출력 룰에
적용하지 않습니다. 분류 기준과 제약은 docs/CLASSIFICATION.md를 참고하세요.
네트워크 접속, DNS 조회, 룰 실행, 보안장비 설정 변경을 수행하지 않습니다.
"""

from __future__ import annotations

import argparse
import ipaddress
import re
import shutil
import sys
import tempfile
import zipfile
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Sequence
from urllib.parse import unquote
from xml.sax.saxutils import escape as xml_escape


__version__ = "1.0.0"
EXCEL_MAX_ROWS = 1_048_576


# 단축 URL/리다이렉터 계열은 "부분 문자열"이 아니라 도메인 경계로만 매칭합니다.
# 예: t.co/abc, sub.t.co/x -> 시그니처
#     tooot.com, att.co, t.co.uk -> t.co 예외에 걸리지 않음
SHORTENER_DOMAINS: frozenset[str] = frozenset(
    item.casefold()
    for item in (
        "cutt.ly",
        "t.me",
        "t.ly",
        "t.co",
        "shorturl.at",
        "tinyurl.com",
        "surl.li",
        "bit.ly",
        "goo.gl",
        "ow.ly",
        "is.gd",
        "v.gd",
        "buff.ly",
        "rebrand.ly",
        "rb.gy",
        "tiny.cc",
        "lnkd.in",
        "trib.al",
        "bit.do",
        "short.io",
        "ln.run",
        "vo.la",
        "wasabisys.com",
        "u.to",
        "clck.ru",
        "urlz.fr",
        "j.mp",
        "t2m.io",
        "2ly.link",
        "surl.lu",
        "reurl.cc",
        "goo.su",
        "x.gd",
        "ppt.cc",
        "qrco.de",
        "lihi2.me",
        "tinyl.io",
        "shorten.ee",
        "srink.in",
        "tr.ee",
    )
)

# 아래 일반 예외 문자열은 기존 요구사항대로 대소문자 무시 + 부분 문자열 방식으로 처리합니다.
# 단축 URL 도메인은 위 SHORTENER_DOMAINS에서 별도로 처리하여 부분일치 오탐을 방지합니다.
EXCEPTION_STRINGS: tuple[str, ...] = tuple(
    item.strip().casefold()
    for item in (
        "GitHub",
        "Microsoft",
        "daum.net",
        "dropbox",
        "google",
        "telegram",
        "amazonaws.com",
        "live.com",
        "discord",
        "raw.githubusercontent.com",
        "mail-bigfile.hiworks.biz",
        "api.github.com",
        "pixeldrain.com",
        "ps.pndsn.com",
        "hypernotepad.com",
        "oraclecloud.com",
        "lite.evernote.com",
        "share.evernote.com",
        "ipfs.io",
        "sawert.dynamic-dns.net",
        "mega.nz",
    )
)

# URL처럼 보이는 도메인은 IANA/TLD 유효성 여부와 관계없이 URL 후보로 인정합니다.
# 다만 content 전체가 단순 파일명(예: index.php, history.txt)처럼 보이는 경우의
# 명백한 오분류를 줄이기 위해 2-label bare 문자열에 한해서 아래 확장자를 제외합니다.
BARE_FILE_SUFFIXES: frozenset[str] = frozenset(
    {
        "7z", "apk", "asp", "aspx", "au3", "bat", "bin", "bmp", "bz2",
        "class", "cmd", "conf", "cfg", "csv", "dat", "db", "dll", "doc",
        "docx", "exe", "gif", "gz", "htm", "html", "ico", "ini", "jar",
        "jpeg", "jpg", "js", "json", "log", "pdf", "php", "phtml", "png",
        "ppt", "pptx", "ps1", "py", "rar", "sh", "sql", "svg", "tar",
        "tgz", "txt", "war", "xls", "xlsx", "xml", "yaml", "yml", "zip",
    }
)


# 점(.)으로 이어진 Java 패키지명, 객체 속성, 프레임워크 내부 경로가
# 도메인처럼 보이는 경우를 URL로 잘못 분류하지 않기 위한 휴리스틱입니다.
# 단일 단어만으로 차단하지 않고, 고신뢰 키워드·접두 조합·CamelCase·룰 옵션을
# 함께 평가하여 실제 도메인 오탐을 줄입니다.
CODE_CHAIN_HIGH_SIGNAL_LABELS: frozenset[str] = frozenset(
    {
        "classloader",
        "getclass",
        "protectiondomain",
        "codesource",
        "runtime",
        "processbuilder",
        "scriptengine",
        "scriptenginemanager",
        "elprocessor",
        "templatesimpl",
        "transformerfactory",
        "objectmapper",
        "initialcontext",
        "trusturlcodebase",
        "classforname",
        "newinstance",
        "filedateformat",
        "catalina",
        "servlet",
        "springframework",
        "jndi",
        "ognl",
        "freemarker",
        "velocity",
        "groovy",
    }
)

CODE_CHAIN_GENERAL_LABELS: frozenset[str] = frozenset(
    {
        "class",
        "module",
        "resource",
        "resources",
        "context",
        "parent",
        "pipeline",
        "first",
        "pattern",
        "suffix",
        "directory",
        "prefix",
        "java",
        "javax",
        "jakarta",
        "lang",
        "org",
        "apache",
        "tomcat",
        "jetty",
        "sun",
        "fasterxml",
        "spring",
        "bean",
        "beans",
        "factory",
        "loader",
        "system",
        "exec",
        "method",
        "property",
        "properties",
        "field",
        "request",
        "response",
        "session",
        "core",
        "naming",
        "lookup",
        "ldap",
        "rmi",
        "jdbc",
    }
)

# 실제 코드 네임스페이스에서 자주 나타나는 연속 label 조합입니다.
CODE_CHAIN_PREFIXES: tuple[tuple[str, ...], ...] = (
    ("class", "module"),
    ("java", "lang"),
    ("javax", "servlet"),
    ("jakarta", "servlet"),
    ("org", "apache"),
    ("org", "springframework"),
    ("com", "sun"),
    ("com", "fasterxml"),
)

# 점 문자열이 단순 IoC가 아니라 행위/취약점 탐지 패턴일 가능성을 높이는 옵션입니다.
CODE_CHAIN_BEHAVIOR_OPTIONS: frozenset[str] = frozenset(
    {
        "pcre",
        "flow",
        "fast_pattern",
        "nocase",
        "distance",
        "within",
        "offset",
        "depth",
        "byte_test",
        "byte_jump",
        "isdataat",
        "dsize",
        "uricontent",
        "http_uri",
        "http_header",
        "http_method",
        "http_client_body",
        "file_data",
    }
)

ACTIONS = (
    "alert",
    "drop",
    "reject",
    "pass",
    "log",
    "sdrop",
    "activate",
    "dynamic",
)

PROTOCOLS = (
    "tcp",
    "udp",
    "icmp",
    "icmp6",
    "ip",
    "ipv6",
    "http",
    "tls",
    "dns",
    "ftp",
    "smtp",
    "ssh",
)

RULE_START_RE = re.compile(
    rf"(?:(?<=\|)|^)\s*(?P<action>{'|'.join(ACTIONS)})\s+"
    rf"(?P<protocol>{'|'.join(PROTOCOLS)})\b",
    re.IGNORECASE,
)

# 악성 IoC에서는 실제 DNS hostname 문법보다 느슨한 host 문자열이 사용되는 경우가 있습니다.
# 예: sample_host.example.test
# 따라서 URL 분류용 도메인 후보에서는 비최종 label의 '_'를 허용합니다.
# 단, 마지막 suffix/TLD label은 기존처럼 영문/숫자/하이픈만 허용해 과도한 오탐을 제한합니다.
IOC_DOMAIN_LABEL = r"[A-Za-z0-9_](?:[A-Za-z0-9_-]{0,61}[A-Za-z0-9_])?"
IOC_TLD_LABEL = r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?"

DOMAIN_RE = re.compile(
    rf"(?<![A-Za-z0-9_-])"
    rf"(?:(?:https?|hxxps?|ftp)://)?"
    rf"\.?"
    rf"(?:{IOC_DOMAIN_LABEL}\.)+"
    rf"{IOC_TLD_LABEL}"
    rf"\.?"
    rf"(?::\d{{1,5}})?"
    rf"(?:/[^\s\"']*)?",
    re.IGNORECASE,
)

IPV4_CANDIDATE_RE = re.compile(r"(?<!\d)(?:\d{1,3}\.){3}\d{1,3}(?:/\d{1,2})?(?!\d)")

HEADER_RE = re.compile(
    r"^\s*\S+\s+(?P<protocol>tcp|udp|ip)\s+"
    r"(?P<src>\S+)\s+(?P<src_port>\S+)\s+"
    r"(?P<direction>->|<>|<-)\s+"
    r"(?P<dst>\S+)\s+(?P<dst_port>\S+)\s*$",
    re.IGNORECASE,
)

CONTENT_RE = re.compile(
    r'^content\s*:\s*(?P<negated>!)?\s*"(?P<value>(?:\\.|[^"\\])*)"',
    re.IGNORECASE | re.DOTALL,
)

MSG_RE = re.compile(
    r'^msg\s*:\s*"(?P<value>(?:\\.|[^"\\])*)"',
    re.IGNORECASE | re.DOTALL,
)

ALLOWED_IP_OPTION_NAMES: frozenset[str] = frozenset({"msg", "sid", "flags"})
ALLOWED_CONTENT_IP_OPTION_NAMES: frozenset[str] = frozenset({"content", "msg", "sid", "flags"})

INVALID_XML_CHAR_RE = re.compile(
    "[\x00-\x08\x0B\x0C\x0E-\x1F\uD800-\uDFFF\uFFFE\uFFFF]"
)


@dataclass(frozen=True)
class ParsedLine:
    number: str
    msg: str
    rule: str


@dataclass(frozen=True)
class Classification:
    category: str
    reason: str
    evidence_content: str


@dataclass(frozen=True)
class ResultRow:
    number: str
    msg: str
    rule: str
    category: str
    reason: str
    evidence_content: str

    def as_cells(self) -> list[str]:
        return [
            self.number,
            self.msg,
            self.rule,
            self.category,
            self.reason,
            self.evidence_content,
        ]


def read_text_auto(path: Path, encoding: str | None = None) -> tuple[str, str]:
    """지정 인코딩 또는 UTF-8/CP949/EUC-KR 순서로 입력을 읽습니다.

    자동 판별은 순차 디코딩 시도이며 통계적 인코딩 탐지가 아닙니다.
    latin-1 대체 디코딩 시 CLI에서 경고합니다.
    """
    raw = path.read_bytes()
    if encoding is not None:
        return raw.decode(encoding).removeprefix("\ufeff"), encoding
    encodings = ("utf-8-sig", "utf-8", "cp949", "euc-kr") if raw.startswith(b"\xef\xbb\xbf") else ("utf-8", "cp949", "euc-kr")
    for encoding in encodings:
        try:
            return raw.decode(encoding), encoding
        except UnicodeDecodeError:
            continue
    # 바이트는 보존하지만 원래 언어의 글자가 정확히 복원되지는 않을 수 있습니다.
    return raw.decode("latin-1"), "latin-1"


def find_rule_start(line: str) -> int | None:
    """실제 Snort 헤더 형태인 action/protocol/.../direction을 찾아 시작 위치를 반환합니다."""
    for match in RULE_START_RE.finditer(line):
        start = match.start("action")
        candidate = line[start:]
        option_pos = candidate.find("(")
        header = candidate if option_pos < 0 else candidate[:option_pos]
        if re.search(r"\s(?:->|<>|<-)\s", header):
            return start
    return None


def unescape_snort_string(value: str) -> str:
    """Snort 따옴표 문자열의 일반적인 역슬래시 이스케이프를 해제합니다."""
    output: list[str] = []
    index = 0
    while index < len(value):
        char = value[index]
        if char != "\\" or index + 1 >= len(value):
            output.append(char)
            index += 1
            continue

        nxt = value[index + 1]
        if nxt in "xX" and index + 3 < len(value):
            pair = value[index + 2 : index + 4]
            if re.fullmatch(r"[0-9A-Fa-f]{2}", pair):
                output.append(chr(int(pair, 16)))
                index += 4
                continue

        escape_map = {"n": "\n", "r": "\r", "t": "\t"}
        output.append(escape_map.get(nxt, nxt))
        index += 2

    return "".join(output)


def decode_pipe_hex(value: str) -> str:
    """content의 |68 74 74 70| 형식 바이트 블록을 판정용 문자열로 변환합니다."""

    def replace(match: re.Match[str]) -> str:
        hex_text = match.group(1)
        try:
            data = bytes.fromhex(hex_text)
        except ValueError:
            return match.group(0)
        try:
            return data.decode("utf-8")
        except UnicodeDecodeError:
            return data.decode("latin-1")

    return re.sub(r"\|((?:\s*[0-9A-Fa-f]{2})+\s*)\|", replace, value)


def normalize_content(value: str) -> str:
    value = decode_pipe_hex(value)
    value = unescape_snort_string(value)
    try:
        value = unquote(value)
    except Exception:
        pass
    return value


# 일부 수집·전처리 과정에서 |2E| 또는 |20|의 파이프가 제거되고,
# 바이트 값만 공백으로 분리된 URL 패턴을 제한적으로 복원합니다.
#
# 예:
#   20 sample.example.test      -> sample.example.test
#   sample 2e example 2e test   -> sample.example.test
#   2e sample 2e example 2e     -> .sample.example.
#
# 2자리 16진수처럼 보이는 모든 토큰을 디코딩하지 않습니다.
# 특히 c1 같은 실제 도메인 label은 그대로 유지하고, URL 구분자로
# 명확히 사용된 2e와 맨 앞의 20만 URL 판정 시에 처리합니다.
LOOSE_URL_DOT_TOKEN_RE = re.compile(r"(?<!\S)2e(?!\S)", re.IGNORECASE)
LOOSE_URL_LEADING_SPACE_TOKEN_RE = re.compile(r"^\s*20[ \t]+", re.IGNORECASE)
LOOSE_URL_DOT_SENTINEL = "\uE000"


def decode_loose_url_hex_tokens(value: str) -> str:
    """파이프가 유실된 URL용 2e/선행 20 토큰을 보수적으로 복원합니다."""
    value = LOOSE_URL_LEADING_SPACE_TOKEN_RE.sub("", value, count=1)

    if LOOSE_URL_DOT_TOKEN_RE.search(value):
        # 치환한 점의 앞뒤 공백만 제거하기 위해 임시 문자를 사용합니다.
        # 원래 문자열에 임시 문자가 있으면 오인하지 않도록 다른 값을 선택합니다.
        sentinel = LOOSE_URL_DOT_SENTINEL
        while sentinel in value:
            sentinel += "\uE001"
        value = LOOSE_URL_DOT_TOKEN_RE.sub(sentinel, value)
        value = re.sub(rf"[ \t]*{re.escape(sentinel)}[ \t]*", ".", value)

    return value


def normalize_url_content(value: str) -> str:
    """일반 content 정규화 후 URL 판정에 필요한 유실 토큰만 추가 복원합니다."""
    return decode_loose_url_hex_tokens(normalize_content(value))


HOST_HEADER_PREFIX_RE = re.compile(r"^\s*host\s*:\s*", re.IGNORECASE)
# 정상 파이프가 전처리 과정에서 일부 또는 모두 제거된 형태도 제한적으로 복구합니다.
# 예: Host3A 20example.com, Host|3A 20example.com, Host3A 20|example.com
HOST_HEX_TEXT_PREFIX_RE = re.compile(
    r"^\s*host\s*(?:\|\s*)?3a\s*20(?:\s*\|)?\s*",
    re.IGNORECASE,
)


def split_host_url_candidate(value: str) -> tuple[str, str]:
    """첫 content에서 Host 계열 접두부를 제거하고 URL 후보와 접두 유형을 반환합니다.

    접두 유형:
    - plain: 일반 URL/도메인
    - loose_hex_recovered: 공백 분리형 2e/선행 20을 복원한 URL
    - host_header: 정상 디코딩된 Host: URL
    - host_hex_text: 파이프가 남아 있는 Host|3A 20| 텍스트
    - host_hex_recovered: 파이프가 일부 또는 모두 제거된 Host3A 20 텍스트
    """
    base_normalized = normalize_content(value).strip()
    normalized = decode_loose_url_hex_tokens(base_normalized).strip()
    loose_hex_recovered = normalized != base_normalized

    if not normalized:
        return "", "plain"

    header_match = HOST_HEADER_PREFIX_RE.match(normalized)
    if header_match:
        return normalized[header_match.end() :].strip(), "host_header"

    hex_match = HOST_HEX_TEXT_PREFIX_RE.match(normalized)
    if hex_match:
        matched_prefix = normalized[: hex_match.end()]
        prefix_kind = "host_hex_text" if matched_prefix.count("|") >= 2 else "host_hex_recovered"
        return normalized[hex_match.end() :].strip(), prefix_kind

    prefix_kind = "loose_hex_recovered" if loose_hex_recovered else "plain"
    return normalized, prefix_kind


def describe_url_form(prefix_kind: str) -> str:
    """근거 문구에 사용할 URL content 형식명을 반환합니다."""
    return {
        "plain": "URL/도메인",
        "loose_hex_recovered": "공백 분리형 2e/20 복원 URL",
        "host_header": "Host 헤더 접두 URL",
        "host_hex_text": "Host|3A 20| 접두 URL",
        "host_hex_recovered": "파이프 유실 Host3A 20 접두 URL",
    }.get(prefix_kind, "URL/도메인")


def split_snort_options(rule: str) -> list[str]:
    """따옴표 내부의 ;를 건드리지 않고 Snort 옵션을 분리합니다."""
    open_pos = rule.find("(")
    close_pos = rule.rfind(")")
    if open_pos < 0:
        return []
    if close_pos <= open_pos:
        close_pos = len(rule)

    body = rule[open_pos + 1 : close_pos]
    options: list[str] = []
    current: list[str] = []
    in_quote = False
    escaped = False

    for char in body:
        if escaped:
            current.append(char)
            escaped = False
            continue
        if char == "\\" and in_quote:
            current.append(char)
            escaped = True
            continue
        if char == '"':
            current.append(char)
            in_quote = not in_quote
            continue
        if char == ";" and not in_quote:
            option = "".join(current).strip()
            if option:
                options.append(option)
            current = []
            continue
        current.append(char)

    final = "".join(current).strip()
    if final:
        options.append(final)
    return options


def extract_contents(rule: str) -> list[str]:
    contents: list[str] = []
    for option in split_snort_options(rule):
        match = CONTENT_RE.match(option)
        if match:
            contents.append(match.group("value"))
    return contents


def extract_msg_from_rule(rule: str) -> str:
    for option in split_snort_options(rule):
        match = MSG_RE.match(option)
        if match:
            return unescape_snort_string(match.group("value"))
    return ""


def extract_option_name(option: str) -> str:
    """Snort 옵션에서 첫 콜론 앞의 옵션명을 소문자로 반환합니다."""
    name, separator, _ = option.partition(":")
    if not separator:
        return option.strip().casefold()
    return name.strip().casefold()


def extract_option_names(rule: str) -> frozenset[str]:
    """룰에 사용된 옵션명을 중복 없이 반환합니다."""
    return frozenset(
        name
        for option in split_snort_options(rule)
        if (name := extract_option_name(option))
    )


def find_code_chain_prefixes(labels: Sequence[str]) -> list[str]:
    """label 배열에서 알려진 코드 네임스페이스 조합을 찾습니다."""
    found: list[str] = []
    lowered = [label.casefold() for label in labels]

    for prefix in CODE_CHAIN_PREFIXES:
        size = len(prefix)
        for index in range(0, len(lowered) - size + 1):
            if tuple(lowered[index : index + size]) == prefix:
                found.append(".".join(prefix))
                break
    return found


def is_camel_case_label(label: str) -> bool:
    """classLoader, HttpServletRequest 같은 내부 대문자 사용을 찾습니다."""
    return bool(re.search(r"[a-z0-9][A-Z]|[A-Z][a-z0-9]+[A-Z]", label))


def detect_dotted_code_chain(value: str, rule: str) -> str | None:
    """
    도메인처럼 보이지만 실제로는 Java/프레임워크 패키지명 또는 객체 속성 체인인
    content를 탐지합니다.

    보수적 판정 원칙:
    - http(s)://, hxxp(s)://, ftp://, 경로(/), 쿼리(?), fragment(#), 사용자정보(@),
      명시적 포트가 있으면 URL 근거가 강하므로 이 휴리스틱을 적용하지 않습니다.
    - 최소 3개 label이면서 코드 의미 키워드가 복수로 결합된 경우만 차단합니다.
    - 단순히 점이 많거나 TLD가 비표준이라는 이유만으로는 차단하지 않습니다.
    """
    normalized = normalize_url_content(value).strip()
    if not normalized:
        return None

    # scheme/path/query/fragment/user-info/port는 실제 URL의 강한 증거입니다.
    if re.match(r"^(?:https?|hxxps?|ftp)://", normalized, re.IGNORECASE):
        return None
    if any(marker in normalized for marker in ("/", "?", "#", "@")):
        return None
    if re.search(r":\d{1,5}\.?$", normalized):
        return None

    # 선행 점은 .example.com 같은 도메인 suffix 패턴일 수 있으므로 제외합니다.
    if normalized.startswith("."):
        return None

    trailing_dot = normalized.endswith(".")
    host = normalized[:-1] if trailing_dot else normalized
    if not host or not re.fullmatch(r"[A-Za-z0-9.-]+", host):
        return None

    labels = host.split(".")
    if len(labels) < 3 or any(not label for label in labels):
        return None

    lowered = [label.casefold() for label in labels]
    high_hits = sorted({label for label in lowered if label in CODE_CHAIN_HIGH_SIGNAL_LABELS})
    general_hits = sorted({label for label in lowered if label in CODE_CHAIN_GENERAL_LABELS})
    prefix_hits = find_code_chain_prefixes(labels)
    camel_hits = [label for label in labels if is_camel_case_label(label)]

    option_names = extract_option_names(rule)
    behavior_hits = sorted(option_names & CODE_CHAIN_BEHAVIOR_OPTIONS)

    # 의미 기반 조건을 먼저 계산합니다. 아래 중 하나도 충족하지 않으면 URL 후보를 유지합니다.
    strong_semantic_chain = bool(high_hits) and (
        bool(prefix_hits) or bool(camel_hits) or len(general_hits) >= 2
    )
    property_chain = len(labels) >= 5 and len(general_hits) >= 4
    namespace_chain = bool(prefix_hits) and (
        bool(high_hits) or len(general_hits) >= 3 or bool(camel_hits)
    )

    if not (strong_semantic_chain or property_chain or namespace_chain):
        return None

    # 점 문자열만으로 결론 내리지 않고 구조/옵션 근거를 점수화합니다.
    score = 0
    score += min(len(high_hits) * 3, 6)
    score += min(len(general_hits), 5)
    score += 3 if prefix_hits else 0
    score += 2 if camel_hits else 0
    score += 2 if len(labels) >= 6 else (1 if len(labels) >= 4 else 0)
    score += 1 if trailing_dot else 0
    score += 2 if "pcre" in option_names else 0
    score += 1 if "flow" in option_names else 0
    score += 1 if "fast_pattern" in option_names else 0
    score += 1 if len(behavior_hits) >= 3 else 0

    if score < 7:
        return None

    details: list[str] = []
    if high_hits:
        details.append("고신뢰 코드 label=" + ",".join(high_hits))
    if general_hits:
        details.append("속성/네임스페이스 label=" + ",".join(general_hits))
    if prefix_hits:
        details.append("코드 접두=" + ",".join(prefix_hits))
    if camel_hits:
        details.append("CamelCase=" + ",".join(camel_hits))
    if behavior_hits:
        details.append("탐지 옵션=" + ",".join(behavior_hits))

    return (
        "첫 번째 content가 도메인이 아니라 Java/프레임워크 패키지·객체 속성 체인으로 판단됨"
        f"(점수={score}; {'; '.join(details)})"
    )


def find_disallowed_ip_option(rule: str) -> str | None:
    """헤더 IP 분류에서 허용되지 않는 첫 옵션명을 반환합니다."""
    for option in split_snort_options(rule):
        name = extract_option_name(option)
        if name and name not in ALLOWED_IP_OPTION_NAMES:
            return name
    return None


def find_disallowed_content_ip_option(rule: str) -> str | None:
    """content IP 분류에서 허용되지 않는 첫 옵션명을 반환합니다."""
    for option in split_snort_options(rule):
        name = extract_option_name(option)
        if name and name not in ALLOWED_CONTENT_IP_OPTION_NAMES:
            return name
    return None


def parse_input_line(line: str, sequence: int) -> ParsedLine:
    line = line.rstrip("\r\n")
    start = find_rule_start(line)

    if start is None:
        rule = line.strip()
        return ParsedLine(str(sequence), extract_msg_from_rule(rule), rule)

    rule = line[start:].rstrip()
    prefix = line[:start].rstrip()
    if prefix.endswith("|"):
        prefix = prefix[:-1]

    number = ""
    msg = ""
    if prefix:
        if "|" in prefix:
            number, msg = prefix.split("|", 1)
        else:
            number = prefix

    number = number.strip() or str(sequence)
    msg = msg.strip() or extract_msg_from_rule(rule)
    return ParsedLine(number, msg, rule)


def extract_url_host(value: str) -> str | None:
    """URL/도메인형 문자열에서 scheme/port/path를 제거한 호스트만 반환합니다."""
    normalized = normalize_url_content(value).strip()
    match = DOMAIN_RE.search(normalized)
    if match is None:
        return None

    domain_text = match.group(0)
    host_port_path = re.sub(
        r"^(?:https?|hxxps?|ftp)://", "", domain_text, flags=re.IGNORECASE
    )
    host_port = host_port_path.split("/", 1)[0]
    host = host_port.rsplit(":", 1)[0].strip().strip(".")
    return host.casefold() if host else None


def find_shortener_exception(contents: Sequence[str]) -> str | None:
    """
    단축 URL 예외를 도메인 경계로 판정합니다.

    host == shortener 또는 host가 shortener의 하위 도메인일 때만 매칭합니다.
    따라서 'airankagent.com' 안의 우연한 't.co' 문자열이나 'tooot.com'은
    t.co 예외로 분류하지 않습니다.
    """
    for raw_content in contents:
        normalized = normalize_url_content(raw_content)
        host_candidate, _ = split_host_url_candidate(raw_content)

        # 파이프 유실형 Host3A 20URL에서도 기존 단축 URL 예외 정책을 유지합니다.
        candidates = tuple(dict.fromkeys((normalized, host_candidate)))
        for candidate in candidates:
            for match in DOMAIN_RE.finditer(candidate):
                domain_text = match.group(0)
                host_port_path = re.sub(
                    r"^(?:https?|hxxps?|ftp)://", "", domain_text, flags=re.IGNORECASE
                )
                host_port = host_port_path.split("/", 1)[0]
                host = host_port.rsplit(":", 1)[0].strip().strip(".").casefold()
                if not host:
                    continue

                for shortener in sorted(SHORTENER_DOMAINS):
                    if host == shortener or host.endswith("." + shortener):
                        return shortener
    return None


def find_exception(contents: Sequence[str]) -> str | None:
    # 1) 단축 URL: 도메인 경계 매칭
    shortener = find_shortener_exception(contents)
    if shortener:
        return shortener

    # 2) 기타 예외: 기존 요구사항대로 부분 문자열 매칭
    for raw_content in contents:
        host_candidate, _ = split_host_url_candidate(raw_content)
        candidates = (
            raw_content.casefold(),
            normalize_url_content(raw_content).casefold(),
            host_candidate.casefold(),
        )
        for exception in EXCEPTION_STRINGS:
            if any(exception in candidate for candidate in candidates):
                return exception
    return None


def find_domain(value: str) -> str | None:
    """
    content 안에서 URL/도메인 형태 문자열을 찾습니다.

    중요: IANA Root Zone 또는 실제 TLD 존재 여부는 검사하지 않습니다.
    따라서 .stor, .onlin, .u, .c0m처럼 비표준/잘린 suffix도 도메인 형태이면
    URL 후보가 될 수 있습니다. 또한 악성 IoC에서 관찰되는 비최종 label의
    밑줄(_)도 허용합니다.
    """
    normalized = normalize_url_content(value)
    for match in DOMAIN_RE.finditer(normalized):
        domain_text = match.group(0)
        has_scheme = bool(re.match(r"^(?:https?|hxxps?|ftp)://", domain_text, re.IGNORECASE))

        host_port_path = re.sub(
            r"^(?:https?|hxxps?|ftp)://", "", domain_text, flags=re.IGNORECASE
        )
        host_port = host_port_path.split("/", 1)[0]
        host = host_port.rsplit(":", 1)[0].strip().strip(".")

        # IPv4(/CIDR)는 도메인으로 승격하지 않습니다.
        if find_ipv4(host):
            continue

        labels = host.casefold().split(".")
        if len(labels) < 2 or any(not label for label in labels):
            continue

        # TLD 유효성 검증은 하지 않되, 단순 '파일명.확장자' 오분류는 제한합니다.
        # 예: history.txt, index.php, payload.dll -> 시그니처 후보
        # 반면 www.example.php, sub.example.txt 같은 다중 label은 URL 형태로 인정합니다.
        has_path = "/" in host_port_path
        had_leading_dot = domain_text.startswith(".")
        if (
            not has_scheme
            and not had_leading_dot
            and not has_path
            and len(labels) == 2
            and labels[-1] in BARE_FILE_SUFFIXES
        ):
            continue

        return domain_text
    return None

def find_pure_domain(value: str) -> str | None:
    """content 전체가 URL/도메인일 때만 정규화된 값을 반환합니다."""
    normalized = normalize_url_content(value).strip()
    if not normalized:
        return None
    if DOMAIN_RE.fullmatch(normalized) is None:
        return None
    domain = find_domain(normalized)
    return normalized if domain == normalized else None


def contains_host_hex_prefix(value: str) -> bool:
    """Host:, Host|3A 20|, 파이프 유실 Host3A 20 형태를 식별합니다."""
    _, prefix_kind = split_host_url_candidate(value)
    return prefix_kind != "plain"


def extract_first_url_content(value: str) -> tuple[str, str] | None:
    """첫 번째 content에서 URL/도메인과 Host 접두 유형을 추출합니다.

    Host 계열 접두부는 판정할 때만 제거하며 실제 원문 룰은 변경하지 않습니다.
    파이프 유실형은 접두부 제거 후 남은 전체 문자열이 도메인/URL일 때만 인정합니다.
    """
    candidate, prefix_kind = split_host_url_candidate(value)
    if not candidate:
        return None

    domain = find_pure_domain(candidate)
    if not domain:
        return None
    return domain, prefix_kind


def is_host_prefix_only_content(value: str) -> tuple[bool, str]:
    """content 전체가 Host 헤더 접두부만인지 판정합니다.

    다음 표기를 모두 대소문자와 무관하게 동일하게 취급합니다.
    - Host|3A 20| / Host|3a 20|
    - 디코딩된 Host:
    - 파이프가 일부 또는 전부 유실된 Host3A 20 / Host3a 20
    """
    candidate, prefix_kind = split_host_url_candidate(value)
    return prefix_kind != "plain" and not candidate, prefix_kind


def extract_split_host_url_contents(contents: Sequence[str]) -> tuple[str, str] | None:
    """분리된 Host 헤더와 도메인 content를 URL 후보로 추출합니다.

    예:
        content:"Host|3A 20|"; content:"example.com";
        content:"Host|3a 20|"; content:"example.com";

    첫 번째 content는 Host 계열 접두부만 포함하고, 두 번째 content 전체가
    URL/도메인일 때만 인정합니다. 실제 Snort 룰 원문은 변경하지 않습니다.
    """
    if len(contents) < 2:
        return None

    host_prefix_only, prefix_kind = is_host_prefix_only_content(contents[0])
    if not host_prefix_only:
        return None

    domain = find_pure_domain(contents[1])
    if not domain:
        return None

    return domain, prefix_kind


def url_has_subdirectory(value: str) -> bool:
    """URL/도메인 값에 호스트 뒤 경로(/...)가 포함되어 있는지 확인합니다."""
    normalized = normalize_url_content(value).strip()
    normalized = re.sub(r"^(?:https?|hxxps?|ftp)://", "", normalized, flags=re.IGNORECASE)
    _, separator, path = normalized.partition("/")
    return bool(separator and path)


def find_ipv4(value: str) -> str | None:
    normalized = normalize_content(value)
    for match in IPV4_CANDIDATE_RE.finditer(normalized):
        candidate = match.group(0)
        try:
            if "/" in candidate:
                interface = ipaddress.ip_interface(candidate)
                if isinstance(interface.ip, ipaddress.IPv4Address):
                    return candidate
            else:
                address = ipaddress.ip_address(candidate)
                if isinstance(address, ipaddress.IPv4Address):
                    return candidate
        except ValueError:
            continue
    return None


def is_url_subpath(value: str) -> bool:
    """두 번째 이후 content가 URL 하위 경로인지 판정합니다.

    파일명·디렉터리에 포함된 일반 공백(U+0020)과 디코딩된 %20은 허용합니다.
    탭·개행·기타 제어문자는 URL 경로로 인정하지 않습니다.
    """
    normalized = normalize_content(value)
    if not normalized:
        return False

    # 일반 공백은 허용하되 탭·개행·기타 제어문자 및 특수 공백은 차단합니다.
    if any(
        ord(char) < 0x20
        or ord(char) == 0x7F
        or (char.isspace() and char != " ")
        for char in normalized
    ):
        return False

    normalized = normalized.strip(" ")
    return normalized.startswith("/")


def extract_header(rule: str) -> str:
    option_pos = rule.find("(")
    return (rule if option_pos < 0 else rule[:option_pos]).strip()


def is_any(value: str) -> bool:
    return value.strip().casefold() == "any"


def validate_ipv4_token(value: str) -> str | None:
    """토큰 전체가 단일 IPv4 또는 IPv4/CIDR일 때 원문 값을 반환합니다."""
    token = value.strip()
    try:
        if "/" in token:
            interface = ipaddress.ip_interface(token)
            return token if isinstance(interface.ip, ipaddress.IPv4Address) else None
        address = ipaddress.ip_address(token)
        return token if isinstance(address, ipaddress.IPv4Address) else None
    except ValueError:
        return None


def find_pure_ipv4(value: str) -> str | None:
    """content 전체가 IPv4 또는 IPv4/CIDR일 때만 반환합니다."""
    normalized = normalize_content(value).strip()
    if not normalized or IPV4_CANDIDATE_RE.fullmatch(normalized) is None:
        return None
    return validate_ipv4_token(normalized)


def match_ip_header(rule: str) -> tuple[str, str, str, str, str] | None:
    """
    헤더에 존재하는 단일 IPv4/CIDR 후보를 찾습니다.

    한쪽 주소가 단일 IPv4/CIDR이고 반대쪽이 any any이면 후보입니다.
    IP 측 포트는 함께 반환하며, 최종 IP 분류는 포트가 정확히 any일 때만 허용합니다.
    숫자·범위·변수·부정 포트 등 any 이외의 값은 시그니처입니다.
    """
    match = HEADER_RE.match(extract_header(rule))
    if not match:
        return None

    direction = match.group("direction")
    if direction not in {"<>", "->"}:
        return None

    protocol = match.group("protocol").casefold()
    src = match.group("src")
    src_port = match.group("src_port")
    dst = match.group("dst")
    dst_port = match.group("dst_port")

    src_ip = validate_ipv4_token(src)
    dst_ip = validate_ipv4_token(dst)

    if src_ip and is_any(dst) and is_any(dst_port):
        return src_ip, "출발지", protocol, direction, src_port
    if is_any(src) and is_any(src_port) and dst_ip:
        return dst_ip, "목적지", protocol, direction, dst_port
    return None


def match_generic_any_header(rule: str) -> tuple[str, str] | None:
    """주소와 포트가 모두 any인 TCP/UDP/IP 헤더를 확인합니다."""
    match = HEADER_RE.match(extract_header(rule))
    if not match:
        return None

    direction = match.group("direction")
    if direction not in {"<>", "->"}:
        return None

    if not all(
        is_any(match.group(name))
        for name in ("src", "src_port", "dst", "dst_port")
    ):
        return None

    return match.group("protocol").casefold(), direction


def classify_content_ip(rule: str, contents: Sequence[str]) -> Classification | None:
    """
    any any 헤더의 단일 양성 content 전체가 IPv4/CIDR이면 IP로 분류합니다.

    복수 content, 부정 content, IP 부분 문자열, 구체 주소·포트가 있는 헤더,
    또는 content/msg/sid/flags 외 추가 탐지 옵션이 있으면 시그니처입니다.
    """
    if not contents:
        return None

    ip_value = find_pure_ipv4(contents[0])
    if ip_value is None:
        return None

    if len(contents) != 1:
        return Classification(
            "시그니처",
            f"첫 번째 content 전체가 IPv4/CIDR '{ip_value}'이나 content가 {len(contents)}개 존재",
            rule,
        )

    content_options = [
        option
        for option in split_snort_options(rule)
        if extract_option_name(option) == "content"
    ]
    if len(content_options) != 1:
        return Classification(
            "시그니처",
            f"IPv4/CIDR content '{ip_value}'의 content 옵션 개수가 1개가 아님",
            rule,
        )

    content_match = CONTENT_RE.match(content_options[0])
    if (
        content_match is None
        or content_options[0][content_match.end() :].strip()
        or content_match.group("negated")
    ):
        return Classification(
            "시그니처",
            f"IPv4/CIDR content '{ip_value}'가 부정 조건이거나 순수 content 옵션이 아님",
            rule,
        )

    generic_header = match_generic_any_header(rule)
    if generic_header is None:
        return Classification(
            "시그니처",
            f"content 전체가 IPv4/CIDR '{ip_value}'이나 헤더가 any any <>/-> any any가 아님",
            rule,
        )

    disallowed_option = find_disallowed_content_ip_option(rule)
    if disallowed_option:
        return Classification(
            "시그니처",
            f"IPv4/CIDR content '{ip_value}'가 있으나 허용 옵션(content, msg, sid, flags) 외 "
            f"'{disallowed_option}' 옵션이 존재",
            rule,
        )

    protocol, direction = generic_header
    return Classification(
        "IP",
        f"{protocol.upper()} {direction} 헤더가 any any 대 any any이고 "
        f"단일 content 전체가 IPv4/CIDR '{ip_value}'임",
        ip_value,
    )

def summarize_value(value: str, limit: int = 70) -> str:
    normalized = normalize_content(value).replace("\n", "\\n").replace("\r", "\\r")
    if len(normalized) <= limit:
        return normalized
    return normalized[: limit - 1] + "…"


def classify_rule(rule: str) -> Classification:
    contents = extract_contents(rule)

    # 부정 content는 해당 지표가 일치하지 않는 조건이므로 순수 IoC로 분류하지 않습니다.
    for option in split_snort_options(rule):
        match = CONTENT_RE.match(option)
        if match and match.group("negated"):
            return Classification(
                "시그니처",
                "부정 content 조건(content:!)이 있어 순수 URL/IP 지표로 분류하지 않음",
                rule,
            )

    # 1. 명시적 URL 예외 문자열: 모든 content에서 대소문자 무시·부분 일치합니다.
    #    URL처럼 보여도 예외 목록이면 항상 시그니처가 우선합니다.
    exception = find_exception(contents)
    if exception:
        return Classification(
            "시그니처",
            f"예외 문자열/도메인 '{exception}'이 content에 해당하여 시그니처 우선",
            rule,
        )

    # 2. Host|3A 20|domain 및 파이프 유실 Host3A 20domain도 URL 후보로 인정합니다.
    #    접두부 제거 후 남은 전체 문자열이 URL/도메인일 때만 허용합니다.

    # 3. 점(.)으로 이어진 코드/객체 속성 체인은 도메인처럼 보여도 시그니처입니다.
    if contents:
        code_chain_reason = detect_dotted_code_chain(contents[0], rule)
        if code_chain_reason:
            return Classification(
                "시그니처",
                code_chain_reason,
                rule,
            )

    # 4. 헤더 IPv4/CIDR 판정을 URL보다 먼저 수행합니다.
    #    IP 측 포트가 any여야 순수 IP 지표입니다. 그 외 포트 조건은 시그니처입니다.
    header_ip = match_ip_header(rule)
    if header_ip:
        ip_value, position, protocol, direction, ip_port = header_ip
        if not is_any(ip_port):
            return Classification(
                "시그니처",
                f"{protocol.upper()} {direction} 헤더의 {position}에 IPv4/CIDR '{ip_value}'가 있으나 "
                f"IP 측 포트 조건 '{ip_port}'이 설정되어 순수 IP 지표가 아님",
                rule,
            )

        disallowed_option = find_disallowed_ip_option(rule)
        if disallowed_option:
            return Classification(
                "시그니처",
                f"{protocol.upper()} 헤더의 {position}에 IPv4/CIDR '{ip_value}'가 있으나 "
                "허용 옵션(msg, sid, flags) 외 "
                f"'{disallowed_option}' 옵션이 존재",
                rule,
            )
        return Classification(
            "IP",
            f"{protocol.upper()} {direction} 헤더의 {position}에 IPv4/CIDR '{ip_value}'가 존재하고 "
            "IP 측 포트와 반대편 주소·포트가 모두 any이며 옵션은 없거나 msg/sid/flags만 사용",
            ip_value,
        )

    # 5. 범용 헤더의 단일 content IPv4/CIDR을 IP로 판정합니다.
    content_ip = classify_content_ip(rule, contents)
    if content_ip:
        return content_ip

    # 6. URL 세부분류:
    #    - content:"URL", content:"Host|3A 20|URL", content:"Host3A 20URL" -> 단일 URL
    #    - content:"Host|3A 20|"; content:"URL"처럼 Host와 도메인이 분리되어도 단일 URL
    #    - URL 뒤의 추가 content가 /로 시작하면 하위 디렉터리
    #    - URL 뒤의 추가 content 중 하나라도 /로 시작하지 않으면 시그니처
    #    IANA/TLD 유효성은 검사하지 않습니다.
    if contents:
        split_host_url = extract_split_host_url_contents(contents)
        if split_host_url:
            domain, prefix_kind = split_host_url
            form_text = f"분리형 {describe_url_form(prefix_kind)}"

            for index, content in enumerate(contents[2:], start=3):
                if not is_url_subpath(content):
                    return Classification(
                        "시그니처",
                        f"첫 번째·두 번째 content가 {form_text} 형태이나 {index}번째 content가 "
                        "'/'로 시작하는 URL 하위 경로가 아님: "
                        f"'{summarize_value(content)}'",
                        rule,
                    )

            evidence_host = extract_url_host(domain) or domain
            has_subdirectory = url_has_subdirectory(domain) or len(contents) >= 3

            if has_subdirectory:
                return Classification(
                    "하위 디렉터리",
                    f"첫 번째 content가 Host 헤더 접두부이고 두 번째 content가 URL/도메인 "
                    f"'{domain}'이며 URL 하위 경로가 존재",
                    evidence_host,
                )

            return Classification(
                "단일 URL",
                f"첫 번째 content가 Host 헤더 접두부이고 두 번째 content 전체가 URL/도메인 "
                f"'{domain}'이며 하위 경로가 없음",
                evidence_host,
            )

        first_url = extract_first_url_content(contents[0])
        if first_url:
            domain, prefix_kind = first_url
            form_text = describe_url_form(prefix_kind)

            for index, content in enumerate(contents[1:], start=2):
                if not is_url_subpath(content):
                    return Classification(
                        "시그니처",
                        f"첫 번째 content는 {form_text} 형태이나 {index}번째 content가 "
                        "'/'로 시작하는 URL 하위 경로가 아님: "
                        f"'{summarize_value(content)}'",
                        rule,
                    )

            evidence_host = extract_url_host(domain) or domain
            has_subdirectory = url_has_subdirectory(domain) or len(contents) >= 2

            if has_subdirectory:
                return Classification(
                    "하위 디렉터리",
                    f"첫 번째 content가 {form_text} 형태 '{domain}'이고 URL 하위 경로가 존재",
                    evidence_host,
                )

            return Classification(
                "단일 URL",
                f"첫 번째 content 전체가 {form_text} 형태 '{domain}'이며 하위 경로가 없음",
                evidence_host,
            )

        # 순수 content IP 조건을 통과하지 못한 IP 포함 문자열은 시그니처입니다.
        first_ip = find_ipv4(contents[0])
        if first_ip:
            return Classification(
                "시그니처",
                f"첫 번째 content에 IPv4 '{first_ip}'가 있으나 순수 단일 IP content 및 "
                "범용 any 헤더 조건을 충족하지 않음",
                rule,
            )

    # 7. PCRE에만 도메인이 있거나 일반 공격 문자열/행위 탐지 조건은 모두 시그니처입니다.
    if not contents:
        return Classification(
            "시그니처",
            "URL content가 없고 순수 TCP/UDP/IP IPv4/CIDR 헤더 조건에도 해당하지 않음",
            rule,
        )

    return Classification(
        "시그니처",
        f"첫 번째 content가 URL/도메인 형태가 아님: '{summarize_value(contents[0])}'",
        rule,
    )

def column_name(index: int) -> str:
    name = ""
    while index:
        index, remainder = divmod(index - 1, 26)
        name = chr(65 + remainder) + name
    return name


def xml_text(value: object) -> str:
    text = "" if value is None else str(value)
    text = INVALID_XML_CHAR_RE.sub(lambda m: f"\\x{ord(m.group(0)):02x}", text)
    # Excel 셀 문자열 한도. Snort 룰은 보통 훨씬 짧지만 명확한 오류를 제공합니다.
    if len(text) > 32767:
        raise ValueError("Excel 셀 최대 길이(32,767자)를 초과한 값이 있습니다.")
    return xml_escape(text, {'"': "&quot;"})


def worksheet_xml(rows: Sequence[Sequence[str]]) -> str:
    if len(rows) > EXCEL_MAX_ROWS:
        raise ValueError("Excel 시트 최대 행 수(헤더 포함 1,048,576행)를 초과했습니다.")
    expected_columns = 6
    row_xml: list[str] = []
    for row_index, row in enumerate(rows, start=1):
        if len(row) != expected_columns:
            raise ValueError(
                f"XLSX 출력 열 수 오류: {row_index}행은 {len(row)}열이며 "
                f"{expected_columns}열이어야 합니다."
            )
        cells: list[str] = []
        for col_index, value in enumerate(row, start=1):
            ref = f"{column_name(col_index)}{row_index}"
            style = "1" if row_index == 1 else ("3" if col_index in (1, 4) else "2")
            text = xml_text(value)
            cells.append(
                f'<c r="{ref}" t="inlineStr" s="{style}">'
                f'<is><t xml:space="preserve">{text}</t></is></c>'
            )
        height = "26" if row_index == 1 else "36"
        row_xml.append(
            f'<row r="{row_index}" ht="{height}" customHeight="1">'
            + "".join(cells)
            + "</row>"
        )

    last_row = max(1, len(rows))
    return f'''<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">
  <dimension ref="A1:F{last_row}"/>
  <sheetViews>
    <sheetView workbookViewId="0">
      <pane ySplit="1" topLeftCell="A2" activePane="bottomLeft" state="frozen"/>
      <selection pane="bottomLeft" activeCell="A2" sqref="A2"/>
    </sheetView>
  </sheetViews>
  <sheetFormatPr defaultRowHeight="15"/>
  <cols>
    <col min="1" max="1" width="11" customWidth="1"/>
    <col min="2" max="2" width="45" customWidth="1"/>
    <col min="3" max="3" width="115" customWidth="1"/>
    <col min="4" max="4" width="15" customWidth="1"/>
    <col min="5" max="5" width="78" customWidth="1"/>
    <col min="6" max="6" width="115" customWidth="1"/>
  </cols>
  <sheetData>{''.join(row_xml)}</sheetData>
  <autoFilter ref="A1:F{last_row}"/>
</worksheet>'''


def workbook_xml(sheet_names: Sequence[str]) -> str:
    sheets = "".join(
        f'<sheet name="{xml_text(name)}" sheetId="{index}" r:id="rId{index}"/>'
        for index, name in enumerate(sheet_names, start=1)
    )
    return f'''<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"
          xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">
  <bookViews><workbookView xWindow="0" yWindow="0" windowWidth="24000" windowHeight="12000"/></bookViews>
  <sheets>{sheets}</sheets>
  <calcPr calcId="191029"/>
</workbook>'''


def workbook_rels_xml(sheet_count: int) -> str:
    relationships = "".join(
        f'<Relationship Id="rId{index}" '
        f'Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" '
        f'Target="worksheets/sheet{index}.xml"/>'
        for index in range(1, sheet_count + 1)
    )
    relationships += (
        f'<Relationship Id="rId{sheet_count + 1}" '
        f'Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/styles" '
        f'Target="styles.xml"/>'
    )
    return f'''<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
  {relationships}
</Relationships>'''


def content_types_xml(sheet_count: int) -> str:
    overrides = "".join(
        f'<Override PartName="/xl/worksheets/sheet{index}.xml" '
        f'ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>'
        for index in range(1, sheet_count + 1)
    )
    return f'''<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
  <Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>
  <Default Extension="xml" ContentType="application/xml"/>
  <Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/>
  <Override PartName="/xl/styles.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.styles+xml"/>
  <Override PartName="/docProps/core.xml" ContentType="application/vnd.openxmlformats-package.core-properties+xml"/>
  <Override PartName="/docProps/app.xml" ContentType="application/vnd.openxmlformats-officedocument.extended-properties+xml"/>
  {overrides}
</Types>'''


ROOT_RELS_XML = '''<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
  <Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="xl/workbook.xml"/>
  <Relationship Id="rId2" Type="http://schemas.openxmlformats.org/package/2006/relationships/metadata/core-properties" Target="docProps/core.xml"/>
  <Relationship Id="rId3" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/extended-properties" Target="docProps/app.xml"/>
</Relationships>'''

STYLES_XML = '''<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<styleSheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">
  <fonts count="2">
    <font><sz val="10"/><name val="Malgun Gothic"/><family val="2"/></font>
    <font><b/><color rgb="FFFFFFFF"/><sz val="10"/><name val="Malgun Gothic"/><family val="2"/></font>
  </fonts>
  <fills count="3">
    <fill><patternFill patternType="none"/></fill>
    <fill><patternFill patternType="gray125"/></fill>
    <fill><patternFill patternType="solid"><fgColor rgb="FF1F4E78"/><bgColor indexed="64"/></patternFill></fill>
  </fills>
  <borders count="2">
    <border><left/><right/><top/><bottom/><diagonal/></border>
    <border>
      <left style="thin"><color rgb="FFD9E1F2"/></left>
      <right style="thin"><color rgb="FFD9E1F2"/></right>
      <top style="thin"><color rgb="FFD9E1F2"/></top>
      <bottom style="thin"><color rgb="FFD9E1F2"/></bottom>
      <diagonal/>
    </border>
  </borders>
  <cellStyleXfs count="1"><xf numFmtId="0" fontId="0" fillId="0" borderId="0"/></cellStyleXfs>
  <cellXfs count="4">
    <xf numFmtId="0" fontId="0" fillId="0" borderId="0" xfId="0"/>
    <xf numFmtId="0" fontId="1" fillId="2" borderId="1" xfId="0" applyAlignment="1">
      <alignment horizontal="center" vertical="center" wrapText="1"/>
    </xf>
    <xf numFmtId="0" fontId="0" fillId="0" borderId="1" xfId="0" applyAlignment="1">
      <alignment vertical="top" wrapText="1"/>
    </xf>
    <xf numFmtId="0" fontId="0" fillId="0" borderId="1" xfId="0" applyAlignment="1">
      <alignment horizontal="center" vertical="top" wrapText="1"/>
    </xf>
  </cellXfs>
  <cellStyles count="1"><cellStyle name="Normal" xfId="0" builtinId="0"/></cellStyles>
  <dxfs count="0"/>
  <tableStyles count="0" defaultTableStyle="TableStyleMedium2" defaultPivotStyle="PivotStyleLight16"/>
</styleSheet>'''


def app_xml(sheet_names: Sequence[str]) -> str:
    titles = "".join(f"<vt:lpstr>{xml_text(name)}</vt:lpstr>" for name in sheet_names)
    return f'''<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Properties xmlns="http://schemas.openxmlformats.org/officeDocument/2006/extended-properties"
            xmlns:vt="http://schemas.openxmlformats.org/officeDocument/2006/docPropsVTypes">
  <Application>Snort Rule Classifier</Application>
  <DocSecurity>0</DocSecurity><ScaleCrop>false</ScaleCrop>
  <HeadingPairs><vt:vector size="2" baseType="variant"><vt:variant><vt:lpstr>Worksheets</vt:lpstr></vt:variant><vt:variant><vt:i4>{len(sheet_names)}</vt:i4></vt:variant></vt:vector></HeadingPairs>
  <TitlesOfParts><vt:vector size="{len(sheet_names)}" baseType="lpstr">{titles}</vt:vector></TitlesOfParts>
  <Company></Company><LinksUpToDate>false</LinksUpToDate><SharedDoc>false</SharedDoc><HyperlinksChanged>false</HyperlinksChanged><AppVersion>16.0300</AppVersion>
</Properties>'''


def core_xml() -> str:
    now = datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
    return f'''<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<cp:coreProperties xmlns:cp="http://schemas.openxmlformats.org/package/2006/metadata/core-properties"
 xmlns:dc="http://purl.org/dc/elements/1.1/"
 xmlns:dcterms="http://purl.org/dc/terms/"
 xmlns:dcmitype="http://purl.org/dc/dcmitype/"
 xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
  <dc:title>Snort 룰 분류결과</dc:title>
  <dc:creator>Snort Rule Classifier {__version__}</dc:creator>
  <cp:lastModifiedBy>Snort Rule Classifier {__version__}</cp:lastModifiedBy>
  <dcterms:created xsi:type="dcterms:W3CDTF">{now}</dcterms:created>
  <dcterms:modified xsi:type="dcterms:W3CDTF">{now}</dcterms:modified>
</cp:coreProperties>'''


def write_xlsx(
    output_path: Path, results: Sequence[ResultRow], *, overwrite: bool = False
) -> None:
    """XLSX를 완성한 뒤 저장합니다. 기존 파일 교체는 명시적으로 허용해야 합니다."""
    if len(results) + 1 > EXCEL_MAX_ROWS:
        raise ValueError("Excel 최대 데이터 행 수(1,048,575건)를 초과했습니다.")
    if not overwrite and output_path.exists():
        raise FileExistsError(f"출력 파일이 이미 존재합니다: {output_path}")
    headers = ["넘버", "msg", "snort 룰", "분류결과", "근거", "근거 내용"]
    sheet_names = ["분류결과", "URL", "IP", "시그니처"]

    all_rows = [headers] + [row.as_cells() for row in results]
    url_categories = {"단일 URL", "하위 디렉터리"}
    categorized = {
        "분류결과": all_rows,
        "URL": [headers] + [row.as_cells() for row in results if row.category in url_categories],
        "IP": [headers] + [row.as_cells() for row in results if row.category == "IP"],
        "시그니처": [headers] + [row.as_cells() for row in results if row.category == "시그니처"],
    }

    output_path.parent.mkdir(parents=True, exist_ok=True)
    temp_path: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            prefix=f".{output_path.name}.", suffix=".tmp",
            dir=output_path.parent, delete=False,
        ) as temp:
            temp_path = Path(temp.name)
        with zipfile.ZipFile(temp_path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            archive.writestr("[Content_Types].xml", content_types_xml(len(sheet_names)))
            archive.writestr("_rels/.rels", ROOT_RELS_XML)
            archive.writestr("docProps/app.xml", app_xml(sheet_names))
            archive.writestr("docProps/core.xml", core_xml())
            archive.writestr("xl/workbook.xml", workbook_xml(sheet_names))
            archive.writestr("xl/_rels/workbook.xml.rels", workbook_rels_xml(len(sheet_names)))
            archive.writestr("xl/styles.xml", STYLES_XML)
            for index, name in enumerate(sheet_names, start=1):
                archive.writestr(f"xl/worksheets/sheet{index}.xml", worksheet_xml(categorized[name]))
        if overwrite:
            temp_path.replace(output_path)
        else:
            # 기존 파일은 배타적 생성(xb)으로 보호하고 저장 실패 시 새 파일만 정리합니다.
            created = False
            try:
                with output_path.open("xb") as destination:
                    created = True
                    with temp_path.open("rb") as source:
                        shutil.copyfileobj(source, destination)
            except BaseException:
                if created:
                    output_path.unlink(missing_ok=True)
                raise
    finally:
        if temp_path is not None:
            temp_path.unlink(missing_ok=True)


def validate_rule_structure(rule: str, line_number: int) -> None:
    """지원하지 않는 행/여러 줄 룰/미완성 따옴표를 거릅니다. 엔진 문법 검증은 아닙니다."""
    prefix = f"입력 {line_number}행"
    if find_rule_start(rule) is None:
        raise ValueError(f"{prefix}: 지원하는 Snort 헤더를 찾지 못했습니다. 한 줄에 룰 하나를 입력하세요.")
    open_pos = rule.find("(")
    if open_pos < 0:
        return  # 내부 v3.5의 옵션 없는 헤더 분류도 유지합니다.
    in_quote = False
    escaped = False
    depth = 0
    closed = False
    for index in range(open_pos, len(rule)):
        char = rule[index]
        if escaped:
            escaped = False
        elif char == "\\" and in_quote:
            escaped = True
        elif char == '"':
            in_quote = not in_quote
        elif not in_quote:
            if char == "(":
                depth += 1
            elif char == ")":
                depth -= 1
                if depth == 0:
                    closed = True
                    tail = rule[index + 1:].strip()
                    if tail:
                        raise ValueError(f"{prefix}: 룰 뒤에 추가 문자열이 있습니다. 한 줄에 룰 하나를 입력하세요.")
                    break
    if in_quote or not closed:
        raise ValueError(f"{prefix}: 따옴표 또는 괄호가 닫히지 않았습니다. 여러 줄 룰은 지원하지 않습니다.")


def process_file(
    input_path: Path, *, encoding: str | None = None
) -> tuple[list[ResultRow], str, int]:
    """결과, 사용 인코딩, 제외한 빈 줄/주석 수를 반환합니다."""
    text, encoding = read_text_auto(input_path, encoding)
    results: list[ResultRow] = []
    skipped_lines = 0

    sequence = 0
    for line_number, raw_line in enumerate(text.splitlines(), start=1):
        if not raw_line.strip() or raw_line.lstrip().startswith("#"):
            skipped_lines += 1
            continue
        sequence += 1
        parsed = parse_input_line(raw_line, sequence)
        validate_rule_structure(parsed.rule, line_number)
        classification = classify_rule(parsed.rule)
        results.append(
            ResultRow(
                parsed.number,
                parsed.msg,
                parsed.rule,
                classification.category,
                classification.reason,
                classification.evidence_content,
            )
        )

    return results, encoding, skipped_lines


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Snort 룰을 URL/IP/시그니처로 분류하여 XLSX로 저장합니다.",
        formatter_class=argparse.RawTextHelpFormatter,
    )
    parser.add_argument("input", type=Path, help="한 줄에 Snort 룰 하나가 저장된 입력 파일")
    parser.add_argument("-o", "--output", type=Path, help="출력 XLSX 경로")
    parser.add_argument("--encoding", help="입력 인코딩 직접 지정 (예: utf-8-sig, cp949)")
    parser.add_argument("--force", action="store_true", help="기존 출력 파일 덮어쓰기 허용")
    parser.add_argument("--version", action="version", version=f"Snort Rule Classifier {__version__}")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    input_path: Path = args.input

    if not input_path.is_file():
        print(f"[오류] 입력 파일을 찾을 수 없습니다: {input_path}", file=sys.stderr)
        return 2

    output_path: Path = args.output or input_path.with_name(f"{input_path.stem}_분류결과.xlsx")
    if output_path.suffix.casefold() != ".xlsx":
        output_path = output_path.with_suffix(".xlsx")

    try:
        if input_path.resolve() == output_path.resolve() or (
            output_path.exists() and input_path.samefile(output_path)
        ):
            raise ValueError("입력 파일과 출력 파일은 서로 다른 경로여야 합니다.")
        if output_path.exists() and not args.force:
            raise FileExistsError(f"출력 파일이 이미 존재합니다: {output_path}")
        results, encoding, skipped_lines = process_file(input_path, encoding=args.encoding)
        if not results:
            raise ValueError("분류할 룰이 없습니다. 입력 파일이 비어 있거나 주석만 있습니다.")
        if encoding == "latin-1" and args.encoding is None:
            print("[주의] 인코딩을 확인하지 못해 latin-1로 읽었습니다. 글자가 깨지면 --encoding을 지정하세요.", file=sys.stderr)
        write_xlsx(output_path, results, overwrite=args.force)
    except FileExistsError as exc:
        print(f"[오류] {exc}. 다른 -o 경로를 지정하거나 --force를 사용하세요.", file=sys.stderr)
        return 4
    except PermissionError as exc:
        print(f"[오류] 파일 접근 권한이 없습니다. Excel에서 출력 파일을 닫고 다시 실행하세요: {exc}", file=sys.stderr)
        return 3
    except (ValueError, LookupError) as exc:
        print(f"[오류] {exc}", file=sys.stderr)
        return 2
    except Exception as exc:
        print(f"[오류] 처리 중 예외가 발생했습니다: {exc}", file=sys.stderr)
        return 1

    counts = {category: 0 for category in ("단일 URL", "하위 디렉터리", "IP", "시그니처")}
    for row in results:
        counts[row.category] += 1

    print(f"입력 파일 : {input_path}")
    print(f"문자 인코딩: {encoding}")
    print(f"처리 룰 수 : {len(results):,}건")
    if skipped_lines:
        print(f"빈 줄·주석 제외: {skipped_lines:,}건")
    print(f"단일 URL   : {counts['단일 URL']:,}건")
    print(f"하위 디렉터리: {counts['하위 디렉터리']:,}건")
    print(f"URL 합계   : {counts['단일 URL'] + counts['하위 디렉터리']:,}건")
    print(f"IP         : {counts['IP']:,}건")
    print(f"시그니처   : {counts['시그니처']:,}건")
    print(f"출력 파일  : {output_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
