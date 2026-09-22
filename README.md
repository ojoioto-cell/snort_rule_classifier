# Snort Rule Classifier

**Classify Snort-style security rules as URLs, IP indicators, or signatures, and export the results to Excel with classification evidence.**

| Item | Details |
| --- | --- |
| Release version | `1.0.0` |
| Python version | Python 3.10 or later |
| Runtime dependencies | Python standard library only |
| Input | A text file containing one rule per line |
| Output | An `.xlsx` workbook with all results and separate URL, IP, and signature sheets |
| Processing | Local file processing; no external API calls or DNS lookups |

This first GitHub release, `v1.0.0`, is based on the internal v3.5 revision.
Classification uses heuristics to help organize and review rules. It does not determine whether a rule is malicious or guarantee detection accuracy or suitability for blocking.

Version 1.0.0 uses Korean CLI messages, workbook labels, and classification explanations. This README provides English descriptions and maps the original output labels below.

## Quick Start

Extract the archive and run the following commands from the `snort-rule-classifier` directory. No `pip install` step is required.

```bash
python snort_rule_classifier.py --version
python snort_rule_classifier.py examples/sample.rules -o output/sample.xlsx
```

On Windows, use `py -3` if the `python` command is unavailable. On Linux or macOS, use `python3` if required by your environment.

Expected results for the 16 included synthetic examples:

| Category | Count |
| --- | ---: |
| Single URL | 5 |
| Subdirectory | 2 |
| IP | 3 |
| Signature | 6 |

You can place your own input files in the local `data/` directory. Both `data/` and `output/` are excluded from Git tracking.

```bash
python snort_rule_classifier.py data/input.rules -o output/result.xlsx
```

## Input Format

The tool supports plain rules and the `number|description|rule` format.

```text
alert tcp any any -> any 80 (msg:"Example domain"; content:"example.test"; sid:1000001;)
10|Split Host example|alert tcp any any -> any 80 (content:"Host|3a 20|"; content:"example.test"; sid:1000002;)
```

- Blank lines and comment lines whose first non-whitespace character is `#` are skipped.
- If a number is not provided, a sequential number is assigned, excluding comments and blank lines.
- If an external description is not provided, the rule's `msg` value is used.
- The `|` delimiter is interpreted only before the start of the rule. HEX blocks in `content` and the `|` and `;` characters in PCRE patterns are preserved.
- Unsupported lines and unclosed quotes or parentheses produce an error with the physical line number. Multiline rules, `include` statements, and trailing comments are not supported.

## Classification Summary

| Category | Typical Conditions | Example |
| --- | --- | --- |
| Single URL (`단일 URL`) | Domain or URL content with no subpath | `content:"example.test";` |
| Subdirectory (`하위 디렉터리`) | A path after the domain or a separate `/...` content value | `content:"example.test"; content:"/download";` |
| IP (`IP`) | A single IPv4/CIDR in a header that meets the restrictions, or a single IP content value with an all-`any` header | `alert tcp 192.0.2.1 any -> any any (...)` |
| Signature (`시그니처`) | Negated content, exception policies, additional IP detection conditions, general attack strings, or other patterns | `content:!"example.test";` |

The tool handles `Host|3A 20|`, `Host|3a 20|`, Host prefixes and domains in separate content options, and certain forms with missing pipe characters. The original URL-shortener and service exception policies are retained.

Header-based IP classification allows only `msg`, `sid`, and `flags`. Content-based IP classification additionally allows `content`. **Under the current policy, even `rev`, `classtype`, and `metadata` exclude a rule from IP classification.** The same option restrictions do not apply to URL classification.

See the [Classification Policy](docs/CLASSIFICATION.md) for detailed precedence and intentional restrictions.

## Command-Line Options

```bash
python snort_rule_classifier.py input.rules
python snort_rule_classifier.py input.rules -o output/result.xlsx
python snort_rule_classifier.py input.rules --encoding cp949 -o output/result.xlsx
python snort_rule_classifier.py input.rules -o output/result.xlsx --force
python snort_rule_classifier.py --help
```

| Option | Description |
| --- | --- |
| `input` | Path to the input text file |
| `-o`, `--output` | Output path. Defaults to `<input_stem>_분류결과.xlsx` |
| `--encoding` | Explicit input encoding. If omitted, decoding is attempted in the order UTF-8, CP949, and EUC-KR |
| `--force` | Explicitly allow an existing output file to be overwritten |
| `--version` | Display the version |

If the output extension is not `.xlsx`, it is changed to `.xlsx`. Processing stops if the input and output refer to the same file, even when `--force` is supplied. If automatic decoding fails, the tool falls back to Latin-1 and prints a warning. EUC-KR files may be reported as CP949 because of encoding compatibility.

| Exit Code | Meaning |
| --- | --- |
| `0` | Completed successfully |
| `1` | Other processing or output errors |
| `2` | Invalid arguments, input file, format, encoding, or size |
| `3` | File access permission error |
| `4` | Output file already exists and overwriting was not allowed |

## Excel Output

The workbook contains four sheets: `분류결과` (All Results), `URL`, `IP`, and `시그니처` (Signatures). Each sheet uses the same six columns. The URL sheet includes both Single URL and Subdirectory results.

| Column in the Workbook | English Meaning | Contents |
| --- | --- | --- |
| `넘버` | Number | Input identifier or sequential number |
| `msg` | Message | External description or the rule's `msg` value |
| `snort 룰` | Snort Rule | Rule text used for classification |
| `분류결과` | Classification | Single URL / Subdirectory / IP / Signature |
| `근거` | Reason | Explanation of the classification |
| `근거 내용` | Evidence | URL: hostname / IP: IPv4 or CIDR / Signature: rule text |

The first row is frozen, filters are enabled, and text wrapping is applied. All cells are stored as text, so input beginning with `=` is not written as an Excel formula.

The rule's content and PCRE patterns are preserved rather than replaced with normalized values. Leading and trailing whitespace and line endings are trimmed, and control characters that XML cannot represent are replaced with visible strings such as `\x00`. URL evidence contains the hostname; the path remains available in the rule column.

## Optional: Install as a Command

You can install the local project into your preferred Python environment, such as a virtual environment.

```bash
python -m pip install .
snort-rule-classifier --version
snort-rule-classifier examples/sample.rules -o output/installed_sample.xlsx
```

The application has no third-party runtime dependencies. This installation method may download the setuptools and wheel build tools, so run the `.py` file directly for offline use. These instructions describe local installation and do not imply that the package has been published to PyPI.

## Tests

```bash
python -m unittest discover -s tests -v
```

Tests use the standard-library `unittest` module to verify classification policies, preservation of rule text, Korean text encodings, XLSX structure, file protection, and error handling. The repository includes GitHub Actions configurations for Linux, Windows, and macOS. See the [Validation Record](docs/VALIDATION.md) for the scope of testing actually performed locally.

## Limitations

- This tool is not a complete Snort/Suricata syntax validator or rule execution engine. It does not fully evaluate detection buffers, PCRE patterns, or option semantics.
- IPv6, IP lists, address variables, and negated addresses are outside the dedicated IP classification scope.
- Actual TLD validity, DNS existence, and URL reachability are not checked.
- Input and results are held in memory. Split large files into smaller batches. Large-scale load testing has not been performed.
- Excel limits are 32,767 characters per cell and 1,048,575 data rows in the All Results sheet. These limits are not performance guarantees.

## Documentation and Releases

The supporting documents linked below are currently in Korean.

- [Classification Policy](docs/CLASSIFICATION.md)
- [GitHub Upload and v1.0.0 Release Guide](docs/GITHUB_UPLOAD.md)
- [Validation Record](docs/VALIDATION.md)
- [Changelog](CHANGELOG.md) · [Release Notes](RELEASE_NOTES.md)
- [Contributing](CONTRIBUTING.md) · [Security](SECURITY.md)

## License

No license has been specified yet. The repository owner should choose distribution terms, add a `LICENSE` file at the repository root, and update this section. Publishing a public repository does not itself grant an open-source license. See [GitHub's Licensing Guide](https://docs.github.com/en/repositories/managing-your-repositorys-settings-and-features/customizing-your-repository/licensing-a-repository).
