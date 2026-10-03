# Capabilities

What Rowan finds, how it decides, how it compares to other open-source
tools, and where it falls short. Status: **alpha (v0.3.4)**.

## In one paragraph

Rowan is one static scanner for the whole of a modern AI application: its
source code, the model files it loads, its dependencies, and its agent and MCP
configuration. It runs locally, needs no account and calls no LLM. Every
finding says what kind of evidence backs it, and every report says what Rowan
could not analyze.

## What it finds

### Source code

- **Injection:** SQL, NoSQL, command, code (`eval`/`exec`), LDAP, header, log, template (SSTI), expression language.
- **Unsafe deserialization:** pickle, YAML, Java and .NET deserializers.
- **Request forgery and file access:** SSRF, path traversal, open redirect, unsafe file upload, XXE.
- **Web:** XSS (including Django `mark_safe` / `format_html` misuse), cookie flags, weak randomness, ReDoS.
- **Secrets:** hardcoded credentials and provider keys.
- **Infrastructure:** Terraform, Dockerfiles and GitHub Actions workflows (including script injection into `run:` steps).

### AI and agent applications

- **Agent tools:** model-chosen tool arguments reaching shells, files, SQL or HTTP.
  Covers LangChain, CrewAI, Vercel AI SDK, LangChain.js, Spring AI,
  LangChain4j and the MCP SDKs for Python, TypeScript, Go and Java.
- **LLM output handling:** model output used as SQL, shell, code, URLs, paths or HTML.
- **MCP servers:** tool arguments as untrusted input, network exposure without auth,
  sampling without approval, stored tool content, risky client configuration files.
- **Model loading:** `torch.load`, Hugging Face downloads, `trust_remote_code`, remote model URLs.
- **Guardrails:** a safety check whose verdict is ignored or fails open.
- **Data exposure:** personal data sent to LLM providers or telemetry.
- **Prompt and instruction files:** hidden Unicode and instruction smuggling in agent instruction files.

### Model files

Rowan inspects model files without loading them, using
[Hayward](https://github.com/hedgerow-dev/hayward), Hedgerow's model-file
scanner: pickle and PyTorch, GGUF, SafeTensors, Keras, ONNX, TensorFlow,
numpy, joblib, skops and PMML, plus Hugging Face config files. It walks
pickle opcodes to find dangerous imports, checks GGUF chat templates for
template injection, and reports files it could not parse rather than calling
them clean.

### Dependencies

Known CVEs from OSV, a reachability hint (is the vulnerable function actually
called?), EPSS exploit likelihood, typosquat and phantom-dependency signals,
plus CycloneDX SBOM and OpenVEX output.

## How it decides

**Three layers of analysis.** Fast pattern rules, Opengrep dataflow within each
file, and Rowan's own cross-file analysis for Python and JS/TS (limited for Go).

**Second-order flows.** Rowan follows data that is stored and read back later:
a request value written to a database or vector store, then read by an
unrelated handler or worker. There is no call between the two, so call-graph
taint tools cannot connect them.

**Evidence tiers.** Each finding is labeled by what backs it: a computed
dataflow, a structural or file-format analysis, a self-evident match (such as a
hardcoded key), or an unverified pattern. A pattern match alone cannot be rated
High or Critical.

**Coverage report.** Each report lists the languages that only got pattern
checks, the passes that were skipped or failed, and files that could not be
read. An incomplete scan is marked incomplete, never shown as clean.

## How it fits your workflow

- **Terminal:** text, JSON, HTML or SARIF reports.
- **CI:** exit codes, baselines (report only new findings), a GitHub Action with SARIF upload, a pre-commit hook.
- **Coding agents:** structured JSON with source-to-sink flows, and an MCP server (`rowan-mcp`) agents can call directly.
- **Experimental:** `rowan hunt` adds LLM-assisted triage and discovery with a model you choose.

## Compared with other open-source tools

As of October 2026. Corrections welcome.

| | Rowan | Semgrep CE / Opengrep | Bandit | CodeQL | Model scanners (picklescan, ModelScan, fickling) |
|---|---|---|---|---|---|
| Source code | Yes | Yes | Python only | Yes | No |
| Model files | Yes | No | No | No | Yes |
| Dependency CVEs | Yes | No | No | No | No |
| Cross-file dataflow | Python, JS/TS; limited Go | No (paid tier) | No | Yes, deep | n/a |
| Stored-then-read flows | Yes, for ORM and vector stores | No | No | Stored-value queries (e.g. stored XSS) | n/a |
| AI agent and MCP rules | Python, JS/TS, Java, Go | Community rules vary | No | System-prompt injection (JS/TS) | n/a |
| Evidence label per finding | Yes | No | Confidence field | No | No |
| Reports what it did not analyze | Yes | Partial | No | Partial | Varies |
| License for private code | MIT | LGPL-2.1 | Apache-2.0 | Free only for open-source code | MIT, Apache-2.0, LGPL |

**Where Rowan leads:** breadth across one AI application (code, models,
dependencies and agent configuration in one scan), AI agent coverage beyond
Python, cross-file and stored-then-read flows without a commercial license, and
honesty about what each finding and each scan actually established.

**Where others lead:** CodeQL and commercial SAST have deeper cross-file
analysis, especially for Java and C#. LLM-based code reviewers find more bugs
that need judgment, such as broken business logic. Dedicated model scanners
have larger allowlists for some formats.

## Measured results

**[RealVuln](../benchmark/results/realvuln-2026-10-02/README.md)** (66 vulnerable
Python apps, independent benchmark, scored with its own scorer):

| Scanner | Repos | Precision | Recall | F2 |
|---|---|---|---|---|
| **Rowan v0.3.0** | 63 | 0.261 | 0.353 | **33.0** |
| SonarQube | 63 | 0.146 | 0.147 | 14.7 |
| Semgrep CE | 63 | 0.141 | 0.067 | 7.5 |

On the 23 repositories with Snyk results, Rowan scores F2 30.9 against Snyk's
20.2, with lower precision (0.296 against 0.411). Rowan's default view, which
hides low-confidence leads, scores precision 0.384 and F2 26.5. Most LLM-based reviewers
score higher than Rowan. Rowan was developed with this benchmark in view, so
read the [caveats](../benchmark/results/realvuln-2026-10-02/README.md#read-these-numbers-carefully).

**[Model files on quickset](../benchmark/results/quickset-2026-10-02/README.md)**
(26 malicious test files, 225 benign including 213 real Hugging Face models):

| Scanner | Detected | False positives | Files read |
|---|---|---|---|
| **Rowan 0.3.0** (Hayward 1.2.4) | **26/26** | **0/225** | **251/251** |
| ModelAudit 0.2.52 | 18/26 | 14/225 | 251/251 |
| picklescan 1.0.5 | 12/26 | 1/192 | 216/251 |
| ModelScan 0.8.8 | 5/26 | 0/80 | 93/251 |

Hedgerow wrote this benchmark too, and its cases are what Hayward was built to
catch: see the [caveats](../benchmark/results/quickset-2026-10-02/README.md#read-these-numbers-carefully).

## Known limits

- **Alpha.** Expect false positives and misses. Treat findings as leads.
- **Weak areas:** authentication and access control, business logic, denial of service.
  `--authz` adds an experimental object-level authorization check for Python.
- **Language depth varies.** Java, Kotlin and C# get within-file dataflow only.
  Ruby, PHP and Rust get pattern checks only. Templates (`.html`, Jinja) get pattern checks only.
- **No Java cross-file analysis yet.**
- **Model files:** 7z archives are not opened; very large files are skipped and reported.
- **Reachability for dependency CVEs** covers a small set of well-known packages.

## Measure it yourself

Every published result in `benchmark/results/` names the corpus, the versions
and the commands to reproduce it. The labeled corpora behind Rowan's own
regression gates ship in `benchmark/ground_truth/`; run them with
`python scripts/benchmark.py`.
