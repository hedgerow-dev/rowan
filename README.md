# Rowan

[![CI](https://github.com/hedgerow-dev/rowan/actions/workflows/ci.yml/badge.svg)](https://github.com/hedgerow-dev/rowan/actions/workflows/ci.yml)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

**Find security issues in your code and AI/ML projects, with evidence you can review.**

Rowan reads your project's source code and model files and reports likely
vulnerabilities: injection, unsafe deserialization, SSRF, leaked secrets,
risky agent tools, unsafe model loading and more. It never runs your code.

> **Alpha.** Treat every finding as a lead to check, not a confirmed bug.
> A clean report does not prove a project is secure.

## Quick start

You need **Python 3.10+** and [pipx](https://pipx.pypa.io), which installs
command-line tools into their own environment (on macOS: `brew install pipx`,
then `pipx ensurepath` and open a new terminal).

**1. Install Rowan:**

```bash
pipx install "rowan-sast[js-crossfile]"
```

Already use uv? `uv tool install "rowan-sast[js-crossfile]"` works too. A plain
`pip install` fails on Homebrew Python by design; see
[getting started](docs/getting-started.md) for a virtual-environment install.

**2. Install the scan engine** ([Opengrep](https://github.com/opengrep/opengrep)) and check it:

```bash
rowan install-engine
export PATH="$HOME/.local/bin:$PATH"
rowan self-test
```

`self-test` should print `[OK]` three times.

**3. Scan a project:**

```bash
rowan scan /path/to/your-project
```

Windows, troubleshooting and more detail: [getting started](docs/getting-started.md).

## Let your coding agent do it

Paste this into Claude Code, Codex, Cursor or any agent that can run terminal commands,
with your project open:

```text
Install Rowan and scan this project for security issues.
1. Install it in its own folder (not inside this project) by following
   https://github.com/hedgerow-dev/rowan/blob/main/docs/getting-started.md
2. Run `rowan self-test`. If the engine is not [OK], stop and tell me.
3. Run: rowan scan <this project's absolute path> --no-project-config
   --no-sca --audit -f json -o <a folder outside this project>/rowan-report.json
4. If summary.degraded is true, tell me the scan is incomplete and why.
5. List the High and Critical findings with file:line links. For each one,
   say whether you checked the code or it is still just a lead.
6. Do not change any code in this project.
```

`--no-sca` keeps this first scan offline. Drop it to also check your
dependencies for known CVEs (this sends package names and versions to OSV).

## Common commands

```bash
rowan scan PATH                                  # readable report
rowan scan PATH --audit                          # include low-severity findings
rowan scan PATH -f json -o report.json           # save a report (also: html, sarif)
rowan scan PATH --ci --severity high             # CI: exit 1 on high/critical findings
rowan scan PATH --write-baseline base.json       # record today's findings...
rowan scan PATH --ci --baseline base.json        # ...then report only new ones
```

With `--ci`, exit code **0** means no findings, **1** means findings, and **2**
means the scan was incomplete. Reports can contain source code and secrets:
review them before sharing.

## What it checks

| Area | Coverage |
|---|---|
| Source code | Injection, unsafe deserialization, path traversal, SSRF, XSS, secrets |
| AI/ML apps | Model loading, agent tools, LLM output handling, prompt files, MCP config |
| Dataflow | Within-file through Opengrep; cross-file for Python and JS/TS, limited for Go |
| Dependencies | Known CVEs, reachability hints, CycloneDX SBOM and OpenVEX output |
| Model files | Pickle, PyTorch, GGUF, SafeTensors, Keras, ONNX, TensorFlow, numpy, joblib (via [Hayward](https://github.com/hedgerow-dev/hayward)) |

Python and JS/TS get the deepest analysis. Java, Kotlin and C# get within-file
dataflow. Ruby, PHP and Rust get limited pattern checks. The report lists what it
could not analyze.

The rule catalog has **593 rules across 48 YAML files**.
That is 398 regex rules and 195 taint rules (Opengrep). See the [rule catalog](docs/rules.md).

## Privacy

`rowan scan` never calls an LLM or uploads your code. Its only network calls
are dependency lookups (OSV and FIRST EPSS), which `--no-sca` turns off.
The experimental `rowan hunt` command does send code to the LLM you configure:
see the [usage guide](docs/usage.md).

## More

- [Getting started](docs/getting-started.md): install, first scan, MCP setup, troubleshooting
- [Capabilities](docs/capabilities.md): what Rowan finds, how it compares, measured results
- [Usage guide](docs/usage.md): every option, configuration, baselines, CI and GitHub Action
- [Contributing](CONTRIBUTING.md) and [architecture](ARCHITECTURE.md)
- [Security policy](SECURITY.md): report a vulnerability in Rowan privately

## License

[MIT](LICENSE). Opengrep is a separate LGPL-2.1 engine and is not bundled.
