# Get started with Rowan

Rowan scans a directory and produces security findings for you to review.
You do not need an LLM account or API key for `scan`.

## 1. Install Rowan

Use Python 3.10 or newer. Rowan is a command-line tool, so install it with
[pipx](https://pipx.pypa.io), which gives it its own environment:

```bash
brew install pipx          # macOS; on Linux use your package manager
pipx ensurepath            # once, then open a new terminal
pipx install "rowan-sast[js-crossfile]"
```

With uv instead: `uv tool install "rowan-sast[js-crossfile]"`.

Without either tool, use a virtual environment. A bare `pip install` is
refused by Homebrew Python and other "externally managed" Pythons:

```bash
python3 -m venv ~/.rowan
source ~/.rowan/bin/activate
python -m pip install "rowan-sast[js-crossfile]"
```

The package is called `rowan-sast` on PyPI; the command it installs is `rowan`.
The extra adds the parsers used for JavaScript, TypeScript and Go cross-file
analysis. Omit it for a smaller installation if you do not need those features.

For development, clone the repository and install it editable instead:
`git clone https://github.com/hedgerow-dev/rowan.git && cd rowan && python -m pip install -e ".[dev,js-crossfile,mcp]"`.

**Windows:** the Python package requires Python 3.10+ too. In PowerShell, create
the environment with `py -m venv .venv` and activate it with
`.venv\Scripts\Activate.ps1`; use `python -m pip` after activation. The engine
installer selects a Windows executable, but a fresh Windows end-to-end setup
has not been validated for this alpha. WSL follows the Linux instructions.

## 2. Install the analysis engine

Rowan requires Opengrep for its default pattern and taint analysis. In the
activated Rowan environment:

```bash
rowan install-engine
export PATH="$HOME/.local/bin:$PATH"
rowan self-test
```

This installs Opengrep v1.31.0 and checks the download against a SHA-256 hash
built into Rowan, so it needs no other tool. A mismatch is refused. To install
a different Opengrep version, install
[Cosign](https://docs.sigstore.dev/cosign/system_config/installation/) first so
Rowan can verify that release's signature.

`self-test` should print `[OK]` for the engine and rules. It exits with an
error if the engine is missing. Keep the environment active
for the next step; reactivate it in new terminals.

## 3. Scan your project

Replace `/absolute/path/to/your-project` with the directory you want reviewed.
Run from the Rowan checkout so the report is written outside the target:

```bash
rowan scan /absolute/path/to/your-project --no-project-config --no-sca --audit -f json -o rowan-report.json
```

This is a source/model scan without dependency-advisory requests. It reads
project files; it does not run the target application's code. `--no-project-config`
prevents the target's `.rowan.yml` from changing the selected options.
`--audit` includes every report view, including lower-confidence leads.

For a readable console summary and dependency checks:

```bash
rowan scan /absolute/path/to/your-project --no-project-config
```

Dependency scanning contacts OSV with package names, ecosystems and versions,
and FIRST's EPSS service with CVE identifiers. Use `--no-sca` when that egress
is unsuitable. Installation itself downloads software and dependencies.

## 4. Read the result

Start with the report's completeness, then inspect the findings:

1. Check `summary.degraded` and warnings. Incomplete analysis is not a clean scan.
2. Read `coverage_summary` and `analysis_capability` to see which analysis ran.
   Explicitly disabled passes and unsupported languages limit what a quiet result means.
3. Review High/Critical findings and their source-to-sink evidence first. Confirm
   that the input is attacker-controlled and that the path is reachable.
4. Treat `pattern-only` matches as hypotheses. `--confirmed` reduces noise but
   does not prove exploitability or guarantee that every vulnerability was found.

Reports can contain private source and secret-like values. Review them before
uploading them to an issue, a coding agent, or a public CI artifact.

## 5. Optional: add an LLM for `hunt`

`rowan hunt` (experimental) runs the same scan, then asks an LLM to rate,
challenge and explain the findings. Unlike `scan`, it **sends code snippets
to the LLM endpoint you choose**, and asks you to confirm the endpoint first.

Pick one path:

| Path | Good for | Setup |
|---|---|---|
| **Ollama** | No code leaves your machine | Install [Ollama](https://ollama.com/download), then `ollama pull qwen2.5-coder` |
| **DeepSeek** | Cheap cloud default | Create a key at [platform.deepseek.com](https://platform.deepseek.com) |
| **OpenRouter** | Any model (Claude, Gemini, GPT, Llama) with one key | Create a key at [openrouter.ai](https://openrouter.ai) |

For a cloud key, load it into the current shell without writing it to a file
or your shell history (`read -s` hides what you type):

```bash
read -rs DEEPSEEK_API_KEY && export DEEPSEEK_API_KEY
```

Use `OPENROUTER_API_KEY` or `OPENAI_API_KEY` the same way. Ollama needs no key.

Then check, preview and run:

```bash
rowan doctor                                    # which backend will be used, and is it ready
rowan estimate /absolute/path/to/your-project   # LLM calls hunt would make; spends nothing
rowan hunt /absolute/path/to/your-project -o hunt-report.txt
```

`doctor --live` also sends one tiny request to prove the key works. Choose a
backend or model explicitly with `--backend` and `--model`, for example
`--backend openrouter --model anthropic/claude-sonnet-4.5`. Any
OpenAI-compatible server works through `--backend local` with
`LOCAL_LLM_BASE_URL` and `LOCAL_LLM_MODEL`. All backends, env vars and
options are in the [hunt section of the usage guide](usage.md#hunt-autonomous-vulnerability-hunting-experimental).

## Use with a coding agent

Copy the [agent prompt in the README](../README.md#let-your-coding-agent-do-it).
The CLI works with any agent that can run terminal commands. No MCP setup is
required for that workflow.

For agents with MCP support, install Rowan with the optional server:

```bash
pipx install --force "rowan-sast[mcp,js-crossfile]"
```

Configure your MCP client with the **absolute path** to the installed executable
(`which rowan-mcp` prints it) and the project root it is allowed to scan:

```json
{
  "mcpServers": {
    "rowan-evidence": {
      "command": "/absolute/path/to/rowan-mcp",
      "env": {
        "ROWAN_MCP_ROOTS": "/absolute/path/to/your-project"
      }
    }
  }
}
```

On Windows, use the environment's `Scripts/rowan-mcp.exe` path. Ask the
agent to call `scan_evidence` with the absolute project directory. The server
uses stdio, disables SCA, ignores project configuration and the repository's own ignore files, and defaults to a
600-second timeout. The allowed roots are a filesystem restriction, not an OS
sandbox. Your agent's own handling of returned source snippets is separate
from Rowan's network behavior.

## Troubleshooting

| Symptom | What to do |
|---|---|
| `rowan: command not found` | Activate the environment used for installation; use `python -m rowan --help` to check the package. |
| `cosign` missing | Only needed for a non-default `--version`. Install Cosign, or use the default version. |
| Engine missing or taint pass degraded | Check `self-test`, engine version, PATH, and the report's warnings. Do not treat the report as complete. |
| Too many findings | Start with the default view or `--severity high`; retain the audit report for deeper review. |
| Slow scan | Try `--policy fast --no-sca`; it intentionally omits dataflow and whole-repository analysis. |
| No engine available | For limited Python-regex analysis, use `--legacy-neuroscan --no-taint --no-sca`. This is reduced coverage. |
| MCP refuses a target | Use an absolute directory within `ROWAN_MCP_ROOTS`; restart the server after changing its environment. |
| CI returns 1 | Findings remain in the selected view/filter. Review them or use an intentional baseline. |
| CI returns 2 | Read stderr: scan analysis is incomplete, or CLI arguments are invalid. |

Next: [full usage guide](usage.md), [CI setup](usage.md#cicd-integration),
[contributing](../CONTRIBUTING.md).
