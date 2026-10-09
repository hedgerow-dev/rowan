# Security Policy

## Reporting a vulnerability

Email **hello@hedgerow.dev** with a description of the issue, the affected version or commit, and
steps to reproduce. Please do not open a public GitHub issue for a security report.

You should get an acknowledgement within 5 business days. This project is maintained by one person,
so fix timelines vary with severity and complexity, but we'll keep you updated as we work on it.

If you'd like to encrypt your report, ask for a key in your first email.

## Scope

In scope:

- Vulnerabilities in Rowan itself: the scanner, its pipeline passes, the MCP server, and the
  supporting scripts (`rowan/`, `scripts/`). Examples: unsafe deserialization of a scan target's
  own files, command injection via a crafted repository, path traversal in report output, or a way
  for a scanned codebase to execute code during a scan.
- Vulnerabilities in how Rowan installs or verifies its Opengrep dependency
  (`rowan/install_opengrep.py`).

Out of scope:

- False negatives or false positives in the rule corpus (`rules/`). These are quality issues, not
  security vulnerabilities. Please open a normal GitHub issue instead.
- Vulnerabilities in Opengrep itself: report those upstream at
  [opengrep/opengrep](https://github.com/opengrep/opengrep).
- Vulnerabilities in a project that Rowan's own rules or benchmarks reference. Report those to
  that project directly.

## Threat model

Rowan reads untrusted source code. It never executes the scanned project, but it does parse it,
pass it to Opengrep, and optionally send snippets to an LLM. Know where the limits are.

What Rowan does:

- Runs Opengrep as an argument list (no shell) with per-batch timeouts and a per-file size cap.
- Passes Opengrep only an allowlisted environment, so API keys in your shell are not inherited.
- Skips symlinks during discovery and escapes user-derived text in HTML reports.
- Restricts the MCP server to allowed root directories and disables project config there.
- Asks for consent before sending source to a cloud LLM, and redacts likely secrets (known
  credential formats, URL passwords, high-entropy literals in secret-named variables) from every
  prompt sent to a non-loopback endpoint.
- Requires `--exploit` plus an explicit `--base-url` for live probes, and refuses a target outside
  loopback and private networks unless you pass `--allow-remote-target`. Link-local addresses,
  including the cloud metadata service, are not treated as local.
- With `--audit-log PATH`, appends one line per LLM call and probe: endpoint, sizes, hashes and
  outcome, never the content.

What Rowan does not do:

- It is not a sandbox. There are no CPU, memory or process limits, and a crafted file can make a
  parser slow or large.
- Secret redaction is pattern-based: a secret in an unusual format can still reach a cloud model.
  `--yes` skips the consent prompt.
- It cannot know whether you are authorised to test a target. `--allow-remote-target` is your
  confirmation, not a check.
- Prompt-injection defence for LLM stages is prompt wording, not isolation.

If you scan code you do not trust, run Rowan in a container or VM with no network and no secrets
in its environment. Only use `--exploit` against systems you are authorised to test.

## Disclosure

We ask for a reasonable window to investigate and ship a fix before any public disclosure. We'll credit
reporters who want credit once a fix is out, unless you'd rather stay anonymous.
