# Oconee AI Agent Risk Scanner

**Find governance gaps before your AI agents act.**

`oconee-scan` is a free, open-source CLI that inspects a repository and the AI
coding-agent configuration around it, then reports where an agent's permitted
actions exceed what the project actually needs.

```bash
npx oconee-scan
```

Everything runs locally. Nothing is uploaded. Nothing in your project is
modified.

---

## What this is — and what it is not

This is a **point-in-time assessment**. It reads configuration files and
reports what an agent _would be allowed to do_ in this repository right now.

It is **not** a runtime enforcement product. It does not sit between an agent
and its actions, it cannot block anything, and a clean report is not evidence
that agent activity is governed — only that no configured risk indicators were
detected at the moment you ran it.

It is also not a compliance attestation. The risk score is a transparent
heuristic, documented in full below, not a certification of any standard.

---

## Installation

Run it without installing anything:

```bash
npx oconee-scan
```

Or install it:

```bash
# Project dev dependency
npm install --save-dev oconee-scan

# Global
npm install --global oconee-scan
```

Requires Node.js 18.17 or newer. Tested on macOS, Linux and Windows.

---

## Usage

```bash
oconee-scan                              # scan the current directory
oconee-scan scan ./path/to/repo          # scan a specific directory
oconee-scan scan --json                  # machine-readable output
oconee-scan scan --output report.json    # write to a file
oconee-scan scan --verbose               # include evidence and recommendations
oconee-scan rules                        # list every detection rule in this build
oconee-scan --help
oconee-scan --version
```

### Options

| Option                   | Description                                              |
| ------------------------ | -------------------------------------------------------- |
| `-p, --path <dir>`       | Directory to scan (default: current directory)           |
| `--json`                 | Emit the machine-readable JSON report                    |
| `-o, --output <file>`    | Write the report to a file instead of stdout             |
| `--verbose`              | Include evidence and recommendations for every finding   |
| `--disable <ids>`        | Comma-separated rule IDs or category names to skip       |
| `--fail-on <severity>`   | Exit `1` when a finding at or above this severity exists |
| `--color` / `--no-color` | Force or disable ANSI colour                             |

### Exit codes

| Code | Meaning                                                                 |
| ---- | ----------------------------------------------------------------------- |
| `0`  | Scan completed and no `--fail-on` threshold was crossed                 |
| `1`  | A finding met or exceeded the `--fail-on` threshold                     |
| `2`  | The scan could not run (bad path, unreadable directory, internal error) |

`--fail-on` defaults to `never`, so a plain scan never fails your build unless
you ask it to. In CI:

```yaml
- run: npx oconee-scan --fail-on high
```

---

## Supported tools

The scanner reads project-scoped configuration for:

| Tool           | Files inspected                                                                                                                              |
| -------------- | -------------------------------------------------------------------------------------------------------------------------------------------- |
| Claude Code    | `.claude/settings.json`, `.claude/settings.local.json`, `.claude/agents/`, `CLAUDE.md`                                                       |
| MCP (any host) | `.mcp.json`, `mcp.json`, `.cursor/mcp.json`, `.vscode/mcp.json`, `.windsurf/mcp.json`, `.roo/mcp.json`, `.gemini/settings.json`              |
| Cursor         | `.cursorrules`, `.cursor/rules/*.mdc`, `.cursor/environment.json`, `.cursor/settings.json`                                                   |
| VS Code        | `.vscode/settings.json`, `.vscode/extensions.json`                                                                                           |
| GitHub Copilot | `.github/copilot-instructions.md`, `.github/instructions/*.instructions.md`, `.github/prompts/*.prompt.md`, Copilot keys in VS Code settings |
| Other agents   | `AGENTS.md`, `AGENT.md`, `GEMINI.md`, `.windsurfrules`, `.clinerules`, `.aider.conf.yml`                                                     |

Plus repository-level context: `.gitignore`, CI/CD definitions,
infrastructure-as-code, deployment manifests, container builds, and credential
file patterns.

Only **project-scoped** configuration is read. The scanner never reads your
home directory, your global agent settings, or anything outside the directory
you point it at.

---

## Privacy model

This is the part that matters most, so it is stated precisely.

**The scanner makes no network requests.** There is no API call, no version
check, no telemetry, and no analytics — by default or otherwise. This release
contains no code that opens a socket.

**Nothing leaves your machine.** No source code, file contents, secrets, file
paths, repository names, findings or scores are transmitted anywhere. Output
goes to your terminal, or to the file you name with `--output`.

**Secret values are never captured.** When a credential pattern is detected,
the scanner records the _pattern class_ (`aws-access-key-id`), the file path
and the line number. The matched text is never placed into a finding, printed,
or written to a report. This is enforced by tests that plant known secrets in a
fixture and assert they never appear in any rendered output.

**Nothing is executed.** The scanner never runs a command it finds in your
configuration, never starts an MCP server, and never executes project code. It
parses files as text and data.

**Nothing is modified.** Every filesystem operation is a read. Symlinks are
indexed but never traversed, so a scan cannot escape the directory you gave it.
This is enforced by tests that hash every fixture file before and after a scan.

If telemetry is ever added, it will be explicit opt-in, off by default, and
documented here before it ships.

---

## Scoring methodology

The **AI Agent Risk Score** runs from 0 to 100, where **higher means greater
governance risk**. It is computed from the findings alone, with no hidden
inputs, so you can reproduce it by hand from the JSON report.

**Step 1 — weight each finding.**

```
points = SEVERITY_WEIGHT × CONFIDENCE_FACTOR
```

| Severity   | Weight |     | Confidence | Factor |
| ---------- | ------ | --- | ---------- | ------ |
| `critical` | 40     |     | `high`     | 1.0    |
| `high`     | 20     |     | `medium`   | 0.8    |
| `medium`   | 8      |     | `low`      | 0.5    |
| `low`      | 3      |     |            |        |
| `info`     | 0      |     |            |        |

`info` findings are informational context and contribute nothing to the score.

**Step 2 — cap each category at 35 points.** Sum the points within each of the
eight categories, then cap. A repository with thirty low-confidence credential
matches cannot outscore one with a genuine permission bypass.

**Step 3 — sum the capped categories and clamp to 0–100.**

Risk levels:

| Score  | Level    |
| ------ | -------- |
| 0–9    | Minimal  |
| 10–29  | Low      |
| 30–54  | Moderate |
| 55–79  | High     |
| 80–100 | Critical |

The `score.breakdown` array in the JSON report shows raw and capped points per
category, so you can see exactly what drove the number.

**What the score does not mean.** It is not a probability of compromise, not a
compliance grade, and not comparable across unrelated repositories as an
absolute measure. It is a way to see which governance gaps in _this_ repository
are largest, and to watch the number move as you close them.

---

## Detection categories

| Category            | What it covers                                                                  |
| ------------------- | ------------------------------------------------------------------------------- |
| Agent Configuration | Permission modes, wildcard grants, bypass flags, hooks, malformed policy        |
| Command Execution   | Pre-approved destructive commands, unrestricted shell, network egress, installs |
| File Access         | Unscoped read/write grants, out-of-tree directories, undenied sensitive paths   |
| Repository Risk     | Infrastructure-as-code, CI/CD, production deployment and container artifacts    |
| Credential Exposure | Environment files, key material, provider credentials, credential patterns      |
| MCP / Tool Access   | Server inventory, broad tool grants, auto-approval, transport and supply chain  |
| Approval Controls   | Missing deny/ask lists, local-only policy, non-interactive CI runs              |
| Auditability        | Missing agent policy, logging, code ownership and disclosure route              |

Run `oconee-scan rules` to list every rule in your installed version with its
ID, title and a one-line summary.

Every finding carries: `rule_id`, `title`, `category`, `severity`,
`confidence`, `description`, `evidence`, `affected_path`, `recommendation` and
`documentation_url`.

---

## Example output

```
Oconee AI Agent Risk Scanner
Find governance gaps before your AI agents act.

Repository: risky-mcp

AI Agent Risk Score: 80/100
Risk Level: Critical

Findings

HIGH
MCP-003 Broad MCP tool permissions
  An MCP server is permitted wholesale rather than tool by tool. Every tool the
  server exposes now and every tool it adds in a future version is pre-approved,
  including write-capable ones.
  .claude/settings.json  ·  confidence: high  ·  MCP / Tool Access

MCP-005 Remote MCP server reached over an unencrypted transport
  An MCP server is configured over plain HTTP to a remote host. Tool arguments,
  tool results and any bearer token sent with them traverse the network in the
  clear and can be modified in transit.
  .mcp.json  ·  confidence: high  ·  MCP / Tool Access

MEDIUM
MCP-002 MCP server launched from an unpinned remote package
  The code that runs with the agent's tool privileges is resolved from a remote
  registry at launch time, so a compromised or newly published version executes
  without review.
  .mcp.json  ·  confidence: high  ·  MCP / Tool Access

LOW
AUDIT-002 No local agent governance policy detected

Summary

  Critical  0
  High      4
  Medium    6
  Low       4

Recommended next steps:
  1. Allow individual tools by name instead of the server as a whole (MCP-003)
  2. Add deny entries for credential paths and deployment commands (APPR-001)
  3. Pin an exact MCP server version, or vendor the server (MCP-002)
```

### JSON report

```jsonc
{
  "schema_version": 1,
  "tool": { "name": "oconee-scan", "version": "0.1.0" },
  "scannedAt": "2026-09-08T04:00:00.000Z",
  "repository": { "name": "my-project", "path": "/Users/me/my-project" },
  "score": {
    "score": 80,
    "level": "Critical",
    "counts": { "info": 1, "low": 4, "medium": 6, "high": 4, "critical": 0 },
    "breakdown": [
      {
        "category": "MCP / Tool Access",
        "rawPoints": 46.4,
        "cappedPoints": 35,
        "findingCount": 7,
      },
    ],
  },
  "findings": [
    {
      "rule_id": "MCP-005",
      "title": "Remote MCP server reached over an unencrypted transport",
      "category": "MCP / Tool Access",
      "severity": "high",
      "confidence": "high",
      "description": "...",
      "evidence": [
        {
          "detail": "Server \"internal-api\" uses an unencrypted endpoint.",
          "path": ".mcp.json",
          "excerpt": "http://internal.example.com/mcp",
        },
      ],
      "affected_path": ".mcp.json",
      "recommendation": "Use an https:// endpoint, or run the server locally over stdio.",
      "documentation_url": "https://www.oconeeruntime.com/tools/agent-risk-scanner/rules/mcp-005",
    },
  ],
  "rulesEvaluated": 46,
  "filesIndexed": 3,
  "truncated": false,
  "warnings": [],
}
```

The JSON shape is versioned by `schema_version`. Adding fields is a minor
change; renaming or removing them is not.

---

## Limitations

Read these before you rely on a result.

- **Configuration is not behaviour.** The scanner reads what a policy _says_.
  It cannot observe what an agent actually did, and a permissive policy that
  nobody exercises looks identical to one that is abused daily.
- **Point-in-time only.** The report describes the repository as of the moment
  you ran it. Anything that changes afterwards is invisible to it.
- **Project scope only.** User- and machine-level agent settings — which
  frequently override project settings — are outside the scan. A repository
  with no configuration may still be running under a very permissive global
  policy.
- **Static credential detection has both error modes.** Pattern matching finds
  known credential formats; it misses novel ones, and it flags synthetic values
  in test fixtures. Low-confidence matches are downgraded, never suppressed.
  Every credential finding needs human confirmation.
- **`.gitignore` evaluation is approximate.** It does not reproduce git's full
  matching semantics. Confirm with `git check-ignore -v <path>`.
- **Absence of evidence is reported as `info` or `low`, not as safety.** A repo
  with no agent configuration is not scored as risky, but it is not scored as
  governed either.
- **Large repositories are indexed with limits.** Directory walking stops at
  25,000 files and depth 12; content scanning is bounded. When a limit is hit,
  `truncated` is `true` in the report.
- **No SARIF or HTML output yet.** The reporter interface is designed for them;
  they are not implemented.

---

## Contributing

New detection rules are the most valuable contribution. A rule is a single file
in `src/rules/` that exports a `Rule` — no changes to the CLI, scoring or
reporting layers are needed.

See [CONTRIBUTING.md](CONTRIBUTING.md) for the rule authoring guide, the
severity and confidence rubric, and the conservative-by-default policy for
uncertain detections.

## Security

To report a vulnerability in the scanner itself, see [SECURITY.md](SECURITY.md).
Please do not open a public issue for a security report.

## License

[Apache-2.0](LICENSE)

---

## Oconee Runtime — AI Action Governance

`oconee-scan` tells you what your AI agents _would be allowed_ to do. It runs
once, reads configuration, and reports.

Governing what agents actually do — evaluating each Action against Policy in
Context, producing a Decision and durable Evidence at the moment the action is
attempted — is a different problem, and it is what
[Oconee Runtime](https://www.oconeeruntime.com) is built for.

**Want continuous policy enforcement instead of a point-in-time scan?**
[Learn more about Oconee Runtime.](https://www.oconeeruntime.com)

The scanner is free, open source, and fully useful on its own. It does not
require an Oconee account, and it never will.
