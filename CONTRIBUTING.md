# Contributing to oconee-scan

Thanks for helping make AI agent governance gaps easier to find.

New **detection rules** are the most valuable contribution. Adding one requires
no changes to the CLI, scoring or reporting layers.

## Getting started

```bash
git clone https://github.com/oconeesoftware/oconee-scan.git
cd oconee-scan
npm install

npm run typecheck   # tsc --noEmit
npm run lint        # eslint
npm test            # vitest
npm run build       # compile to dist/
npm run dev -- .    # run the CLI from source
```

## Architecture in one page

The scan runs in two phases.

**Phase 1 — collectors** (`src/scanners/`) walk the repository once and build a
read-only `ScanContext`: a file index, parsed agent and MCP configuration,
normalised permission models, and credential indicators. Collectors know about
_file formats_.

**Phase 2 — rules** (`src/rules/`) are pure functions over that context. They
receive everything they need and emit findings. Rules know about _risk_.

```
src/
  cli/         argument parsing, help, exit codes
  scanners/    read-only discovery and parsing -> ScanContext
  rules/       pure evaluation over the context -> Finding[]
  scoring/     Finding[] -> RiskScore
  reporters/   ScanResult -> terminal / JSON text
  types/       the domain model
  utils/       filesystem, JSONC, globbing, secrets, colour
```

Rules must not touch the filesystem, spawn processes, or open sockets. If a
rule needs data that is not on the context, add it to a collector.

## Adding a rule

1. Pick the right pack in `src/rules/` (or add one and register it in
   `src/rules/index.ts`).
2. Choose an ID: `PREFIX-NNN`, where the prefix matches the category —
   `AGENT`, `EXEC`, `FILE`, `REPO`, `CRED`, `MCP`, `APPR`, `AUDIT`. IDs are
   permanent once released; never reuse a retired one.
3. Write the rule:

```ts
const MCP_009: Rule = {
  id: 'MCP-009',
  title: 'Short, specific statement of the condition',
  category: 'MCP / Tool Access',
  summary: 'One line for `oconee-scan rules`.',
  evaluate(context): RuleFinding[] {
    // Pure. Read from `context` only.
    return [];
  },
};
```

4. Add it to the pack's exported array.
5. Add a fixture under `test/fixtures/` and a test that asserts the rule fires
   on it — **and** a test that it does _not_ fire on `safe-project`.

## Severity and confidence

These two fields are independent, and both feed the score. Getting them right
matters more than adding another rule.

**Severity** — the consequence if the condition is real:

| Severity   | Use when                                                                                                 |
| ---------- | -------------------------------------------------------------------------------------------------------- |
| `critical` | An irreversible or high-impact action is pre-approved with no decision point                             |
| `high`     | A control is absent or bypassed on a capability that reaches credentials, production or external systems |
| `medium`   | A meaningful gap that requires another condition to cause harm                                           |
| `low`      | A weakness in defence-in-depth, or missing governance hygiene                                            |
| `info`     | Context a reader should know; contributes zero points to the score                                       |

**Confidence** — how certain the detection is:

| Confidence | Use when                                                                           |
| ---------- | ---------------------------------------------------------------------------------- |
| `high`     | The condition is stated explicitly in configuration and cannot be read another way |
| `medium`   | Inferred from strong but indirect signals (naming conventions, file layout)        |
| `low`      | Heuristic; a reasonable project could trigger it legitimately                      |

## Conservative by default

When certainty is low, choose the quieter behaviour. This is a governance tool:
a report that cries wolf gets ignored, and an ignored report governs nothing.

Concretely:

- **Absence of configuration is not risk.** A repository with no agent config
  gets `info` or `low` ("posture unknown"), never `high`.
- **Do not infer capability from source code.** `AGENT-006` fires because a
  permission entry grants `Bash`, not because the repo contains shell scripts.
- **A low-confidence rule caps its own severity.** A `low`-confidence
  credential heuristic reports `medium` at most, never `high`.
- **Prefer one finding with several pieces of evidence** over several findings
  that say the same thing. The engine merges duplicates by `rule_id` +
  `affected_path`; design rules so that merge is meaningful.
- **Repository context is context.** Infrastructure code and CI pipelines are
  not defects. They raise blast radius, so they are reported at `low`/`medium`.

## The rules that are not negotiable

Any change that violates one of these will be rejected regardless of how useful
the detection is. Each is covered by `test/safety.test.ts`.

- **Never capture a secret value.** Report the pattern class, path and line
  number. A matched value must not reach a `Finding`, a log, or a report.
- **Never make a network request.** The scanner has no network code and will
  not gain any.
- **Never execute anything found in the scanned project** — no commands from
  configuration, no MCP servers, no project code.
- **Never write to the scanned project.** The only write is `--output`.
- **Never read outside the scan root.** Symlinks are indexed, never traversed.
- **No runtime dependencies.** The published package must stay dependency-free.

## Writing finding text

Findings are read by someone deciding whether to act. Write for them.

- **Description**: what the condition is, and _why it matters_ — the mechanism
  by which it becomes a problem. Two or three sentences.
- **Recommendation**: what to change, specifically enough to act on. "Scope
  shell grants to specific command prefixes" beats "review your permissions".
- **Evidence**: where you saw it. Never a secret value.
- Do not imply the scanner enforces anything. It reports.

## Pull requests

- Keep `npm run lint`, `npm run typecheck`, `npm test` and
  `npm run format:check` green; CI runs all four on Linux, macOS and Windows
  against Node 20 and 22.
- One logical change per PR.
- For a new rule, say in the description what a false positive would look like
  and why you think the rate is acceptable.

## Code of conduct

Be straightforward and civil. Assume the other person is trying to make the
tool better.

## License

By contributing, you agree that your contributions are licensed under
[Apache-2.0](LICENSE).
