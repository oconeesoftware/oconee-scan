# Agent guidance for oconee-scan

This repository is a security tool. Its value depends on guarantees that are
easy to break by accident, so the constraints below are not style preferences.

## Invariants — do not violate these

1. **No network access.** This package contains no outbound network code and
   must not gain any. No telemetry, no version checks, no analytics.
2. **No runtime dependencies.** The published package is first-party source
   plus the Node standard library. Adding a runtime dependency needs an
   explicit human decision.
3. **Never capture a secret value.** Credential detection reports pattern
   class, path and line number only. A matched value must never reach a
   `Finding`, a log line, or a report file.
4. **Read-only against the scanned project.** The only file the scanner ever
   writes is the `--output` path.
5. **Never execute anything discovered in a scanned project** — no commands
   from configuration, no MCP servers, no project code.

`test/safety.test.ts` enforces all five. If a change makes one of those tests
fail, the change is wrong — not the test.

## Where things go

- New detection logic → a `Rule` in `src/rules/`. Rules are pure functions over
  `ScanContext` and must not touch the filesystem.
- New file formats or discovery → a collector in `src/scanners/`.
- Scoring, reporting and the CLI rarely need to change to add a detection.

## Expectations

- Every new rule needs a fixture, a positive test, and a test asserting it does
  _not_ fire on `test/fixtures/safe-project`.
- Keep `npm run lint`, `npm run typecheck`, `npm test` and `npm run format:check`
  green before proposing a change.
- Rule IDs are permanent once released. Never reuse a retired ID.
- When detection certainty is low, choose the quieter behaviour. See the
  severity and confidence rubric in [CONTRIBUTING.md](CONTRIBUTING.md).

## Requires a human decision

- Adding a runtime dependency
- Changing the scoring weights, category cap or risk-level bands
- Changing the JSON `schema_version` or removing a field from it
- Publishing to npm, or anything that changes release workflows
