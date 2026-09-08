# Test fixtures

These directories are synthetic repositories used to exercise the detection
rules. They are committed deliberately.

**Every credential-shaped value in here is fake.** The strings in
`sensitive-repo/.env`, `sensitive-repo/deploy.pem` and
`sensitive-repo/config/service-account.json` were generated to match the
*shape* of real credential formats so the pattern detectors have something to
find. None of them authenticate to anything.

Credential formats that platform secret scanners block on sight — Stripe,
GitHub and Slack tokens among them — are deliberately **not** committed here.
`test/safety.test.ts` assembles those at runtime into a temporary directory
instead, so no string in this repository ever matches a real provider format
while the detectors are still covered.

They exist so that `test/safety.test.ts` can plant a known value and assert it
never appears in any rendered report — which is the test that keeps the
"secret values are never captured" guarantee honest.

Do not add a real credential here, and do not "fix" these files by removing the
patterns: the tests depend on them.

| Fixture | Exercises |
| --- | --- |
| `safe-project` | A well-governed baseline; rules must stay quiet on it |
| `risky-claude` | Permission bypass, wildcard grants, destructive commands, hooks |
| `risky-mcp` | Broad tool grants, auto-approval, plaintext transport, unpinned servers |
| `sensitive-repo` | Environment files, key material, provider credentials |
| `infra-repo` | Infrastructure-as-code, CI/CD, deployment and container artifacts |
| `invalid-config` | Malformed JSON, and valid JSONC with comments and trailing commas |
| `empty-repo` | A repository with effectively no content |
