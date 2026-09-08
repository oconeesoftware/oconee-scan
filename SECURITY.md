# Security Policy

## Reporting a vulnerability

Please report security issues in `oconee-scan` privately.

**Preferred:** open a [private security advisory](https://github.com/oconeesoftware/oconee-scan/security/advisories/new)
on this repository.

**Alternative:** email **security@oconeeruntime.com**.

Please do **not** open a public issue for a security report, and please do not
include real credentials, real file paths from a private repository, or any
customer data in your report. A synthetic reproduction is always sufficient.

### What to include

- A description of the issue and its impact
- A minimal configuration or directory layout that reproduces it
- The `oconee-scan` version (`oconee-scan --version`), Node version and OS

### What to expect

| Stage                  | Target                           |
| ---------------------- | -------------------------------- |
| Acknowledgement        | 3 business days                  |
| Initial assessment     | 10 business days                 |
| Fix or mitigation plan | Communicated with the assessment |

We will keep you updated as the issue progresses and will credit you in the
advisory unless you prefer otherwise.

## Supported versions

Security fixes are applied to the latest published minor version. While the
project is pre-1.0, only the most recent release is supported.

## Scope

In scope for this policy:

- The `oconee-scan` CLI and the `oconee-scan` npm package
- The build and release workflows in this repository

Out of scope:

- The commercial Oconee Runtime product — report those to
  security@oconeeruntime.com directly
- Findings that a rule _should_ have detected but did not. Those are detection
  gaps rather than vulnerabilities in the scanner; please open a
  [detection issue](https://github.com/oconeesoftware/oconee-scan/issues/new?labels=detection)
  instead.

## Security properties this project commits to

These are the guarantees the scanner is built to hold. A defect in any of them
is a security issue, not a bug:

1. **No network access.** The scanner makes no outbound network requests. It
   contains no telemetry, no version check and no analytics.
2. **No secret values in output.** Detected credentials are reported by pattern
   class, path and line number. A matched value is never captured into a
   finding, printed to a terminal, or written to a report file.
3. **Read-only operation.** The scanner never writes to, deletes from, or
   otherwise modifies the directory it scans. The only file it ever writes is
   the path given to `--output`.
4. **No execution.** The scanner never runs a command found in a scanned
   configuration, never launches an MCP server, and never executes project
   code.
5. **No scope escape.** File reads are confined to the scan root. Symlinks are
   indexed but never traversed.

Each of these is covered by an automated test in `test/safety.test.ts`. If you
find a way to violate one, that is exactly the kind of report we want.

## Supply chain

`oconee-scan` ships with **zero runtime dependencies**. Everything in the
published package is either first-party source or the Node standard library.
Development dependencies are updated weekly by Dependabot, and every push runs
CodeQL analysis.
