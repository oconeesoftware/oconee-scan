import { execFileSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';
import { exitCodeFor } from '../src/cli/index.js';
import { parseArgs } from '../src/cli/args.js';
import { getReporter } from '../src/reporters/index.js';
import type { Severity } from '../src/types/index.js';
import { fixturePath, scanFixture } from './helpers.js';

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const cliEntry = path.join(repoRoot, 'src', 'cli', 'index.ts');

/** Run the CLI through tsx so tests do not depend on a prior build. */
function runCli(args: readonly string[]): { stdout: string; status: number } {
  try {
    const stdout = execFileSync(
      process.execPath,
      [path.join(repoRoot, 'node_modules', 'tsx', 'dist', 'cli.mjs'), cliEntry, ...args],
      {
        encoding: 'utf8',
        stdio: ['ignore', 'pipe', 'pipe'],
        env: { ...process.env, NO_COLOR: '1' },
      },
    );
    return { stdout, status: 0 };
  } catch (error) {
    const failure = error as { stdout?: string; status?: number };
    return { stdout: failure.stdout ?? '', status: failure.status ?? 1 };
  }
}

describe('argument parsing', () => {
  it('defaults to scanning the current directory', () => {
    const args = parseArgs([]);
    expect(args.command).toBe('scan');
    expect(args.target).toBe('.');
    expect(args.json).toBe(false);
  });

  it('accepts a positional path', () => {
    expect(parseArgs(['some/dir']).target).toBe('some/dir');
    expect(parseArgs(['scan', 'some/dir']).target).toBe('some/dir');
  });

  it('accepts flags in both spaced and equals form', () => {
    expect(parseArgs(['--output', 'r.json']).output).toBe('r.json');
    expect(parseArgs(['--output=r.json']).output).toBe('r.json');
    expect(parseArgs(['--path=/tmp/x']).target).toBe('/tmp/x');
    expect(parseArgs(['--disable=MCP-001,Auditability']).disabled).toEqual([
      'MCP-001',
      'Auditability',
    ]);
  });

  it('recognises help and version regardless of position', () => {
    expect(parseArgs(['--help']).command).toBe('help');
    expect(parseArgs(['scan', '.', '--version']).command).toBe('version');
  });

  it('reports unknown options instead of ignoring them', () => {
    expect(parseArgs(['--nope']).errors).toContain('Unknown option: --nope');
  });

  it('validates --fail-on values', () => {
    expect(parseArgs(['--fail-on', 'high']).failOn).toBe('high');
    expect(parseArgs(['--fail-on', 'banana']).errors.length).toBe(1);
    expect(parseArgs(['--fail-on']).errors).toContain('--fail-on requires a severity.');
  });

  it('rejects a second positional argument', () => {
    expect(parseArgs(['a', 'b']).errors).toContain('Unexpected argument: b');
  });
});

describe('exit codes', () => {
  const counts = (partial: Partial<Record<Severity, number>>): Record<Severity, number> => ({
    info: 0,
    low: 0,
    medium: 0,
    high: 0,
    critical: 0,
    ...partial,
  });

  it('returns 0 when no threshold is requested', () => {
    expect(exitCodeFor(counts({ critical: 5 }), undefined)).toBe(0);
    expect(exitCodeFor(counts({ critical: 5 }), 'never')).toBe(0);
  });

  it('fails when a finding meets or exceeds the threshold', () => {
    expect(exitCodeFor(counts({ high: 1 }), 'high')).toBe(1);
    expect(exitCodeFor(counts({ critical: 1 }), 'high')).toBe(1);
    expect(exitCodeFor(counts({ medium: 3 }), 'high')).toBe(0);
    expect(exitCodeFor(counts({ low: 1 }), 'low')).toBe(1);
  });
});

describe('reporters', () => {
  const result = scanFixture('risky-mcp');

  it('emits valid, parseable JSON with a schema version', () => {
    const rendered = getReporter('json').render(result);
    const parsed = JSON.parse(rendered) as Record<string, unknown>;
    expect(parsed['schema_version']).toBe(1);
    expect(parsed['findings']).toBeInstanceOf(Array);
    expect(parsed['score']).toBeTruthy();
  });

  it('emits no ANSI escapes in the JSON reporter', () => {
    const rendered = getReporter('json').render(result);
    expect(rendered).not.toMatch(new RegExp(String.fromCharCode(27)));
  });

  it('renders the score, level and required branding in terminal output', () => {
    const rendered = getReporter('terminal').render(result);
    expect(rendered).toContain('AI Agent Risk Score:');
    expect(rendered).toContain(`${result.score.score}/100`);
    expect(rendered).toContain('Oconee Runtime — AI Action Governance');
    expect(rendered).toContain('https://www.oconeeruntime.com');
  });

  it('does not claim to provide runtime enforcement', () => {
    const rendered = getReporter('terminal').render(result);
    expect(rendered).toContain('point-in-time');
    expect(rendered).toMatch(/does not enforce anything at runtime/i);
  });

  it('renders a clean result without findings', () => {
    const empty = {
      ...result,
      findings: [],
      score: {
        ...result.score,
        score: 0,
        counts: { info: 0, low: 0, medium: 0, high: 0, critical: 0 },
      },
    };
    const rendered = getReporter('terminal').render(empty);
    expect(rendered).toContain('No governance findings');
  });
});

describe('end-to-end CLI', () => {
  it('prints help', () => {
    const { stdout, status } = runCli(['--help']);
    expect(status).toBe(0);
    expect(stdout).toContain('Usage');
    expect(stdout).toContain('npx oconee-scan');
  });

  it('prints a version', () => {
    const { stdout, status } = runCli(['--version']);
    expect(status).toBe(0);
    expect(stdout.trim()).toMatch(/^\d+\.\d+\.\d+/);
  });

  it('lists rules', () => {
    const { stdout, status } = runCli(['rules']);
    expect(status).toBe(0);
    expect(stdout).toContain('Detection rules');
    expect(stdout).toContain('MCP-003');
  });

  it('scans a fixture and prints a score', () => {
    const { stdout, status } = runCli([fixturePath('safe-project')]);
    expect(status).toBe(0);
    expect(stdout).toContain('AI Agent Risk Score:');
  });

  it('emits JSON to stdout with --json', () => {
    const { stdout } = runCli([fixturePath('risky-claude'), '--json']);
    const parsed = JSON.parse(stdout) as { findings: unknown[] };
    expect(parsed.findings.length).toBeGreaterThan(0);
  });

  it('writes a report file with --output', () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'oconee-cli-'));
    try {
      const target = path.join(dir, 'nested', 'report.json');
      const { status } = runCli([fixturePath('risky-mcp'), '--json', '--output', target]);
      expect(status).toBe(0);
      expect(JSON.parse(fs.readFileSync(target, 'utf8'))).toHaveProperty('findings');
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });

  it('honours --disable', () => {
    const { stdout } = runCli([
      fixturePath('risky-mcp'),
      '--json',
      '--disable',
      'MCP-001,Auditability',
    ]);
    const parsed = JSON.parse(stdout) as { findings: Array<{ rule_id: string; category: string }> };
    expect(parsed.findings.some((f) => f.rule_id === 'MCP-001')).toBe(false);
    expect(parsed.findings.some((f) => f.category === 'Auditability')).toBe(false);
  });

  it('exits 1 when --fail-on is crossed and 0 when it is not', () => {
    expect(runCli([fixturePath('risky-claude'), '--fail-on', 'critical']).status).toBe(1);
    expect(runCli([fixturePath('safe-project'), '--fail-on', 'critical']).status).toBe(0);
  });

  it('exits 2 for an unusable target path', () => {
    expect(runCli([path.join(repoRoot, 'no-such-directory')]).status).toBe(2);
  });

  it('exits 2 for an unknown option', () => {
    expect(runCli(['--not-a-flag']).status).toBe(2);
  });
});
