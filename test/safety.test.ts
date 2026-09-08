import { createHash } from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { describe, expect, it } from 'vitest';
import { getReporter } from '../src/reporters/index.js';
import { scan } from '../src/scan.js';
import { fixturePath, scanFixture } from './helpers.js';

/**
 * The privacy and safety guarantees in the README are load-bearing claims.
 * These tests exist so that a future rule cannot quietly break one of them.
 */

/** Synthetic secret values planted in the committed sensitive-repo fixture. */
const PLANTED_SECRETS = [
  'hunter2correcthorse',
  'AKIAI0SF0DNN7SELFTST',
  'RklYVFVSRSAtIG5vdCBhIHJlYWwga2V5',
  'postgres://app:hunter2correcthorse@db.internal:5432/prod',
];

/**
 * Provider formats that platform secret scanners block on sight. These are
 * assembled at runtime rather than committed, so no string in this repository
 * ever matches a real credential format -- the values exist only for the
 * lifetime of the test.
 */
const RUNTIME_SECRETS: ReadonlyArray<{ env: string; value: string }> = [
  { env: 'STRIPE_SECRET', value: ['sk', 'live', '51H8QzTvNbGkRxPl4Mw7Jd2Fa'].join('_') },
  { env: 'GITHUB_TOKEN', value: ['ghp', 'R7kQm2Xv9TbLn4Wp8Ys3Dc6Hj1Ez5Ua0Ov2Q'].join('_') },
  { env: 'SLACK_TOKEN', value: ['xoxb', '204212345678', 'ZmFrZXNsYWNrdG9rZW4'].join('-') },
];

/** Build a throwaway repository containing the runtime-only secrets. */
function withRuntimeSecretRepo(run: (root: string) => void): void {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'oconee-secrets-'));
  try {
    const lines = RUNTIME_SECRETS.map((entry) => `${entry.env}=${entry.value}`);
    fs.writeFileSync(path.join(root, '.env'), `${lines.join('\n')}\n`);
    run(root);
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
}

function snapshotTree(root: string): Map<string, string> {
  const snapshot = new Map<string, string>();
  const walk = (dir: string): void => {
    for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
      const absolute = path.join(dir, entry.name);
      if (entry.isDirectory()) {
        walk(absolute);
        continue;
      }
      if (!entry.isFile()) continue;
      const stat = fs.statSync(absolute);
      const hash = createHash('sha256').update(fs.readFileSync(absolute)).digest('hex');
      snapshot.set(path.relative(root, absolute), `${hash}:${stat.size}:${stat.mtimeMs}`);
    }
  };
  walk(root);
  return snapshot;
}

describe('secrets are never emitted', () => {
  const result = scanFixture('sensitive-repo');

  it('keeps secret values out of the JSON report', () => {
    const rendered = getReporter('json').render(result);
    for (const secret of PLANTED_SECRETS) {
      expect(rendered).not.toContain(secret);
    }
  });

  it('keeps secret values out of the terminal report', () => {
    for (const verbose of [false, true]) {
      const rendered = getReporter('terminal', { verbose }).render(result);
      for (const secret of PLANTED_SECRETS) {
        expect(rendered).not.toContain(secret);
      }
    }
  });

  it('reports the pattern class and location instead of the value', () => {
    const rendered = getReporter('json').render(result);
    expect(rendered).toContain('aws-access-key-id');
    expect(rendered).toMatch(/"line":\s*\d+/);
  });

  it('keeps provider-format credentials out of every report', () => {
    withRuntimeSecretRepo((root) => {
      const result = scan(root);
      const rendered = [
        getReporter('json').render(result),
        getReporter('terminal', { verbose: true }).render(result),
        getReporter('terminal').render(result),
      ].join('\n');

      // The scanner must have noticed them...
      expect(rendered).toContain('stripe-live-key');
      expect(rendered).toContain('github-token');
      expect(rendered).toContain('slack-token');

      // ...without ever reproducing a value.
      for (const entry of RUNTIME_SECRETS) {
        expect(rendered).not.toContain(entry.value);
      }
    });
  });

  it('keeps MCP environment variable values out of the report', () => {
    const mcp = getReporter('json').render(scanFixture('risky-mcp'));
    expect(mcp).toContain('GITHUB_PERSONAL_ACCESS_TOKEN');
    expect(mcp).not.toContain('set-me');
  });
});

describe('the scanner never modifies the scanned project', () => {
  it.each([
    'safe-project',
    'risky-claude',
    'risky-mcp',
    'sensitive-repo',
    'infra-repo',
    'invalid-config',
  ])('leaves %s byte-for-byte identical', (fixture) => {
    const root = fixturePath(fixture);
    const before = snapshotTree(root);
    scan(root);
    const after = snapshotTree(root);
    expect([...after.keys()].sort()).toEqual([...before.keys()].sort());
    for (const [file, digest] of before) {
      expect(after.get(file)).toBe(digest);
    }
  });
});

describe('unsupported and hostile inputs', () => {
  it('throws a typed error for a path that does not exist', () => {
    expect(() => scan(fixturePath('does-not-exist'))).toThrowError(/does not exist/i);
  });

  it('throws a typed error when the target is a file', () => {
    expect(() => scan(path.join(fixturePath('safe-project'), 'README.md'))).toThrowError(
      /not a directory/i,
    );
  });

  it('does not follow symlinks out of the scan root', () => {
    const root = fs.mkdtempSync(path.join(process.env['TMPDIR'] ?? '/tmp', 'oconee-symlink-'));
    try {
      fs.writeFileSync(path.join(root, 'README.md'), '# fixture\n');
      fs.symlinkSync(fixturePath('sensitive-repo'), path.join(root, 'escape'), 'dir');
      const result = scan(root);
      const paths = JSON.stringify(result.findings);
      expect(paths).not.toContain('escape/.env');
      expect(paths).not.toContain('deploy.pem');
    } finally {
      fs.rmSync(root, { recursive: true, force: true });
    }
  });

  it('handles a directory containing only binary content', () => {
    const root = fs.mkdtempSync(path.join(process.env['TMPDIR'] ?? '/tmp', 'oconee-binary-'));
    try {
      fs.writeFileSync(path.join(root, 'blob.bin'), Buffer.from([0, 1, 2, 3, 0, 255]));
      fs.writeFileSync(path.join(root, 'image.png'), Buffer.from([0x89, 0x50, 0x4e, 0x47, 0]));
      const result = scan(root);
      expect(result.findings.some((f) => f.category === 'Credential Exposure')).toBe(false);
    } finally {
      fs.rmSync(root, { recursive: true, force: true });
    }
  });
});
