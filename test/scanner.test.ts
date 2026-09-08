import { describe, expect, it } from 'vitest';
import { ALL_RULES } from '../src/rules/index.js';
import { CATEGORIES, SEVERITIES } from '../src/types/index.js';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { scan } from '../src/scan.js';
import { findingsFor, ruleIds, scanFixture } from './helpers.js';

describe('rule registry', () => {
  it('has unique rule ids', () => {
    const ids = ALL_RULES.map((rule) => rule.id);
    expect(new Set(ids).size).toBe(ids.length);
  });

  it('assigns every rule a known category', () => {
    for (const rule of ALL_RULES) {
      expect(CATEGORIES).toContain(rule.category);
    }
  });

  it('gives every rule a title and a summary', () => {
    for (const rule of ALL_RULES) {
      expect(rule.title.length).toBeGreaterThan(0);
      expect(rule.summary.length).toBeGreaterThan(0);
    }
  });
});

describe('finding shape', () => {
  it('populates every required field on every finding', () => {
    for (const fixture of ['risky-claude', 'risky-mcp', 'sensitive-repo', 'infra-repo']) {
      const result = scanFixture(fixture);
      expect(result.findings.length).toBeGreaterThan(0);
      for (const finding of result.findings) {
        expect(finding.rule_id).toMatch(/^[A-Z]+-\d{3}$/);
        expect(finding.title.length).toBeGreaterThan(0);
        expect(CATEGORIES).toContain(finding.category);
        expect(SEVERITIES).toContain(finding.severity);
        expect(['low', 'medium', 'high']).toContain(finding.confidence);
        expect(finding.description.length).toBeGreaterThan(20);
        expect(finding.evidence.length).toBeGreaterThan(0);
        expect(finding.affected_path.length).toBeGreaterThan(0);
        expect(finding.recommendation.length).toBeGreaterThan(10);
        expect(finding.documentation_url).toMatch(/^https:\/\//);
      }
    }
  });

  it('never emits duplicate rule_id + path pairs', () => {
    for (const fixture of ['risky-claude', 'risky-mcp', 'sensitive-repo', 'infra-repo']) {
      const result = scanFixture(fixture);
      const keys = result.findings.map((f) => `${f.rule_id}::${f.affected_path}`);
      expect(new Set(keys).size).toBe(keys.length);
    }
  });
});

describe('safe project', () => {
  const result = scanFixture('safe-project');

  it('scores in the low range', () => {
    expect(result.score.score).toBeLessThan(30);
    expect(['Minimal', 'Low', 'Moderate']).toContain(result.score.level);
  });

  it('raises no critical or high findings', () => {
    expect(result.score.counts.critical).toBe(0);
    expect(result.score.counts.high).toBe(0);
  });

  it('does not report missing governance artifacts that are present', () => {
    const ids = ruleIds(result);
    expect(ids).not.toContain('AUDIT-002'); // AGENTS.md present
    expect(ids).not.toContain('AUDIT-003'); // CODEOWNERS present
    expect(ids).not.toContain('AUDIT-004'); // SECURITY.md present
    expect(ids).not.toContain('AGENT-001'); // permissions present
    expect(ids).not.toContain('APPR-001'); // deny entries present
  });

  it('does not flag scoped shell permissions as unrestricted', () => {
    expect(ruleIds(result)).not.toContain('EXEC-002');
  });
});

describe('risky Claude Code configuration', () => {
  const result = scanFixture('risky-claude');
  const ids = ruleIds(result);

  it('detects the permission bypass mode as critical', () => {
    const finding = findingsFor(result, 'AGENT-003')[0];
    expect(finding).toBeDefined();
    expect(finding?.severity).toBe('critical');
  });

  it('detects unconstrained tool grants', () => {
    expect(ids).toContain('AGENT-002');
    expect(ids).toContain('EXEC-002');
    expect(ids).toContain('AGENT-006');
  });

  it('detects destructive pre-approved commands', () => {
    expect(findingsFor(result, 'EXEC-001').length).toBeGreaterThan(0);
  });

  it('detects out-of-tree directory access', () => {
    const finding = findingsFor(result, 'FILE-002')[0];
    expect(finding?.severity).toBe('high');
  });

  it('detects blanket project MCP enablement and shell hooks', () => {
    expect(ids).toContain('AGENT-007');
    expect(ids).toContain('AGENT-005');
  });

  it('scores in the high or critical range', () => {
    expect(result.score.score).toBeGreaterThanOrEqual(55);
    expect(['High', 'Critical']).toContain(result.score.level);
  });
});

describe('risky MCP configuration', () => {
  const result = scanFixture('risky-mcp');
  const ids = ruleIds(result);

  it('inventories the declared servers', () => {
    const inventory = findingsFor(result, 'MCP-001')[0];
    expect(inventory).toBeDefined();
    expect(inventory?.severity).toBe('info');
  });

  it('detects broad MCP tool permissions', () => {
    expect(findingsFor(result, 'MCP-003').length).toBeGreaterThan(0);
  });

  it('detects unpinned package-runner launches', () => {
    expect(ids).toContain('MCP-002');
  });

  it('detects plaintext transport to a remote host', () => {
    const finding = findingsFor(result, 'MCP-005')[0];
    expect(finding?.severity).toBe('high');
  });

  it('detects a filesystem server rooted outside the project', () => {
    expect(ids).toContain('MCP-006');
  });

  it('detects credential-named environment variables without reading values', () => {
    const finding = findingsFor(result, 'MCP-004')[0];
    expect(finding).toBeDefined();
    const serialised = JSON.stringify(finding);
    expect(serialised).toContain('GITHUB_PERSONAL_ACCESS_TOKEN');
    expect(serialised).not.toContain('set-me');
  });

  it('detects a server with no declared transport', () => {
    expect(ids).toContain('MCP-008');
  });
});

describe('sensitive repository', () => {
  const result = scanFixture('sensitive-repo');
  const ids = ruleIds(result);

  it('detects environment files, key material and provider credentials', () => {
    expect(ids).toContain('CRED-001');
    expect(ids).toContain('CRED-003');
    expect(ids).toContain('CRED-005');
  });

  it('detects that credential files are not git-ignored', () => {
    expect(ids).toContain('CRED-002');
  });

  it('detects credential patterns by class', () => {
    const findings = findingsFor(result, 'CRED-004');
    expect(findings.length).toBeGreaterThan(0);
    const patterns = findings.flatMap((f) => f.evidence.map((e) => e.excerpt ?? ''));
    expect(patterns.join(' ')).toMatch(/aws-access-key-id|private-key-block|stripe-live-key/);
  });

  it('reports credentials at full severity when they are not under a fixture path', () => {
    // Paths are relative to the scan root, so scanning the fixture directly
    // means nothing inside it looks like a fixture.
    expect(findingsFor(result, 'CRED-003')[0]?.severity).toBe('high');
    expect(findingsFor(result, 'CRED-005')[0]?.severity).toBe('high');
  });

  it('does not treat .env.example as a live credential file', () => {
    const envFindings = findingsFor(result, 'CRED-001');
    const paths = envFindings.flatMap((f) => f.evidence.map((e) => e.path));
    expect(paths).not.toContain('.env.example');
  });
});

describe('fixture-path downgrading', () => {
  /** Build a throwaway repo so the test does not depend on this repo's layout. */
  function withTempRepo(files: Record<string, string>, run: (root: string) => void): void {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), 'oconee-fixture-'));
    try {
      for (const [relative, contents] of Object.entries(files)) {
        const absolute = path.join(root, relative);
        fs.mkdirSync(path.dirname(absolute), { recursive: true });
        fs.writeFileSync(absolute, contents);
      }
      run(root);
    } finally {
      fs.rmSync(root, { recursive: true, force: true });
    }
  }

  const KEY = '-----BEGIN RSA PRIVATE KEY-----\nc3ludGhldGlj\n-----END RSA PRIVATE KEY-----\n';

  it('downgrades a credential finding whose matches are all under fixture paths', () => {
    withTempRepo({ 'test/fixtures/app/deploy.pem': KEY }, (root) => {
      const finding = scan(root).findings.find((f) => f.rule_id === 'CRED-003');
      expect(finding).toBeDefined();
      expect(finding?.severity).toBe('medium');
      expect(finding?.confidence).toBe('low');
      expect(finding?.description).toMatch(/test-fixture paths/);
    });
  });

  it('keeps full severity when any match sits outside a fixture path', () => {
    withTempRepo({ 'test/fixtures/app/deploy.pem': KEY, 'deploy.pem': KEY }, (root) => {
      const finding = scan(root).findings.find((f) => f.rule_id === 'CRED-003');
      expect(finding?.severity).toBe('high');
      expect(finding?.description).not.toMatch(/test-fixture paths/);
    });
  });

  it('downgrades rather than suppressing', () => {
    withTempRepo({ 'test/fixtures/app/deploy.pem': KEY }, (root) => {
      const ids = scan(root).findings.map((f) => f.rule_id);
      expect(ids).toContain('CRED-003');
    });
  });
});

describe('infrastructure repository', () => {
  const result = scanFixture('infra-repo');
  const ids = ruleIds(result);

  it('detects infrastructure-as-code, CI/CD, deployment and container artifacts', () => {
    expect(ids).toContain('REPO-001');
    expect(ids).toContain('REPO-002');
    expect(ids).toContain('REPO-003');
    expect(ids).toContain('REPO-004');
  });

  it('treats repository risk as context, not as a critical defect', () => {
    for (const finding of result.findings.filter((f) => f.category === 'Repository Risk')) {
      expect(['info', 'low', 'medium']).toContain(finding.severity);
    }
  });
});

describe('invalid configuration', () => {
  const result = scanFixture('invalid-config');
  const ids = ruleIds(result);

  it('reports unparseable configuration instead of crashing', () => {
    const findings = findingsFor(result, 'AGENT-009');
    expect(findings.length).toBeGreaterThanOrEqual(2);
    const paths = findings.map((f) => f.affected_path);
    expect(paths).toContain('.claude/settings.json');
    expect(paths).toContain('.mcp.json');
  });

  it('still parses JSONC with comments and trailing commas', () => {
    expect(ids).toContain('AGENT-008');
  });
});

describe('empty repository', () => {
  const result = scanFixture('empty-repo');

  it('completes without error', () => {
    expect(result.findings).toBeDefined();
    expect(result.filesIndexed).toBeGreaterThanOrEqual(1);
  });

  it('reports unknown posture at low severity rather than high risk', () => {
    expect(result.score.counts.critical).toBe(0);
    expect(result.score.counts.high).toBe(0);
    expect(result.score.score).toBeLessThan(20);
  });
});
