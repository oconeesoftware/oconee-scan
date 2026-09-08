import type { Rule, RuleFinding } from '../types/index.js';
import { isCloudCredentialFile, isEnvFile, isKeyMaterial } from '../scanners/credentials.js';
import { denyCovers, evidence, firstN, isUnconstrained, parsePermissionRule } from './helpers.js';

const WRITE_TOOL = /^(?:write|edit|multiedit|notebookedit|create_?file|apply_?patch)$/i;
const READ_TOOL = /^(?:read|glob|grep|search|view)$/i;

const FILE_001: Rule = {
  id: 'FILE-001',
  title: 'Agent write access is not scoped to a path',
  category: 'File Access',
  summary: 'File-writing tools are allowed with no path constraint.',
  evaluate(context): RuleFinding[] {
    const findings: RuleFinding[] = [];
    for (const model of context.permissions) {
      const unscoped = model.allow
        .map((raw) => parsePermissionRule(raw, model.source))
        .filter((rule) => WRITE_TOOL.test(rule.tool) && isUnconstrained(rule));
      if (unscoped.length === 0) continue;
      findings.push({
        severity: 'medium',
        confidence: 'high',
        description:
          'File-modifying tools are permitted without a path constraint. The agent can rewrite any file it ' +
          'can reach, including CI definitions, deployment manifests and the agent policy itself.',
        evidence: unscoped.map((rule) =>
          evidence('Write-capable tool allowed with no path constraint.', {
            path: rule.source,
            excerpt: rule.raw,
          }),
        ),
        affected_path: model.source,
        recommendation:
          'Scope write grants to the directories the workflow edits (for example `Edit(src/**)`), and deny ' +
          'writes to CI, deployment and policy files.',
      });
    }
    return findings;
  },
};

const FILE_002: Rule = {
  id: 'FILE-002',
  title: 'Agent access extended beyond the project directory',
  category: 'File Access',
  summary: 'Configuration adds directories outside the repository to the agent working set.',
  evaluate(context): RuleFinding[] {
    const findings: RuleFinding[] = [];
    for (const model of context.permissions) {
      if (model.additionalDirectories.length === 0) continue;
      const escaping = model.additionalDirectories.filter(
        (dir) =>
          dir.startsWith('/') ||
          dir.startsWith('~') ||
          dir.startsWith('..') ||
          /^[A-Za-z]:[\\/]/.test(dir),
      );
      const severity = escaping.length > 0 ? 'high' : 'low';
      findings.push({
        severity,
        confidence: 'high',
        description:
          escaping.length > 0
            ? 'Agent file access is extended to absolute or parent-relative directories outside the ' +
              'repository. The blast radius of an agent mistake is no longer bounded by this project.'
            : 'Agent file access is extended to additional directories. Anything reachable from those paths ' +
              'becomes part of the agent’s resource surface.',
        evidence: firstN(model.additionalDirectories, 6).map((dir) =>
          evidence(`Additional directory in scope: ${dir}`, {
            path: model.source,
            excerpt: `permissions.additionalDirectories[] = ${dir}`,
          }),
        ),
        affected_path: model.source,
        recommendation:
          'Remove out-of-tree directories from checked-in configuration. If cross-repository work is needed, ' +
          'grant it per session rather than to every contributor by default.',
      });
    }
    return findings;
  },
};

const FILE_003: Rule = {
  id: 'FILE-003',
  title: 'Sensitive paths are not denied to agents',
  category: 'File Access',
  summary: 'A permission policy exists but does not deny credential or key material paths.',
  evaluate(context): RuleFinding[] {
    if (context.permissions.length === 0) return [];

    const sensitiveFiles = context.match(
      (file) =>
        isEnvFile(file.path) || isKeyMaterial(file.path) || isCloudCredentialFile(file.path),
    );
    if (sensitiveFiles.length === 0) return [];

    const covered = ['.env', 'secret', '.pem', 'credential', 'key'].some((fragment) =>
      denyCovers(context.permissions, fragment),
    );
    if (covered) return [];

    const source = context.permissions[0]!.source;
    return [
      {
        severity: 'high',
        confidence: 'medium',
        description:
          'The repository contains credential or key material, and the agent permission policy contains no ' +
          'deny entry covering those paths. Any tool with read access can pull the contents into the model ' +
          'context, where it may be echoed into logs, transcripts or subsequent tool calls.',
        evidence: firstN(sensitiveFiles, 6).map((file) =>
          evidence('Sensitive file is within the agent’s readable scope.', { path: file.path }),
        ),
        affected_path: source,
        recommendation:
          'Add deny entries covering `.env*`, private keys and provider credential files (for Claude Code, ' +
          '`Read(./.env)` and similar under `permissions.deny`).',
      },
    ];
  },
};

const FILE_004: Rule = {
  id: 'FILE-004',
  title: 'Read access granted with no path constraint',
  category: 'File Access',
  summary: 'Read/search tools are allowed globally while sensitive files exist in the tree.',
  evaluate(context): RuleFinding[] {
    const unconstrainedReads = context.permissions.flatMap((model) =>
      model.allow
        .map((raw) => parsePermissionRule(raw, model.source))
        .filter((rule) => READ_TOOL.test(rule.tool) && isUnconstrained(rule)),
    );
    if (unconstrainedReads.length === 0) return [];

    const hasSensitive =
      context.match(
        (file) =>
          isEnvFile(file.path) || isKeyMaterial(file.path) || isCloudCredentialFile(file.path),
      ).length > 0;

    return [
      {
        // Broad read access is normal for coding agents; it only becomes a
        // real finding when there is something sensitive to read.
        severity: hasSensitive ? 'medium' : 'low',
        confidence: 'medium',
        description:
          'Read and search tools are permitted across the whole working tree. Read access determines what can ' +
          'enter the model context, which is the first step of both accidental disclosure and prompt ' +
          'injection via repository content.',
        evidence: firstN(unconstrainedReads, 5).map((rule) =>
          evidence('Read-capable tool allowed with no path constraint.', {
            path: rule.source,
            excerpt: rule.raw,
          }),
        ),
        affected_path: unconstrainedReads[0]!.source,
        recommendation:
          'Pair broad read access with explicit deny entries for credentials, key material and any directory ' +
          'holding customer data.',
      },
    ];
  },
};

export const fileAccessRules: readonly Rule[] = [FILE_001, FILE_002, FILE_003, FILE_004];
