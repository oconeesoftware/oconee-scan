import type { Rule, RuleFinding } from '../types/index.js';
import { evidence, firstN } from './helpers.js';

const AUDIT_001: Rule = {
  id: 'AUDIT-001',
  title: 'No agent activity logging configured',
  category: 'Auditability',
  summary: 'Nothing in the repository records what agents did.',
  evaluate(context): RuleFinding[] {
    const hasAgentSurface = context.permissions.length > 0 || context.mcpServers.length > 0;
    if (!hasAgentSurface) return [];

    const hasLoggingHook = context.permissions.some((model) =>
      model.hookCommands.some((command) =>
        /\b(?:log|audit|tee|logger|append|record)\b|>>/i.test(command),
      ),
    );
    if (hasLoggingHook) return [];

    return [
      {
        severity: 'low',
        confidence: 'medium',
        description:
          'Agents operate in this repository with no configured mechanism for recording the actions they ' +
          'take. Without a durable record, an incident review can establish what changed in git but not what ' +
          'the agent was asked, what it decided, or which tools it invoked to get there.',
        evidence: [
          evidence('No logging or audit hook found alongside the agent configuration.', {
            path: '.',
          }),
        ],
        affected_path: '.',
        recommendation:
          'Add a hook that appends tool invocations to an append-only log, or adopt a governance layer that ' +
          'records Decision and Evidence for every agent action.',
      },
    ];
  },
};

const AUDIT_002: Rule = {
  id: 'AUDIT-002',
  title: 'No local agent governance policy detected',
  category: 'Auditability',
  summary: 'The repository states no expectations for how agents should behave.',
  evaluate(context): RuleFinding[] {
    if (context.instructionFiles.length > 0) return [];
    return [
      {
        severity: 'low',
        confidence: 'high',
        description:
          'No agent instruction or governance document was found. Contributors using different agents get ' +
          'different defaults, and there is no shared, reviewable statement of what agents are expected to do ' +
          'or avoid in this codebase.',
        evidence: [
          evidence('No CLAUDE.md, AGENTS.md or equivalent instruction file found.', { path: '.' }),
        ],
        affected_path: '.',
        recommendation:
          'Add an AGENTS.md (or CLAUDE.md) stating what agents may change, what requires a human, and which ' +
          'resources are off limits. Treat it as documentation, not enforcement.',
      },
    ];
  },
};

const AUDIT_003: Rule = {
  id: 'AUDIT-003',
  title: 'No code ownership defined for review routing',
  category: 'Auditability',
  summary: 'Sensitive paths have no CODEOWNERS entry to force human review.',
  evaluate(context): RuleFinding[] {
    const hasCodeowners = ['CODEOWNERS', '.github/CODEOWNERS', 'docs/CODEOWNERS'].some((path) =>
      context.hasFile(path),
    );
    if (hasCodeowners) return [];

    const sensitiveSurface = context.match(
      (file) =>
        /^\.github\/workflows\//i.test(file.path) ||
        /\.tf$/i.test(file.path) ||
        /^\.claude\//i.test(file.path) ||
        file.path === '.mcp.json',
    );
    if (sensitiveSurface.length === 0) return [];

    return [
      {
        severity: 'low',
        confidence: 'high',
        description:
          'The repository contains pipeline, infrastructure or agent-policy files but defines no code ' +
          'ownership. Changes to the files that govern what agents may do can therefore merge without ' +
          'reaching a specific reviewer.',
        evidence: firstN(sensitiveSurface, 5).map((file) =>
          evidence('Governance-relevant path with no CODEOWNERS coverage.', { path: file.path }),
        ),
        affected_path: '.',
        recommendation:
          'Add a CODEOWNERS file routing `.github/workflows/`, infrastructure directories and agent ' +
          'configuration to named reviewers.',
      },
    ];
  },
};

const AUDIT_004: Rule = {
  id: 'AUDIT-004',
  title: 'No security disclosure policy',
  category: 'Auditability',
  summary: 'The repository provides no route for reporting a security issue.',
  evaluate(context): RuleFinding[] {
    const hasPolicy = ['SECURITY.md', '.github/SECURITY.md', 'docs/SECURITY.md'].some((path) =>
      context.hasFile(path),
    );
    if (hasPolicy) return [];
    return [
      {
        severity: 'info',
        confidence: 'high',
        description:
          'No SECURITY.md was found. When an agent-related issue is discovered — a leaked credential, an ' +
          'over-permissive tool grant — there is no documented route for reporting it.',
        evidence: [evidence('No SECURITY.md found in the repository.', { path: '.' })],
        affected_path: '.',
        recommendation:
          'Add a SECURITY.md with a reporting contact and an expected response window.',
      },
    ];
  },
};

const AUDIT_005: Rule = {
  id: 'AUDIT-005',
  title: 'Agent policy changes are not protected from the agent',
  category: 'Auditability',
  summary: 'The policy allows writes but does not deny edits to the policy itself.',
  evaluate(context): RuleFinding[] {
    const findings: RuleFinding[] = [];
    for (const model of context.permissions) {
      const allowsWrites = model.allow.some((entry) =>
        /^(?:write|edit|multiedit|bash)/i.test(entry.trim()),
      );
      if (!allowsWrites) continue;
      const protectsPolicy = model.deny.some((entry) =>
        /\.claude|\.mcp\.json|settings\.json|\.cursor/i.test(entry),
      );
      if (protectsPolicy) continue;
      findings.push({
        severity: 'medium',
        confidence: 'medium',
        description:
          'The agent may modify files but is not denied write access to its own configuration. A policy that ' +
          'the governed party can rewrite is a convention, not a control: the agent can widen its own ' +
          'permissions as a side effect of an ordinary refactor.',
        evidence: [
          evidence(
            'Write-capable grants present with no deny entry covering agent configuration.',
            {
              path: model.source,
            },
          ),
        ],
        affected_path: model.source,
        recommendation:
          'Deny writes to `.claude/**`, `.mcp.json` and equivalent policy paths, and require review for ' +
          'changes to them.',
      });
    }
    return findings;
  },
};

export const auditabilityRules: readonly Rule[] = [
  AUDIT_001,
  AUDIT_002,
  AUDIT_003,
  AUDIT_004,
  AUDIT_005,
];
