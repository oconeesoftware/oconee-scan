import type { Rule, RuleFinding } from '../types/index.js';
import { evidence, firstN, isUnconstrained, parsePermissionRule } from './helpers.js';

const APPR_001: Rule = {
  id: 'APPR-001',
  title: 'Permission policy defines no deny rules',
  category: 'Approval Controls',
  summary: 'An allow-list exists without any explicit denial of high-impact actions.',
  evaluate(context): RuleFinding[] {
    const findings: RuleFinding[] = [];
    for (const model of context.permissions) {
      if (model.allow.length === 0) continue;
      if (model.deny.length > 0) continue;
      findings.push({
        severity: 'medium',
        confidence: 'high',
        description:
          'The policy grants capabilities but never denies any. A deny list is what holds when an allow entry ' +
          'turns out to be broader than intended, so a policy without one has no second line: the only thing ' +
          'standing between the agent and a high-impact action is the precision of the allow patterns.',
        evidence: [
          evidence(
            `${model.allow.length} allow entr${model.allow.length === 1 ? 'y' : 'ies'} and no deny entries.`,
            { path: model.source, excerpt: 'permissions.deny = []' },
          ),
        ],
        affected_path: model.source,
        recommendation:
          'Add deny entries for credential paths, deployment and infrastructure commands, and writes to CI ' +
          'definitions. Deny takes precedence over allow, so it is the durable control.',
      });
    }
    return findings;
  },
};

const APPR_002: Rule = {
  id: 'APPR-002',
  title: 'No actions routed to human approval',
  category: 'Approval Controls',
  summary: 'The policy has an allow list but no ask list, so nothing is escalated by design.',
  evaluate(context): RuleFinding[] {
    const findings: RuleFinding[] = [];
    for (const model of context.permissions) {
      if (model.allow.length === 0) continue;
      if (model.ask.length > 0) continue;
      // A policy that also denies broadly is a defensible design, so this is
      // reported low rather than medium.
      const severity = model.deny.length > 0 ? 'info' : 'low';
      findings.push({
        severity,
        confidence: 'medium',
        description:
          'No action class is explicitly routed to human approval. Approval becomes whatever the host does by ' +
          'default rather than a deliberate decision about which actions warrant a person in the loop.',
        evidence: [
          evidence('Policy defines allow entries but no ask entries.', {
            path: model.source,
            excerpt: 'permissions.ask = []',
          }),
        ],
        affected_path: model.source,
        recommendation:
          'Name the action classes that should always reach a human — deploys, migrations, credential access, ' +
          'dependency additions — and place them in the `ask` list.',
      });
    }
    return findings;
  },
};

const APPR_003: Rule = {
  id: 'APPR-003',
  title: 'Local-only agent policy is not shared with the team',
  category: 'Approval Controls',
  summary: 'Permissions live only in a local settings file that other contributors never receive.',
  evaluate(context): RuleFinding[] {
    const localOnly = context.permissions.filter((model) => model.source.includes('.local.'));
    const shared = context.permissions.filter((model) => !model.source.includes('.local.'));
    if (localOnly.length === 0 || shared.length > 0) return [];
    return [
      {
        severity: 'low',
        confidence: 'high',
        description:
          'The only agent permission policy found is in a local settings file. Local settings are ' +
          'conventionally git-ignored, so every other contributor and every CI job operates under a different ' +
          'and unreviewed posture.',
        evidence: localOnly.map((model) =>
          evidence('Permissions found only in a local-scoped settings file.', {
            path: model.source,
          }),
        ),
        affected_path: localOnly[0]!.source,
        recommendation:
          'Move the shared baseline into the checked-in settings file and keep only personal overrides local.',
      },
    ];
  },
};

const APPR_004: Rule = {
  id: 'APPR-004',
  title: 'Agent runs non-interactively in CI without a scoped policy',
  category: 'Approval Controls',
  summary: 'A workflow invokes a coding agent where no human can answer an approval prompt.',
  evaluate(context): RuleFinding[] {
    const AGENT_INVOCATION =
      /\b(?:claude|anthropics\/claude-code-action|aider|goose|cursor-agent|codex|opencode)\b/i;
    const workflows = context.match((file) => /^\.github\/workflows\/.+\.ya?ml$/i.test(file.path));

    const findings: RuleFinding[] = [];
    for (const workflow of workflows) {
      const text = context.readText(workflow.path);
      if (text === undefined) continue;
      if (!AGENT_INVOCATION.test(text)) continue;

      const hasScopedPolicy = context.permissions.some(
        (model) => model.allow.length > 0 || model.deny.length > 0,
      );
      findings.push({
        severity: hasScopedPolicy ? 'low' : 'medium',
        confidence: 'low',
        description:
          'A CI workflow appears to invoke a coding agent. Non-interactive runs have no human available to ' +
          'answer an approval prompt, so whatever the policy allows is what happens — and CI runners usually ' +
          'hold deployment credentials that a developer laptop does not.',
        evidence: [
          evidence('Workflow references a coding agent invocation.', { path: workflow.path }),
        ],
        affected_path: workflow.path,
        recommendation:
          'Give agent CI jobs their own minimal allow-list, run them with least-privilege tokens, and require ' +
          'that their output land in a pull request rather than on a protected branch.',
      });
    }
    return findings;
  },
};

const APPR_005: Rule = {
  id: 'APPR-005',
  title: 'Every configured tool is pre-approved',
  category: 'Approval Controls',
  summary: 'The allow-list covers all capabilities with nothing left to ask or deny.',
  evaluate(context): RuleFinding[] {
    const findings: RuleFinding[] = [];
    for (const model of context.permissions) {
      if (model.allow.length < 3) continue;
      if (model.ask.length > 0 || model.deny.length > 0) continue;
      const unconstrainedCount = model.allow
        .map((raw) => parsePermissionRule(raw, model.source))
        .filter(isUnconstrained).length;
      if (unconstrainedCount === 0) continue;
      findings.push({
        severity: 'medium',
        confidence: 'medium',
        description:
          'The policy is allow-only, and several entries are unconstrained. In practice this makes the ' +
          'approval control inert: there is no action class that produces a decision point, so nothing in the ' +
          'configuration can stop a mistaken action before it takes effect.',
        evidence: firstN(model.allow, 6).map((entry) =>
          evidence('Allow entry with no corresponding ask/deny control.', {
            path: model.source,
            excerpt: entry,
          }),
        ),
        affected_path: model.source,
        recommendation:
          'Pair the allow-list with ask and deny entries so at least the high-impact action classes reach a ' +
          'decision point.',
      });
    }
    return findings;
  },
};

export const approvalControlRules: readonly Rule[] = [
  APPR_001,
  APPR_002,
  APPR_003,
  APPR_004,
  APPR_005,
];
