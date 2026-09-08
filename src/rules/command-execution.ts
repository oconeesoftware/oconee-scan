import type { Rule, RuleFinding, Severity } from '../types/index.js';
import {
  evidence,
  firstN,
  isNetworkEgressCommand,
  isUnconstrained,
  matchDangerousCommand,
  parsePermissionRule,
} from './helpers.js';

const SHELL_TOOL = /^(?:bash|shell|terminal|run_?command|execute)$/i;

const EXEC_001: Rule = {
  id: 'EXEC-001',
  title: 'Destructive command pre-approved for agent execution',
  category: 'Command Execution',
  summary: 'An allow-list entry pre-approves a command class that is destructive or irreversible.',
  evaluate(context): RuleFinding[] {
    const findings: RuleFinding[] = [];
    for (const model of context.permissions) {
      for (const raw of model.allow) {
        const rule = parsePermissionRule(raw, model.source);
        if (!SHELL_TOOL.test(rule.tool) || rule.argument === undefined) continue;
        const match = matchDangerousCommand(rule.argument);
        if (!match) continue;
        findings.push({
          severity: 'critical',
          confidence: 'high',
          description:
            'A command class that causes irreversible change is pre-approved in the agent allow-list. The ' +
            'agent can execute it with no decision point, so a single bad inference produces an effect that ' +
            'cannot be undone by declining a prompt.',
          evidence: [
            evidence(`${match.label} is pre-approved.`, { path: model.source, excerpt: rule.raw }),
          ],
          affected_path: model.source,
          recommendation:
            'Remove the entry from the allow-list. If the workflow genuinely needs it, move it to the `ask` ' +
            'list so a human authorises each occurrence in context.',
        });
      }
    }
    return findings;
  },
};

const EXEC_002: Rule = {
  id: 'EXEC-002',
  title: 'Unrestricted shell execution permitted',
  category: 'Command Execution',
  summary: 'A shell tool is allowed with no command constraint at all.',
  evaluate(context): RuleFinding[] {
    const findings: RuleFinding[] = [];
    for (const model of context.permissions) {
      const unrestricted = model.allow
        .map((raw) => parsePermissionRule(raw, model.source))
        .filter((rule) => SHELL_TOOL.test(rule.tool) && isUnconstrained(rule));
      if (unrestricted.length === 0) continue;
      findings.push({
        severity: 'high',
        confidence: 'high',
        description:
          'Shell execution is permitted without a command constraint. Every other restriction in the policy ' +
          'is advisory once this grant exists, because arbitrary shell can read any readable file, reach any ' +
          'reachable network endpoint and use any credential available to the process.',
        evidence: unrestricted.map((rule) =>
          evidence('Shell tool allowed with no argument constraint.', {
            path: rule.source,
            excerpt: rule.raw,
          }),
        ),
        affected_path: model.source,
        recommendation:
          'Replace the blanket grant with specific command prefixes the workflow actually needs, and add deny ' +
          'entries for credential, deployment and infrastructure commands.',
      });
    }
    return findings;
  },
};

const EXEC_003: Rule = {
  id: 'EXEC-003',
  title: 'Network egress commands permitted without restriction',
  category: 'Command Execution',
  summary: 'The agent may run commands that can send repository contents to an external endpoint.',
  evaluate(context): RuleFinding[] {
    const findings: RuleFinding[] = [];
    for (const model of context.permissions) {
      const egress = model.allow
        .map((raw) => parsePermissionRule(raw, model.source))
        .filter(
          (rule) =>
            SHELL_TOOL.test(rule.tool) &&
            rule.argument !== undefined &&
            isNetworkEgressCommand(rule.argument) &&
            // A pinned URL is a bounded grant; an unbounded one is not.
            !/https?:\/\/[^\s*]+$/i.test(rule.argument),
        );
      if (egress.length === 0) continue;
      findings.push({
        severity: 'medium',
        confidence: 'medium',
        description:
          'Commands capable of network egress are pre-approved without a destination constraint. Combined ' +
          'with read access to the repository, this is the shape of an exfiltration path: the agent can be ' +
          'induced to send local content to an attacker-chosen endpoint.',
        evidence: firstN(egress, 5).map((rule) =>
          evidence('Network-capable command allowed without a destination constraint.', {
            path: rule.source,
            excerpt: rule.raw,
          }),
        ),
        affected_path: model.source,
        recommendation:
          'Constrain egress commands to known hosts, or deny them and provide the data the workflow needs ' +
          'through a reviewed script instead.',
      });
    }
    return findings;
  },
};

const EXEC_004: Rule = {
  id: 'EXEC-004',
  title: 'Package installation permitted for agent execution',
  category: 'Command Execution',
  summary: 'The agent may install dependencies, which executes third-party install scripts.',
  evaluate(context): RuleFinding[] {
    const INSTALL =
      /\b(?:npm|pnpm|yarn|bun)\s+(?:i|install|add)\b|\bpip3?\s+install\b|\bgem\s+install\b|\bcargo\s+install\b|\bgo\s+install\b|\bbrew\s+install\b|\buvx?\b|\bnpx\b/i;
    const findings: RuleFinding[] = [];
    for (const model of context.permissions) {
      const installs = model.allow
        .map((raw) => parsePermissionRule(raw, model.source))
        .filter(
          (rule) =>
            SHELL_TOOL.test(rule.tool) &&
            rule.argument !== undefined &&
            INSTALL.test(rule.argument),
        );
      if (installs.length === 0) continue;
      findings.push({
        severity: 'medium',
        confidence: 'medium',
        description:
          'Dependency installation is pre-approved. Install commands execute publisher-controlled lifecycle ' +
          'scripts on the developer machine, so this grant delegates code execution to whatever package the ' +
          'agent decides to fetch.',
        evidence: firstN(installs, 5).map((rule) =>
          evidence('Package installation command pre-approved.', {
            path: rule.source,
            excerpt: rule.raw,
          }),
        ),
        affected_path: model.source,
        recommendation:
          'Scope installs to a lockfile-driven command (`npm ci`) rather than arbitrary `install <package>`, ' +
          'and require approval for adding new dependencies.',
      });
    }
    return findings;
  },
};

const EXEC_005: Rule = {
  id: 'EXEC-005',
  title: 'Hook command performs a high-impact operation',
  category: 'Command Execution',
  summary: 'A configured hook runs a destructive or network-capable command automatically.',
  evaluate(context): RuleFinding[] {
    const findings: RuleFinding[] = [];
    for (const model of context.permissions) {
      for (const command of model.hookCommands) {
        const match = matchDangerousCommand(command);
        const egress = isNetworkEgressCommand(command);
        if (!match && !egress) continue;
        const severity: Severity = match ? 'high' : 'medium';
        findings.push({
          severity,
          confidence: 'medium',
          description:
            'A hook command performs a high-impact operation. Hooks run automatically around tool calls and ' +
            'are not gated by the agent permission prompt, so the operation happens without a decision point.',
          evidence: [
            evidence(
              match
                ? `Hook command matches: ${match.label}.`
                : 'Hook command performs network egress.',
              {
                path: model.source,
                excerpt: command.length > 120 ? `${command.slice(0, 117)}...` : command,
              },
            ),
          ],
          affected_path: model.source,
          recommendation:
            'Move the logic into a reviewed script with a narrow purpose, and avoid destructive or ' +
            'network-egress operations in automatically-triggered hooks.',
        });
      }
    }
    return findings;
  },
};

export const commandExecutionRules: readonly Rule[] = [
  EXEC_001,
  EXEC_002,
  EXEC_003,
  EXEC_004,
  EXEC_005,
];
