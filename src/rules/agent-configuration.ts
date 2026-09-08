import type { Rule, RuleFinding } from '../types/index.js';
import { evidence, firstN, isUnconstrained, parsePermissionRule } from './helpers.js';

const AGENT_001: Rule = {
  id: 'AGENT-001',
  title: 'No agent governance configuration detected',
  category: 'Agent Configuration',
  summary: 'The repository declares no agent permissions, so posture is inherited and unknown.',
  evaluate(context): RuleFinding[] {
    const hasAgentSurface =
      context.claudeSettings.length > 0 ||
      context.mcpServers.length > 0 ||
      context.cursorConfigs.length > 0 ||
      context.cursorRuleFiles.length > 0 ||
      context.copilotArtifacts.length > 0 ||
      context.instructionFiles.length > 0;

    if (context.permissions.length > 0) return [];

    return [
      {
        // Absence of config is not proof of risk: an unconfigured repo simply
        // inherits whatever the developer's machine allows. Reported low.
        severity: hasAgentSurface ? 'low' : 'info',
        confidence: 'high',
        description:
          'No project-scoped agent permission policy was found. Agents operating in this repository ' +
          'fall back to user- or machine-level settings, which are not reviewable in version control ' +
          'and may differ between contributors.',
        evidence: [
          evidence(
            hasAgentSurface
              ? 'Agent tooling artifacts are present but no permissions block was found.'
              : 'No agent tooling configuration of any kind was found in this repository.',
            { path: '.' },
          ),
        ],
        affected_path: '.',
        recommendation:
          'Add a checked-in policy (for Claude Code, `.claude/settings.json` with a `permissions` block) ' +
          'defining allow, ask and deny lists so every contributor and CI job inherits the same posture.',
      },
    ];
  },
};

const AGENT_002: Rule = {
  id: 'AGENT-002',
  title: 'Wildcard tool permission grants unrestricted agent capability',
  category: 'Agent Configuration',
  summary: 'An allow-list entry grants a tool with no argument constraint, or grants all tools.',
  evaluate(context): RuleFinding[] {
    const findings: RuleFinding[] = [];
    for (const model of context.permissions) {
      const wildcards = model.allow
        .map((raw) => parsePermissionRule(raw, model.source))
        .filter((rule) => rule.tool === '*' || (isUnconstrained(rule) && rule.tool !== ''));
      if (wildcards.length === 0) continue;

      const grantsEverything = wildcards.some((rule) => rule.tool === '*');
      findings.push({
        severity: grantsEverything ? 'critical' : 'high',
        confidence: 'high',
        description:
          'The agent permission allow-list contains entries with no argument constraint. Any action the ' +
          'named tool can perform is pre-approved, so the policy cannot distinguish a safe action from a ' +
          'destructive one at decision time.',
        evidence: firstN(wildcards, 6).map((rule) =>
          evidence(`Unconstrained allow entry: ${rule.raw}`, {
            path: model.source,
            excerpt: `permissions.allow[] = ${rule.raw}`,
          }),
        ),
        affected_path: model.source,
        recommendation:
          'Replace unconstrained grants with narrowly scoped entries (for example `Bash(npm run test:*)` ' +
          'rather than `Bash`), and move anything that cannot be scoped into the `ask` list.',
      });
    }
    return findings;
  },
};

const AGENT_003: Rule = {
  id: 'AGENT-003',
  title: 'Permission prompts disabled by default mode',
  category: 'Agent Configuration',
  summary: 'A configured default mode bypasses or auto-accepts permission prompts.',
  evaluate(context): RuleFinding[] {
    const findings: RuleFinding[] = [];
    for (const model of context.permissions) {
      const mode = model.defaultMode?.trim();
      if (!mode) continue;
      const normalised = mode.toLowerCase();
      if (normalised === 'default' || normalised === 'plan') continue;

      const bypass = normalised === 'bypasspermissions';
      findings.push({
        severity: bypass ? 'critical' : 'high',
        confidence: 'high',
        description: bypass
          ? 'The configuration sets a default mode that bypasses permission checks entirely. Every agent ' +
            'action is executed without a policy decision or a human approval step.'
          : `The configuration sets a default mode of "${mode}", which auto-accepts a class of agent ` +
            'actions without an approval prompt.',
        evidence: [
          evidence(`permissions.defaultMode = "${mode}"`, {
            path: model.source,
            excerpt: `permissions.defaultMode = "${mode}"`,
          }),
        ],
        affected_path: model.source,
        recommendation: bypass
          ? 'Remove `bypassPermissions` from checked-in configuration. Reserve it for disposable sandboxes ' +
            'that hold no credentials and no production access.'
          : 'Return the default mode to `default` and grant specific, scoped allow-list entries instead.',
      });
    }
    return findings;
  },
};

const AGENT_004: Rule = {
  id: 'AGENT-004',
  title: 'Permission bypass flag committed to repository automation',
  category: 'Agent Configuration',
  summary: 'A script, workflow or task file invokes an agent with permission checks disabled.',
  evaluate(context): RuleFinding[] {
    const bypassFlags = [
      '--dangerously-skip-permissions',
      '--yolo',
      '--auto-approve-tools',
      '--dangerously-allow-browser',
    ];
    const candidates = context.match(
      (file) =>
        file.path.startsWith('.github/workflows/') ||
        file.path.startsWith('.gitlab/') ||
        file.path === '.gitlab-ci.yml' ||
        file.path.startsWith('scripts/') ||
        file.path.startsWith('.claude/') ||
        file.path === 'Makefile' ||
        file.path === 'package.json' ||
        /\.(?:sh|bash|zsh|ps1|ya?ml)$/i.test(file.path),
    );

    const findings: RuleFinding[] = [];
    for (const candidate of candidates) {
      const text = context.readText(candidate.path);
      if (text === undefined) continue;
      const lines = text.split('\n');
      for (let index = 0; index < lines.length; index += 1) {
        const line = lines[index]!;
        const flag = bypassFlags.find((needle) => line.includes(needle));
        if (!flag) continue;
        findings.push({
          severity: 'high',
          confidence: 'high',
          description:
            'Repository automation invokes a coding agent with permission enforcement disabled. Any action ' +
            'the agent chooses during that run executes without a policy decision, in an environment that ' +
            'typically holds CI credentials.',
          evidence: [
            evidence(`Permission bypass flag "${flag}" found in committed automation.`, {
              path: candidate.path,
              line: index + 1,
              excerpt: flag,
            }),
          ],
          affected_path: candidate.path,
          recommendation:
            'Remove the bypass flag. Give the automation an explicit, minimal allow-list, and run it with ' +
            'scoped credentials that cannot reach production resources.',
        });
        break; // one finding per file is enough
      }
    }
    return findings;
  },
};

const AGENT_005: Rule = {
  id: 'AGENT-005',
  title: 'Agent hooks execute shell commands',
  category: 'Agent Configuration',
  summary: 'Hook definitions run shell commands automatically around agent tool calls.',
  evaluate(context): RuleFinding[] {
    const findings: RuleFinding[] = [];
    for (const model of context.permissions) {
      if (model.hookCommands.length === 0) continue;
      findings.push({
        // Hooks are a governance *feature* as often as a risk, so this is
        // reported as awareness rather than as a defect.
        severity: 'low',
        confidence: 'high',
        description:
          'The configuration defines hooks that execute shell commands automatically when the agent runs ' +
          'tools. Hooks run with the developer’s full privileges and are not subject to the agent ' +
          'permission prompt, so their contents are part of the trusted computing base.',
        evidence: firstN(model.hookCommands, 5).map((command) =>
          evidence('Hook command configured.', {
            path: model.source,
            excerpt: command.length > 120 ? `${command.slice(0, 117)}...` : command,
          }),
        ),
        affected_path: model.source,
        recommendation:
          'Review each hook command as trusted code. Keep hook logic in version-controlled scripts, avoid ' +
          'interpolating agent-supplied values into shell strings, and require review for hook changes.',
      });
    }
    return findings;
  },
};

const AGENT_006: Rule = {
  id: 'AGENT-006',
  title: 'Shell execution capability detected',
  category: 'Agent Configuration',
  summary: 'Agent configuration explicitly permits shell/terminal tool use.',
  evaluate(context): RuleFinding[] {
    const shellRules = context.permissions.flatMap((model) =>
      model.allow
        .map((raw) => parsePermissionRule(raw, model.source))
        .filter((rule) => /^(?:bash|shell|terminal|run_?command|execute)$/i.test(rule.tool)),
    );
    if (shellRules.length === 0) return [];

    const anyUnconstrained = shellRules.some(isUnconstrained);
    const source = shellRules[0]!.source;
    return [
      {
        severity: anyUnconstrained ? 'high' : 'medium',
        confidence: 'high',
        description:
          'Agent configuration permits shell-related functionality. Shell access is the broadest action ' +
          'surface an agent can hold: it subsumes file access, network egress and credential use, and it is ' +
          'the capability least well described by a static allow-list.',
        evidence: firstN(shellRules, 6).map((rule) =>
          evidence(
            isUnconstrained(rule)
              ? 'Shell tool permitted with no command constraint.'
              : 'Shell tool permitted for a scoped command pattern.',
            { path: rule.source, excerpt: rule.raw },
          ),
        ),
        affected_path: source,
        recommendation:
          'Scope shell grants to specific command prefixes, deny credential and infrastructure commands ' +
          'explicitly, and require approval for anything outside the allow-list.',
      },
    ];
  },
};

const AGENT_007: Rule = {
  id: 'AGENT-007',
  title: 'Project MCP servers enabled without individual review',
  category: 'Agent Configuration',
  summary: 'Configuration auto-enables every MCP server declared in the project.',
  evaluate(context): RuleFinding[] {
    const findings: RuleFinding[] = [];
    for (const settings of context.claudeSettings) {
      const data = settings.data as Record<string, unknown> | undefined;
      if (!data) continue;
      if (data['enableAllProjectMcpServers'] !== true) continue;
      findings.push({
        severity: 'medium',
        confidence: 'high',
        description:
          'Every MCP server defined in the project is enabled automatically. A contributor (or a dependency ' +
          'update to a checked-in config) can introduce a new tool server that is trusted without any ' +
          'explicit approval step.',
        evidence: [
          evidence('enableAllProjectMcpServers = true', {
            path: settings.path,
            excerpt: 'enableAllProjectMcpServers = true',
          }),
        ],
        affected_path: settings.path,
        recommendation:
          'Disable blanket enablement and list trusted servers explicitly (for example via ' +
          '`enabledMcpjsonServers`), so adding a tool server requires a reviewed change.',
      });
    }
    return findings;
  },
};

const AGENT_008: Rule = {
  id: 'AGENT-008',
  title: 'Editor AI settings auto-approve agent actions',
  category: 'Agent Configuration',
  summary: 'VS Code or Cursor settings enable automatic execution of agent-proposed actions.',
  evaluate(context): RuleFinding[] {
    const risky: Array<{ path: string; key: string; value: string }> = [];

    for (const settings of context.vscodeSettings) {
      if (!settings.data) continue;
      for (const [key, value] of Object.entries(settings.data)) {
        const lowered = key.toLowerCase();
        const autoExecKey =
          /(?:autoapprove|auto_approve|automaticallyapprove|agent\.autoexecute|terminal\.autoreplies|chat\.tools\.autoapprove|experimental\.autoapprove)/.test(
            lowered,
          );
        if (!autoExecKey) continue;
        if (value === false) continue;
        risky.push({ path: settings.path, key, value: describeValue(value) });
      }
    }

    for (const config of context.cursorConfigs) {
      const data = config.data as Record<string, unknown> | undefined;
      if (!data) continue;
      for (const key of ['autoRun', 'yoloMode', 'autoApprove', 'autoAcceptEdits']) {
        if (data[key] === true) risky.push({ path: config.path, key, value: 'true' });
      }
    }

    if (risky.length === 0) return [];
    return [
      {
        severity: 'high',
        confidence: 'medium',
        description:
          'Editor configuration enables automatic approval of agent-proposed actions. The human review step ' +
          'that normally sits between an agent decision and its effect is removed for every contributor who ' +
          'opens this workspace.',
        evidence: firstN(risky, 6).map((item) =>
          evidence(`Auto-approval setting enabled: ${item.key}`, {
            path: item.path,
            excerpt: `${item.key} = ${item.value}`,
          }),
        ),
        affected_path: risky[0]!.path,
        recommendation:
          'Turn auto-approval off in checked-in workspace settings. If a team wants it locally, keep it in ' +
          'personal settings rather than shipping it to everyone who clones the repository.',
      },
    ];
  },
};

const AGENT_009: Rule = {
  id: 'AGENT-009',
  title: 'Agent configuration file could not be parsed',
  category: 'Agent Configuration',
  summary: 'A discovered configuration file is malformed, so its policy may not apply.',
  evaluate(context): RuleFinding[] {
    return context.parseErrors.map((failure) => ({
      severity: 'medium' as const,
      confidence: 'high' as const,
      description:
        'An agent or tool configuration file exists but could not be parsed. Hosts differ in how they ' +
        'handle malformed configuration: some ignore the file entirely, which silently drops any ' +
        'restrictions it was meant to impose.',
      evidence: [
        evidence(`Parse error: ${failure.parseError ?? 'unknown'}`, { path: failure.path }),
      ],
      affected_path: failure.path,
      recommendation:
        'Fix the syntax error and validate the file in CI so a malformed policy fails the build rather than ' +
        'silently disabling itself.',
    }));
  },
};

const AGENT_010: Rule = {
  id: 'AGENT-010',
  title: 'Agent instructions grant standing autonomy',
  category: 'Agent Configuration',
  summary: 'A checked-in instruction file tells agents to act without asking.',
  evaluate(context): RuleFinding[] {
    const AUTONOMY_PHRASES: ReadonlyArray<{ label: string; regex: RegExp }> = [
      {
        label: 'instructs the agent not to ask for confirmation',
        regex: /\b(?:do\s+not|don'?t|never)\s+(?:ask|prompt|confirm|request\s+permission)/i,
      },
      {
        label: 'instructs the agent to proceed without approval',
        regex: /\bwithout\s+(?:asking|confirmation|approval|permission)\b/i,
      },
      {
        label: 'instructs the agent to auto-commit or auto-push',
        regex: /\b(?:always|automatically)\s+(?:commit|push|deploy|merge)\b/i,
      },
      {
        label: 'instructs the agent to skip verification',
        regex: /\b(?:skip|bypass|ignore)\s+(?:the\s+)?(?:tests?|checks?|lint|ci|review)\b/i,
      },
    ];

    const findings: RuleFinding[] = [];
    for (const file of new Set(context.instructionFiles)) {
      const text = context.readText(file);
      if (text === undefined) continue;
      const matched = AUTONOMY_PHRASES.filter((phrase) => phrase.regex.test(text));
      if (matched.length === 0) continue;
      findings.push({
        severity: 'medium',
        confidence: 'low',
        description:
          'A checked-in agent instruction file contains language that directs agents to act without human ' +
          'confirmation. Instruction files are not an enforcement boundary, but they shape default agent ' +
          'behaviour for everyone working in the repository.',
        evidence: matched.map((phrase) =>
          evidence(`Instruction text ${phrase.label}.`, { path: file }),
        ),
        affected_path: file,
        recommendation:
          'Keep autonomy grants out of instruction files and express them as scoped, reviewable permission ' +
          'entries instead, where they can be audited and revoked.',
      });
    }
    return findings;
  },
};

function describeValue(value: unknown): string {
  if (Array.isArray(value)) return `[${value.length} entries]`;
  if (typeof value === 'object' && value !== null) return '{object}';
  return String(value);
}

export const agentConfigurationRules: readonly Rule[] = [
  AGENT_001,
  AGENT_002,
  AGENT_003,
  AGENT_004,
  AGENT_005,
  AGENT_006,
  AGENT_007,
  AGENT_008,
  AGENT_009,
  AGENT_010,
];
