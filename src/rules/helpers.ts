import type { Evidence, PermissionModel, ScanContext, Severity } from '../types/index.js';

export const DOCS_BASE = 'https://www.oconeeruntime.com/tools/agent-risk-scanner/rules';

export function docsUrlFor(ruleId: string): string {
  return `${DOCS_BASE}/${ruleId.toLowerCase()}`;
}

/** A permission entry such as `Bash(npm run test:*)` split into its parts. */
export interface PermissionRule {
  readonly raw: string;
  readonly source: string;
  /** Tool name, e.g. `Bash`, `Read`, `Write`, `mcp__github`. */
  readonly tool: string;
  /** Text inside the parentheses, if present. */
  readonly argument?: string;
}

export function parsePermissionRule(raw: string, source: string): PermissionRule {
  const match = /^([^(]+)\((.*)\)\s*$/.exec(raw.trim());
  if (!match) return { raw, source, tool: raw.trim() };
  return { raw, source, tool: match[1]!.trim(), argument: match[2]!.trim() };
}

export function permissionRules(
  context: ScanContext,
  list: 'allow' | 'deny' | 'ask',
): PermissionRule[] {
  return context.permissions.flatMap((model) =>
    model[list].map((raw) => parsePermissionRule(raw, model.source)),
  );
}

/** True when a permission entry grants a tool with no argument constraint. */
export function isUnconstrained(rule: PermissionRule): boolean {
  if (rule.argument === undefined) return true;
  const argument = rule.argument;
  return argument === '' || argument === '*' || argument === '**' || argument === ':*';
}

export function isMcpTool(tool: string): boolean {
  return tool.toLowerCase().startsWith('mcp__');
}

/** `mcp__server__tool` -> `server`. */
export function mcpServerFromTool(tool: string): string | undefined {
  const parts = tool.split('__');
  return parts.length >= 2 ? parts[1] : undefined;
}

/** Tools that can write to the filesystem or the outside world. */
export const WRITE_CAPABLE_TOOLS = new Set(['write', 'edit', 'multiedit', 'notebookedit', 'bash']);

export interface DangerousCommandMatch {
  readonly label: string;
  readonly pattern: string;
}

/**
 * Command shapes that are materially destructive or exfiltration-capable.
 * Matched against permission entries and hook commands only -- never against
 * commands found in the scanned project's own source.
 */
const DANGEROUS_COMMANDS: ReadonlyArray<{ label: string; regex: RegExp }> = [
  { label: 'Recursive force delete (rm -rf)', regex: /\brm\s+(?:-[a-z]*[rf][a-z]*\s+)+/i },
  { label: 'Privilege escalation (sudo/doas)', regex: /\b(?:sudo|doas)\b/i },
  {
    label: 'Remote script execution (curl|wget piped to a shell)',
    regex: /\b(?:curl|wget)\b[^|]*\|\s*(?:sudo\s+)?(?:ba|z|k|)sh\b/i,
  },
  { label: 'World-writable permissions (chmod 777)', regex: /\bchmod\s+(?:-R\s+)?0?777\b/i },
  { label: 'Force push to a remote', regex: /\bgit\s+push\b[^\n]*(?:--force\b|-f\b)/i },
  {
    label: 'Package publish',
    regex: /\b(?:npm|pnpm|yarn)\s+publish\b|\bcargo\s+publish\b|\btwine\s+upload\b/i,
  },
  {
    label: 'Infrastructure apply/destroy',
    regex: /\b(?:terraform|tofu)\s+(?:apply|destroy)\b|\bpulumi\s+(?:up|destroy)\b/i,
  },
  {
    label: 'Cluster mutation (kubectl apply/delete)',
    regex: /\bkubectl\s+(?:apply|delete|drain|scale)\b/i,
  },
  {
    label: 'Cloud CLI mutation',
    regex: /\b(?:aws|gcloud|az)\s+\S+\s+(?:delete|create|update|put|terminate|deploy)\b/i,
  },
  { label: 'Credential file access', regex: /(?:\.aws\/credentials|\.ssh\/id_|\.netrc|\.npmrc)/i },
  { label: 'Shell evaluation of dynamic input', regex: /\beval\s|\bexec\s+["'$]/i },
  { label: 'Database drop/truncate', regex: /\b(?:drop\s+(?:database|table)|truncate\s+table)\b/i },
];

export function matchDangerousCommand(command: string): DangerousCommandMatch | undefined {
  for (const candidate of DANGEROUS_COMMANDS) {
    if (candidate.regex.test(command)) {
      return { label: candidate.label, pattern: candidate.regex.source };
    }
  }
  return undefined;
}

/** Network-egress commands, which matter for exfiltration risk. */
export function isNetworkEgressCommand(command: string): boolean {
  return /\b(?:curl|wget|nc|ncat|scp|rsync|ssh|ftp|httpie|http)\b/i.test(command);
}

export function evidence(detail: string, extra: Partial<Evidence> = {}): Evidence {
  return { detail, ...extra };
}

/** Lower a severity by `steps` levels; used when confidence is thin. */
const SEVERITY_ORDER: readonly Severity[] = ['info', 'low', 'medium', 'high', 'critical'];

export function downgrade(severity: Severity, steps = 1): Severity {
  const index = SEVERITY_ORDER.indexOf(severity);
  return SEVERITY_ORDER[Math.max(0, index - steps)]!;
}

export function upgrade(severity: Severity, steps = 1): Severity {
  const index = SEVERITY_ORDER.indexOf(severity);
  return SEVERITY_ORDER[Math.min(SEVERITY_ORDER.length - 1, index + steps)]!;
}

/** True when any deny entry plausibly covers the given path fragment. */
export function denyCovers(models: readonly PermissionModel[], fragment: string): boolean {
  const needle = fragment.toLowerCase();
  return models.some((model) => model.deny.some((entry) => entry.toLowerCase().includes(needle)));
}

/** Cap a list rendered into evidence so reports stay readable. */
export function firstN<T>(items: readonly T[], count: number): T[] {
  return items.slice(0, count);
}
