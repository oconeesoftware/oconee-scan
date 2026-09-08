/**
 * Core domain types for the Oconee AI Agent Risk Scanner.
 *
 * Terminology follows the Oconee governance model:
 *   Actor -> Agent -> Action -> Resource -> Context -> Policy -> Decision -> Evidence
 *
 * A Rule inspects the Context, reasons about what Actions an Agent could take
 * against which Resources, and emits Findings backed by Evidence.
 */

export const SEVERITIES = ['info', 'low', 'medium', 'high', 'critical'] as const;
export type Severity = (typeof SEVERITIES)[number];

export const CONFIDENCES = ['low', 'medium', 'high'] as const;
export type Confidence = (typeof CONFIDENCES)[number];

export const CATEGORIES = [
  'Agent Configuration',
  'Command Execution',
  'File Access',
  'Repository Risk',
  'Credential Exposure',
  'MCP / Tool Access',
  'Approval Controls',
  'Auditability',
] as const;
export type Category = (typeof CATEGORIES)[number];

/**
 * A single piece of supporting evidence for a finding.
 *
 * `excerpt` is optional and MUST NEVER contain a secret value. Rules that
 * detect credentials describe the pattern class instead of the match.
 */
export interface Evidence {
  /** Human-readable statement of what was observed. */
  readonly detail: string;
  /** Repository-relative path the observation came from, if any. */
  readonly path?: string;
  /** 1-based line number, if the observation is line-anchored. */
  readonly line?: number;
  /** Safe, non-secret excerpt (e.g. a config key path). */
  readonly excerpt?: string;
}

export interface Finding {
  readonly rule_id: string;
  readonly title: string;
  readonly category: Category;
  readonly severity: Severity;
  readonly confidence: Confidence;
  readonly description: string;
  readonly evidence: readonly Evidence[];
  /** Repository-relative path, or '.' when the finding is repository-wide. */
  readonly affected_path: string;
  readonly recommendation: string;
  readonly documentation_url: string;
}

/** A rule emits findings without its own severity/category boilerplate. */
export type RuleFinding = Omit<Finding, 'rule_id' | 'title' | 'category' | 'documentation_url'> &
  Partial<Pick<Finding, 'rule_id' | 'title' | 'category' | 'documentation_url'>>;

export interface Rule {
  readonly id: string;
  readonly title: string;
  readonly category: Category;
  /** One-line statement of what the rule looks for; shown by `--list-rules`. */
  readonly summary: string;
  readonly documentationUrl?: string;
  /**
   * Pure, read-only evaluation. Rules must not touch the filesystem directly;
   * everything they need is on the context.
   */
  evaluate(context: ScanContext): readonly RuleFinding[];
}

export interface FileEntry {
  /** Repository-relative POSIX path. */
  readonly path: string;
  /** Lowercased basename, for cheap matching. */
  readonly name: string;
  readonly size: number;
}

/** A configuration file that was located and (attempted to be) parsed. */
export interface ParsedConfig<T = unknown> {
  readonly path: string;
  readonly data: T | undefined;
  /** Present when the file exists but could not be parsed. */
  readonly parseError?: string;
}

export interface McpServerConfig {
  readonly name: string;
  /** File the server definition came from. */
  readonly source: string;
  readonly command?: string;
  readonly args?: readonly string[];
  readonly url?: string;
  readonly type?: string;
  /** Environment variable NAMES only. Values are never retained. */
  readonly envKeys: readonly string[];
  /** Tool names auto-approved for this server, where the format expresses it. */
  readonly autoApprove: readonly string[];
  readonly raw: Record<string, unknown>;
}

export interface PermissionModel {
  /** File the permissions came from. */
  readonly source: string;
  readonly allow: readonly string[];
  readonly deny: readonly string[];
  readonly ask: readonly string[];
  readonly defaultMode?: string;
  readonly additionalDirectories: readonly string[];
  /** True when the config declares hooks that run shell commands. */
  readonly hookCommands: readonly string[];
}

export interface SecretIndicator {
  readonly path: string;
  /** Pattern class, e.g. 'aws-access-key-id'. Never the matched value. */
  readonly patternId: string;
  readonly patternLabel: string;
  readonly line: number;
  readonly confidence: Confidence;
}

export interface ScanContext {
  readonly rootDir: string;
  readonly projectName: string;
  readonly files: readonly FileEntry[];
  readonly fileSet: ReadonlySet<string>;
  /** Directories that exist in the repo (POSIX, relative, no trailing slash). */
  readonly dirSet: ReadonlySet<string>;
  /** Cached, size-capped text reads. Returns undefined for missing/binary/oversized files. */
  readText(path: string): string | undefined;
  /** True if the repo-relative path exists as a file. */
  hasFile(path: string): boolean;
  /** All indexed files whose path matches the predicate. */
  match(predicate: (entry: FileEntry) => boolean): readonly FileEntry[];

  // --- Collected artifacts -------------------------------------------------
  readonly claudeSettings: readonly ParsedConfig[];
  readonly mcpServers: readonly McpServerConfig[];
  readonly permissions: readonly PermissionModel[];
  readonly cursorConfigs: readonly ParsedConfig[];
  readonly cursorRuleFiles: readonly string[];
  readonly vscodeSettings: readonly ParsedConfig<Record<string, unknown>>[];
  readonly copilotArtifacts: readonly string[];
  readonly instructionFiles: readonly string[];
  readonly secretIndicators: readonly SecretIndicator[];
  readonly gitignore: readonly string[];
  /** Config files that exist but failed to parse. */
  readonly parseErrors: readonly ParsedConfig[];
  /** Non-fatal problems encountered while scanning (permissions, IO). */
  readonly warnings: readonly string[];
  /** True when the file walk hit its budget and the index is partial. */
  readonly truncated: boolean;
}

export interface ScoreBreakdownEntry {
  readonly category: Category;
  readonly rawPoints: number;
  readonly cappedPoints: number;
  readonly findingCount: number;
}

export type RiskLevel = 'Minimal' | 'Low' | 'Moderate' | 'High' | 'Critical';

export interface RiskScore {
  readonly score: number;
  readonly level: RiskLevel;
  readonly counts: Readonly<Record<Severity, number>>;
  readonly breakdown: readonly ScoreBreakdownEntry[];
  readonly methodologyUrl: string;
}

export interface ScanResult {
  readonly tool: { readonly name: string; readonly version: string };
  readonly scannedAt: string;
  readonly repository: { readonly name: string; readonly path: string };
  readonly score: RiskScore;
  readonly findings: readonly Finding[];
  readonly rulesEvaluated: number;
  readonly filesIndexed: number;
  readonly truncated: boolean;
  readonly warnings: readonly string[];
}

export interface Reporter {
  readonly name: string;
  render(result: ScanResult): string;
}
