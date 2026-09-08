import type { Finding, Rule, ScanContext } from '../types/index.js';
import { agentConfigurationRules } from './agent-configuration.js';
import { approvalControlRules } from './approval-controls.js';
import { auditabilityRules } from './auditability.js';
import { commandExecutionRules } from './command-execution.js';
import { credentialExposureRules } from './credential-exposure.js';
import { fileAccessRules } from './file-access.js';
import { docsUrlFor } from './helpers.js';
import { mcpRules } from './mcp.js';
import { repositoryRiskRules } from './repository-risk.js';

/**
 * The rule registry. Adding a detection means adding a `Rule` to one of these
 * packs -- nothing in the CLI, scoring or reporting layer needs to change.
 */
export const ALL_RULES: readonly Rule[] = [
  ...agentConfigurationRules,
  ...commandExecutionRules,
  ...fileAccessRules,
  ...repositoryRiskRules,
  ...credentialExposureRules,
  ...mcpRules,
  ...approvalControlRules,
  ...auditabilityRules,
];

export function ruleById(id: string): Rule | undefined {
  return ALL_RULES.find((rule) => rule.id === id);
}

export interface EvaluateOptions {
  readonly rules?: readonly Rule[];
  /** Rule IDs or category names to skip. */
  readonly disabled?: readonly string[];
  /** Collects non-fatal rule failures. */
  readonly onError?: (ruleId: string, error: unknown) => void;
}

const SEVERITY_RANK: Record<Finding['severity'], number> = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
  info: 4,
};

/**
 * Run every rule against the context. A rule that throws is skipped and
 * reported, so one bad detection cannot fail an entire scan.
 */
export function evaluateRules(context: ScanContext, options: EvaluateOptions = {}): Finding[] {
  const rules = options.rules ?? ALL_RULES;
  const disabled = new Set((options.disabled ?? []).map((entry) => entry.toLowerCase()));
  const findings: Finding[] = [];

  for (const rule of rules) {
    if (disabled.has(rule.id.toLowerCase()) || disabled.has(rule.category.toLowerCase())) continue;
    let produced: readonly ReturnType<Rule['evaluate']>[number][];
    try {
      produced = rule.evaluate(context);
    } catch (error) {
      options.onError?.(rule.id, error);
      continue;
    }
    for (const partial of produced) {
      findings.push({
        rule_id: partial.rule_id ?? rule.id,
        title: partial.title ?? rule.title,
        category: partial.category ?? rule.category,
        documentation_url:
          partial.documentation_url ??
          rule.documentationUrl ??
          docsUrlFor(partial.rule_id ?? rule.id),
        severity: partial.severity,
        confidence: partial.confidence,
        description: partial.description,
        evidence: partial.evidence,
        affected_path: partial.affected_path,
        recommendation: partial.recommendation,
      });
    }
  }

  return sortFindings(mergeDuplicates(findings));
}

/**
 * A rule may legitimately fire several times for the same file (four
 * destructive commands in one allow-list, say). Reporting that as four
 * identical findings inflates both the output and the score, so same
 * rule + same path collapses into one finding carrying all the evidence.
 */
export function mergeDuplicates(findings: readonly Finding[]): Finding[] {
  const merged = new Map<string, Finding>();

  for (const finding of findings) {
    const key = `${finding.rule_id}::${finding.affected_path}`;
    const existing = merged.get(key);
    if (!existing) {
      merged.set(key, finding);
      continue;
    }
    merged.set(key, {
      ...existing,
      // Keep the most serious severity and the strongest confidence seen.
      severity:
        SEVERITY_RANK[finding.severity] < SEVERITY_RANK[existing.severity]
          ? finding.severity
          : existing.severity,
      confidence:
        CONFIDENCE_RANK[finding.confidence] > CONFIDENCE_RANK[existing.confidence]
          ? finding.confidence
          : existing.confidence,
      evidence: dedupeEvidence([...existing.evidence, ...finding.evidence]),
    });
  }

  return [...merged.values()];
}

const CONFIDENCE_RANK: Record<Finding['confidence'], number> = { low: 0, medium: 1, high: 2 };

function dedupeEvidence(evidence: readonly Finding['evidence'][number][]): Finding['evidence'] {
  const seen = new Set<string>();
  const out: Finding['evidence'][number][] = [];
  for (const item of evidence) {
    const key = `${item.detail}|${item.path ?? ''}|${item.line ?? ''}|${item.excerpt ?? ''}`;
    if (seen.has(key)) continue;
    seen.add(key);
    out.push(item);
    // Evidence lists past this length stop informing the reader.
    if (out.length >= 20) break;
  }
  return out;
}

/** Severity first, then rule id, then path -- so output is deterministic. */
export function sortFindings(findings: readonly Finding[]): Finding[] {
  return [...findings].sort((a, b) => {
    const bySeverity = SEVERITY_RANK[a.severity] - SEVERITY_RANK[b.severity];
    if (bySeverity !== 0) return bySeverity;
    const byRule = a.rule_id.localeCompare(b.rule_id);
    if (byRule !== 0) return byRule;
    return a.affected_path.localeCompare(b.affected_path);
  });
}
