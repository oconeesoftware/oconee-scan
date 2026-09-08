import type { Finding, Reporter, ScanResult, Severity } from '../types/index.js';
import { bold, cyan, dim, gray, green, magenta, red, yellow } from '../utils/color.js';

const SEVERITY_ORDER: readonly Severity[] = ['critical', 'high', 'medium', 'low', 'info'];

/** Findings shown per severity group before the tail is summarised. */
const MAX_PER_SEVERITY = 8;

const SEVERITY_STYLE: Readonly<Record<Severity, (text: string) => string>> = {
  critical: (text) => bold(magenta(text)),
  high: (text) => bold(red(text)),
  medium: (text) => yellow(text),
  low: (text) => cyan(text),
  info: (text) => gray(text),
};

function scoreStyle(score: number): (text: string) => string {
  if (score >= 80) return (text) => bold(magenta(text));
  if (score >= 55) return (text) => bold(red(text));
  if (score >= 30) return (text) => bold(yellow(text));
  if (score >= 10) return (text) => bold(cyan(text));
  return (text) => bold(green(text));
}

/** Wrap to a width, preserving words; used for descriptions. */
function wrap(text: string, width: number, indent: string): string[] {
  const words = text.split(/\s+/).filter(Boolean);
  const lines: string[] = [];
  let current = '';
  for (const word of words) {
    if (current === '') current = word;
    else if (current.length + 1 + word.length <= width) current += ` ${word}`;
    else {
      lines.push(indent + current);
      current = word;
    }
  }
  if (current !== '') lines.push(indent + current);
  return lines;
}

function terminalWidth(): number {
  const columns = process.stdout.columns ?? 100;
  return Math.max(60, Math.min(columns, 100));
}

export interface TerminalOptions {
  /** Show evidence and recommendation for every finding. */
  readonly verbose?: boolean;
}

export function createTerminalReporter(options: TerminalOptions = {}): Reporter {
  return {
    name: 'terminal',
    render(result: ScanResult): string {
      const width = terminalWidth();
      const bodyWidth = width - 4;
      const out: string[] = [];

      out.push('');
      out.push(bold('Oconee AI Agent Risk Scanner'));
      out.push(dim('Find governance gaps before your AI agents act.'));
      out.push('');
      out.push(`Repository: ${bold(result.repository.name)}`);
      out.push(dim(`Path:       ${result.repository.path}`));
      out.push(
        dim(
          `Files:      ${result.filesIndexed.toLocaleString()} indexed${result.truncated ? ' (truncated)' : ''}`,
        ),
      );
      out.push('');

      const style = scoreStyle(result.score.score);
      out.push(`${bold('AI Agent Risk Score:')} ${style(`${result.score.score}/100`)}`);
      out.push(`${bold('Risk Level:')} ${style(result.score.level)}`);
      out.push('');

      if (result.findings.length === 0) {
        out.push(green('No governance findings were raised by this scan.'));
        out.push(
          dim(
            'A clean result means no configured risk indicators were detected — not that agent activity is governed.',
          ),
        );
      } else {
        out.push(bold('Findings'));
        out.push('');
        for (const severity of SEVERITY_ORDER) {
          const group = result.findings.filter((finding) => finding.severity === severity);
          if (group.length === 0) continue;
          out.push(SEVERITY_STYLE[severity](severity.toUpperCase()));
          const shown = options.verbose ? group : group.slice(0, MAX_PER_SEVERITY);
          for (const finding of shown) {
            out.push(...renderFinding(finding, bodyWidth, options.verbose ?? false));
          }
          if (shown.length < group.length) {
            out.push(
              dim(
                `  ...and ${group.length - shown.length} more ${severity} findings (--verbose or --json for the full list)`,
              ),
            );
            out.push('');
          }
          out.push('');
        }
      }

      out.push(bold('Summary'));
      out.push('');
      for (const severity of SEVERITY_ORDER) {
        const count = result.score.counts[severity];
        if (count === 0 && severity === 'info') continue;
        const label = severity.charAt(0).toUpperCase() + severity.slice(1);
        out.push(`  ${label.padEnd(9)} ${count}`);
      }
      out.push('');

      const steps = nextSteps(result.findings);
      if (steps.length > 0) {
        out.push(bold('Recommended next steps:'));
        steps.forEach((step, index) => {
          out.push(
            ...wrap(`${index + 1}. ${step}`, bodyWidth, '  ').map((line, lineIndex) =>
              lineIndex === 0 ? line : `     ${line.trim()}`,
            ),
          );
        });
        out.push('');
      }

      if (result.warnings.length > 0) {
        out.push(dim(`Warnings (${result.warnings.length}):`));
        for (const warning of result.warnings.slice(0, 5)) out.push(dim(`  - ${warning}`));
        if (result.warnings.length > 5)
          out.push(dim(`  - ...and ${result.warnings.length - 5} more`));
        out.push('');
      }

      out.push(dim('Score methodology: ' + result.score.methodologyUrl));
      out.push(
        dim(
          'This is a point-in-time, local, read-only assessment. It is not a compliance attestation and it does not enforce anything at runtime.',
        ),
      );
      out.push('');
      out.push(bold('Oconee Runtime — AI Action Governance'));
      out.push('Govern what AI agents are allowed to do.');
      out.push(cyan('https://www.oconeeruntime.com'));
      out.push('');
      out.push(
        dim(
          'Want continuous policy enforcement instead of a point-in-time scan? Learn more about Oconee Runtime.',
        ),
      );
      out.push('');

      return `${out.join('\n')}\n`;
    },
  };
}

function renderFinding(finding: Finding, width: number, verbose: boolean): string[] {
  const lines: string[] = [];
  lines.push(`${bold(finding.rule_id)} ${finding.title}`);
  lines.push(...wrap(finding.description, width, '  '));
  lines.push(
    dim(`  ${finding.affected_path}  ·  confidence: ${finding.confidence}  ·  ${finding.category}`),
  );

  if (verbose) {
    for (const item of finding.evidence.slice(0, 8)) {
      const location = item.path ? `${item.path}${item.line ? `:${item.line}` : ''}` : '';
      const excerpt = item.excerpt ? ` — ${item.excerpt}` : '';
      lines.push(dim(`    evidence: ${item.detail}${location ? ` [${location}]` : ''}${excerpt}`));
    }
    lines.push(...wrap(`Recommendation: ${finding.recommendation}`, width - 2, '    '));
    lines.push(dim(`    ${finding.documentation_url}`));
  }
  lines.push('');
  return lines;
}

/**
 * Next steps are derived from the highest-severity findings present, so the
 * list reflects this repository rather than a generic checklist.
 */
function nextSteps(findings: readonly Finding[]): string[] {
  const steps: string[] = [];
  const seen = new Set<string>();
  for (const finding of findings) {
    if (finding.severity === 'info') continue;
    const key = finding.category;
    if (seen.has(key)) continue;
    seen.add(key);
    steps.push(`${finding.recommendation} (${finding.rule_id})`);
    if (steps.length === 3) break;
  }
  return steps;
}

export const terminalReporter: Reporter = createTerminalReporter();
