import type { Confidence, SecretIndicator } from '../types/index.js';

/**
 * Credential *indicator* detection.
 *
 * Design constraint that outranks detection quality: a matched value is never
 * captured, stored, logged or returned. Every detector yields only a pattern
 * identifier, the file path and a line number. There is deliberately no code
 * path in this module that can place matched text into a `SecretIndicator`.
 */
interface SecretPattern {
  readonly id: string;
  readonly label: string;
  readonly regex: RegExp;
  readonly confidence: Confidence;
}

/** Values that look like credentials but are obviously placeholders. */
const PLACEHOLDER =
  /(?:changeme|change_me|your[-_]?|example|placeholder|dummy|sample|redacted|xxxx+|\.\.\.|<[^>]*>|\$\{|%\(|replace[-_]?me|insert[-_]?|todo|fake|test[-_]?value|null|undefined)/i;

const PATTERNS: readonly SecretPattern[] = [
  {
    id: 'private-key-block',
    label: 'PEM private key block',
    regex: /-----BEGIN(?: [A-Z]+)* PRIVATE KEY-----/,
    confidence: 'high',
  },
  {
    id: 'aws-access-key-id',
    label: 'AWS access key ID',
    regex: /\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/,
    confidence: 'high',
  },
  {
    id: 'github-token',
    label: 'GitHub access token',
    regex: /\bgh[pousr]_[A-Za-z0-9]{36,}\b/,
    confidence: 'high',
  },
  {
    id: 'github-fine-grained-pat',
    label: 'GitHub fine-grained personal access token',
    regex: /\bgithub_pat_[A-Za-z0-9_]{50,}\b/,
    confidence: 'high',
  },
  {
    id: 'anthropic-api-key',
    label: 'Anthropic API key',
    regex: /\bsk-ant-[A-Za-z0-9_-]{20,}\b/,
    confidence: 'high',
  },
  {
    id: 'openai-api-key',
    label: 'OpenAI-style API key',
    regex: /\bsk-(?:proj-)?[A-Za-z0-9_-]{24,}\b/,
    confidence: 'medium',
  },
  {
    id: 'google-api-key',
    label: 'Google API key',
    regex: /\bAIza[0-9A-Za-z_-]{35}\b/,
    confidence: 'high',
  },
  {
    id: 'slack-token',
    label: 'Slack token',
    regex: /\bxox[baprs]-[A-Za-z0-9-]{10,}\b/,
    confidence: 'high',
  },
  {
    id: 'stripe-live-key',
    label: 'Stripe live secret key',
    regex: /\b[rs]k_live_[A-Za-z0-9]{16,}\b/,
    confidence: 'high',
  },
  {
    id: 'sendgrid-api-key',
    label: 'SendGrid API key',
    regex: /\bSG\.[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{16,}\b/,
    confidence: 'high',
  },
  {
    id: 'npm-auth-token',
    label: 'npm registry auth token',
    regex: /_authToken\s*=\s*\S{8,}/,
    confidence: 'high',
  },
  {
    id: 'json-web-token',
    label: 'JSON Web Token',
    regex: /\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b/,
    confidence: 'medium',
  },
  {
    id: 'generic-credential-assignment',
    label: 'Credential-shaped assignment',
    regex:
      /\b(?:pass(?:word|wd)?|secret|token|api[_-]?key|access[_-]?key|client[_-]?secret|auth)\b\s*[:=]\s*["']?[A-Za-z0-9/+_.-]{12,}/i,
    confidence: 'low',
  },
];

/**
 * Paths that hold examples, fixtures or test data by convention. Matches there
 * are overwhelmingly synthetic, so only unambiguous patterns are reported and
 * always at low confidence.
 */
const TEMPLATE_HINT =
  /(?:\.example$|\.sample$|\.template$|\.dist$|\.md$|\.mdx$|\.txt$|\.lock$|\.snap$|(?:^|\/)example|(?:^|\/)__(?:tests?|mocks?|fixtures?|snapshots?)__\/|(?:^|\/)(?:tests?|spec|fixtures?|mocks?|testdata|__pycache__)\/|\.(?:test|spec|stories)\.[jt]sx?$|_test\.(?:go|py|rb)$|(?:^|\/)test_[^/]*\.py$)/i;

const MAX_LINES_SCANNED = 5_000;
const MAX_LINE_LENGTH = 2_000;
/** More than this many pattern classes in one file adds noise, not signal. */
const MAX_INDICATORS_PER_FILE = 12;

export function detectSecretIndicators(filePath: string, contents: string): SecretIndicator[] {
  const isTemplate = TEMPLATE_HINT.test(filePath);
  const indicators: SecretIndicator[] = [];
  const lines = contents.split('\n', MAX_LINES_SCANNED);
  const seen = new Set<string>();

  for (let index = 0; index < lines.length; index += 1) {
    const rawLine = lines[index]!;
    if (rawLine.length > MAX_LINE_LENGTH) continue;
    const line = rawLine.trim();
    if (line.length === 0 || line.startsWith('#') || line.startsWith('//')) continue;

    for (const pattern of PATTERNS) {
      if (seen.has(pattern.id)) continue;
      if (!pattern.regex.test(line)) continue;
      if (PLACEHOLDER.test(line)) continue;
      // In template/doc files, only unambiguous high-confidence patterns are
      // reported at all, and always downgraded.
      if (isTemplate && pattern.confidence !== 'high') continue;
      const confidence: Confidence = isTemplate ? 'low' : pattern.confidence;
      seen.add(pattern.id);
      indicators.push({
        path: filePath,
        patternId: pattern.id,
        patternLabel: pattern.label,
        line: index + 1,
        confidence,
      });
      if (indicators.length >= MAX_INDICATORS_PER_FILE) return indicators;
    }
  }
  return indicators;
}

/** Exposed for tests: the pattern identifiers this build can report. */
export function knownSecretPatternIds(): readonly string[] {
  return PATTERNS.map((pattern) => pattern.id);
}
