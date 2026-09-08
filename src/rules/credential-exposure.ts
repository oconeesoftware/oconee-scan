import type { Confidence, Rule, RuleFinding, Severity } from '../types/index.js';
import { isCloudCredentialFile, isEnvFile, isKeyMaterial } from '../scanners/credentials.js';
import { isIgnoredByGitignore } from '../utils/gitignore.js';
import { isLikelyFixturePath } from '../utils/paths.js';
import { downgrade, evidence, firstN } from './helpers.js';

/**
 * Credential rules fire on the *presence* of a file. When every matching file
 * sits under a test-fixture path the material is almost certainly synthetic,
 * so the finding is reported one severity lower and at low confidence rather
 * than being suppressed outright -- a real secret in a fixture directory is
 * still a real secret.
 */
function fixtureAdjusted<T extends { readonly path: string }>(
  files: readonly T[],
  severity: Severity,
  confidence: Confidence,
): { severity: Severity; confidence: Confidence; note: string } {
  const allFixtures = files.length > 0 && files.every((file) => isLikelyFixturePath(file.path));
  if (!allFixtures) return { severity, confidence, note: '' };
  return {
    severity: downgrade(severity),
    confidence: 'low',
    note: ' All matches are under test-fixture paths, so this is reported at reduced severity; confirm the values are synthetic.',
  };
}

const CRED_001: Rule = {
  id: 'CRED-001',
  title: 'Environment file present in the working tree',
  category: 'Credential Exposure',
  summary: 'A .env file exists and is readable by any agent operating in the repository.',
  evaluate(context): RuleFinding[] {
    const envFiles = context.match((file) => isEnvFile(file.path));
    if (envFiles.length === 0) return [];
    const adjusted = fixtureAdjusted(envFiles, 'medium', 'high');
    return [
      {
        severity: adjusted.severity,
        confidence: adjusted.confidence,
        description:
          'One or more environment files are present in the working tree. Environment files are the most ' +
          'common place real credentials sit on a developer machine, and they are plain text inside the ' +
          'directory agents are pointed at.' +
          adjusted.note,
        evidence: firstN(envFiles, 8).map((file) =>
          evidence('Environment file present.', { path: file.path }),
        ),
        affected_path: envFiles[0]!.path,
        recommendation:
          'Keep environment files out of the agent’s readable scope with an explicit deny rule, and move ' +
          'production credentials to a secret manager rather than a file on disk.',
      },
    ];
  },
};

const CRED_002: Rule = {
  id: 'CRED-002',
  title: 'Credential file is not excluded from version control',
  category: 'Credential Exposure',
  summary: 'A .env or key file is present and no .gitignore rule appears to exclude it.',
  evaluate(context): RuleFinding[] {
    const sensitive = context.match(
      (file) =>
        isEnvFile(file.path) || isKeyMaterial(file.path) || isCloudCredentialFile(file.path),
    );
    if (sensitive.length === 0) return [];

    const unignored = sensitive.filter(
      (file) => !isIgnoredByGitignore(file.path, context.gitignore),
    );
    if (unignored.length === 0) return [];

    const hasGitignore = context.hasFile('.gitignore');
    // The gitignore evaluation is approximate, so confidence starts capped.
    const adjusted = fixtureAdjusted(unignored, 'high', 'medium');
    return [
      {
        severity: adjusted.severity,
        confidence: adjusted.confidence,
        description:
          'Credential-bearing files appear not to be excluded from version control. If they are committed, ' +
          'the credentials reach every clone, every CI runner and every agent that indexes repository ' +
          'history, and revocation becomes the only remedy.' +
          adjusted.note,
        evidence: firstN(unignored, 8).map((file) =>
          evidence(
            hasGitignore
              ? 'File is not matched by any .gitignore pattern.'
              : 'Repository has no .gitignore file.',
            { path: file.path },
          ),
        ),
        affected_path: unignored[0]!.path,
        recommendation:
          'Add the paths to .gitignore, confirm with `git check-ignore -v <path>`, and rotate anything that ' +
          'has already been committed — removing the file does not remove it from history.',
      },
    ];
  },
};

const CRED_003: Rule = {
  id: 'CRED-003',
  title: 'Private key material present in the repository',
  category: 'Credential Exposure',
  summary: 'Files whose type implies private key material were found.',
  evaluate(context): RuleFinding[] {
    const keyFiles = context.match((file) => isKeyMaterial(file.path));
    if (keyFiles.length === 0) return [];
    const adjusted = fixtureAdjusted(keyFiles, 'high', 'medium');
    return [
      {
        severity: adjusted.severity,
        confidence: adjusted.confidence,
        description:
          'Files matching private key naming conventions are present. Key material grants standing access ' +
          'that outlives any single session, and it is exactly the kind of resource an agent with broad read ' +
          'access can surface into a transcript.' +
          adjusted.note,
        evidence: firstN(keyFiles, 8).map((file) =>
          evidence('File name matches private key material conventions.', { path: file.path }),
        ),
        affected_path: keyFiles[0]!.path,
        recommendation:
          'Move key material out of the repository, deny agent read access to these paths, and rotate any key ' +
          'that has been committed.',
      },
    ];
  },
};

const CRED_004: Rule = {
  id: 'CRED-004',
  title: 'Credential pattern detected in repository file',
  category: 'Credential Exposure',
  summary: 'A file contains text matching a known credential format.',
  evaluate(context): RuleFinding[] {
    if (context.secretIndicators.length === 0) return [];

    // Group by file so a report lists files, not individual matches.
    const byFile = new Map<string, typeof context.secretIndicators>();
    for (const indicator of context.secretIndicators) {
      const existing = byFile.get(indicator.path);
      byFile.set(indicator.path, existing ? [...existing, indicator] : [indicator]);
    }

    // Beyond a handful of files, per-file findings stop being actionable and
    // start dominating the report; the tail is summarised instead.
    const MAX_INDIVIDUAL_FILES = 10;
    const entries = [...byFile.entries()];
    const individual = entries.slice(0, MAX_INDIVIDUAL_FILES);
    const remainder = entries.slice(MAX_INDIVIDUAL_FILES);

    const findings: RuleFinding[] = [];
    for (const [path, indicators] of individual) {
      const highest = indicators.some((item) => item.confidence === 'high')
        ? 'high'
        : indicators.some((item) => item.confidence === 'medium')
          ? 'medium'
          : 'low';
      // Low-confidence heuristics never exceed medium severity.
      const severity: Severity =
        highest === 'high' ? 'high' : highest === 'medium' ? 'medium' : 'low';
      findings.push({
        severity,
        confidence: highest,
        description:
          'Text matching a known credential format was found in this file. The scanner records the pattern ' +
          'class and location only; the matched value is never read into a finding, printed or written to a ' +
          'report.',
        evidence: firstN(indicators, 6).map((indicator) =>
          evidence(`${indicator.patternLabel} detected (value not captured).`, {
            path: indicator.path,
            line: indicator.line,
            excerpt: `pattern: ${indicator.patternId}`,
          }),
        ),
        affected_path: path,
        recommendation:
          'Confirm whether the value is a live credential. If it is, rotate it first, then remove it from the ' +
          'file and from git history, and replace it with a secret-manager reference.',
      });
    }

    if (remainder.length > 0) {
      findings.push({
        severity: 'medium',
        confidence: 'low',
        description:
          `${remainder.length} further files contain text matching a known credential format. They are ` +
          'summarised here rather than listed individually; run with --json for the complete set.',
        evidence: firstN(remainder, 10).map(([path]) =>
          evidence('Additional file with a credential-shaped match.', { path }),
        ),
        affected_path: '.',
        recommendation:
          'Review the full JSON report, then adopt a pre-commit secret scanner so new matches are caught ' +
          'before they are committed.',
      });
    }

    return findings;
  },
};

const CRED_005: Rule = {
  id: 'CRED-005',
  title: 'Provider credential or session file present',
  category: 'Credential Exposure',
  summary: 'A cloud, registry or cluster credential file is inside the scanned tree.',
  evaluate(context): RuleFinding[] {
    const files = context.match((file) => isCloudCredentialFile(file.path));
    if (files.length === 0) return [];
    const adjusted = fixtureAdjusted(files, 'high', 'medium');
    return [
      {
        severity: adjusted.severity,
        confidence: adjusted.confidence,
        description:
          'Provider credential or session files are present inside the scanned tree. These grant an agent ' +
          'with shell access the same authority as the developer over cloud, registry or cluster resources, ' +
          'without needing to handle a secret value directly.' +
          adjusted.note,
        evidence: firstN(files, 8).map((file) =>
          evidence('Provider credential/configuration file present.', { path: file.path }),
        ),
        affected_path: files[0]!.path,
        recommendation:
          'Keep provider credentials outside project directories, use short-lived credentials where the ' +
          'provider supports them, and deny agent access to these paths.',
      },
    ];
  },
};

export const credentialExposureRules: readonly Rule[] = [
  CRED_001,
  CRED_002,
  CRED_003,
  CRED_004,
  CRED_005,
];
