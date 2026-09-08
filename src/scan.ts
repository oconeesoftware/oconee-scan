import fs from 'node:fs';
import path from 'node:path';
import { ALL_RULES, evaluateRules, type EvaluateOptions } from './rules/index.js';
import { buildScanContext, DEFAULT_LIMITS, type WalkLimits } from './scanners/index.js';
import { calculateScore } from './scoring/index.js';
import type { ScanResult } from './types/index.js';
import { VERSION } from './version.js';

export interface ScanOptions extends EvaluateOptions {
  readonly limits?: WalkLimits;
}

export class ScanError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'ScanError';
  }
}

/**
 * Run a full point-in-time scan of `targetDir`.
 *
 * The scan is read-only by construction: nothing in the collector or rule path
 * opens a file for writing, spawns a process, or opens a network socket.
 */
export function scan(targetDir: string, options: ScanOptions = {}): ScanResult {
  const resolved = path.resolve(targetDir);

  let stat: fs.Stats;
  try {
    stat = fs.statSync(resolved);
  } catch {
    throw new ScanError(`Path does not exist: ${resolved}`);
  }
  if (!stat.isDirectory()) {
    throw new ScanError(`Not a directory: ${resolved}`);
  }

  const rules = options.rules ?? ALL_RULES;
  const context = buildScanContext(resolved, options.limits ?? DEFAULT_LIMITS);
  const ruleErrors: string[] = [];
  const findings = evaluateRules(context, {
    rules,
    ...(options.disabled ? { disabled: options.disabled } : {}),
    onError: (ruleId, error) => {
      ruleErrors.push(
        `Rule ${ruleId} failed: ${error instanceof Error ? error.message : String(error)}`,
      );
      options.onError?.(ruleId, error);
    },
  });

  return {
    tool: { name: 'oconee-scan', version: VERSION },
    scannedAt: new Date().toISOString(),
    repository: { name: context.projectName, path: resolved },
    score: calculateScore(findings),
    findings,
    rulesEvaluated: rules.length,
    filesIndexed: context.files.length,
    truncated: context.truncated,
    warnings: [...context.warnings, ...ruleErrors],
  };
}
