/**
 * Public library surface. The CLI is a thin wrapper over `scan()`, so the same
 * engine can be embedded in other tooling.
 */
export { scan, ScanError, type ScanOptions } from './scan.js';
export { ALL_RULES, evaluateRules, ruleById, sortFindings } from './rules/index.js';
export {
  calculateScore,
  riskLevelFor,
  pointsFor,
  SEVERITY_WEIGHT,
  CONFIDENCE_FACTOR,
  CATEGORY_CAP,
  METHODOLOGY_URL,
} from './scoring/index.js';
export { buildScanContext, COLLECTORS, DEFAULT_LIMITS } from './scanners/index.js';
export { getReporter, jsonReporter, createTerminalReporter } from './reporters/index.js';
export { VERSION } from './version.js';
export type * from './types/index.js';
