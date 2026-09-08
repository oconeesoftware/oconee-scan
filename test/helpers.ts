import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { scan } from '../src/scan.js';
import type { Finding, ScanResult } from '../src/types/index.js';

const here = path.dirname(fileURLToPath(import.meta.url));

export function fixturePath(name: string): string {
  return path.join(here, 'fixtures', name);
}

export function scanFixture(name: string): ScanResult {
  return scan(fixturePath(name));
}

export function ruleIds(result: ScanResult): string[] {
  return result.findings.map((finding) => finding.rule_id);
}

export function findingsFor(result: ScanResult, ruleId: string): Finding[] {
  return result.findings.filter((finding) => finding.rule_id === ruleId);
}

/** Every string a report could conceivably print, flattened. */
export function allText(result: ScanResult): string {
  return JSON.stringify(result);
}
