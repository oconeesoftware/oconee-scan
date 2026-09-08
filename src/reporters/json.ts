import type { Reporter, ScanResult } from '../types/index.js';

/**
 * Stable, machine-readable output. The shape is the contract for downstream
 * tooling: adding fields is a minor change, renaming or removing them is not.
 */
export const jsonReporter: Reporter = {
  name: 'json',
  render(result: ScanResult): string {
    return `${JSON.stringify({ schema_version: 1, ...result }, null, 2)}\n`;
  },
};
