import { claudeCodeCollector } from './claude-code.js';
import { DEFAULT_LIMITS, ScanContextBuilder, type WalkLimits } from './context.js';
import {
  copilotCollector,
  cursorCollector,
  instructionCollector,
  vscodeCollector,
} from './editors.js';
import { credentialCollector } from './credentials.js';
import { mcpCollector } from './mcp.js';
import { repositoryCollector } from './repository.js';
import type { Collector } from './types.js';

export { ScanContextBuilder, DEFAULT_LIMITS };
export type { Collector, WalkLimits };

/**
 * Collector order matters in one place only: the Copilot collector reads
 * VS Code settings gathered by the VS Code collector.
 */
export const COLLECTORS: readonly Collector[] = [
  repositoryCollector,
  claudeCodeCollector,
  mcpCollector,
  cursorCollector,
  vscodeCollector,
  copilotCollector,
  instructionCollector,
  credentialCollector,
];

export function buildScanContext(
  rootDir: string,
  limits: WalkLimits = DEFAULT_LIMITS,
): ScanContextBuilder {
  const builder = new ScanContextBuilder(rootDir, limits);
  builder.indexFiles();
  for (const collector of COLLECTORS) {
    try {
      collector.collect(builder);
    } catch (error) {
      builder.warnings.push(
        `Collector "${collector.name}" failed: ${error instanceof Error ? error.message : String(error)}`,
      );
    }
  }
  return builder;
}
