import type { Reporter } from '../types/index.js';
import { jsonReporter } from './json.js';
import { createTerminalReporter, terminalReporter, type TerminalOptions } from './terminal.js';

export { jsonReporter, terminalReporter, createTerminalReporter };
export type { TerminalOptions };

export type ReporterName = 'terminal' | 'json';

/**
 * Reporters are looked up by name so new formats (SARIF, HTML) can be added
 * here without touching the CLI or the engine.
 */
export function getReporter(name: ReporterName, options: TerminalOptions = {}): Reporter {
  switch (name) {
    case 'json':
      return jsonReporter;
    case 'terminal':
    default:
      return createTerminalReporter(options);
  }
}
