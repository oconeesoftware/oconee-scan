import type { ScanContextBuilder } from './context.js';

/**
 * A collector performs read-only discovery and parsing, populating the scan
 * context. Collectors know about file formats; rules know about risk.
 */
export interface Collector {
  readonly name: string;
  collect(builder: ScanContextBuilder): void;
}
