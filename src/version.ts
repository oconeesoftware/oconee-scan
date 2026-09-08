import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

/**
 * Read the version from package.json at runtime so it cannot drift from the
 * published artifact. Falls back to '0.0.0-dev' when the file is unreachable
 * (e.g. an unusual bundling setup).
 */
function readVersion(): string {
  try {
    const here = path.dirname(fileURLToPath(import.meta.url));
    // dist/version.js -> package.json is one level up; src/version.ts -> two.
    for (const candidate of [
      path.join(here, '..', 'package.json'),
      path.join(here, '..', '..', 'package.json'),
    ]) {
      if (!fs.existsSync(candidate)) continue;
      const parsed = JSON.parse(fs.readFileSync(candidate, 'utf8')) as {
        name?: string;
        version?: string;
      };
      if (parsed.name === 'oconee-scan' && typeof parsed.version === 'string')
        return parsed.version;
    }
  } catch {
    // fall through
  }
  return '0.0.0-dev';
}

export const VERSION: string = readVersion();
