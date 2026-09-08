#!/usr/bin/env node
/**
 * TypeScript strips a leading shebang from emitted output, so it is re-added
 * to the built CLI entry point here and the file is made executable.
 */
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const target = path.join(root, 'dist', 'cli', 'index.js');

if (!fs.existsSync(target)) {
  console.error(`add-shebang: ${target} not found — did the build run?`);
  process.exit(1);
}

const contents = fs.readFileSync(target, 'utf8');
if (!contents.startsWith('#!')) {
  fs.writeFileSync(target, `#!/usr/bin/env node\n${contents}`, 'utf8');
}
fs.chmodSync(target, 0o755);
console.log(`add-shebang: prepared ${path.relative(root, target)}`);
