import fs from 'node:fs';
import path from 'node:path';
import { getReporter } from '../reporters/index.js';
import { ALL_RULES } from '../rules/index.js';
import { scan, ScanError } from '../scan.js';
import type { Severity } from '../types/index.js';
import { SEVERITIES } from '../types/index.js';
import { bold, configureColor, dim } from '../utils/color.js';
import { VERSION } from '../version.js';
import { parseArgs, type ParsedArgs } from './args.js';
import { helpText } from './help.js';

const EXIT_OK = 0;
const EXIT_THRESHOLD = 1;
const EXIT_ERROR = 2;

export function run(argv: readonly string[]): number {
  const args = parseArgs(argv);

  configureColor({
    ...(args.color === true ? { force: true } : {}),
    ...(args.color === false ? { disable: true } : {}),
    // JSON on stdout must never carry escape codes.
    ...(args.json && args.output === undefined ? { disable: true } : {}),
  });

  if (args.errors.length > 0) {
    for (const error of args.errors) process.stderr.write(`oconee-scan: ${error}\n`);
    process.stderr.write('Run `oconee-scan --help` for usage.\n');
    return EXIT_ERROR;
  }

  switch (args.command) {
    case 'help':
      process.stdout.write(`${helpText()}\n`);
      return EXIT_OK;
    case 'version':
      process.stdout.write(`${VERSION}\n`);
      return EXIT_OK;
    case 'rules':
      process.stdout.write(renderRules());
      return EXIT_OK;
    case 'scan':
    default:
      return runScan(args);
  }
}

function runScan(args: ParsedArgs): number {
  let result;
  try {
    result = scan(args.target, { disabled: args.disabled });
  } catch (error) {
    if (error instanceof ScanError) {
      process.stderr.write(`oconee-scan: ${error.message}\n`);
      return EXIT_ERROR;
    }
    process.stderr.write(
      `oconee-scan: unexpected error: ${error instanceof Error ? error.message : String(error)}\n`,
    );
    return EXIT_ERROR;
  }

  const reporter = getReporter(args.json ? 'json' : 'terminal', { verbose: args.verbose });
  const rendered = reporter.render(result);

  if (args.output !== undefined) {
    try {
      const outputPath = path.resolve(args.output);
      fs.mkdirSync(path.dirname(outputPath), { recursive: true });
      fs.writeFileSync(outputPath, rendered, 'utf8');
    } catch (error) {
      process.stderr.write(
        `oconee-scan: could not write ${args.output}: ${error instanceof Error ? error.message : String(error)}\n`,
      );
      return EXIT_ERROR;
    }
    process.stderr.write(`Report written to ${args.output}\n`);
  } else {
    process.stdout.write(rendered);
  }

  return exitCodeFor(result.score.counts, args.failOn);
}

/** `--fail-on high` fails on any critical or high finding. */
export function exitCodeFor(
  counts: Readonly<Record<Severity, number>>,
  failOn: string | undefined,
): number {
  if (failOn === undefined || failOn === 'never') return EXIT_OK;
  const threshold = SEVERITIES.indexOf(failOn as Severity);
  if (threshold < 0) return EXIT_OK;
  for (let index = SEVERITIES.length - 1; index >= threshold; index -= 1) {
    if (counts[SEVERITIES[index]!] > 0) return EXIT_THRESHOLD;
  }
  return EXIT_OK;
}

function renderRules(): string {
  const lines: string[] = ['', bold(`Detection rules (${ALL_RULES.length})`), ''];
  let currentCategory = '';
  for (const rule of [...ALL_RULES].sort((a, b) =>
    a.category === b.category ? a.id.localeCompare(b.id) : a.category.localeCompare(b.category),
  )) {
    if (rule.category !== currentCategory) {
      currentCategory = rule.category;
      lines.push(bold(currentCategory));
    }
    lines.push(`  ${rule.id.padEnd(12)} ${rule.title}`);
    lines.push(dim(`  ${' '.repeat(12)} ${rule.summary}`));
  }
  lines.push('');
  return `${lines.join('\n')}\n`;
}

// Entry point. Guarded so the module can also be imported by tests.
const invokedDirectly =
  process.argv[1] !== undefined &&
  (process.argv[1].endsWith('oconee-scan') ||
    process.argv[1].endsWith(`cli${path.sep}index.js`) ||
    process.argv[1].endsWith(`cli${path.sep}index.ts`));

if (invokedDirectly) {
  process.exitCode = run(process.argv.slice(2));
}
