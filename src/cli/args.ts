export interface ParsedArgs {
  readonly command: 'scan' | 'rules' | 'help' | 'version';
  readonly target: string;
  readonly json: boolean;
  readonly output?: string;
  readonly verbose: boolean;
  readonly color?: boolean;
  readonly disabled: readonly string[];
  /** Exit non-zero when a finding at or above this severity is present. */
  readonly failOn?: string;
  readonly errors: readonly string[];
}

const KNOWN_COMMANDS = new Set(['scan', 'rules']);
const FAIL_ON_VALUES = new Set(['critical', 'high', 'medium', 'low', 'info', 'never']);

/**
 * Hand-rolled argument parsing: the CLI has a small, stable surface and a
 * parser dependency would be the largest thing in the install tree.
 */
export function parseArgs(argv: readonly string[]): ParsedArgs {
  const errors: string[] = [];
  let command: ParsedArgs['command'] = 'scan';
  let target = '.';
  let json = false;
  let output: string | undefined;
  let verbose = false;
  let color: boolean | undefined;
  let failOn: string | undefined;
  const disabled: string[] = [];

  const args = [...argv];
  let positionalSeen = false;

  if (args.length > 0 && KNOWN_COMMANDS.has(args[0]!)) {
    command = args.shift() as ParsedArgs['command'];
  }

  while (args.length > 0) {
    const arg = args.shift()!;

    if (arg === '--') break;

    if (arg === '-h' || arg === '--help') return { ...empty(), command: 'help' };
    if (arg === '-v' || arg === '--version') return { ...empty(), command: 'version' };

    if (arg === '--json') {
      json = true;
      continue;
    }
    if (arg === '--verbose') {
      verbose = true;
      continue;
    }
    if (arg === '--no-color') {
      color = false;
      continue;
    }
    if (arg === '--color') {
      color = true;
      continue;
    }
    if (arg === '--output' || arg === '-o') {
      const value = args.shift();
      if (value === undefined) errors.push('--output requires a file path.');
      else output = value;
      continue;
    }
    if (arg.startsWith('--output=')) {
      output = arg.slice('--output='.length);
      continue;
    }
    if (arg === '--path' || arg === '-p') {
      const value = args.shift();
      if (value === undefined) errors.push('--path requires a directory.');
      else target = value;
      continue;
    }
    if (arg.startsWith('--path=')) {
      target = arg.slice('--path='.length);
      continue;
    }
    if (arg === '--disable') {
      const value = args.shift();
      if (value === undefined) errors.push('--disable requires a rule id or category.');
      else
        disabled.push(
          ...value
            .split(',')
            .map((entry) => entry.trim())
            .filter(Boolean),
        );
      continue;
    }
    if (arg.startsWith('--disable=')) {
      disabled.push(
        ...arg
          .slice('--disable='.length)
          .split(',')
          .map((entry) => entry.trim())
          .filter(Boolean),
      );
      continue;
    }
    if (arg === '--fail-on' || arg.startsWith('--fail-on=')) {
      const value = arg.includes('=') ? arg.slice('--fail-on='.length) : args.shift();
      if (value === undefined) {
        errors.push('--fail-on requires a severity.');
      } else if (!FAIL_ON_VALUES.has(value.toLowerCase())) {
        errors.push(`--fail-on expects one of ${[...FAIL_ON_VALUES].join(', ')} (got "${value}").`);
      } else {
        failOn = value.toLowerCase();
      }
      continue;
    }

    if (arg.startsWith('-')) {
      errors.push(`Unknown option: ${arg}`);
      continue;
    }

    if (positionalSeen) {
      errors.push(`Unexpected argument: ${arg}`);
      continue;
    }
    positionalSeen = true;
    target = arg;
  }

  return {
    command,
    target,
    json,
    ...(output !== undefined ? { output } : {}),
    verbose,
    ...(color !== undefined ? { color } : {}),
    disabled,
    ...(failOn !== undefined ? { failOn } : {}),
    errors,
  };
}

function empty(): ParsedArgs {
  return {
    command: 'scan',
    target: '.',
    json: false,
    verbose: false,
    disabled: [],
    errors: [],
  };
}
