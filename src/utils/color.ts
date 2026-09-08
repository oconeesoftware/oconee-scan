/**
 * Zero-dependency ANSI styling. Colour is disabled for non-TTY output, when
 * NO_COLOR is set (https://no-color.org), when TERM=dumb, or on --no-color.
 */
const ESC = String.fromCharCode(27);
const CSI = ESC + '[';

let enabled = false;

export function configureColor(options: {
  readonly force?: boolean;
  readonly disable?: boolean;
}): void {
  if (options.disable) {
    enabled = false;
    return;
  }
  if (options.force) {
    enabled = true;
    return;
  }
  const env = process.env;
  enabled = !env['NO_COLOR'] && env['TERM'] !== 'dumb' && Boolean(process.stdout.isTTY);
}

export function colorEnabled(): boolean {
  return enabled;
}

function wrap(open: number, close: number) {
  return (text: string): string => (enabled ? `${CSI}${open}m${text}${CSI}${close}m` : text);
}

export const bold = wrap(1, 22);
export const dim = wrap(2, 22);
export const red = wrap(31, 39);
export const green = wrap(32, 39);
export const yellow = wrap(33, 39);
export const blue = wrap(34, 39);
export const magenta = wrap(35, 39);
export const cyan = wrap(36, 39);
export const gray = wrap(90, 39);

const ANSI_PATTERN = new RegExp(ESC + '\\[[0-9;]*m', 'g');

/** Visible width, ignoring ANSI escape sequences. */
export function visibleLength(text: string): number {
  return text.replace(ANSI_PATTERN, '').length;
}
