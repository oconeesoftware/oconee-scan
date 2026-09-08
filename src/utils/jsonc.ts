/**
 * Tolerant JSON reader for the configuration dialects agent tooling uses:
 * VS Code settings allow `//` and block comments plus trailing commas, and
 * hand-edited MCP configs frequently contain both.
 *
 * Strings are respected so that comment-like or comma-like characters inside
 * values are never stripped.
 */
export function stripJsonComments(input: string): string {
  let out = '';
  let inString = false;
  let inLineComment = false;
  let inBlockComment = false;
  let escaped = false;

  for (let i = 0; i < input.length; i += 1) {
    const char = input[i]!;
    const next = input[i + 1];

    if (inLineComment) {
      if (char === '\n') {
        inLineComment = false;
        out += char;
      }
      continue;
    }
    if (inBlockComment) {
      if (char === '*' && next === '/') {
        inBlockComment = false;
        i += 1;
      } else if (char === '\n') {
        out += char; // preserve line numbering
      }
      continue;
    }
    if (inString) {
      out += char;
      if (escaped) escaped = false;
      else if (char === '\\') escaped = true;
      else if (char === '"') inString = false;
      continue;
    }
    if (char === '"') {
      inString = true;
      out += char;
      continue;
    }
    if (char === '/' && next === '/') {
      inLineComment = true;
      i += 1;
      continue;
    }
    if (char === '/' && next === '*') {
      inBlockComment = true;
      i += 1;
      continue;
    }
    out += char;
  }
  return out;
}

/** Remove trailing commas before `}` or `]`, outside of strings. */
export function stripTrailingCommas(input: string): string {
  let out = '';
  let inString = false;
  let escaped = false;

  for (let i = 0; i < input.length; i += 1) {
    const char = input[i]!;
    if (inString) {
      out += char;
      if (escaped) escaped = false;
      else if (char === '\\') escaped = true;
      else if (char === '"') inString = false;
      continue;
    }
    if (char === '"') {
      inString = true;
      out += char;
      continue;
    }
    if (char === ',') {
      let j = i + 1;
      while (j < input.length && /\s/.test(input[j]!)) j += 1;
      const following = input[j];
      if (following === '}' || following === ']') continue; // drop the comma
    }
    out += char;
  }
  return out;
}

export interface JsoncResult<T> {
  readonly data?: T;
  readonly error?: string;
}

export function parseJsonc<T = unknown>(text: string): JsoncResult<T> {
  const cleaned = stripTrailingCommas(stripJsonComments(text));
  try {
    return { data: JSON.parse(cleaned) as T };
  } catch (error) {
    return { error: error instanceof Error ? error.message : String(error) };
  }
}

/** Narrow an unknown value to a plain object without asserting its shape. */
export function asRecord(value: unknown): Record<string, unknown> | undefined {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) return undefined;
  return value as Record<string, unknown>;
}

/** Coerce a value to a string array, tolerating a bare string. */
export function asStringArray(value: unknown): string[] {
  if (typeof value === 'string') return [value];
  if (!Array.isArray(value)) return [];
  return value.filter((item): item is string => typeof item === 'string');
}
