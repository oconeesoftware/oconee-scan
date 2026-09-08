import { describe, expect, it } from 'vitest';
import { isIgnoredByGitignore } from '../src/utils/gitignore.js';
import {
  asStringArray,
  parseJsonc,
  stripJsonComments,
  stripTrailingCommas,
} from '../src/utils/jsonc.js';
import { globToRegExp, matchesAnyGlob } from '../src/utils/paths.js';
import { detectSecretIndicators, knownSecretPatternIds } from '../src/utils/secrets.js';

describe('jsonc parsing', () => {
  it('parses plain JSON', () => {
    expect(parseJsonc('{"a":1}').data).toEqual({ a: 1 });
  });

  it('strips line and block comments', () => {
    const text = '{\n // a comment\n "a": 1, /* inline */ "b": 2\n}';
    expect(parseJsonc(text).data).toEqual({ a: 1, b: 2 });
  });

  it('does not strip comment-like text inside strings', () => {
    expect(parseJsonc('{"url":"https://example.com/x"}').data).toEqual({
      url: 'https://example.com/x',
    });
    expect(stripJsonComments('{"a":"/* not a comment */"}')).toBe('{"a":"/* not a comment */"}');
  });

  it('does not strip commas inside strings', () => {
    expect(stripTrailingCommas('{"a":"x, y"}')).toBe('{"a":"x, y"}');
  });

  it('strips trailing commas', () => {
    expect(parseJsonc('{"a":1,}').data).toEqual({ a: 1 });
    expect(parseJsonc('[1,2,]').data).toEqual([1, 2]);
  });

  it('preserves line numbering when stripping block comments', () => {
    const stripped = stripJsonComments('{\n/* one\ntwo */\n"a":1}');
    expect(stripped.split('\n').length).toBe(4);
  });

  it('returns an error rather than throwing on invalid input', () => {
    const result = parseJsonc('not json');
    expect(result.data).toBeUndefined();
    expect(result.error).toBeTruthy();
  });

  it('coerces values to string arrays', () => {
    expect(asStringArray('x')).toEqual(['x']);
    expect(asStringArray(['x', 1, 'y'])).toEqual(['x', 'y']);
    expect(asStringArray(undefined)).toEqual([]);
  });
});

describe('glob matching', () => {
  it('matches * within a single segment only', () => {
    expect(globToRegExp('*.ts').test('index.ts')).toBe(true);
    expect(globToRegExp('*.ts').test('src/index.ts')).toBe(false);
  });

  it('matches ** across segments', () => {
    expect(matchesAnyGlob('a/b/c/.env', ['**/.env'])).toBe(true);
    expect(matchesAnyGlob('.env', ['**/.env'])).toBe(true);
    expect(matchesAnyGlob('a/b/keys.pem', ['**/*.pem'])).toBe(true);
  });

  it('escapes regex metacharacters in literal segments', () => {
    expect(globToRegExp('a.b').test('a.b')).toBe(true);
    expect(globToRegExp('a.b').test('axb')).toBe(false);
  });
});

describe('gitignore evaluation', () => {
  it('matches a bare name at any depth', () => {
    expect(isIgnoredByGitignore('a/b/.env', ['.env'])).toBe(true);
    expect(isIgnoredByGitignore('.env', ['.env'])).toBe(true);
  });

  it('anchors a leading slash to the repository root', () => {
    expect(isIgnoredByGitignore('.env', ['/.env'])).toBe(true);
    expect(isIgnoredByGitignore('a/.env', ['/.env'])).toBe(false);
  });

  it('ignores everything under a directory pattern', () => {
    expect(isIgnoredByGitignore('secrets/key.pem', ['secrets/'])).toBe(true);
  });

  it('honours later negations', () => {
    expect(isIgnoredByGitignore('.env.example', ['.env*', '!.env.example'])).toBe(false);
  });

  it('treats an empty pattern list as not ignored', () => {
    expect(isIgnoredByGitignore('.env', [])).toBe(false);
  });
});

describe('secret indicator detection', () => {
  it('reports the pattern class without the matched value', () => {
    const indicators = detectSecretIndicators('.env', 'AWS_ACCESS_KEY_ID=AKIAI0SF0DNN7SELFTST\n');
    expect(indicators).toHaveLength(1);
    expect(indicators[0]?.patternId).toBe('aws-access-key-id');
    expect(JSON.stringify(indicators)).not.toContain('AKIAI0SF0DNN7SELFTST');
  });

  it('skips obvious placeholders', () => {
    expect(detectSecretIndicators('.env', 'API_KEY=your-key-here\n')).toHaveLength(0);
    expect(detectSecretIndicators('.env', 'password=changeme\n')).toHaveLength(0);
    expect(detectSecretIndicators('.env', 'secret=${VAULT_SECRET}\n')).toHaveLength(0);
  });

  it('skips comments', () => {
    expect(
      detectSecretIndicators('.env', '# AWS_ACCESS_KEY_ID=AKIAI0SF0DNN7SELFTST\n'),
    ).toHaveLength(0);
  });

  it('downgrades matches in test and fixture paths', () => {
    const indicators = detectSecretIndicators(
      'src/__tests__/keys.test.ts',
      'const key = "AKIAI0SF0DNN7SELFTST";\n',
    );
    expect(indicators[0]?.confidence).toBe('low');
  });

  it('suppresses low-confidence patterns entirely in test paths', () => {
    expect(
      detectSecretIndicators('test/fixtures/app.ts', 'const password = "abcdefghijklmnop";\n'),
    ).toHaveLength(0);
  });

  it('reports each pattern class at most once per file', () => {
    const contents = Array.from(
      { length: 10 },
      () => 'AWS_ACCESS_KEY_ID=AKIAI0SF0DNN7SELFTST',
    ).join('\n');
    expect(detectSecretIndicators('.env', contents)).toHaveLength(1);
  });

  it('exposes a stable set of pattern ids', () => {
    const ids = knownSecretPatternIds();
    expect(ids).toContain('private-key-block');
    expect(ids).toContain('github-token');
    expect(new Set(ids).size).toBe(ids.length);
  });

  it('handles empty and whitespace-only input', () => {
    expect(detectSecretIndicators('.env', '')).toHaveLength(0);
    expect(detectSecretIndicators('.env', '\n\n   \n')).toHaveLength(0);
  });
});
