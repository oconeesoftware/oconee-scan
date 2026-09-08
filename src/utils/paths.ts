import path from 'node:path';

/** Convert any platform path to a POSIX-style repo-relative path. */
export function toPosix(relativePath: string): string {
  return relativePath.split(path.sep).join('/');
}

/** Directories never worth walking: vendored code, build output, VCS internals. */
export const IGNORED_DIRECTORIES: ReadonlySet<string> = new Set([
  '.git',
  '.hg',
  '.svn',
  'node_modules',
  'bower_components',
  'vendor',
  'dist',
  'build',
  'out',
  'target',
  'coverage',
  '.next',
  '.nuxt',
  '.svelte-kit',
  '.turbo',
  '.cache',
  '.parcel-cache',
  '.gradle',
  '.idea',
  '__pycache__',
  '.pytest_cache',
  '.mypy_cache',
  '.tox',
  '.venv',
  'venv',
  'env',
  '.terraform',
  '.serverless',
  'Pods',
  'DerivedData',
  '.vscode-test',
  '.yarn',
  '.pnpm-store',
  'playwright-report',
  'test-results',
  'storybook-static',
  '.docusaurus',
  '.astro',
  '.output',
  '.vercel',
  '.netlify',
  '.wrangler',
  '.expo',
  '.dart_tool',
  '.terragrunt-cache',
  '.bundle',
  'htmlcov',
]);

/** Extensions we never attempt to read as text. */
const BINARY_EXTENSIONS: ReadonlySet<string> = new Set([
  '.png',
  '.jpg',
  '.jpeg',
  '.gif',
  '.webp',
  '.avif',
  '.ico',
  '.bmp',
  '.tiff',
  '.pdf',
  '.zip',
  '.gz',
  '.tgz',
  '.bz2',
  '.xz',
  '.7z',
  '.rar',
  '.jar',
  '.war',
  '.mp3',
  '.mp4',
  '.mov',
  '.avi',
  '.wav',
  '.ogg',
  '.webm',
  '.woff',
  '.woff2',
  '.ttf',
  '.otf',
  '.eot',
  '.so',
  '.dylib',
  '.dll',
  '.exe',
  '.bin',
  '.wasm',
  '.class',
  '.o',
  '.a',
  '.sqlite',
  '.db',
  '.parquet',
]);

export function looksBinary(filePath: string): boolean {
  return BINARY_EXTENSIONS.has(path.extname(filePath).toLowerCase());
}

/**
 * Minimal glob matcher supporting `*` (within a segment), `**` (across
 * segments) and `?`. Sufficient for the literal-ish patterns rules use; we
 * deliberately avoid a glob dependency.
 */
export function globToRegExp(pattern: string): RegExp {
  let out = '';
  for (let i = 0; i < pattern.length; i += 1) {
    const char = pattern[i]!;
    if (char === '*') {
      if (pattern[i + 1] === '*') {
        // `**/` consumes any number of leading segments (including none).
        if (pattern[i + 2] === '/') {
          out += '(?:.*/)?';
          i += 2;
        } else {
          out += '.*';
          i += 1;
        }
      } else {
        out += '[^/]*';
      }
    } else if (char === '?') {
      out += '[^/]';
    } else {
      out += char.replace(/[.+^${}()|[\]\\]/g, '\\$&');
    }
  }
  return new RegExp(`^${out}$`);
}

export function matchesAnyGlob(candidate: string, patterns: readonly string[]): boolean {
  return patterns.some((pattern) => globToRegExp(pattern).test(candidate));
}

/** Basename without directory, lowercased. */
export function baseName(filePath: string): string {
  return filePath.slice(filePath.lastIndexOf('/') + 1).toLowerCase();
}

/**
 * Paths that hold deliberately synthetic material: test fixtures, sample
 * projects, mocks. A `.env` or key file under one of these is far more likely
 * to be a test artifact than a live credential, so rules that fire on file
 * presence downgrade there rather than suppressing or over-reporting.
 */
const FIXTURE_PATH =
  /(?:^|\/)(?:__(?:tests?|mocks?|fixtures?|snapshots?)__|tests?|spec|specs|fixtures?|mocks?|testdata|test-data|examples?|samples?|e2e|cypress|playwright)\//i;

export function isLikelyFixturePath(filePath: string): boolean {
  return FIXTURE_PATH.test(filePath);
}
