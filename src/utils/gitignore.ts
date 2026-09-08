import { globToRegExp } from './paths.js';

/**
 * Approximate .gitignore evaluation.
 *
 * This is intentionally a heuristic: fully reproducing git's matching rules
 * (nested ignore files, `git check-ignore` semantics, index state) is out of
 * scope for a read-only scanner. Rules that rely on it report `medium`
 * confidence at most.
 */
export function isIgnoredByGitignore(filePath: string, patterns: readonly string[]): boolean {
  let ignored = false;

  for (const rawPattern of patterns) {
    let pattern = rawPattern;
    let negated = false;
    if (pattern.startsWith('!')) {
      negated = true;
      pattern = pattern.slice(1);
    }
    if (pattern === '') continue;

    const anchored = pattern.startsWith('/');
    if (anchored) pattern = pattern.slice(1);
    const directoryOnly = pattern.endsWith('/');
    if (directoryOnly) pattern = pattern.slice(0, -1);
    if (pattern === '') continue;

    const candidates = anchored || pattern.includes('/') ? [pattern] : [pattern, `**/${pattern}`];
    const matched = candidates.some((candidate) => {
      const regex = globToRegExp(candidate);
      if (regex.test(filePath)) return true;
      // A directory pattern also ignores everything beneath it.
      return globToRegExp(`${candidate}/**`).test(filePath);
    });

    if (matched) ignored = !negated;
  }

  return ignored;
}
