import fs from 'node:fs';
import path from 'node:path';
import type {
  FileEntry,
  McpServerConfig,
  ParsedConfig,
  PermissionModel,
  ScanContext,
  SecretIndicator,
} from '../types/index.js';
import { IGNORED_DIRECTORIES, looksBinary, toPosix } from '../utils/paths.js';

export interface WalkLimits {
  readonly maxFiles: number;
  readonly maxDepth: number;
  /** Files larger than this are indexed but never read. */
  readonly maxReadBytes: number;
}

export const DEFAULT_LIMITS: WalkLimits = {
  maxFiles: 25_000,
  maxDepth: 12,
  maxReadBytes: 2 * 1024 * 1024,
};

/**
 * Mutable builder used by collectors. Rules only ever see the readonly
 * `ScanContext` view, so they cannot mutate shared state.
 */
export class ScanContextBuilder implements ScanContext {
  readonly rootDir: string;
  readonly projectName: string;
  readonly files: FileEntry[] = [];
  readonly fileSet = new Set<string>();
  readonly dirSet = new Set<string>();

  readonly claudeSettings: ParsedConfig[] = [];
  readonly mcpServers: McpServerConfig[] = [];
  readonly permissions: PermissionModel[] = [];
  readonly cursorConfigs: ParsedConfig[] = [];
  readonly cursorRuleFiles: string[] = [];
  readonly vscodeSettings: ParsedConfig<Record<string, unknown>>[] = [];
  readonly copilotArtifacts: string[] = [];
  readonly instructionFiles: string[] = [];
  readonly secretIndicators: SecretIndicator[] = [];
  readonly gitignore: string[] = [];
  readonly parseErrors: ParsedConfig[] = [];
  readonly warnings: string[] = [];

  truncated = false;

  private readonly limits: WalkLimits;
  private readonly textCache = new Map<string, string | undefined>();

  constructor(rootDir: string, limits: WalkLimits = DEFAULT_LIMITS) {
    this.rootDir = rootDir;
    this.limits = limits;
    this.projectName = path.basename(path.resolve(rootDir)) || rootDir;
  }

  /** Depth-first, read-only walk. Symlinks are indexed but never followed. */
  indexFiles(): void {
    const queue: Array<{ dir: string; depth: number }> = [{ dir: this.rootDir, depth: 0 }];

    while (queue.length > 0) {
      const { dir, depth } = queue.pop()!;
      if (depth > this.limits.maxDepth) continue;

      let entries: fs.Dirent[];
      try {
        entries = fs.readdirSync(dir, { withFileTypes: true });
      } catch (error) {
        this.warnings.push(
          `Could not read directory ${toPosix(path.relative(this.rootDir, dir)) || '.'}: ${errorMessage(error)}`,
        );
        continue;
      }

      for (const entry of entries) {
        if (this.files.length >= this.limits.maxFiles) {
          this.truncated = true;
          return;
        }
        const absolute = path.join(dir, entry.name);
        const relative = toPosix(path.relative(this.rootDir, absolute));
        if (relative === '' || relative.startsWith('..')) continue;

        if (entry.isSymbolicLink()) {
          // Never traverse a symlink: it can escape the repository root.
          continue;
        }
        if (entry.isDirectory()) {
          if (IGNORED_DIRECTORIES.has(entry.name)) continue;
          this.dirSet.add(relative);
          queue.push({ dir: absolute, depth: depth + 1 });
          continue;
        }
        if (!entry.isFile()) continue;

        let size = 0;
        try {
          size = fs.statSync(absolute).size;
        } catch {
          // A file that vanished mid-walk is not worth a warning.
          continue;
        }
        const file: FileEntry = { path: relative, name: entry.name.toLowerCase(), size };
        this.files.push(file);
        this.fileSet.add(relative);
      }
    }
  }

  readText(relativePath: string): string | undefined {
    if (this.textCache.has(relativePath)) return this.textCache.get(relativePath);

    let text: string | undefined;
    const absolute = path.resolve(this.rootDir, relativePath);
    // Defence in depth: never read outside the scan root.
    const root = path.resolve(this.rootDir);
    if (absolute !== root && !absolute.startsWith(root + path.sep)) {
      this.textCache.set(relativePath, undefined);
      return undefined;
    }
    if (looksBinary(relativePath)) {
      this.textCache.set(relativePath, undefined);
      return undefined;
    }
    try {
      const stat = fs.statSync(absolute);
      if (!stat.isFile() || stat.size > this.limits.maxReadBytes) {
        this.textCache.set(relativePath, undefined);
        return undefined;
      }
      const buffer = fs.readFileSync(absolute);
      // A NUL byte in the first block is the cheapest reliable binary signal.
      if (buffer.subarray(0, 4096).includes(0)) {
        this.textCache.set(relativePath, undefined);
        return undefined;
      }
      text = buffer.toString('utf8');
    } catch (error) {
      // A file that simply is not there is the normal case for probe reads.
      if (!isNotFound(error)) {
        this.warnings.push(`Could not read ${relativePath}: ${errorMessage(error)}`);
      }
      text = undefined;
    }
    this.textCache.set(relativePath, text);
    return text;
  }

  hasFile(relativePath: string): boolean {
    return this.fileSet.has(relativePath);
  }

  match(predicate: (entry: FileEntry) => boolean): FileEntry[] {
    return this.files.filter(predicate);
  }

  addParseError(config: ParsedConfig): void {
    this.parseErrors.push(config);
  }
}

function isNotFound(error: unknown): boolean {
  return (
    typeof error === 'object' &&
    error !== null &&
    'code' in error &&
    ((error as { code?: string }).code === 'ENOENT' ||
      (error as { code?: string }).code === 'ENOTDIR')
  );
}

export function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}
