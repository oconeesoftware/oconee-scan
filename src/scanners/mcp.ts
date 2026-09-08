import type { McpServerConfig } from '../types/index.js';
import { asRecord, asStringArray, parseJsonc } from '../utils/jsonc.js';
import type { ScanContextBuilder } from './context.js';
import type { Collector } from './types.js';

/**
 * Known project-scoped MCP configuration locations. The key under which
 * servers live differs by host, so each entry names the keys to try.
 */
const MCP_SOURCES: ReadonlyArray<{ path: string; keys: readonly string[] }> = [
  { path: '.mcp.json', keys: ['mcpServers', 'servers'] },
  { path: 'mcp.json', keys: ['mcpServers', 'servers'] },
  { path: '.cursor/mcp.json', keys: ['mcpServers', 'servers'] },
  { path: '.vscode/mcp.json', keys: ['servers', 'mcpServers'] },
  { path: '.claude/settings.json', keys: ['mcpServers'] },
  { path: '.claude/settings.local.json', keys: ['mcpServers'] },
  { path: '.windsurf/mcp.json', keys: ['mcpServers', 'servers'] },
  { path: '.roo/mcp.json', keys: ['mcpServers', 'servers'] },
  { path: '.gemini/settings.json', keys: ['mcpServers'] },
];

/** Field names various hosts use for "run this tool without asking". */
const AUTO_APPROVE_KEYS = ['autoApprove', 'alwaysAllow', 'autoApproved', 'allowedTools'];

function toServer(
  name: string,
  source: string,
  definition: Record<string, unknown>,
): McpServerConfig {
  const env = asRecord(definition['env']);
  const autoApprove: string[] = [];
  for (const key of AUTO_APPROVE_KEYS) {
    autoApprove.push(...asStringArray(definition[key]));
  }
  const command = definition['command'];
  const url = definition['url'] ?? definition['endpoint'] ?? definition['serverUrl'];
  const type = definition['type'] ?? definition['transport'];

  return {
    name,
    source,
    ...(typeof command === 'string' ? { command } : {}),
    args: asStringArray(definition['args']),
    ...(typeof url === 'string' ? { url } : {}),
    ...(typeof type === 'string' ? { type } : {}),
    // Only environment variable NAMES are retained; values are discarded here
    // and never reach a finding.
    envKeys: env ? Object.keys(env) : [],
    autoApprove,
    raw: definition,
  };
}

export const mcpCollector: Collector = {
  name: 'mcp',
  collect(builder: ScanContextBuilder): void {
    const seen = new Set<string>();

    for (const source of MCP_SOURCES) {
      if (!builder.hasFile(source.path)) continue;
      const text = builder.readText(source.path);
      if (text === undefined) continue;

      const { data, error } = parseJsonc(text);
      if (error !== undefined) {
        // `.claude/settings.json` parse failures are already recorded by the
        // Claude collector; avoid reporting the same file twice.
        if (!source.path.startsWith('.claude/')) {
          builder.addParseError({ path: source.path, data: undefined, parseError: error });
        }
        continue;
      }
      const record = asRecord(data);
      if (!record) continue;

      for (const key of source.keys) {
        const servers = asRecord(record[key]);
        if (!servers) continue;
        for (const [name, definition] of Object.entries(servers)) {
          const definitionRecord = asRecord(definition);
          if (!definitionRecord) continue;
          const dedupeKey = `${source.path}::${name}`;
          if (seen.has(dedupeKey)) continue;
          seen.add(dedupeKey);
          builder.mcpServers.push(toServer(name, source.path, definitionRecord));
        }
      }
    }
  },
};
