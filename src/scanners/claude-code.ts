import type { PermissionModel } from '../types/index.js';
import { asRecord, asStringArray, parseJsonc } from '../utils/jsonc.js';
import type { ScanContextBuilder } from './context.js';
import type { Collector } from './types.js';

/** Project-scoped Claude Code settings files, in precedence order. */
export const CLAUDE_SETTINGS_PATHS = ['.claude/settings.json', '.claude/settings.local.json'];

function extractHookCommands(settings: Record<string, unknown>): string[] {
  const hooks = asRecord(settings['hooks']);
  if (!hooks) return [];
  const commands: string[] = [];
  for (const matchers of Object.values(hooks)) {
    if (!Array.isArray(matchers)) continue;
    for (const matcher of matchers) {
      const matcherRecord = asRecord(matcher);
      const inner = matcherRecord?.['hooks'];
      if (!Array.isArray(inner)) continue;
      for (const hook of inner) {
        const hookRecord = asRecord(hook);
        const command = hookRecord?.['command'];
        if (typeof command === 'string') commands.push(command);
      }
    }
  }
  return commands;
}

export function toPermissionModel(
  source: string,
  settings: Record<string, unknown>,
): PermissionModel | undefined {
  const permissions = asRecord(settings['permissions']);
  const hookCommands = extractHookCommands(settings);
  if (!permissions && hookCommands.length === 0) return undefined;

  const defaultMode = permissions?.['defaultMode'];
  return {
    source,
    allow: asStringArray(permissions?.['allow']),
    deny: asStringArray(permissions?.['deny']),
    ask: asStringArray(permissions?.['ask']),
    ...(typeof defaultMode === 'string' ? { defaultMode } : {}),
    additionalDirectories: asStringArray(permissions?.['additionalDirectories']),
    hookCommands,
  };
}

export const claudeCodeCollector: Collector = {
  name: 'claude-code',
  collect(builder: ScanContextBuilder): void {
    for (const settingsPath of CLAUDE_SETTINGS_PATHS) {
      if (!builder.hasFile(settingsPath)) continue;
      const text = builder.readText(settingsPath);
      if (text === undefined) continue;

      const { data, error } = parseJsonc(text);
      if (error !== undefined) {
        const failed = { path: settingsPath, data: undefined, parseError: error };
        builder.claudeSettings.push(failed);
        builder.addParseError(failed);
        continue;
      }
      const record = asRecord(data);
      builder.claudeSettings.push({ path: settingsPath, data: record ?? data });
      if (!record) continue;

      const model = toPermissionModel(settingsPath, record);
      if (model) builder.permissions.push(model);
    }

    // Sub-agent definitions and slash commands widen the agent's action surface.
    for (const entry of builder.match((file) => file.path.startsWith('.claude/'))) {
      if (entry.path.startsWith('.claude/agents/') && entry.path.endsWith('.md')) {
        builder.instructionFiles.push(entry.path);
      }
    }
  },
};
