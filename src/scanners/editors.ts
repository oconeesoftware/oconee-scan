import { asRecord, parseJsonc } from '../utils/jsonc.js';
import type { ScanContextBuilder } from './context.js';
import type { Collector } from './types.js';

/** Files that instruct an agent how to behave in this repository. */
const INSTRUCTION_FILES = [
  'CLAUDE.md',
  'CLAUDE.local.md',
  'AGENTS.md',
  'AGENT.md',
  'GEMINI.md',
  '.cursorrules',
  '.windsurfrules',
  '.clinerules',
  '.aider.conf.yml',
  '.github/copilot-instructions.md',
];

export const cursorCollector: Collector = {
  name: 'cursor',
  collect(builder: ScanContextBuilder): void {
    for (const configPath of ['.cursor/environment.json', '.cursor/settings.json']) {
      if (!builder.hasFile(configPath)) continue;
      const text = builder.readText(configPath);
      if (text === undefined) continue;
      const { data, error } = parseJsonc(text);
      if (error !== undefined) {
        const failed = { path: configPath, data: undefined, parseError: error };
        builder.cursorConfigs.push(failed);
        builder.addParseError(failed);
        continue;
      }
      builder.cursorConfigs.push({ path: configPath, data: asRecord(data) ?? data });
    }

    if (builder.hasFile('.cursorrules')) builder.cursorRuleFiles.push('.cursorrules');
    for (const entry of builder.match(
      (file) => file.path.startsWith('.cursor/rules/') && file.path.endsWith('.mdc'),
    )) {
      builder.cursorRuleFiles.push(entry.path);
    }
  },
};

export const vscodeCollector: Collector = {
  name: 'vscode',
  collect(builder: ScanContextBuilder): void {
    for (const configPath of ['.vscode/settings.json', '.vscode/extensions.json']) {
      if (!builder.hasFile(configPath)) continue;
      const text = builder.readText(configPath);
      if (text === undefined) continue;
      const { data, error } = parseJsonc(text);
      if (error !== undefined) {
        const failed = { path: configPath, data: undefined, parseError: error };
        builder.vscodeSettings.push(failed);
        builder.addParseError(failed);
        continue;
      }
      const record = asRecord(data);
      if (record) builder.vscodeSettings.push({ path: configPath, data: record });
    }
  },
};

export const copilotCollector: Collector = {
  name: 'copilot',
  collect(builder: ScanContextBuilder): void {
    if (builder.hasFile('.github/copilot-instructions.md')) {
      builder.copilotArtifacts.push('.github/copilot-instructions.md');
    }
    for (const entry of builder.match(
      (file) =>
        (file.path.startsWith('.github/instructions/') && file.path.endsWith('.instructions.md')) ||
        (file.path.startsWith('.github/prompts/') && file.path.endsWith('.prompt.md')) ||
        file.path === '.github/copilot-workspace.json' ||
        file.path === '.github/copilot-setup-steps.yml',
    )) {
      builder.copilotArtifacts.push(entry.path);
    }
    // Copilot settings surface inside VS Code settings; flag their presence.
    for (const settings of builder.vscodeSettings) {
      if (!settings.data) continue;
      const hasCopilotKeys = Object.keys(settings.data).some((key) =>
        key.toLowerCase().startsWith('github.copilot'),
      );
      if (hasCopilotKeys) builder.copilotArtifacts.push(settings.path);
    }
  },
};

export const instructionCollector: Collector = {
  name: 'agent-instructions',
  collect(builder: ScanContextBuilder): void {
    for (const file of INSTRUCTION_FILES) {
      if (builder.hasFile(file)) builder.instructionFiles.push(file);
    }
  },
};
