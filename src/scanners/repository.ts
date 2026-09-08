import type { ScanContextBuilder } from './context.js';
import type { Collector } from './types.js';

export const repositoryCollector: Collector = {
  name: 'repository',
  collect(builder: ScanContextBuilder): void {
    const gitignore = builder.readText('.gitignore');
    if (gitignore === undefined) return;
    for (const rawLine of gitignore.split('\n')) {
      const line = rawLine.trim();
      if (line.length === 0 || line.startsWith('#')) continue;
      builder.gitignore.push(line);
    }
  },
};
