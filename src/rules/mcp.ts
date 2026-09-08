import type { Rule, RuleFinding } from '../types/index.js';
import {
  evidence,
  firstN,
  isMcpTool,
  isUnconstrained,
  mcpServerFromTool,
  parsePermissionRule,
} from './helpers.js';

/** Environment variable names that name a credential rather than a setting. */
const CREDENTIAL_ENV_KEY =
  /(?:token|secret|password|passwd|api[_-]?key|access[_-]?key|private[_-]?key|credential|auth)/i;

/** Filesystem roots that hand an MCP server the whole machine. */
const BROAD_FILESYSTEM_ROOT = /^(?:\/|~|\/home|\/Users|\/etc|\/var|[A-Za-z]:\\?)$/;

const MCP_001: Rule = {
  id: 'MCP-001',
  title: 'MCP servers extend the agent action surface',
  category: 'MCP / Tool Access',
  summary: 'Inventory of project-scoped MCP servers available to agents.',
  evaluate(context): RuleFinding[] {
    if (context.mcpServers.length === 0) return [];
    return [
      {
        severity: 'info',
        confidence: 'high',
        description:
          'This repository declares MCP servers. Each server adds Actions the Agent can take against ' +
          'Resources outside the repository, and those actions are governed by the server’s own permissions ' +
          'rather than by the repository’s.',
        evidence: firstN(context.mcpServers, 10).map((server) =>
          evidence(`MCP server "${server.name}" declared.`, {
            path: server.source,
            excerpt: server.url ?? server.command ?? server.type ?? 'server definition',
          }),
        ),
        affected_path: context.mcpServers[0]!.source,
        recommendation:
          'Maintain an owner and a stated purpose for every MCP server, and review the tool list each server ' +
          'exposes as part of onboarding it.',
      },
    ];
  },
};

const MCP_002: Rule = {
  id: 'MCP-002',
  title: 'MCP server launched from an unpinned remote package',
  category: 'MCP / Tool Access',
  summary: 'A server is started via a package runner that resolves a version at run time.',
  evaluate(context): RuleFinding[] {
    const RUNNERS = /^(?:npx|pnpx|bunx|uvx|pipx)$/i;
    const findings: RuleFinding[] = [];
    for (const server of context.mcpServers) {
      if (!server.command || !RUNNERS.test(server.command)) continue;
      const args = server.args ?? [];
      const packageArg = args.find((arg) => !arg.startsWith('-'));
      const pinned = packageArg !== undefined && /@\d[\w.-]*$/.test(packageArg);
      if (pinned) continue;
      findings.push({
        severity: 'medium',
        confidence: 'high',
        description:
          'The MCP server is launched with a package runner and no pinned version. The code that runs with ' +
          'the agent’s tool privileges is resolved from a remote registry at launch time, so a compromised or ' +
          'newly published version executes without review.',
        evidence: [
          evidence(
            `Server "${server.name}" launches via ${server.command} without a pinned version.`,
            {
              path: server.source,
              excerpt: [server.command, ...args].join(' ').slice(0, 160),
            },
          ),
        ],
        affected_path: server.source,
        recommendation:
          'Pin an exact version (`package@1.2.3`), or vendor the server and launch it from a checked-in path ' +
          'so upgrades go through review.',
      });
    }
    return findings;
  },
};

const MCP_003: Rule = {
  id: 'MCP-003',
  title: 'Broad MCP tool permissions',
  category: 'MCP / Tool Access',
  summary: 'An MCP server is allowed wholesale, or its write-capable tools are auto-approved.',
  evaluate(context): RuleFinding[] {
    const findings: RuleFinding[] = [];

    // 1. Wildcard allow-list entries for an MCP server.
    for (const model of context.permissions) {
      const broad = model.allow
        .map((raw) => parsePermissionRule(raw, model.source))
        .filter(
          (rule) =>
            isMcpTool(rule.tool) && isUnconstrained(rule) && rule.tool.split('__').length <= 2,
        );
      if (broad.length === 0) continue;
      findings.push({
        severity: 'high',
        confidence: 'high',
        description:
          'An MCP server is permitted wholesale rather than tool by tool. Every tool the server exposes now ' +
          'and every tool it adds in a future version is pre-approved, including write-capable ones.',
        evidence: broad.map((rule) =>
          evidence(
            `MCP server "${mcpServerFromTool(rule.tool) ?? rule.tool}" allowed without naming individual tools.`,
            { path: rule.source, excerpt: rule.raw },
          ),
        ),
        affected_path: model.source,
        recommendation:
          'Allow individual tools by name (`mcp__server__read_issue`) instead of the server as a whole, and ' +
          're-review the list when the server is upgraded.',
      });
    }

    // 2. Host-level auto-approve lists on the server definition itself.
    for (const server of context.mcpServers) {
      if (server.autoApprove.length === 0) continue;
      const wildcard = server.autoApprove.some((tool) => tool === '*' || tool.endsWith('*'));
      const writeLike = server.autoApprove.filter((tool) =>
        /(?:write|create|update|delete|remove|push|merge|deploy|execute|run|send|post|put|patch)/i.test(
          tool,
        ),
      );
      if (!wildcard && writeLike.length === 0) continue;
      findings.push({
        severity: wildcard ? 'high' : 'medium',
        confidence: 'high',
        description:
          'An MCP server exposes write-capable tools that are auto-approved. Actions taken through those ' +
          'tools reach external systems with no approval step and, in most hosts, no local audit record.',
        evidence: firstN(wildcard ? server.autoApprove : writeLike, 8).map((tool) =>
          evidence(`Auto-approved tool on server "${server.name}": ${tool}`, {
            path: server.source,
            excerpt: tool,
          }),
        ),
        affected_path: server.source,
        recommendation:
          'Remove write-capable tools from the auto-approve list. Keep auto-approval for read-only tools only, ' +
          'and require confirmation for anything that mutates an external system.',
      });
    }

    return findings;
  },
};

const MCP_004: Rule = {
  id: 'MCP-004',
  title: 'MCP server configuration references credentials inline',
  category: 'MCP / Tool Access',
  summary: 'A server definition carries credential-named environment variables.',
  evaluate(context): RuleFinding[] {
    const findings: RuleFinding[] = [];
    for (const server of context.mcpServers) {
      const credentialKeys = server.envKeys.filter((key) => CREDENTIAL_ENV_KEY.test(key));
      if (credentialKeys.length === 0) continue;
      findings.push({
        severity: 'medium',
        confidence: 'medium',
        description:
          'An MCP server definition declares credential-named environment variables. If the values are ' +
          'literals rather than references, they are committed to version control; either way the server ' +
          'holds standing access to an external system on the agent’s behalf.',
        // Only variable NAMES are reported. Values are never read into evidence.
        evidence: firstN(credentialKeys, 8).map((key) =>
          evidence(`Credential-named environment variable on server "${server.name}".`, {
            path: server.source,
            excerpt: `env.${key}`,
          }),
        ),
        affected_path: server.source,
        recommendation:
          'Reference credentials indirectly (`${VAR}` expansion or a secret manager) rather than embedding ' +
          'values, and scope each token to the minimum permissions the server needs.',
      });
    }
    return findings;
  },
};

const MCP_005: Rule = {
  id: 'MCP-005',
  title: 'Remote MCP server reached over an unencrypted transport',
  category: 'MCP / Tool Access',
  summary: 'A server URL uses http:// to a non-loopback host.',
  evaluate(context): RuleFinding[] {
    const findings: RuleFinding[] = [];
    for (const server of context.mcpServers) {
      if (!server.url || !/^http:\/\//i.test(server.url)) continue;
      const isLoopback = /^http:\/\/(?:localhost|127\.0\.0\.1|\[::1\])(?::\d+)?(?:\/|$)/i.test(
        server.url,
      );
      if (isLoopback) continue;
      findings.push({
        severity: 'high',
        confidence: 'high',
        description:
          'An MCP server is configured over plain HTTP to a remote host. Tool arguments, tool results and any ' +
          'bearer token sent with them traverse the network in the clear and can be modified in transit, ' +
          'which turns the transport into an injection point for agent instructions.',
        evidence: [
          evidence(`Server "${server.name}" uses an unencrypted endpoint.`, {
            path: server.source,
            excerpt: server.url.replace(/\?.*$/, ''),
          }),
        ],
        affected_path: server.source,
        recommendation: 'Use an https:// endpoint, or run the server locally over stdio.',
      });
    }
    return findings;
  },
};

const MCP_006: Rule = {
  id: 'MCP-006',
  title: 'MCP filesystem server rooted outside the project',
  category: 'MCP / Tool Access',
  summary: 'A filesystem-style server is given a home, root or system directory.',
  evaluate(context): RuleFinding[] {
    const findings: RuleFinding[] = [];
    for (const server of context.mcpServers) {
      const args = server.args ?? [];
      const looksFilesystem =
        /filesystem|file-?system|fs\b/i.test(server.name) ||
        args.some((arg) => /server-filesystem|mcp-filesystem/i.test(arg));
      if (!looksFilesystem) continue;

      const broadRoots = args.filter(
        (arg) =>
          !arg.startsWith('-') &&
          (BROAD_FILESYSTEM_ROOT.test(arg) || /^(?:~|\/)(?:Users|home)\/[^/]+\/?$/.test(arg)),
      );
      if (broadRoots.length === 0) continue;
      findings.push({
        severity: 'high',
        confidence: 'medium',
        description:
          'A filesystem MCP server is rooted at a home or system directory rather than the project. The ' +
          'agent’s file access surface extends to every repository, credential file and personal document ' +
          'under that root, regardless of what the repository policy says.',
        evidence: broadRoots.map((root) =>
          evidence(`Server "${server.name}" is rooted at ${root}.`, {
            path: server.source,
            excerpt: root,
          }),
        ),
        affected_path: server.source,
        recommendation:
          'Root filesystem servers at the specific project directory, and run one server per project rather ' +
          'than a single machine-wide server.',
      });
    }
    return findings;
  },
};

const MCP_007: Rule = {
  id: 'MCP-007',
  title: 'MCP server executes a script from the repository',
  category: 'MCP / Tool Access',
  summary: 'A server launches an interpreter against a path inside the working tree.',
  evaluate(context): RuleFinding[] {
    const INTERPRETER = /^(?:node|python3?|ruby|perl|bash|sh|zsh|deno|bun|php)$/i;
    const findings: RuleFinding[] = [];
    for (const server of context.mcpServers) {
      if (!server.command || !INTERPRETER.test(server.command)) continue;
      const scriptArg = (server.args ?? []).find((arg) => !arg.startsWith('-'));
      if (!scriptArg) continue;
      findings.push({
        severity: 'medium',
        confidence: 'medium',
        description:
          'An MCP server runs a script from the working tree. Whoever can change that file controls code ' +
          'that executes with the agent’s tool privileges, which makes it a higher-value target than ordinary ' +
          'application source.',
        evidence: [
          evidence(`Server "${server.name}" executes a local script via ${server.command}.`, {
            path: server.source,
            excerpt: scriptArg,
          }),
        ],
        affected_path: server.source,
        recommendation:
          'Require review for changes to MCP server entry points (a CODEOWNERS entry is enough), and keep ' +
          'them out of directories that agents are allowed to write.',
      });
    }
    return findings;
  },
};

const MCP_008: Rule = {
  id: 'MCP-008',
  title: 'MCP server definition could not be attributed to a transport',
  category: 'MCP / Tool Access',
  summary: 'A server declares neither a command nor a URL, so its behaviour is unclear.',
  evaluate(context): RuleFinding[] {
    const orphans = context.mcpServers.filter((server) => !server.command && !server.url);
    if (orphans.length === 0) return [];
    return [
      {
        severity: 'low',
        confidence: 'medium',
        description:
          'One or more MCP server definitions declare neither a launch command nor an endpoint. The scanner ' +
          'cannot determine what code will run, so these servers are not covered by the transport and ' +
          'supply-chain checks.',
        evidence: firstN(orphans, 6).map((server) =>
          evidence(`Server "${server.name}" has no command or url field.`, { path: server.source }),
        ),
        affected_path: orphans[0]!.source,
        recommendation:
          'Make each server definition explicit about its transport so it can be reviewed and scanned.',
      },
    ];
  },
};

export const mcpRules: readonly Rule[] = [
  MCP_001,
  MCP_002,
  MCP_003,
  MCP_004,
  MCP_005,
  MCP_006,
  MCP_007,
  MCP_008,
];
