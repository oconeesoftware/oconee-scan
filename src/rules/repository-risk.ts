import type { FileEntry, Rule, RuleFinding } from '../types/index.js';
import { evidence, firstN } from './helpers.js';

/**
 * Repository-risk rules describe the *blast radius* of an agent mistake in
 * this repository. They are context, not defects: infrastructure code is not
 * a vulnerability. They are reported at low/medium severity and are what makes
 * the same agent configuration riskier in one repo than another.
 */

const IAC_PATTERNS: ReadonlyArray<{ label: string; test: (file: FileEntry) => boolean }> = [
  { label: 'Terraform / OpenTofu', test: (f) => /\.tf$|\.tfvars$|\.tf\.json$/i.test(f.path) },
  { label: 'Pulumi', test: (f) => /(?:^|\/)Pulumi\.[\w.-]*ya?ml$/i.test(f.path) },
  {
    label: 'CloudFormation / SAM',
    test: (f) =>
      /(?:^|\/)(?:template|cloudformation)\.ya?ml$|(?:^|\/)samconfig\.toml$/i.test(f.path),
  },
  {
    label: 'Kubernetes manifests',
    test: (f) => /(?:^|\/)(?:k8s|kubernetes|manifests|deploy(?:ment)?s?)\/.+\.ya?ml$/i.test(f.path),
  },
  { label: 'Helm chart', test: (f) => /(?:^|\/)Chart\.ya?ml$/i.test(f.path) },
  {
    label: 'Ansible',
    test: (f) => /(?:^|\/)(?:playbook|site)\.ya?ml$|(?:^|\/)ansible\.cfg$/i.test(f.path),
  },
  { label: 'Serverless Framework', test: (f) => /(?:^|\/)serverless\.ya?ml$/i.test(f.path) },
  { label: 'CDK', test: (f) => /(?:^|\/)cdk\.json$/i.test(f.path) },
];

const CICD_PATTERNS: ReadonlyArray<{ label: string; test: (file: FileEntry) => boolean }> = [
  { label: 'GitHub Actions', test: (f) => /^\.github\/workflows\/.+\.ya?ml$/i.test(f.path) },
  { label: 'GitLab CI', test: (f) => f.path === '.gitlab-ci.yml' },
  { label: 'CircleCI', test: (f) => f.path.startsWith('.circleci/') },
  { label: 'Jenkins', test: (f) => /(?:^|\/)Jenkinsfile$/i.test(f.path) },
  { label: 'Azure Pipelines', test: (f) => /(?:^|\/)azure-pipelines\.ya?ml$/i.test(f.path) },
  { label: 'Buildkite', test: (f) => f.path.startsWith('.buildkite/') },
  { label: 'Travis CI', test: (f) => f.path === '.travis.yml' },
];

const DEPLOY_PATTERNS: ReadonlyArray<{ label: string; test: (file: FileEntry) => boolean }> = [
  {
    label: 'Production compose file',
    test: (f) => /docker-compose\.(?:prod|production)[\w.-]*\.ya?ml$/i.test(f.path),
  },
  {
    label: 'Platform deployment manifest',
    test: (f) =>
      /(?:^|\/)(?:render|vercel|netlify|fly|app|railway)\.(?:ya?ml|json|toml)$/i.test(f.path),
  },
  { label: 'Procfile', test: (f) => /(?:^|\/)Procfile$/i.test(f.path) },
  {
    label: 'Deployment script',
    test: (f) => /(?:^|\/)deploy[\w.-]*\.(?:sh|ps1|py)$/i.test(f.path),
  },
  {
    label: 'Production environment file',
    test: (f) => /\.env\.(?:prod|production)[\w.-]*$/i.test(f.path),
  },
  {
    label: 'Database migration directory',
    test: (f) => /(?:^|\/)migrations?\/.+\.(?:sql|js|ts|py|rb)$/i.test(f.path),
  },
];

function collect(
  context: Parameters<Rule['evaluate']>[0],
  patterns: typeof IAC_PATTERNS,
): Map<string, FileEntry[]> {
  const found = new Map<string, FileEntry[]>();
  for (const file of context.files) {
    for (const pattern of patterns) {
      if (!pattern.test(file)) continue;
      const existing = found.get(pattern.label);
      if (existing) existing.push(file);
      else found.set(pattern.label, [file]);
    }
  }
  return found;
}

const REPO_001: Rule = {
  id: 'REPO-001',
  title: 'Infrastructure-as-code present in the repository',
  category: 'Repository Risk',
  summary: 'Changes made here can alter real infrastructure once applied.',
  evaluate(context): RuleFinding[] {
    const found = collect(context, IAC_PATTERNS);
    if (found.size === 0) return [];
    const total = [...found.values()].reduce((sum, files) => sum + files.length, 0);
    return [
      {
        severity: 'medium',
        confidence: 'high',
        description:
          'This repository defines infrastructure as code. An agent edit here does not stay in the ' +
          'repository: once applied, it changes cloud resources, network boundaries or access policy. The ' +
          'same agent permissions carry materially more consequence in this repository than in an ' +
          'application-only one.',
        evidence: firstN([...found.entries()], 6).map(([label, files]) =>
          evidence(`${label} detected (${files.length} file${files.length === 1 ? '' : 's'}).`, {
            path: files[0]!.path,
          }),
        ),
        affected_path: '.',
        recommendation:
          'Require human review for infrastructure changes, deny agent writes to infrastructure directories, ' +
          `and keep apply/deploy credentials out of any environment an agent can reach (${total} matching files).`,
      },
    ];
  },
};

const REPO_002: Rule = {
  id: 'REPO-002',
  title: 'CI/CD definitions present in the repository',
  category: 'Repository Risk',
  summary: 'Pipeline files are an execution path an agent edit can reach.',
  evaluate(context): RuleFinding[] {
    const found = collect(context, CICD_PATTERNS);
    if (found.size === 0) return [];
    return [
      {
        severity: 'low',
        confidence: 'high',
        description:
          'This repository defines CI/CD pipelines. Pipeline definitions execute with repository secrets, so ' +
          'an agent able to write to them can obtain credentials indirectly without ever reading a secret ' +
          'file — the edit runs later, in an environment the agent never touched.',
        evidence: firstN([...found.entries()], 6).map(([label, files]) =>
          evidence(`${label} configuration detected.`, { path: files[0]!.path }),
        ),
        affected_path: '.',
        recommendation:
          'Deny agent writes to pipeline definitions, require review for workflow changes (CODEOWNERS), and ' +
          'scope pipeline secrets to the jobs that need them.',
      },
    ];
  },
};

const REPO_003: Rule = {
  id: 'REPO-003',
  title: 'Production deployment indicators present',
  category: 'Repository Risk',
  summary: 'The repository contains artifacts that target a production environment.',
  evaluate(context): RuleFinding[] {
    const found = collect(context, DEPLOY_PATTERNS);
    if (found.size === 0) return [];
    return [
      {
        severity: 'medium',
        confidence: 'medium',
        description:
          'Artifacts that target a production environment are present. Agent actions in this repository have ' +
          'a path to production, so the cost of an incorrect action is measured in customer impact rather ' +
          'than in a reverted commit.',
        evidence: firstN([...found.entries()], 6).map(([label, files]) =>
          evidence(`${label} detected.`, { path: files[0]!.path }),
        ),
        affected_path: '.',
        recommendation:
          'Separate production deployment paths from the agent’s working scope, and require an explicit human ' +
          'decision for any action that reaches a production environment.',
      },
    ];
  },
};

const REPO_004: Rule = {
  id: 'REPO-004',
  title: 'Container build files present',
  category: 'Repository Risk',
  summary: 'Dockerfiles define what ships; edits propagate to running workloads.',
  evaluate(context): RuleFinding[] {
    const dockerfiles = context.match((file) =>
      /(?:^|\/)(?:Dockerfile|Containerfile)(?:\.[\w.-]+)?$/i.test(file.path),
    );
    if (dockerfiles.length === 0) return [];
    return [
      {
        severity: 'low',
        confidence: 'high',
        description:
          'Container build definitions are present. Changes to a base image, an installed package or an ' +
          'entrypoint reach every deployed instance of the workload, and are easy to miss in review because ' +
          'they look like ordinary configuration.',
        evidence: firstN(dockerfiles, 5).map((file) =>
          evidence('Container build file detected.', { path: file.path }),
        ),
        affected_path: dockerfiles[0]!.path,
        recommendation:
          'Require review for container build changes and pin base images by digest so an edit cannot ' +
          'silently change what runs.',
      },
    ];
  },
};

export const repositoryRiskRules: readonly Rule[] = [REPO_001, REPO_002, REPO_003, REPO_004];
