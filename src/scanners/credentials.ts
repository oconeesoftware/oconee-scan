import type { FileEntry } from '../types/index.js';
import { baseName, matchesAnyGlob } from '../utils/paths.js';
import { detectSecretIndicators } from '../utils/secrets.js';
import type { ScanContextBuilder } from './context.js';
import type { Collector } from './types.js';

/** Real environment files (templates are handled separately). */
export const ENV_FILE_GLOBS = ['**/.env', '**/.env.*', '**/*.env'];
/**
 * Template markers may appear anywhere after `.env` -- `.env.example`, but also
 * `.env.example.v2` and `.env.sample.local`.
 */
const ENV_TEMPLATE_MARKER =
  /(?:^|[.\-_])(?:example|sample|template|dist|tpl|defaults?)(?:$|[.\-_])/i;

/** Files whose very presence implies key material. */
export const KEY_MATERIAL_GLOBS = [
  '**/*.pem',
  '**/*.key',
  '**/*.p12',
  '**/*.pfx',
  '**/*.jks',
  '**/*.keystore',
  '**/*.ppk',
  '**/id_rsa',
  '**/id_dsa',
  '**/id_ecdsa',
  '**/id_ed25519',
];

/** Provider credential/config files that grant standing access. */
export const CLOUD_CREDENTIAL_GLOBS = [
  '**/.aws/credentials',
  '**/.aws/config',
  '**/.npmrc',
  '**/.netrc',
  '**/.pypirc',
  '**/.docker/config.json',
  '**/kubeconfig',
  '**/.kube/config',
  '**/service-account*.json',
  '**/gha-creds-*.json',
  '**/terraform.tfvars',
  '**/*.auto.tfvars',
  '**/secrets.yaml',
  '**/secrets.yml',
  '**/secrets.json',
];

/** Extensions worth reading for credential indicators. */
const SCANNABLE_EXTENSIONS =
  /\.(?:env|json|jsonc|ya?ml|toml|ini|cfg|conf|properties|tfvars|tf|sh|bash|zsh|ps1|py|rb|js|mjs|cjs|ts|go|java|cs|php|xml|txt|md)$/i;

const NO_EXTENSION_SCANNABLE = new Set([
  '.env',
  '.npmrc',
  '.netrc',
  '.pypirc',
  'dockerfile',
  'makefile',
  'procfile',
  'credentials',
  'config',
  'kubeconfig',
]);

/** Content scanning is bounded so a huge repo cannot stall the CLI. */
const MAX_FILES_CONTENT_SCANNED = 1_500;
const MAX_FILE_BYTES_CONTENT_SCANNED = 512 * 1024;

export function isEnvFile(filePath: string): boolean {
  if (!matchesAnyGlob(filePath, ENV_FILE_GLOBS)) return false;
  return !ENV_TEMPLATE_MARKER.test(baseName(filePath));
}

export function isEnvTemplate(filePath: string): boolean {
  return matchesAnyGlob(filePath, ENV_FILE_GLOBS) && ENV_TEMPLATE_MARKER.test(baseName(filePath));
}

export function isKeyMaterial(filePath: string): boolean {
  return matchesAnyGlob(filePath, KEY_MATERIAL_GLOBS);
}

export function isCloudCredentialFile(filePath: string): boolean {
  return matchesAnyGlob(filePath, CLOUD_CREDENTIAL_GLOBS);
}

function shouldScanContents(entry: FileEntry): boolean {
  if (entry.size === 0 || entry.size > MAX_FILE_BYTES_CONTENT_SCANNED) return false;
  const name = baseName(entry.path);
  if (NO_EXTENSION_SCANNABLE.has(name)) return true;
  if (name.startsWith('.env')) return true;
  return SCANNABLE_EXTENSIONS.test(name);
}

export const credentialCollector: Collector = {
  name: 'credentials',
  collect(builder: ScanContextBuilder): void {
    // Highest-value files first, so the budget is never spent on noise.
    const prioritised = [...builder.files].sort((a, b) => rank(a.path) - rank(b.path));

    let scanned = 0;
    for (const entry of prioritised) {
      if (scanned >= MAX_FILES_CONTENT_SCANNED) break;
      if (!shouldScanContents(entry)) continue;
      const text = builder.readText(entry.path);
      if (text === undefined) continue;
      scanned += 1;
      builder.secretIndicators.push(...detectSecretIndicators(entry.path, text));
    }
  },
};

function rank(filePath: string): number {
  if (isEnvFile(filePath)) return 0;
  if (isCloudCredentialFile(filePath) || isKeyMaterial(filePath)) return 1;
  if (/\.(?:tfvars|ini|cfg|conf|properties)$/i.test(filePath)) return 2;
  if (/\.(?:ya?ml|json|toml)$/i.test(filePath)) return 3;
  return 4;
}
