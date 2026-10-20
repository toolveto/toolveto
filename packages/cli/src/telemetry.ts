import * as fs from 'node:fs';
import * as path from 'node:path';
import * as os from 'node:os';
import * as crypto from 'node:crypto';
import type { SuiteSummary } from '@toolveto/core';

export const CLI_VERSION = '0.2.0';
export const DEFAULT_CLOUD_API_URL = process.env.TOOLVETO_API_URL || 'https://api.toolveto.ai';

export interface CliLocalState {
  installId: string;
  totalRuns: number;
  lastRunAt?: number;
  lastVersionCheckAt?: number;
  latestKnownVersion?: string;
  latestReleaseNotes?: string;
}

export interface CliCheckPayload {
  installId: string;
  cliVersion: string;
  command: string;
  osPlatform: string;
  osArch: string;
  nodeVersion: string;
  isCi: boolean;
  ciProvider: string;
  isContainerized: boolean;
  runnerType: 'self-hosted-enterprise' | 'cloud-hosted-ci' | 'local-workstation';
  triggerEvent: string;
  orgHash: string;
  pipelineHash: string;
  authenticated: boolean;
  targetHash: string;
  runNumber: number;
  score: number;
  tier: string;
  fatalVetoTriggered: boolean;
  fatalVetoCodes: string[];
  toolsEvaluatedCount: number;
  mutationToolsCount: number;
  totalChecks: number;
  passedChecks: number;
  failedChecks: number;
  warnedChecks: number;
  criticalFailures: number;
  failedCheckIds: string[];
  durationMs: number;
}

export interface VersionCheckResponse {
  latestVersion: string;
  latestCorpusVersion: string;
  sealedCorpusChecksCount: number;
  releaseUrl: string;
  upgradeCommand: string;
  securityAdvisory?: string;
}

/**
 * Checks whether anonymous CLI telemetry & version checks are disabled via standard
 * Trivy / Grype / Console Do-Not-Track conventions.
 */
export function isTelemetryDisabled(options?: { noTelemetry?: boolean; skipUpdateCheck?: boolean }): boolean {
  if (options?.noTelemetry) return true;
  const dnt = (process.env.DO_NOT_TRACK || '').trim().toLowerCase();
  if (dnt === '1' || dnt === 'true') return true;
  const tvNoTel = (process.env.TOOLVETO_NO_TELEMETRY || '').trim().toLowerCase();
  if (tvNoTel === '1' || tvNoTel === 'true') return true;
  const tvTelDisabled = (process.env.TOOLVETO_TELEMETRY_DISABLED || '').trim().toLowerCase();
  if (tvTelDisabled === '1' || tvTelDisabled === 'true') return true;
  return false;
}

export function isUpdateCheckDisabled(options?: { skipUpdateCheck?: boolean; json?: boolean; format?: string }): boolean {
  if (options?.skipUpdateCheck) return true;
  if (options?.json || options?.format === 'json') return true;
  const skipEnv = (process.env.TOOLVETO_SKIP_UPDATE_CHECK || '').trim().toLowerCase();
  if (skipEnv === '1' || skipEnv === 'true') return true;
  return false;
}

export interface CiIdentity {
  isCi: boolean;
  ciProvider: string;
  isContainerized: boolean;
  runnerType: 'self-hosted-enterprise' | 'cloud-hosted-ci' | 'local-workstation';
  triggerEvent: string;
  ciOrgIdentity?: string;
  ciRepoIdentity?: string;
  ciPipelineIdentity?: string;
  ciRunNumber?: number;
}

export function detectContainerRuntime(): boolean {
  try {
    if (process.env.KUBERNETES_SERVICE_HOST) return true;
    if (process.env.CONTAINER || process.env.DOCKER_CONTAINER) return true;
    if (fs.existsSync('/.dockerenv') || fs.existsSync('/run/.containerenv')) return true;
  } catch {
    // Ignore fs errors
  }
  return false;
}

/**
 * Extracts git remote origin URL (stripped of any embedded credentials) so ephemeral
 * containers or stateless runners auditing the same repository produce a stable identity.
 */
export function resolveGitRemoteIdentity(cwd: string = process.cwd()): string | undefined {
  try {
    const gitConfigPath = path.join(cwd, '.git', 'config');
    if (fs.existsSync(gitConfigPath)) {
      const content = fs.readFileSync(gitConfigPath, 'utf-8');
      const match = content.match(/\[remote "origin"\][\s\S]*?url\s*=\s*([^\r\n]+)/);
      if (match && match[1]) {
        // Strip credentials from https://token@github.com/org/repo.git and normalize SSH git@github.com:org/repo.git
        return match[1]
          .trim()
          .replace(/^https?:\/\/[^@]+@/, 'https://')
          .replace(/^git@([^:]+):/, 'https://$1/')
          .replace(/\.git$/, '')
          .toLowerCase();
      }
    }
  } catch {
    // Ignore git read errors
  }
  return undefined;
}

export function extractOrgFromRemote(remoteUrl?: string): string | undefined {
  if (!remoteUrl) return undefined;
  const match = remoteUrl.match(/^https?:\/\/([^/]+)\/([^/]+)/i);
  if (match && match[1] && match[2]) {
    return `${match[1]}/${match[2]}`.toLowerCase();
  }
  return undefined;
}

export function detectCiProvider(cwd: string = process.cwd()): CiIdentity {
  const isContainerized = detectContainerRuntime();
  const gitRemote = resolveGitRemoteIdentity(cwd);
  const gitOrg = extractOrgFromRemote(gitRemote);

  if (process.env.GITHUB_ACTIONS === 'true') {
    const repo = process.env.GITHUB_REPOSITORY || process.env.GITHUB_REPOSITORY_ID || gitRemote;
    const owner = process.env.GITHUB_REPOSITORY_OWNER || process.env.GITHUB_REPOSITORY_OWNER_ID || (repo && repo.includes('/') ? repo.split('/')[0] : gitOrg);
    const workflow = process.env.GITHUB_WORKFLOW || 'default-workflow';
    const triggerEvent = process.env.GITHUB_EVENT_NAME || 'push';
    const isSelfHosted = process.env.RUNNER_ENVIRONMENT === 'self-hosted' || Boolean(process.env.KUBERNETES_SERVICE_HOST);
    const runNum = parseInt(process.env.GITHUB_RUN_NUMBER || '', 10);
    return {
      isCi: true,
      ciProvider: 'github-actions',
      isContainerized,
      runnerType: isSelfHosted ? 'self-hosted-enterprise' : 'cloud-hosted-ci',
      triggerEvent,
      ciOrgIdentity: owner ? `gh_org:${owner.toLowerCase()}` : undefined,
      ciRepoIdentity: repo ? `gh:${repo.toLowerCase()}` : undefined,
      ciPipelineIdentity: repo ? `gh_pipe:${repo.toLowerCase()}:${workflow.toLowerCase()}` : undefined,
      ciRunNumber: Number.isFinite(runNum) && runNum > 0 ? runNum : undefined,
    };
  }
  if (process.env.GITLAB_CI === 'true') {
    const repo = process.env.CI_PROJECT_PATH || process.env.CI_PROJECT_ID || gitRemote;
    const ns = process.env.CI_PROJECT_ROOT_NAMESPACE || process.env.CI_PROJECT_NAMESPACE || gitOrg;
    const triggerEvent = process.env.CI_PIPELINE_SOURCE || 'push';
    const serverHost = (process.env.CI_SERVER_HOST || 'gitlab.com').toLowerCase();
    const isSelfHosted = serverHost !== 'gitlab.com' || Boolean(process.env.KUBERNETES_SERVICE_HOST);
    const runNum = parseInt(process.env.CI_PIPELINE_IID || process.env.CI_PIPELINE_ID || '', 10);
    return {
      isCi: true,
      ciProvider: 'gitlab-ci',
      isContainerized,
      runnerType: isSelfHosted ? 'self-hosted-enterprise' : 'cloud-hosted-ci',
      triggerEvent,
      ciOrgIdentity: ns ? `gl_org:${serverHost}/${ns.toLowerCase()}` : undefined,
      ciRepoIdentity: repo ? `gl:${repo.toLowerCase()}` : undefined,
      ciPipelineIdentity: repo ? `gl_pipe:${repo.toLowerCase()}:${triggerEvent}` : undefined,
      ciRunNumber: Number.isFinite(runNum) && runNum > 0 ? runNum : undefined,
    };
  }
  if (process.env.CIRCLECI === 'true') {
    const org = process.env.CIRCLE_PROJECT_USERNAME || gitOrg || '';
    const repoName = process.env.CIRCLE_PROJECT_REPONAME || '';
    const job = process.env.CIRCLE_JOB || 'build';
    const repo = org && repoName ? `${org}/${repoName}` : gitRemote;
    const runNum = parseInt(process.env.CIRCLE_BUILD_NUM || '', 10);
    return {
      isCi: true,
      ciProvider: 'circleci',
      isContainerized,
      runnerType: process.env.KUBERNETES_SERVICE_HOST ? 'self-hosted-enterprise' : 'cloud-hosted-ci',
      triggerEvent: process.env.CIRCLE_PR_NUMBER ? 'pull_request' : 'push',
      ciOrgIdentity: org ? `cci_org:${org.toLowerCase()}` : undefined,
      ciRepoIdentity: repo ? `cci:${repo.toLowerCase()}` : undefined,
      ciPipelineIdentity: repo ? `cci_pipe:${repo.toLowerCase()}:${job.toLowerCase()}` : undefined,
      ciRunNumber: Number.isFinite(runNum) && runNum > 0 ? runNum : undefined,
    };
  }
  if (process.env.JENKINS_URL) {
    const job = process.env.JOB_NAME || gitRemote;
    const runNum = parseInt(process.env.BUILD_NUMBER || '', 10);
    let jenkinsHost = 'jenkins';
    try {
      jenkinsHost = new URL(process.env.JENKINS_URL).hostname.toLowerCase();
    } catch {
      // Fallback
    }
    return {
      isCi: true,
      ciProvider: 'jenkins',
      isContainerized,
      runnerType: 'self-hosted-enterprise',
      triggerEvent: process.env.CHANGE_ID ? 'pull_request' : 'ci_job',
      ciOrgIdentity: `jk_org:${jenkinsHost}`,
      ciRepoIdentity: job ? `jk:${job.toLowerCase()}` : undefined,
      ciPipelineIdentity: job ? `jk_pipe:${jenkinsHost}/${job.toLowerCase()}` : undefined,
      ciRunNumber: Number.isFinite(runNum) && runNum > 0 ? runNum : undefined,
    };
  }
  if (process.env.TF_BUILD === 'True' || process.env.TF_BUILD === 'true') {
    const orgUri = process.env.SYSTEM_COLLECTIONURI || gitOrg || 'ado';
    const proj = process.env.SYSTEM_TEAMPROJECT || '';
    const repo = process.env.BUILD_REPOSITORY_NAME || gitRemote;
    const defName = process.env.BUILD_DEFINITIONNAME || 'pipeline';
    const runNum = parseInt(process.env.BUILD_BUILDID || '', 10);
    return {
      isCi: true,
      ciProvider: 'azure-devops',
      isContainerized,
      runnerType: process.env.KUBERNETES_SERVICE_HOST ? 'self-hosted-enterprise' : 'cloud-hosted-ci',
      triggerEvent: (process.env.BUILD_REASON || 'push').toLowerCase(),
      ciOrgIdentity: `ado_org:${orgUri.toLowerCase()}:${proj.toLowerCase()}`,
      ciRepoIdentity: repo ? `ado:${repo.toLowerCase()}` : undefined,
      ciPipelineIdentity: `ado_pipe:${proj.toLowerCase()}/${defName.toLowerCase()}`,
      ciRunNumber: Number.isFinite(runNum) && runNum > 0 ? runNum : undefined,
    };
  }
  if (process.env.BUILDKITE === 'true') {
    const orgSlug = process.env.BUILDKITE_ORGANIZATION_SLUG || gitOrg;
    const slug = process.env.BUILDKITE_PIPELINE_SLUG || gitRemote;
    const runNum = parseInt(process.env.BUILDKITE_BUILD_NUMBER || '', 10);
    return {
      isCi: true,
      ciProvider: 'buildkite',
      isContainerized,
      runnerType: 'self-hosted-enterprise',
      triggerEvent: process.env.BUILDKITE_PULL_REQUEST && process.env.BUILDKITE_PULL_REQUEST !== 'false' ? 'pull_request' : 'push',
      ciOrgIdentity: orgSlug ? `bk_org:${orgSlug.toLowerCase()}` : undefined,
      ciRepoIdentity: slug ? `bk:${slug.toLowerCase()}` : undefined,
      ciPipelineIdentity: slug ? `bk_pipe:${slug.toLowerCase()}` : undefined,
      ciRunNumber: Number.isFinite(runNum) && runNum > 0 ? runNum : undefined,
    };
  }
  if (process.env.CI === 'true' || process.env.CI === '1') {
    const runNum = parseInt(process.env.BUILD_NUMBER || process.env.CI_BUILD_NUMBER || '', 10);
    return {
      isCi: true,
      ciProvider: 'generic-ci',
      isContainerized,
      runnerType: isContainerized ? 'self-hosted-enterprise' : 'cloud-hosted-ci',
      triggerEvent: 'ci_pipeline',
      ciOrgIdentity: gitOrg ? `ci_org:${gitOrg}` : undefined,
      ciRepoIdentity: gitRemote ? `ci:${gitRemote}` : undefined,
      ciPipelineIdentity: gitRemote ? `ci_pipe:${gitRemote}` : undefined,
      ciRunNumber: Number.isFinite(runNum) && runNum > 0 ? runNum : undefined,
    };
  }
  return {
    isCi: false,
    ciProvider: 'local-terminal',
    isContainerized,
    runnerType: 'local-workstation',
    triggerEvent: 'interactive_cli',
    ciOrgIdentity: gitOrg ? `local_org:${gitOrg}` : undefined,
    ciRepoIdentity: gitRemote ? `local_repo:${gitRemote}` : undefined,
    ciPipelineIdentity: gitRemote ? `local_cli:${gitRemote}` : undefined,
  };
}

export function getOrCreateCliState(customHomeDir?: string, cwd: string = process.cwd()): { state: CliLocalState; statePath: string } {
  const home = customHomeDir || process.env.HOME || os.homedir();
  const dir = path.join(home, '.toolveto');
  const statePath = path.join(dir, 'cli-state.json');

  try {
    if (fs.existsSync(statePath)) {
      const parsed = JSON.parse(fs.readFileSync(statePath, 'utf-8'));
      if (parsed && typeof parsed.installId === 'string') {
        return {
          state: {
            installId: parsed.installId,
            totalRuns: typeof parsed.totalRuns === 'number' ? parsed.totalRuns : 0,
            lastRunAt: parsed.lastRunAt,
            lastVersionCheckAt: parsed.lastVersionCheckAt,
            latestKnownVersion: parsed.latestKnownVersion,
            latestReleaseNotes: parsed.latestReleaseNotes,
          },
          statePath,
        };
      }
    }
  } catch {
    // Fallback to generating or deriving state
  }

  // In ephemeral CI containers or Docker runs where ~/.toolveto/cli-state.json is wiped every job,
  // derive a deterministic, privacy-preserving installId from CI repository metadata or git remote origin
  // so 500 CI runs of the same repo don't look like 500 fake "unique installs".
  const ci = detectCiProvider(cwd);
  const gitRemote = resolveGitRemoteIdentity(cwd);
  let deterministicSeed: string | undefined;

  if (ci.isCi && ci.ciRepoIdentity) {
    deterministicSeed = `ci_repo:${ci.ciRepoIdentity}`;
  } else if (ci.isCi && gitRemote) {
    deterministicSeed = `ci_git:${gitRemote}`;
  }

  const installId = deterministicSeed
    ? `tv_ci_${crypto.createHash('sha256').update(deterministicSeed).digest('hex').slice(0, 16)}`
    : `tv_cli_${crypto.randomBytes(8).toString('hex')}`;

  const freshState: CliLocalState = {
    installId,
    totalRuns: ci.ciRunNumber ? ci.ciRunNumber - 1 : 0,
  };

  try {
    if (!fs.existsSync(dir)) {
      fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
    }
    fs.writeFileSync(statePath, JSON.stringify(freshState, null, 2), { mode: 0o600 });
  } catch {
    // Best-effort persistence (e.g., read-only container filesystem)
  }

  return { state: freshState, statePath };
}

export function saveCliState(state: CliLocalState, statePath: string): void {
  try {
    const dir = path.dirname(statePath);
    if (!fs.existsSync(dir)) {
      fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
    }
    fs.writeFileSync(statePath, JSON.stringify(state, null, 2), { mode: 0o600 });
  } catch {
    // Best-effort persistence
  }
}

export function compareSemver(current: string, latest: string): number {
  const clean = (v: string) => v.replace(/^v/i, '').split('-')[0].split('.').map((n) => parseInt(n, 10) || 0);
  const [cMaj = 0, cMin = 0, cPat = 0] = clean(current);
  const [lMaj = 0, lMin = 0, lPat = 0] = clean(latest);
  if (lMaj !== cMaj) return lMaj > cMaj ? 1 : -1;
  if (lMin !== cMin) return lMin > cMin ? 1 : -1;
  if (lPat !== cPat) return lPat > cPat ? 1 : -1;
  return 0;
}

/**
 * Formats a Trivy / Grype style CLI version update & PLG upgrade notice.
 * Printed to stderr so stdout (`--json` or piped output) is never polluted.
 */
export function formatTrivyStyleNotice(params: {
  currentVersion: string;
  latestVersion?: string;
  latestCorpusVersion?: string;
  summary: SuiteSummary;
  authenticated: boolean;
  runNumber: number;
}): string {
  const lines: string[] = [];
  const hasNewerBinary =
    params.latestVersion && compareSemver(params.currentVersion, params.latestVersion) > 0;

  const failedResults = params.summary.results.filter((r) => r.status === 'FAIL');
  const criticalCount = failedResults.filter((r) => r.severity === 'CRITICAL' || r.severity === 'HIGH').length;

  lines.push('');
  lines.push('┌──────────────────────────────────────────────────────────────────────────────┐');

  // 1. Trivy / Grype Binary & Corpus Update Checker Notice
  if (hasNewerBinary) {
    lines.push(
      `│ 🔔 Notice: A new ToolVeto CLI release is available: v${params.currentVersion} → v${params.latestVersion}`.padEnd(79) + '│'
    );
    lines.push(
      `│    Upgrade command: npm i -g toolveto@latest  (or npx toolveto@latest check)`.padEnd(79) + '│'
    );
    if (params.latestCorpusVersion) {
      lines.push(
        `│    Corpus DB:       Sealed Corpus ${params.latestCorpusVersion} (adds new MCP rug-pull signatures)`.padEnd(79) + '│'
      );
    }
    lines.push('├──────────────────────────────────────────────────────────────────────────────┤');
  }

  // 2. PLG Tier Contextual Nudge (Free OSS -> Team CI / Shield Runtime)
  if (!params.authenticated) {
    if (criticalCount > 0 || params.summary.fatalVetoTriggered) {
      lines.push(
        `│ 🛡️  PLG Security Advisory: ${criticalCount} high/critical agent wreck vector(s) detected.`.padEnd(79) + '│'
      );
      lines.push(
        `│    • Local CLI evaluated the 40% public corpus (Run #${params.runNumber}).`.padEnd(79) + '│'
      );
      lines.push(
        `│    • Unlock the 60% Sealed Honeytrap Corpus, GitHub PR Fix Bot & <1.8ms      │`
      );
      lines.push(
        `│      @toolveto/shield runtime airbag for 10 3rd-party MCP servers:           │`
      );
      lines.push(
        `│      👉 https://toolveto.ai/pricing?utm_source=npx_toolveto&utm_medium=cli   │`
      );
    } else {
      lines.push(
        `│ ✨ Passed local public corpus (Score: ${params.summary.score}/100 • Run #${params.runNumber}).`.padEnd(79) + '│'
      );
      lines.push(
        `│    Automate this gate in GitHub PRs + unlock the 60% Sealed Honeytrap Corpus:│`
      );
      lines.push(
        `│    👉 Run \`toolveto login\` or visit https://toolveto.ai/pricing?utm_source=cli│`
      );
    }
  }

  lines.push('└──────────────────────────────────────────────────────────────────────────────┘');
  lines.push('  (Disable telemetry/update checks anytime with DO_NOT_TRACK=1 or --skip-update-check)');
  return lines.join('\n');
}

/**
 * Executes non-blocking anonymous PLG telemetry upload + Trivy/Grype-style version check.
 * Guaranteed never to throw or fail a user's CLI command.
 */
export async function runPlgTelemetryAndUpdateCheck(params: {
  summary: SuiteSummary;
  target: string;
  durationMs: number;
  options?: {
    json?: boolean;
    format?: string;
    noTelemetry?: boolean;
    skipUpdateCheck?: boolean;
    customHomeDir?: string;
    apiUrl?: string;
  };
}): Promise<{
  telemetrySent: boolean;
  updateAvailable: boolean;
  latestVersion?: string;
  noticeText?: string;
  payload?: CliCheckPayload;
}> {
  const { state, statePath } = getOrCreateCliState(params.options?.customHomeDir);
  state.totalRuns += 1;
  state.lastRunAt = Date.now();

  const apiUrl = (
    params.options?.apiUrl ||
    process.env.TOOLVETO_API_URL ||
    DEFAULT_CLOUD_API_URL
  ).replace(/\/+$/, '');

  // Check if user is authenticated via env or ~/.toolveto/config.json
  const home = params.options?.customHomeDir || process.env.HOME || os.homedir();
  const configPath = path.join(home, '.toolveto', 'config.json');
  const authenticated = Boolean(process.env.TOOLVETO_TOKEN || fs.existsSync(configPath));

  const ciInfo = detectCiProvider();
  const gitRemote = resolveGitRemoteIdentity();
  const canonicalTarget = ciInfo.ciRepoIdentity || gitRemote || path.resolve(params.target || '.');
  const targetHash = `sha256_${crypto.createHash('sha256').update(canonicalTarget).digest('hex').slice(0, 16)}`;
  const orgSeed = ciInfo.ciOrgIdentity || extractOrgFromRemote(gitRemote) || `org_fallback:${state.installId}`;
  const orgHash = `org_${crypto.createHash('sha256').update(orgSeed).digest('hex').slice(0, 14)}`;
  const pipelineSeed = ciInfo.ciPipelineIdentity || canonicalTarget;
  const pipelineHash = `pipe_${crypto.createHash('sha256').update(pipelineSeed).digest('hex').slice(0, 14)}`;

  const failedResults = params.summary.results.filter((r) => r.status === 'FAIL');
  const passedCount = params.summary.results.filter((r) => r.status === 'PASS').length;
  const warnedCount = params.summary.results.filter((r) => r.status === 'WARN').length;
  const criticalFailures = failedResults.filter(
    (r) => r.severity === 'CRITICAL' || r.severity === 'HIGH'
  ).length;

  const uniqueTools = new Set(params.summary.results.map((r) => r.tool).filter(Boolean));
  const mutationTools = new Set(
    params.summary.results
      .filter((r) => r.checkId.startsWith('TC-IDEMP') || r.checkId.startsWith('TC-PAIR') || r.checkId.startsWith('TC-ELICIT'))
      .map((r) => r.tool)
      .filter(Boolean)
  );
  const fatalVetoCodes = Array.isArray((params.summary as any).fatalVetoes)
    ? (params.summary as any).fatalVetoes.map(String)
    : params.summary.fatalVetoTriggered
    ? ['VETO_CRITICAL']
    : [];

  const payload: CliCheckPayload = {
    installId: state.installId,
    cliVersion: CLI_VERSION,
    command: 'check',
    osPlatform: process.platform,
    osArch: process.arch,
    nodeVersion: process.version,
    isCi: ciInfo.isCi,
    ciProvider: ciInfo.ciProvider,
    isContainerized: ciInfo.isContainerized,
    runnerType: ciInfo.runnerType,
    triggerEvent: ciInfo.triggerEvent,
    orgHash,
    pipelineHash,
    authenticated,
    targetHash,
    runNumber: state.totalRuns,
    score: params.summary.score,
    tier: params.summary.tier,
    fatalVetoTriggered: Boolean(params.summary.fatalVetoTriggered),
    fatalVetoCodes,
    toolsEvaluatedCount: Math.max(1, uniqueTools.size),
    mutationToolsCount: mutationTools.size,
    totalChecks: params.summary.results.length,
    passedChecks: passedCount,
    failedChecks: failedResults.length,
    warnedChecks: warnedCount,
    criticalFailures,
    failedCheckIds: failedResults.map((r) => r.checkId).slice(0, 15),
    durationMs: Math.max(1, Math.round(params.durationMs)),
  };

  let telemetrySent = false;
  let latestVersion = state.latestKnownVersion;
  let latestCorpusVersion = 'v1.1';

  // 1. Send anonymous CLI run stats if not opted out
  if (!isTelemetryDisabled(params.options)) {
    try {
      const res = await fetch(`${apiUrl}/api/v1/cli/telemetry`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload),
        signal: AbortSignal.timeout(1200),
      });
      if (res.ok) {
        telemetrySent = true;
        const data = (await res.json().catch(() => ({}))) as any;
        if (data.latestVersion) {
          latestVersion = String(data.latestVersion);
          state.latestKnownVersion = latestVersion;
          state.lastVersionCheckAt = Date.now();
        }
        if (data.latestCorpusVersion) {
          latestCorpusVersion = String(data.latestCorpusVersion);
        }
        if (typeof data.runNumber === 'number' && data.runNumber > state.totalRuns) {
          state.totalRuns = data.runNumber;
          payload.runNumber = data.runNumber;
        }
      }
    } catch {
      // Silently ignore offline/network errors
    }
  }

  // 2. Trivy / Grype style Version Check (throttled to once every 24h unless telemetry already returned it)
  const twentyFourHoursMs = 24 * 60 * 60 * 1000;
  const needsVersionCheck =
    !state.lastVersionCheckAt || Date.now() - state.lastVersionCheckAt > twentyFourHoursMs;

  if (!isUpdateCheckDisabled(params.options) && (!latestVersion || needsVersionCheck)) {
    try {
      const res = await fetch(`${apiUrl}/api/v1/cli/version-check?current=${encodeURIComponent(CLI_VERSION)}`, {
        method: 'GET',
        signal: AbortSignal.timeout(1200),
      });
      if (res.ok) {
        const vData = (await res.json()) as VersionCheckResponse;
        if (vData.latestVersion) {
          latestVersion = vData.latestVersion;
          state.latestKnownVersion = latestVersion;
          state.lastVersionCheckAt = Date.now();
        }
        if (vData.latestCorpusVersion) {
          latestCorpusVersion = vData.latestCorpusVersion;
        }
      }
    } catch {
      // Silently ignore offline/network errors
    }
  }

  saveCliState(state, statePath);

  const updateAvailable = Boolean(latestVersion && compareSemver(CLI_VERSION, latestVersion) > 0);
  let noticeText: string | undefined;

  if (!isUpdateCheckDisabled(params.options)) {
    noticeText = formatTrivyStyleNotice({
      currentVersion: CLI_VERSION,
      latestVersion,
      latestCorpusVersion,
      summary: params.summary,
      authenticated,
      runNumber: state.totalRuns,
    });
    console.error(noticeText);
  }

  return {
    telemetrySent,
    updateAvailable,
    latestVersion,
    noticeText,
    payload,
  };
}
