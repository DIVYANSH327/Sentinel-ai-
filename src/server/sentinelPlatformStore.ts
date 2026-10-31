import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import {
  OperatorUser,
  AuthorizedAsset,
  ScopePolicy,
  AssessmentPlan,
  SecurityJob,
  SecurityFinding,
  RemediationItem,
  PollingAgentRecord,
  DeviceEnrollmentCode,
  PlatformAuditLog,
  issueDeviceEnrollmentCode,
} from '../lib/policyEngine';
import { sha256Hex, sanitizeText } from '../lib/sentinelEngine';

export interface SentinelPlatformState {
  schemaVersion: number;
  operators: Array<OperatorUser & { passwordHash: string }>;
  activeSessions: Record<string, { operator: OperatorUser; issuedAt: string }>;
  assets: AuthorizedAsset[];
  policies: ScopePolicy[];
  plans: AssessmentPlan[];
  jobs: SecurityJob[];
  findings: SecurityFinding[];
  remediations: RemediationItem[];
  enrollmentCodes: DeviceEnrollmentCode[];
  agents: PollingAgentRecord[];
  auditLogs: PlatformAuditLog[];
  integrationStatus: {
    databasePersisted: boolean;
    geminiTestedLive: boolean;
    kaliAgentPolledLive: boolean;
    lastTestedAt: string;
  };
}

const DATA_DIR = path.resolve(process.cwd(), process.env.SENTINEL_DATA_DIR || 'data');
const PLATFORM_DB_FILE = path.join(DATA_DIR, 'sentinel-platform-db.json');
const AGENT_VAULT_FILE = path.join(DATA_DIR, 'sentinel-polling-vault.json');

function ensureDataDir(): void {
  if (!fs.existsSync(DATA_DIR)) {
    fs.mkdirSync(DATA_DIR, { recursive: true, mode: 0o700 });
  }
}

export function createSeedPlatformState(): SentinelPlatformState {
  const now = new Date();
  const in90Days = new Date(now.getTime() + 90 * 86400_000).toISOString();
  const in2Hours = new Date(now.getTime() + 2 * 3600_000).toISOString();
  const tenMinsAgo = new Date(now.getTime() - 10 * 60_000).toISOString();

  const defaultAgentToken = 'stnl_agent_default_kali_poll_token_9f8e7d6c5b4a';
  savePollingAgentVaultToken('agt-kali-01', defaultAgentToken);

  return {
    schemaVersion: 2,
    operators: [
      {
        id: 'op-01',
        email: 'neha.raut@sentinel.research.internal',
        displayName: 'Neha Raut',
        role: 'lead_researcher',
        passwordHash: sha256Hex('sentinel-lead-2026'),
      },
      {
        id: 'op-02',
        email: 'marcus.chen@sentinel.research.internal',
        displayName: 'Marcus Chen',
        role: 'security_reviewer',
        passwordHash: sha256Hex('sentinel-reviewer-2026'),
      },
      {
        id: 'op-03',
        email: 'elena.rostova@sentinel.research.internal',
        displayName: 'Elena Rostova',
        role: 'auditor',
        passwordHash: sha256Hex('sentinel-auditor-2026'),
      },
    ],
    activeSessions: {
      'default-operator-session': {
        operator: {
          id: 'op-01',
          email: 'neha.raut@sentinel.research.internal',
          displayName: 'Neha Raut',
          role: 'lead_researcher',
        },
        issuedAt: now.toISOString(),
      },
    },
    assets: [
      {
        id: 'ast-101',
        name: 'Sentinel Auth Gateway (Staging)',
        targetHost: 'auth.staging.sentinel.internal',
        ipOrCidr: '10.24.0.15',
        environment: 'staging',
        ownerTeam: 'Identity & Access Engineering',
        authorizationRef: 'AUTH-2026-9012',
        verified: true,
        verifiedBy: 'Neha Raut',
        expiresAt: in90Days,
        createdAt: tenMinsAgo,
      },
      {
        id: 'ast-102',
        name: 'Telemetry Ingestion API (Isolated Lab)',
        targetHost: 'ingest.lab.sentinel.internal',
        ipOrCidr: '10.24.0.28',
        environment: 'isolated_lab',
        ownerTeam: 'Core Platform Team',
        authorizationRef: 'AUTH-2026-9015',
        verified: true,
        verifiedBy: 'Marcus Chen',
        expiresAt: in90Days,
        createdAt: tenMinsAgo,
      },
      {
        id: 'ast-103',
        name: 'Partner Billing Webhook Service (Pending Verification)',
        targetHost: 'billing.staging.sentinel.internal',
        ipOrCidr: '10.24.0.44',
        environment: 'staging',
        ownerTeam: 'Payments Infrastructure',
        authorizationRef: 'AUTH-2026-9040',
        verified: false,
        verifiedBy: null,
        expiresAt: in90Days,
        createdAt: tenMinsAgo,
      },
    ],
    policies: [
      {
        id: 'pol-201',
        name: 'Staging Identity Passive & SAST Policy',
        authorizationRef: 'AUTH-2026-9012',
        permittedHosts: ['auth.staging.sentinel.internal', '*.staging.sentinel.internal'],
        permittedCidrs: ['10.24.0.0/24'],
        allowedCategories: ['passive_http_headers', 'static_code_analysis', 'intrusive_review_only'],
        maxRateLimitRpm: 30,
        requireHumanApprovalForIntrusive: true,
        expiresAt: in90Days,
        active: true,
        createdAt: tenMinsAgo,
      },
      {
        id: 'pol-202',
        name: 'Isolated Lab Telemetry Policy',
        authorizationRef: 'AUTH-2026-9015',
        permittedHosts: ['ingest.lab.sentinel.internal', '*.lab.sentinel.internal'],
        permittedCidrs: ['10.24.0.0/24', '192.168.56.0/24'],
        allowedCategories: ['passive_http_headers', 'static_code_analysis'],
        maxRateLimitRpm: 45,
        requireHumanApprovalForIntrusive: true,
        expiresAt: in90Days,
        active: true,
        createdAt: tenMinsAgo,
      },
    ],
    plans: [
      {
        id: 'pln-301',
        title: 'Staging Auth Gateway Header & SAST Verification Plan',
        objective:
          'Verify HTTP transport security headers on auth.staging.sentinel.internal and audit token validation source code for injection or secret exposure.',
        assetId: 'ast-101',
        policyId: 'pol-201',
        generatedBySource: 'deterministic_fallback',
        modelName: 'policy-structured-planner-v1',
        safetyAttestation:
          'Validated against AUTH-2026-9012. Contains only structured JSON steps for passive_http_headers and static_code_analysis; zero shell commands.',
        createdBy: 'Neha Raut',
        createdAt: tenMinsAgo,
        steps: [
          {
            stepNumber: 1,
            title: 'Passive HTTP Security-Header Inspection on auth.staging.sentinel.internal',
            category: 'passive_http_headers',
            targetHost: 'auth.staging.sentinel.internal',
            rationale:
              'Verify Strict-Transport-Security, Content-Security-Policy, X-Content-Type-Options, and X-Frame-Options headers within 15 req/min rate limit.',
            safeToolConfig: {
              toolName: 'passive_header_inspector',
              inspectedControls: [
                'Strict-Transport-Security',
                'Content-Security-Policy',
                'X-Content-Type-Options',
                'X-Frame-Options',
              ],
              rateLimitRpm: 15,
            },
            requiresHumanApproval: false,
          },
          {
            stepNumber: 2,
            title: 'Safe Static Analysis of OAuth Callback Handler Snippet',
            category: 'static_code_analysis',
            targetHost: 'auth.staging.sentinel.internal',
            rationale:
              'Scan user-supplied TypeScript handler code for CWE-78 command execution sinks, CWE-798 hardcoded secrets, and CWE-89 SQL concatenation.',
            safeToolConfig: {
              toolName: 'static_ast_pattern_scanner',
              inspectedControls: ['CWE-78 OS Command Injection', 'CWE-798 Hardcoded Secrets', 'CWE-89 SQL Injection'],
              rateLimitRpm: 15,
            },
            requiresHumanApproval: false,
          },
        ],
      },
    ],
    jobs: [
      {
        id: 'job-401',
        assetId: 'ast-101',
        policyId: 'pol-201',
        category: 'passive_http_headers',
        targetHost: 'auth.staging.sentinel.internal',
        rateLimitRpm: 15,
        status: 'completed',
        requiresApproval: false,
        approvedBy: null,
        approvedAt: null,
        claimedByAgentId: 'agt-kali-01',
        idempotencyClaimKey: 'claim-seed-401-alpha',
        claimedAt: tenMinsAgo,
        expiresAt: in2Hours,
        resultSummary: {
          checkedItems: 6,
          findingsCount: 2,
          summaryText: 'Passive header check completed: missing HSTS and CSP headers detected.',
          headersInspected: {
            'content-type': 'application/json; charset=utf-8',
            'x-frame-options': 'DENY',
            'x-content-type-options': 'nosniff',
          },
        },
        completedAt: tenMinsAgo,
        createdBy: 'Neha Raut',
        createdAt: tenMinsAgo,
      },
      {
        id: 'job-402',
        assetId: 'ast-102',
        policyId: 'pol-202',
        category: 'passive_http_headers',
        targetHost: 'ingest.lab.sentinel.internal',
        rateLimitRpm: 20,
        status: 'queued',
        requiresApproval: false,
        approvedBy: null,
        approvedAt: null,
        claimedByAgentId: null,
        idempotencyClaimKey: null,
        claimedAt: null,
        expiresAt: in2Hours,
        resultSummary: null,
        completedAt: null,
        createdBy: 'Neha Raut',
        createdAt: now.toISOString(),
      },
      {
        id: 'job-403',
        assetId: 'ast-101',
        policyId: 'pol-201',
        category: 'intrusive_review_only',
        targetHost: 'auth.staging.sentinel.internal',
        rateLimitRpm: 10,
        status: 'pending_approval',
        requiresApproval: true,
        approvedBy: null,
        approvedAt: null,
        claimedByAgentId: null,
        idempotencyClaimKey: null,
        claimedAt: null,
        expiresAt: in2Hours,
        resultSummary: null,
        completedAt: null,
        createdBy: 'Neha Raut',
        createdAt: now.toISOString(),
      },
    ],
    findings: [
      {
        id: 'fnd-501',
        jobId: 'job-401',
        assetId: 'ast-101',
        targetHost: 'auth.staging.sentinel.internal',
        title: 'Missing HTTP Strict-Transport-Security (HSTS) Header',
        severity: 'medium',
        category: 'passive_http_headers',
        cweId: 'CWE-319',
        description:
          'Passive HTTP response inspection confirmed that auth.staging.sentinel.internal does not return a Strict-Transport-Security header.',
        evidence: 'GET https://auth.staging.sentinel.internal/ -> Strict-Transport-Security header absent',
        status: 'remediation_planned',
        discoveredAt: tenMinsAgo,
      },
      {
        id: 'fnd-502',
        jobId: 'job-401',
        assetId: 'ast-101',
        targetHost: 'auth.staging.sentinel.internal',
        title: 'Hardcoded Service API Key in Legacy Token Verifier (tokenVerifier.ts)',
        severity: 'high',
        category: 'static_code_analysis',
        cweId: 'CWE-798',
        description:
          'Static AST/pattern scanner detected a hardcoded credential literal assigned to fallbackSecret in tokenVerifier.ts.',
        evidence: 'Matched pattern in tokenVerifier.ts: secret = "stnl_fallback_998877665544"',
        status: 'remediation_planned',
        discoveredAt: tenMinsAgo,
      },
    ],
    remediations: [
      {
        id: 'rem-601',
        findingId: 'fnd-501',
        findingTitle: 'Missing HTTP Strict-Transport-Security (HSTS) Header',
        targetHost: 'auth.staging.sentinel.internal',
        title: 'Enforce Strict-Transport-Security Header on Staging Auth Gateway',
        proposedFix:
          'Add Strict-Transport-Security header with max-age=31536000; includeSubDomains in reverse proxy response headers.',
        configOrCodeDiff: `+ Strict-Transport-Security: max-age=31536000; includeSubDomains`,
        requiresHumanApproval: true,
        approvalStatus: 'pending_approval',
        approvedBy: null,
        approvalNote: null,
        approvedAt: null,
        createdAt: tenMinsAgo,
      },
      {
        id: 'rem-602',
        findingId: 'fnd-502',
        findingTitle: 'Hardcoded Service API Key in Legacy Token Verifier (tokenVerifier.ts)',
        targetHost: 'auth.staging.sentinel.internal',
        title: 'Replace Hardcoded Secret with Server Environment Variable',
        proposedFix:
          'Remove hardcoded string literal and read process.env.AUTH_VERIFIER_SECRET with fail-closed startup validation.',
        configOrCodeDiff: `- const secret = "stnl_fallback_998877665544";\n+ const secret = process.env.AUTH_VERIFIER_SECRET;`,
        requiresHumanApproval: true,
        approvalStatus: 'approved',
        approvedBy: 'Marcus Chen',
        approvalNote: 'Verified PR #418 in staging repository; no live system auto-modification performed.',
        approvedAt: tenMinsAgo,
        createdAt: tenMinsAgo,
      },
    ],
    enrollmentCodes: [
      issueDeviceEnrollmentCode({
        targetHostname: 'kali-field-usb02',
        linuxUser: 'kali',
        issuedBy: 'Neha Raut',
        ttlMinutes: 15,
        now,
      }).record,
    ],
    agents: [
      {
        id: 'agt-kali-01',
        hostname: 'kali-research-usb01',
        linuxUser: 'kali',
        uid: 1000,
        version: '2.1.0',
        osInfo: 'Kali GNU/Linux Rolling 2026.1 (x86_64)',
        serviceAccount: 'kali',
        systemdAutostartEnabled: true,
        credentialFingerprint: `stnl_agent_••••${defaultAgentToken.slice(-6)}`,
        credentialHash: sha256Hex(defaultAgentToken),
        pollingMode: 'outbound_https_poll',
        // Never displayed as online until an authenticated heartbeat/poll is received
        status: 'waiting_poll',
        heartbeatVerifiedLive: false,
        currentJobId: null,
        currentJobStatus: 'idle',
        lastHeartbeatAt: null,
        lastPollAt: tenMinsAgo,
        claimedJobsCount: 1,
        completedJobsCount: 1,
        enrolledAt: tenMinsAgo,
        revokedAt: null,
        uninstalledAt: null,
      },
    ],
    auditLogs: [
      {
        id: 'aud-701',
        timestamp: tenMinsAgo,
        actor: 'Neha Raut (lead_researcher)',
        action: 'POLICY_VERIFIED_JOB_COMPLETED',
        resourceType: 'job',
        resourceId: 'job-401',
        decision: 'allowed',
        summary: 'Completed passive_http_headers check on auth.staging.sentinel.internal under authorization AUTH-2026-9012.',
        metadata: { authorizationRef: 'AUTH-2026-9012', rateLimitRpm: 15, findingsCount: 2 },
      },
      {
        id: 'aud-702',
        timestamp: now.toISOString(),
        actor: 'Neha Raut (lead_researcher)',
        action: 'JOB_HELD_FOR_HUMAN_APPROVAL',
        resourceType: 'job',
        resourceId: 'job-403',
        decision: 'approval_required',
        summary: 'Held intrusive_review_only job on auth.staging.sentinel.internal pending human security reviewer approval.',
        metadata: { authorizationRef: 'AUTH-2026-9012', category: 'intrusive_review_only' },
      },
    ],
    integrationStatus: {
      databasePersisted: true,
      geminiTestedLive: false,
      kaliAgentPolledLive: false,
      lastTestedAt: now.toISOString(),
    },
  };
}

export function loadPlatformState(): SentinelPlatformState {
  ensureDataDir();
  if (!fs.existsSync(PLATFORM_DB_FILE)) {
    const seed = createSeedPlatformState();
    savePlatformState(seed);
    return seed;
  }
  try {
    const raw = fs.readFileSync(PLATFORM_DB_FILE, 'utf8');
    const parsed = JSON.parse(raw) as SentinelPlatformState;
    if (!Array.isArray(parsed.enrollmentCodes)) {
      parsed.enrollmentCodes = [];
    }
    return parsed;
  } catch {
    const seed = createSeedPlatformState();
    savePlatformState(seed);
    return seed;
  }
}

export function savePlatformState(state: SentinelPlatformState): void {
  ensureDataDir();
  state.integrationStatus.databasePersisted = true;
  const tmp = `${PLATFORM_DB_FILE}.tmp`;
  fs.writeFileSync(tmp, JSON.stringify(state, null, 2), { encoding: 'utf8', mode: 0o600 });
  fs.renameSync(tmp, PLATFORM_DB_FILE);
}

export function savePollingAgentVaultToken(agentId: string, tokenPlaintext: string): void {
  ensureDataDir();
  let vault: Record<string, string> = {};
  if (fs.existsSync(AGENT_VAULT_FILE)) {
    try {
      vault = JSON.parse(fs.readFileSync(AGENT_VAULT_FILE, 'utf8')) as Record<string, string>;
    } catch {
      vault = {};
    }
  }
  vault[agentId] = tokenPlaintext;
  fs.writeFileSync(AGENT_VAULT_FILE, JSON.stringify(vault, null, 2), { encoding: 'utf8', mode: 0o600 });
}

export function getPollingAgentVaultToken(agentId: string): string | null {
  if (!fs.existsSync(AGENT_VAULT_FILE)) return null;
  try {
    const vault = JSON.parse(fs.readFileSync(AGENT_VAULT_FILE, 'utf8')) as Record<string, string>;
    return vault[agentId] || null;
  } catch {
    return null;
  }
}

export function appendAuditLog(
  state: SentinelPlatformState,
  entry: Omit<PlatformAuditLog, 'id' | 'timestamp'>
): PlatformAuditLog {
  const record: PlatformAuditLog = {
    id: `aud-${crypto.randomBytes(4).toString('hex')}`,
    timestamp: new Date().toISOString(),
    actor: entry.actor,
    action: entry.action,
    resourceType: entry.resourceType,
    resourceId: entry.resourceId,
    decision: entry.decision,
    summary: sanitizeText(entry.summary),
    metadata: entry.metadata,
  };
  state.auditLogs.unshift(record);
  return record;
}

export function toSanitizedBootstrapPayload(state: SentinelPlatformState, sessionToken = 'default-operator-session') {
  const session = state.activeSessions[sessionToken] || Object.values(state.activeSessions)[0] || null;
  const hasConfiguredGeminiSecret = Boolean(
    process.env.GEMINI_API_KEY &&
      process.env.GEMINI_API_KEY !== 'MY_GEMINI_API_KEY' &&
      process.env.GEMINI_API_KEY.trim().length > 10
  );

  return {
    currentOperator: session ? session.operator : null,
    availableOperators: state.operators.map((o) => ({
      id: o.id,
      email: o.email,
      displayName: o.displayName,
      role: o.role,
    })),
    assets: state.assets,
    policies: state.policies,
    plans: state.plans,
    jobs: state.jobs,
    findings: state.findings,
    remediations: state.remediations,
    enrollmentCodes: (state.enrollmentCodes || []).map((c) => ({
      id: c.id,
      codePreview: c.codePreview,
      targetHostname: c.targetHostname,
      linuxUser: c.linuxUser,
      issuedBy: c.issuedBy,
      issuedAt: c.issuedAt,
      expiresAt: c.expiresAt,
      consumedAt: c.consumedAt,
      consumedByAgentId: c.consumedByAgentId,
      status: c.status,
    })),
    agents: state.agents.map((a) => ({
      id: a.id,
      hostname: a.hostname,
      linuxUser: a.linuxUser,
      uid: a.uid,
      version: a.version,
      osInfo: a.osInfo || 'Kali GNU/Linux Rolling 2026.1 (x86_64)',
      serviceAccount: a.serviceAccount || a.linuxUser,
      systemdAutostartEnabled: a.systemdAutostartEnabled ?? true,
      credentialFingerprint: a.credentialFingerprint,
      pollingMode: a.pollingMode,
      status: a.status,
      heartbeatVerifiedLive: Boolean(a.heartbeatVerifiedLive),
      currentJobId: a.currentJobId || null,
      currentJobStatus: a.currentJobStatus || 'idle',
      lastHeartbeatAt: a.lastHeartbeatAt,
      lastPollAt: a.lastPollAt,
      claimedJobsCount: a.claimedJobsCount,
      completedJobsCount: a.completedJobsCount,
      enrolledAt: a.enrolledAt,
      revokedAt: a.revokedAt || null,
      uninstalledAt: a.uninstalledAt || null,
    })),
    auditLogs: state.auditLogs.slice(0, 60),
    integrationStatus: {
      ...state.integrationStatus,
      geminiSecretConfigured: hasConfiguredGeminiSecret,
    },
  };
}
