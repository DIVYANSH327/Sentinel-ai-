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
} from '../lib/policyEngine';

export type PlatformTabId =
  | 'overview'
  | 'agent-setup'
  | 'authorized-assets'
  | 'scope-policies'
  | 'assessment-plans'
  | 'job-queue'
  | 'findings'
  | 'remediation'
  | 'agent-health'
  | 'audit-logs';

export type SanitizedEnrollmentCode = Omit<DeviceEnrollmentCode, 'codeHash'>;
export type SanitizedAgentRecord = Omit<PollingAgentRecord, 'credentialHash'>;

export interface PlatformBootstrapPayload {
  currentOperator: OperatorUser | null;
  availableOperators: OperatorUser[];
  assets: AuthorizedAsset[];
  policies: ScopePolicy[];
  plans: AssessmentPlan[];
  jobs: SecurityJob[];
  findings: SecurityFinding[];
  remediations: RemediationItem[];
  enrollmentCodes?: SanitizedEnrollmentCode[];
  agents: SanitizedAgentRecord[];
  auditLogs: PlatformAuditLog[];
  integrationStatus: {
    databasePersisted: boolean;
    geminiTestedLive: boolean;
    geminiSecretConfigured: boolean;
    kaliAgentPolledLive: boolean;
    lastTestedAt: string;
  };
}

export function buildClientMockBootstrap(): PlatformBootstrapPayload {
  const nowIso = new Date().toISOString();
  const in90Days = new Date(Date.now() + 90 * 86400_000).toISOString();
  const in2Hours = new Date(Date.now() + 2 * 3600_000).toISOString();
  const in10Mins = new Date(Date.now() + 10 * 60_000).toISOString();

  return {
    currentOperator: {
      id: 'op-01',
      email: 'neha.raut@sentinel.research.internal',
      displayName: 'Neha Raut',
      role: 'lead_researcher',
    },
    availableOperators: [
      {
        id: 'op-01',
        email: 'neha.raut@sentinel.research.internal',
        displayName: 'Neha Raut',
        role: 'lead_researcher',
      },
      {
        id: 'op-02',
        email: 'marcus.chen@sentinel.research.internal',
        displayName: 'Marcus Chen',
        role: 'security_reviewer',
      },
      {
        id: 'op-03',
        email: 'elena.rostova@sentinel.research.internal',
        displayName: 'Elena Rostova',
        role: 'auditor',
      },
    ],
    assets: [
      {
        id: 'ast-mock-1',
        name: 'Sentinel Auth Gateway (Mock Demo)',
        targetHost: 'auth.staging.sentinel.internal',
        ipOrCidr: '10.24.0.15',
        environment: 'staging',
        ownerTeam: 'Identity Engineering',
        authorizationRef: 'AUTH-2026-9012',
        verified: true,
        verifiedBy: 'Neha Raut',
        expiresAt: in90Days,
        createdAt: nowIso,
      },
    ],
    policies: [
      {
        id: 'pol-mock-1',
        name: 'Staging Passive & SAST Policy (Mock Demo)',
        authorizationRef: 'AUTH-2026-9012',
        permittedHosts: ['auth.staging.sentinel.internal', '*.staging.sentinel.internal'],
        permittedCidrs: ['10.24.0.0/24'],
        allowedCategories: ['passive_http_headers', 'static_code_analysis', 'intrusive_review_only'],
        maxRateLimitRpm: 30,
        requireHumanApprovalForIntrusive: true,
        expiresAt: in90Days,
        active: true,
        createdAt: nowIso,
      },
    ],
    plans: [],
    jobs: [
      {
        id: 'job-mock-1',
        assetId: 'ast-mock-1',
        policyId: 'pol-mock-1',
        category: 'passive_http_headers',
        targetHost: 'auth.staging.sentinel.internal',
        rateLimitRpm: 15,
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
        createdAt: nowIso,
      },
    ],
    findings: [],
    remediations: [],
    enrollmentCodes: [
      {
        id: 'enr-mock-01',
        codePreview: 'STNL-ENROLL-8F2A••••',
        targetHostname: 'kali-field-usb01',
        linuxUser: 'kali',
        issuedBy: 'Neha Raut',
        issuedAt: nowIso,
        expiresAt: in10Mins,
        consumedAt: null,
        consumedByAgentId: null,
        status: 'active',
      },
    ],
    agents: [
      {
        id: 'agt-mock-1',
        hostname: 'kali-research-usb01',
        linuxUser: 'kali',
        uid: 1000,
        version: '2.1.0',
        osInfo: 'Kali GNU/Linux Rolling 2026.1 (x86_64)',
        serviceAccount: 'kali',
        systemdAutostartEnabled: true,
        credentialFingerprint: 'stnl_agent_••••4d91a0',
        pollingMode: 'outbound_https_poll',
        // Never displayed as online until an authenticated heartbeat is received
        status: 'waiting_poll',
        heartbeatVerifiedLive: false,
        currentJobId: null,
        currentJobStatus: 'idle',
        lastHeartbeatAt: null,
        lastPollAt: null,
        claimedJobsCount: 0,
        completedJobsCount: 0,
        enrolledAt: nowIso,
        revokedAt: null,
        uninstalledAt: null,
      },
    ],
    auditLogs: [
      {
        id: 'aud-mock-1',
        timestamp: nowIso,
        actor: 'system',
        action: 'MOCK_MODE_ACTIVE',
        resourceType: 'auth',
        resourceId: 'mock',
        decision: 'allowed',
        summary: 'Client-side Mock/Demo mode active. Agent remains in waiting_poll state until a heartbeat is verified.',
        metadata: {},
      },
    ],
    integrationStatus: {
      databasePersisted: false,
      geminiTestedLive: false,
      geminiSecretConfigured: false,
      kaliAgentPolledLive: false,
      lastTestedAt: nowIso,
    },
  };
}
