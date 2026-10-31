export type ConnectionStatus = 'Not configured' | 'Waiting for Kali' | 'Connected' | 'Error';

export type NavPageId = 'dashboard' | 'wizard' | 'agent-manager' | 'secure-config' | 'diagnostics';

export interface PredefinedOperationSpec {
  id: 'passive_port_inventory' | 'tls_cipher_audit' | 'intrusive_vuln_verification' | 'signed_patch_deployment';
  name: string;
  category: 'reconnaissance' | 'compliance' | 'intrusive_test' | 'patch_deployment';
  requiresHumanApproval: boolean;
  description: string;
  kaliScannerBinary: string;
  fixedArgumentsPreview: string;
}

export interface PublicEnrollmentSummary {
  id: string;
  label: string;
  codeHint: string;
  createdAt: string;
  expiresAt: string;
  usedAt?: string | null;
  usedByAgentId?: string | null;
  revoked?: boolean;
}

export interface PublicAgentSummary {
  id: string;
  hostname: string;
  linuxUser: string;
  uid: number;
  agentVersion: string;
  configFilePath: string;
  configFileMode: string;
  systemdUnitName: string;
  systemdUnitStatus: 'active (running)' | 'inactive (dead)' | 'failed' | 'activating';
  systemdEnabled: boolean;
  tokenFingerprint: string;
  tokenIssuedAt: string;
  tokenExpiresAt: string;
  tokenRotationCount: number;
  revoked: boolean;
  revokedReason: string | null;
  enrolledAt: string;
  lastHeartbeatAt: string | null;
  lastVerifiedIp: string;
  allowedTargets: string[];
}

export interface SanitizedLogEntry {
  id: string;
  timestamp: string;
  level: 'INFO' | 'WARN' | 'ERROR';
  source: 'sentinel-agent.service' | 'enrollment-authority' | 'policy-guard';
  message: string;
}

export interface AuditEvent {
  id: string;
  timestamp: string;
  actor: string;
  eventType: string;
  severity: 'info' | 'warning' | 'critical';
  summary: string;
  metadata: Record<string, string | number | boolean>;
}

export interface ScanJob {
  id: string;
  agentId: string;
  operationId: PredefinedOperationSpec['id'];
  operationName: string;
  target: string;
  requiresHumanApproval: boolean;
  status: 'queued' | 'pending_human_approval' | 'approved_dispatched' | 'completed' | 'rejected';
  createdAt: string;
  approvedBy: string | null;
  approverNote: string | null;
  approvedAt: string | null;
  rejectionReason: string | null;
}

export interface WizardChecklistState {
  step1WindowsUsbPrepared: boolean;
  step2PackageDownloaded: boolean;
  step3KaliUsbMounted: boolean;
  step4NonRootInstalled: boolean;
  step5BackendConfigured: boolean;
  step6SystemdVerified: boolean;
}

export interface ControlPlaneStatus {
  connectionStatus: ConnectionStatus;
  connectionReason: string;
  backendUrl: string;
  allowedTargets: string[];
  setupPackageVersion: string;
  activeAgent: PublicAgentSummary | null;
  pendingEnrollment: PublicEnrollmentSummary | null;
  enrollments: PublicEnrollmentSummary[];
  sanitizedLogs: SanitizedLogEntry[];
  auditEvents: AuditEvent[];
  scanJobs: ScanJob[];
  predefinedOperations: PredefinedOperationSpec[];
  wizardChecklist: WizardChecklistState;
  serverTimestamp: string;
}

export interface SetupPackageFile {
  path: string;
  description: string;
  mode: string;
  content: string;
  sha256: string;
  sizeBytes: number;
}

export interface SetupPackageManifest {
  version: string;
  archiveFilename: string;
  generatedAt: string;
  containsLiveSecrets: false;
  autorunIncluded: false;
  files: SetupPackageFile[];
  packageSha256: string;
}

export interface DiagnosticCheckResult {
  id: string;
  name: string;
  category: string;
  passed: boolean;
  expectedCode: string;
  actualCode: string;
  detail: string;
}

export interface DiagnosticSuiteResponse {
  ok: boolean;
  executedAt: string;
  isRealBackendTest: boolean;
  allPassed: boolean;
  passedCount: number;
  totalCount: number;
  checks: DiagnosticCheckResult[];
  targetScopeSampleCheck: {
    inScopeSample: string;
    inScopeResult: boolean;
    outOfScopeSample: string;
    outOfScopeResult: boolean;
  };
}

export function buildDemoModeStatus(
  overrideConnectionState: ConnectionStatus,
  baseStatus: ControlPlaneStatus | null,
  isDemo = true
): ControlPlaneStatus {
  const prefix = isDemo ? '[DEMO SIMULATION] ' : '';
  const nowIso = new Date().toISOString();
  const twoMinsAgo = new Date(Date.now() - 110_000).toISOString();
  const tenMinsAgo = new Date(Date.now() - 600_000).toISOString();
  const inTwelveMins = new Date(Date.now() + 720_000).toISOString();
  const inSevenDays = new Date(Date.now() + 7 * 86400_000).toISOString();

  const predefinedOperations: PredefinedOperationSpec[] = baseStatus?.predefinedOperations || [
    {
      id: 'passive_port_inventory',
      name: 'Baseline Service Port Inventory',
      category: 'reconnaissance',
      requiresHumanApproval: false,
      description: 'Non-intrusive TCP SYN/connect enumeration restricted to top 100 research lab ports.',
      kaliScannerBinary: '/usr/bin/nmap',
      fixedArgumentsPreview: 'nmap -sT --top-ports 100 -T3 --open <validated-target>',
    },
    {
      id: 'tls_cipher_audit',
      name: 'TLS 1.3 & Certificate Chain Audit',
      category: 'compliance',
      requiresHumanApproval: false,
      description: 'Read-only TLS handshake inspection verifying cipher suites and certificate expiration.',
      kaliScannerBinary: '/usr/bin/sslscan',
      fixedArgumentsPreview: 'sslscan --no-failed --tlsall <validated-target>:443',
    },
    {
      id: 'intrusive_vuln_verification',
      name: 'Intrusive CVE Proof-of-Concept Check',
      category: 'intrusive_test',
      requiresHumanApproval: true,
      description: 'Active payload verification against isolated lab service. Requires explicit human operator sign-off.',
      kaliScannerBinary: '/usr/bin/nuclei',
      fixedArgumentsPreview: 'nuclei -u <validated-target> -tags cve -rate-limit 15',
    },
    {
      id: 'signed_patch_deployment',
      name: 'Signed Security Advisory Patch Rollout',
      category: 'patch_deployment',
      requiresHumanApproval: true,
      description: 'Applies PGP-verified remediation bundle on approved lab target. Requires explicit human operator sign-off.',
      kaliScannerBinary: '/usr/local/lib/sentinel-agent/apply-signed-patch',
      fixedArgumentsPreview: 'apply-signed-patch --verify-sig --target <validated-target>',
    },
  ];

  const demoAgent: PublicAgentSummary | null =
    overrideConnectionState === 'Connected' || overrideConnectionState === 'Error'
      ? {
          id: 'agt-demo-94f1',
          hostname: 'kali-research-usb02',
          linuxUser: 'kali',
          uid: 1000,
          agentVersion: '1.4.2',
          configFilePath: '/home/kali/.config/sentinel-agent/agent.conf',
          configFileMode: '0600',
          systemdUnitName: 'sentinel-agent.service',
          systemdUnitStatus: overrideConnectionState === 'Connected' ? 'active (running)' : 'failed',
          systemdEnabled: true,
          tokenFingerprint: 'stnl_live_••••8a4c19',
          tokenIssuedAt: tenMinsAgo,
          tokenExpiresAt: inSevenDays,
          tokenRotationCount: 1,
          revoked: overrideConnectionState === 'Error',
          revokedReason: overrideConnectionState === 'Error' ? `${prefix}Credential revoked or service halted` : null,
          enrolledAt: tenMinsAgo,
          lastHeartbeatAt: twoMinsAgo,
          lastVerifiedIp: '10.24.0.48',
          allowedTargets: ['10.24.0.0/24', '192.168.56.0/24', 'lab-node-01.sentinel.internal'],
        }
      : null;

  const reasonByState: Record<ConnectionStatus, string> = {
    'Not configured':
      `${prefix}No Kali agent enrolled yet. Configure Backend HTTPS URL and issue a single-use enrollment code.`,
    'Waiting for Kali':
      `${prefix}Single-use enrollment code (SEN-ENROLL-7F2A-••••-9C) issued and awaiting Kali Linux agent handshake.`,
    Connected:
      `${prefix}Verified heartbeat from kali@kali-research-usb02 (UID 1000) via user-level sentinel-agent.service.`,
    Error:
      `${prefix}Agent credential revoked or user-level systemd unit reported failed state.`,
  };

  return {
    connectionStatus: overrideConnectionState,
    connectionReason: reasonByState[overrideConnectionState],
    backendUrl: 'https://sentinel-research.internal',
    allowedTargets: ['10.24.0.0/24', '192.168.56.0/24', 'lab-node-01.sentinel.internal'],
    setupPackageVersion: '1.4.2',
    activeAgent: demoAgent,
    pendingEnrollment:
      overrideConnectionState === 'Waiting for Kali'
        ? {
            id: 'enr-demo-01',
            label: 'kali-live-usb-bench',
            codeHint: 'SEN-ENROLL-7F2A-••••-9C',
            createdAt: twoMinsAgo,
            expiresAt: inTwelveMins,
          }
        : null,
    enrollments: [
      {
        id: 'enr-demo-01',
        label: 'kali-live-usb-bench',
        codeHint: 'SEN-ENROLL-7F2A-••••-9C',
        createdAt: tenMinsAgo,
        expiresAt: inTwelveMins,
        usedAt: overrideConnectionState === 'Connected' ? twoMinsAgo : null,
        usedByAgentId: overrideConnectionState === 'Connected' ? 'agt-demo-94f1' : null,
        revoked: false,
      },
    ],
    sanitizedLogs: [
      {
        id: 'dlog-1',
        timestamp: twoMinsAgo,
        level: overrideConnectionState === 'Error' ? 'ERROR' : 'INFO',
        source: 'sentinel-agent.service',
        message:
          overrideConnectionState === 'Error'
            ? '[DEMO] Heartbeat rejected for Bearer stnl_live_[REDACTED]: credential revoked by operator.'
            : '[DEMO] Heartbeat OK from kali@kali-research-usb02 (UID 1000) · config=/home/kali/.config/sentinel-agent/agent.conf (0600)',
      },
      {
        id: 'dlog-2',
        timestamp: tenMinsAgo,
        level: 'INFO',
        source: 'enrollment-authority',
        message:
          '[DEMO] Single-use enrollment code SEN-ENROLL-[REDACTED] exchanged for scoped credential stnl_live_[REDACTED].',
      },
    ],
    auditEvents: [
      {
        id: 'daud-1',
        timestamp: twoMinsAgo,
        actor: 'kali@kali-research-usb02',
        eventType: overrideConnectionState === 'Error' ? 'TOKEN_REVOKED' : 'HEARTBEAT_VERIFIED',
        severity: overrideConnectionState === 'Error' ? 'critical' : 'info',
        summary:
          overrideConnectionState === 'Error'
            ? '[DEMO] Simulated credential revocation event.'
            : '[DEMO] Simulated heartbeat verified from non-root UID 1000.',
        metadata: { uid: 1000, demo: true },
      },
    ],
    scanJobs: [
      {
        id: 'job-demo-1',
        agentId: 'agt-demo-94f1',
        operationId: 'passive_port_inventory',
        operationName: 'Baseline Service Port Inventory',
        target: '10.24.0.15',
        requiresHumanApproval: false,
        status: 'queued',
        createdAt: twoMinsAgo,
        approvedBy: null,
        approverNote: null,
        approvedAt: null,
        rejectionReason: null,
      },
      {
        id: 'job-demo-2',
        agentId: 'agt-demo-94f1',
        operationId: 'intrusive_vuln_verification',
        operationName: 'Intrusive CVE Proof-of-Concept Check',
        target: '10.24.0.22',
        requiresHumanApproval: true,
        status: 'pending_human_approval',
        createdAt: tenMinsAgo,
        approvedBy: null,
        approverNote: null,
        approvedAt: null,
        rejectionReason: null,
      },
    ],
    predefinedOperations,
    wizardChecklist: {
      step1WindowsUsbPrepared: overrideConnectionState !== 'Not configured',
      step2PackageDownloaded: overrideConnectionState !== 'Not configured',
      step3KaliUsbMounted: overrideConnectionState === 'Connected' || overrideConnectionState === 'Error',
      step4NonRootInstalled: overrideConnectionState === 'Connected' || overrideConnectionState === 'Error',
      step5BackendConfigured: overrideConnectionState !== 'Not configured',
      step6SystemdVerified: overrideConnectionState === 'Connected',
    },
    serverTimestamp: nowIso,
  };
}
