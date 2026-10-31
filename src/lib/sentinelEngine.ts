import crypto from 'node:crypto';

export type ConnectionStatus = 'Not configured' | 'Waiting for Kali' | 'Connected' | 'Error';

export type PredefinedOperationId =
  | 'passive_port_inventory'
  | 'tls_cipher_audit'
  | 'intrusive_vuln_verification'
  | 'signed_patch_deployment';

export interface PredefinedOperationSpec {
  id: PredefinedOperationId;
  name: string;
  category: 'reconnaissance' | 'compliance' | 'intrusive_test' | 'patch_deployment';
  requiresHumanApproval: boolean;
  description: string;
  kaliScannerBinary: string;
  fixedArgumentsPreview: string;
}

export const PREDEFINED_OPERATIONS: Record<PredefinedOperationId, PredefinedOperationSpec> = {
  passive_port_inventory: {
    id: 'passive_port_inventory',
    name: 'Baseline Service Port Inventory',
    category: 'reconnaissance',
    requiresHumanApproval: false,
    description: 'Non-intrusive TCP SYN/connect enumeration restricted to top 100 research lab ports.',
    kaliScannerBinary: '/usr/bin/nmap',
    fixedArgumentsPreview: 'nmap -sT --top-ports 100 -T3 --open <validated-target>',
  },
  tls_cipher_audit: {
    id: 'tls_cipher_audit',
    name: 'TLS 1.3 & Certificate Chain Audit',
    category: 'compliance',
    requiresHumanApproval: false,
    description: 'Read-only TLS handshake inspection verifying cipher suites and certificate expiration.',
    kaliScannerBinary: '/usr/bin/sslscan',
    fixedArgumentsPreview: 'sslscan --no-failed --tlsall <validated-target>:443',
  },
  intrusive_vuln_verification: {
    id: 'intrusive_vuln_verification',
    name: 'Intrusive CVE Proof-of-Concept Check',
    category: 'intrusive_test',
    requiresHumanApproval: true,
    description: 'Active payload verification against isolated lab service. Requires explicit human operator sign-off.',
    kaliScannerBinary: '/usr/bin/nuclei',
    fixedArgumentsPreview: 'nuclei -u <validated-target> -tags cve -rate-limit 15',
  },
  signed_patch_deployment: {
    id: 'signed_patch_deployment',
    name: 'Signed Security Advisory Patch Rollout',
    category: 'patch_deployment',
    requiresHumanApproval: true,
    description: 'Applies PGP-verified remediation bundle on approved lab target. Requires explicit human operator sign-off.',
    kaliScannerBinary: '/usr/local/lib/sentinel-agent/apply-signed-patch',
    fixedArgumentsPreview: 'apply-signed-patch --verify-sig --target <validated-target>',
  },
};

export interface EnrollmentRecord {
  id: string;
  label: string;
  codeHash: string;
  codeHint: string;
  createdAt: string;
  expiresAt: string;
  usedAt: string | null;
  usedByAgentId: string | null;
  revoked: boolean;
}

export interface RegisteredAgent {
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
  tokenHash: string;
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
  eventType:
    | 'BACKEND_URL_UPDATED'
    | 'ENROLLMENT_CODE_ISSUED'
    | 'AGENT_ENROLLED'
    | 'ENROLLMENT_REJECTED'
    | 'HEARTBEAT_VERIFIED'
    | 'HEARTBEAT_REJECTED'
    | 'TOKEN_ROTATED'
    | 'TOKEN_REVOKED'
    | 'SCAN_JOB_QUEUED'
    | 'SCAN_JOB_PENDING_APPROVAL'
    | 'SCAN_JOB_APPROVED'
    | 'SCAN_JOB_REJECTED'
    | 'PACKAGE_DOWNLOADED';
  severity: 'info' | 'warning' | 'critical';
  summary: string;
  metadata: Record<string, string | number | boolean>;
}

export interface ScanJob {
  id: string;
  agentId: string;
  operationId: PredefinedOperationId;
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

export interface SentinelStoreState {
  schemaVersion: number;
  backendUrl: string;
  allowedTargets: string[];
  setupPackageVersion: string;
  enrollments: EnrollmentRecord[];
  agents: RegisteredAgent[];
  sanitizedLogs: SanitizedLogEntry[];
  auditEvents: AuditEvent[];
  scanJobs: ScanJob[];
  wizardChecklist: WizardChecklistState;
}

export interface EngineResult<T> {
  ok: boolean;
  code: string;
  message: string;
  data?: T;
}

export function sha256Hex(input: string): string {
  return crypto.createHash('sha256').update(input, 'utf8').digest('hex');
}

export function sanitizeText(raw: string): string {
  if (!raw) return '';
  return raw
    .replace(/stnl_live_[A-Za-z0-9_-]+/g, 'stnl_live_[REDACTED]')
    .replace(/SEN-ENROLL-[A-Za-z0-9-]+/g, 'SEN-ENROLL-[REDACTED]')
    .replace(/Bearer\s+[A-Za-z0-9._~+/-]+=*/gi, 'Bearer [REDACTED]')
    .replace(/(api[_-]?key|token|secret|password)\s*[:=]\s*[^\s,;]+/gi, '$1=[REDACTED]');
}

export function createInitialStoreState(defaultBackendUrl = ''): SentinelStoreState {
  return {
    schemaVersion: 1,
    backendUrl: defaultBackendUrl,
    allowedTargets: ['10.24.0.0/24', '192.168.56.0/24', 'lab-node-01.sentinel.internal', 'lab-node-02.sentinel.internal'],
    setupPackageVersion: '1.4.2',
    enrollments: [],
    agents: [],
    sanitizedLogs: [
      {
        id: 'log-init-1',
        timestamp: new Date().toISOString(),
        level: 'INFO',
        source: 'enrollment-authority',
        message: 'Sentinel USB Connect control plane initialized. Waiting for operator configuration and single-use Kali agent enrollment.',
      },
    ],
    auditEvents: [
      {
        id: 'aud-init-1',
        timestamp: new Date().toISOString(),
        actor: 'system',
        eventType: 'BACKEND_URL_UPDATED',
        severity: 'info',
        summary: 'Control plane store initialized with zero active agent credentials.',
        metadata: { packageVersion: '1.4.2' },
      },
    ],
    scanJobs: [],
    wizardChecklist: {
      step1WindowsUsbPrepared: false,
      step2PackageDownloaded: false,
      step3KaliUsbMounted: false,
      step4NonRootInstalled: false,
      step5BackendConfigured: false,
      step6SystemdVerified: false,
    },
  };
}

export function validateHttpsBackendUrl(urlStr: string): EngineResult<{ normalizedUrl: string }> {
  const trimmed = (urlStr || '').trim().replace(/\/+$/, '');
  if (!trimmed) {
    return {
      ok: false,
      code: 'EMPTY_BACKEND_URL',
      message: 'Backend URL is required.',
    };
  }
  let parsed: URL;
  try {
    parsed = new URL(trimmed);
  } catch {
    return {
      ok: false,
      code: 'MALFORMED_BACKEND_URL',
      message: 'Backend URL must be a valid full URL (e.g. https://sentinel.example.org).',
    };
  }

  const isLocalhostDev =
    parsed.hostname === 'localhost' ||
    parsed.hostname === '127.0.0.1';

  if (parsed.protocol !== 'https:' && !isLocalhostDev) {
    return {
      ok: false,
      code: 'HTTPS_REQUIRED',
      message: 'Production Sentinel control plane URLs must use HTTPS (https://).',
    };
  }

  if (parsed.username || parsed.password || parsed.search.includes('token=') || parsed.search.includes('key=')) {
    return {
      ok: false,
      code: 'CREDENTIALS_IN_URL_FORBIDDEN',
      message: 'Never embed credentials, tokens, or secrets inside the Backend URL.',
    };
  }

  return {
    ok: true,
    code: 'VALID_URL',
    message: 'Backend URL validated.',
    data: { normalizedUrl: trimmed },
  };
}

function ipToUint32(ip: string): number | null {
  const parts = ip.split('.');
  if (parts.length !== 4) return null;
  let acc = 0;
  for (const part of parts) {
    if (!/^\d+$/.test(part)) return null;
    const num = Number(part);
    if (num < 0 || num > 255) return null;
    acc = ((acc << 8) >>> 0) + num;
  }
  return acc >>> 0;
}

export function isTargetInAllowedScope(target: string, allowedTargets: string[]): boolean {
  const cleanTarget = (target || '').trim().toLowerCase();
  if (!cleanTarget) return false;

  // Reject any shell injection or path characters in target
  if (/[;&|`$<>()\\/\s]/.test(cleanTarget)) {
    return false;
  }

  // Never allow wildcard 0.0.0.0/0 or localhost loopback as a scan target
  if (cleanTarget === '0.0.0.0/0' || cleanTarget === '127.0.0.1' || cleanTarget === 'localhost') {
    return false;
  }

  const targetIp = ipToUint32(cleanTarget);

  for (const rawAllowed of allowedTargets) {
    const allowed = rawAllowed.trim().toLowerCase();
    if (!allowed) continue;

    if (allowed.includes('/')) {
      const [cidrBase, prefixStr] = allowed.split('/');
      const prefix = Number(prefixStr);
      const baseIp = ipToUint32(cidrBase);
      if (targetIp !== null && baseIp !== null && prefix >= 8 && prefix <= 32) {
        const mask = prefix === 0 ? 0 : (~0 << (32 - prefix)) >>> 0;
        if ((targetIp & mask) >>> 0 === (baseIp & mask) >>> 0) {
          return true;
        }
      }
    } else if (cleanTarget === allowed) {
      return true;
    }
  }

  return false;
}

export function computeConnectionStatus(
  state: SentinelStoreState,
  now: Date = new Date()
): {
  status: ConnectionStatus;
  reason: string;
  activeAgent: RegisteredAgent | null;
  pendingEnrollment: EnrollmentRecord | null;
} {
  const nowMs = now.getTime();
  const activeAgent = state.agents[0] || null;

  if (activeAgent) {
    if (activeAgent.revoked) {
      return {
        status: 'Error',
        reason: `Agent credential revoked: ${activeAgent.revokedReason || 'Operator revocation'}. Issue a new single-use enrollment code to re-enroll.`,
        activeAgent,
        pendingEnrollment: null,
      };
    }

    if (new Date(activeAgent.tokenExpiresAt).getTime() <= nowMs) {
      return {
        status: 'Error',
        reason: 'Agent credential has expired. Rotate the credential or re-enroll from Kali Linux.',
        activeAgent,
        pendingEnrollment: null,
      };
    }

    if (activeAgent.systemdUnitStatus === 'failed') {
      return {
        status: 'Error',
        reason: 'Kali user-level systemd unit reported failed state.',
        activeAgent,
        pendingEnrollment: null,
      };
    }

    if (!activeAgent.lastHeartbeatAt) {
      return {
        status: 'Waiting for Kali',
        reason: 'Agent enrolled, waiting for initial systemd service heartbeat from Kali Linux.',
        activeAgent,
        pendingEnrollment: null,
      };
    }

    const heartbeatAgeSec = (nowMs - new Date(activeAgent.lastHeartbeatAt).getTime()) / 1000;
    if (heartbeatAgeSec > 300) {
      return {
        status: 'Error',
        reason: `Heartbeat stale (${Math.round(heartbeatAgeSec)}s since last report). Verify Kali network reachability and user systemd service.`,
        activeAgent,
        pendingEnrollment: null,
      };
    }

    return {
      status: 'Connected',
      reason: `Verified heartbeat from ${activeAgent.linuxUser}@${activeAgent.hostname} (UID ${activeAgent.uid}) via ${activeAgent.systemdUnitName}.`,
      activeAgent,
      pendingEnrollment: null,
    };
  }

  const validPendingEnrollment = state.enrollments.find(
    (e) => !e.usedAt && !e.revoked && new Date(e.expiresAt).getTime() > nowMs
  );

  if (validPendingEnrollment && state.backendUrl) {
    return {
      status: 'Waiting for Kali',
      reason: `Single-use enrollment code (${validPendingEnrollment.codeHint}) is active and waiting for Kali Linux agent handshake.`,
      activeAgent: null,
      pendingEnrollment: validPendingEnrollment,
    };
  }

  const expiredUnclaimed = state.enrollments.find(
    (e) => !e.usedAt && !e.revoked && new Date(e.expiresAt).getTime() <= nowMs
  );
  if (expiredUnclaimed) {
    return {
      status: 'Error',
      reason: `Enrollment code ${expiredUnclaimed.codeHint} expired before Kali connected. Generate a fresh single-use code.`,
      activeAgent: null,
      pendingEnrollment: null,
    };
  }

  return {
    status: 'Not configured',
    reason: 'No Kali Linux agent is enrolled yet. Configure the Backend URL and issue a single-use enrollment code.',
    activeAgent: null,
    pendingEnrollment: null,
  };
}

export function issueEnrollmentCode(
  state: SentinelStoreState,
  params: { label?: string; ttlMinutes?: number; now?: Date }
): EngineResult<{
  enrollmentCodePlaintext: string;
  enrollmentRecord: EnrollmentRecord;
}> {
  const now = params.now || new Date();
  const ttlMinutes = Math.min(Math.max(params.ttlMinutes ?? 15, 1), 60);
  const label = (params.label || 'kali-live-usb-agent').trim();

  if (!state.backendUrl) {
    return {
      ok: false,
      code: 'BACKEND_URL_NOT_CONFIGURED',
      message: 'Configure a valid Backend HTTPS URL before issuing an enrollment code.',
    };
  }

  // Revoke any previous unused enrollment codes so only one active code is open at a time
  for (const existing of state.enrollments) {
    if (!existing.usedAt && !existing.revoked) {
      existing.revoked = true;
    }
  }

  const randomSegmentA = crypto.randomBytes(3).toString('hex').toUpperCase();
  const randomSegmentB = crypto.randomBytes(3).toString('hex').toUpperCase();
  const randomSegmentC = crypto.randomBytes(3).toString('hex').toUpperCase();
  const plaintextCode = `SEN-ENROLL-${randomSegmentA}-${randomSegmentB}-${randomSegmentC}`;
  const codeHash = sha256Hex(plaintextCode);
  const codeHint = `SEN-ENROLL-${randomSegmentA}-••••-${randomSegmentC.slice(-2)}`;

  const record: EnrollmentRecord = {
    id: `enr-${crypto.randomBytes(4).toString('hex')}`,
    label,
    codeHash,
    codeHint,
    createdAt: now.toISOString(),
    expiresAt: new Date(now.getTime() + ttlMinutes * 60_000).toISOString(),
    usedAt: null,
    usedByAgentId: null,
    revoked: false,
  };

  state.enrollments.unshift(record);
  state.auditEvents.unshift({
    id: `aud-${crypto.randomBytes(4).toString('hex')}`,
    timestamp: now.toISOString(),
    actor: 'operator',
    eventType: 'ENROLLMENT_CODE_ISSUED',
    severity: 'info',
    summary: `Issued short-lived single-use enrollment code (${codeHint}) valid for ${ttlMinutes}m.`,
    metadata: { enrollmentId: record.id, label, ttlMinutes },
  });

  return {
    ok: true,
    code: 'ENROLLMENT_CODE_ISSUED',
    message: 'Single-use enrollment code issued. Copy it to the Kali agent configuration.',
    data: {
      enrollmentCodePlaintext: plaintextCode,
      enrollmentRecord: record,
    },
  };
}

export function enrollAgentWithCode(
  state: SentinelStoreState,
  params: {
    enrollmentCode: string;
    hostname: string;
    linuxUser: string;
    uid: number;
    agentVersion?: string;
    configFileMode?: string;
    configFilePath?: string;
    clientIp?: string;
    now?: Date;
  }
): EngineResult<{
  agentCredentialToken: string;
  agent: RegisteredAgent;
}> {
  const now = params.now || new Date();
  const rawCode = (params.enrollmentCode || '').trim();

  if (!rawCode) {
    return {
      ok: false,
      code: 'INVALID_ENROLLMENT_CODE',
      message: 'Enrollment code is required.',
    };
  }

  const incomingHash = sha256Hex(rawCode);
  const matchingRecord = state.enrollments.find((e) => e.codeHash === incomingHash);

  if (!matchingRecord) {
    state.auditEvents.unshift({
      id: `aud-${crypto.randomBytes(4).toString('hex')}`,
      timestamp: now.toISOString(),
      actor: 'kali-agent',
      eventType: 'ENROLLMENT_REJECTED',
      severity: 'warning',
      summary: 'Rejected enrollment attempt: unknown single-use enrollment code.',
      metadata: { reason: 'INVALID_ENROLLMENT_CODE', hostname: params.hostname || 'unknown' },
    });
    return {
      ok: false,
      code: 'INVALID_ENROLLMENT_CODE',
      message: 'Invalid enrollment code. Verify the code issued by Sentinel USB Connect.',
    };
  }

  if (matchingRecord.usedAt !== null) {
    state.auditEvents.unshift({
      id: `aud-${crypto.randomBytes(4).toString('hex')}`,
      timestamp: now.toISOString(),
      actor: 'kali-agent',
      eventType: 'ENROLLMENT_REJECTED',
      severity: 'critical',
      summary: `Rejected replay attempt on consumed single-use code (${matchingRecord.codeHint}).`,
      metadata: { reason: 'ENROLLMENT_CODE_ALREADY_USED', enrollmentId: matchingRecord.id },
    });
    return {
      ok: false,
      code: 'ENROLLMENT_CODE_ALREADY_USED',
      message: 'This single-use enrollment code has already been used and cannot be replayed.',
    };
  }

  if (matchingRecord.revoked || new Date(matchingRecord.expiresAt).getTime() <= now.getTime()) {
    state.auditEvents.unshift({
      id: `aud-${crypto.randomBytes(4).toString('hex')}`,
      timestamp: now.toISOString(),
      actor: 'kali-agent',
      eventType: 'ENROLLMENT_REJECTED',
      severity: 'warning',
      summary: `Rejected enrollment attempt with expired/revoked code (${matchingRecord.codeHint}).`,
      metadata: { reason: 'ENROLLMENT_CODE_EXPIRED', enrollmentId: matchingRecord.id },
    });
    return {
      ok: false,
      code: 'ENROLLMENT_CODE_EXPIRED',
      message: 'Enrollment code has expired or been revoked. Issue a new single-use enrollment code.',
    };
  }

  const cleanUser = (params.linuxUser || '').trim();
  const uid = Number(params.uid);
  if (!cleanUser || cleanUser.toLowerCase() === 'root' || uid === 0 || !Number.isInteger(uid) || uid < 1000) {
    state.auditEvents.unshift({
      id: `aud-${crypto.randomBytes(4).toString('hex')}`,
      timestamp: now.toISOString(),
      actor: 'kali-agent',
      eventType: 'ENROLLMENT_REJECTED',
      severity: 'critical',
      summary: `Rejected enrollment from privileged/system user (${cleanUser || 'unknown'}, UID ${uid}). Agent must run as non-root user (UID >= 1000).`,
      metadata: { reason: 'ROOT_EXECUTION_FORBIDDEN', linuxUser: cleanUser, uid },
    });
    return {
      ok: false,
      code: 'ROOT_EXECUTION_FORBIDDEN',
      message: 'Security Policy Violation: Sentinel agent must run as an ordinary non-root Linux user (UID >= 1000), never as root.',
    };
  }

  const configFileMode = (params.configFileMode || '0600').trim();
  if (configFileMode !== '0600' && configFileMode !== '600') {
    state.auditEvents.unshift({
      id: `aud-${crypto.randomBytes(4).toString('hex')}`,
      timestamp: now.toISOString(),
      actor: 'kali-agent',
      eventType: 'ENROLLMENT_REJECTED',
      severity: 'warning',
      summary: `Rejected enrollment due to permissive local config mode (${configFileMode}). Expected 0600.`,
      metadata: { reason: 'INSECURE_CONFIG_PERMISSIONS', configFileMode },
    });
    return {
      ok: false,
      code: 'INSECURE_CONFIG_PERMISSIONS',
      message: 'Local Kali credential file must have restrictive 0600 permissions (chmod 600 ~/.config/sentinel-agent/agent.conf).',
    };
  }

  const rawToken = `stnl_live_${crypto.randomBytes(24).toString('hex')}`;
  const tokenHash = sha256Hex(rawToken);
  const tokenFingerprint = `stnl_live_••••${rawToken.slice(-6)}`;
  const agentId = `agt-${crypto.randomBytes(4).toString('hex')}`;

  matchingRecord.usedAt = now.toISOString();
  matchingRecord.usedByAgentId = agentId;

  const agent: RegisteredAgent = {
    id: agentId,
    hostname: (params.hostname || 'kali-live').trim(),
    linuxUser: cleanUser,
    uid,
    agentVersion: (params.agentVersion || state.setupPackageVersion).trim(),
    configFilePath: params.configFilePath || `/home/${cleanUser}/.config/sentinel-agent/agent.conf`,
    configFileMode: '0600',
    systemdUnitName: 'sentinel-agent.service',
    systemdUnitStatus: 'active (running)',
    systemdEnabled: true,
    tokenHash,
    tokenFingerprint,
    tokenIssuedAt: now.toISOString(),
    tokenExpiresAt: new Date(now.getTime() + 7 * 24 * 3600_000).toISOString(),
    tokenRotationCount: 0,
    revoked: false,
    revokedReason: null,
    enrolledAt: now.toISOString(),
    lastHeartbeatAt: now.toISOString(),
    lastVerifiedIp: params.clientIp || '10.24.0.42',
    allowedTargets: [...state.allowedTargets],
  };

  // Replace or prepend active agent
  state.agents = [agent, ...state.agents.filter((a) => a.id !== agent.id)];
  state.wizardChecklist.step4NonRootInstalled = true;
  state.wizardChecklist.step5BackendConfigured = true;

  state.sanitizedLogs.unshift({
    id: `log-${crypto.randomBytes(4).toString('hex')}`,
    timestamp: now.toISOString(),
    level: 'INFO',
    source: 'enrollment-authority',
    message: sanitizeText(
      `Enrolled Kali agent ${agent.linuxUser}@${agent.hostname} (UID ${agent.uid}) using single-use code ${matchingRecord.codeHint}. Credential stored in ${agent.configFilePath} (mode ${agent.configFileMode}).`
    ),
  });

  state.auditEvents.unshift({
    id: `aud-${crypto.randomBytes(4).toString('hex')}`,
    timestamp: now.toISOString(),
    actor: `${agent.linuxUser}@${agent.hostname}`,
    eventType: 'AGENT_ENROLLED',
    severity: 'info',
    summary: `Kali agent enrolled as non-root user ${agent.linuxUser} (UID ${agent.uid}) with credential ${tokenFingerprint}.`,
    metadata: {
      agentId: agent.id,
      uid: agent.uid,
      configFileMode: agent.configFileMode,
      tokenFingerprint,
    },
  });

  return {
    ok: true,
    code: 'AGENT_ENROLLED',
    message: 'Kali agent successfully enrolled with scoped credential.',
    data: {
      agentCredentialToken: rawToken,
      agent,
    },
  };
}

export function recordAgentHeartbeat(
  state: SentinelStoreState,
  params: {
    bearerToken: string;
    linuxUser: string;
    uid: number;
    systemdUnitStatus?: 'active (running)' | 'inactive (dead)' | 'failed' | 'activating';
    lastLogLine?: string;
    clientIp?: string;
    now?: Date;
  }
): EngineResult<{ agent: RegisteredAgent }> {
  const now = params.now || new Date();
  const rawToken = (params.bearerToken || '').trim().replace(/^Bearer\s+/i, '');

  if (!rawToken) {
    return {
      ok: false,
      code: 'UNAUTHORIZED_TOKEN',
      message: 'Missing Bearer credential token.',
    };
  }

  const incomingHash = sha256Hex(rawToken);
  const agent = state.agents.find((a) => a.tokenHash === incomingHash);

  if (!agent) {
    state.auditEvents.unshift({
      id: `aud-${crypto.randomBytes(4).toString('hex')}`,
      timestamp: now.toISOString(),
      actor: 'unknown-client',
      eventType: 'HEARTBEAT_REJECTED',
      severity: 'warning',
      summary: 'Rejected heartbeat with unrecognized Bearer credential hash.',
      metadata: { reason: 'UNAUTHORIZED_TOKEN' },
    });
    return {
      ok: false,
      code: 'UNAUTHORIZED_TOKEN',
      message: 'Invalid or unknown agent credential token.',
    };
  }

  if (agent.revoked) {
    state.auditEvents.unshift({
      id: `aud-${crypto.randomBytes(4).toString('hex')}`,
      timestamp: now.toISOString(),
      actor: `${agent.linuxUser}@${agent.hostname}`,
      eventType: 'HEARTBEAT_REJECTED',
      severity: 'critical',
      summary: `Rejected heartbeat from revoked credential (${agent.tokenFingerprint}).`,
      metadata: { reason: 'CREDENTIAL_REVOKED', agentId: agent.id },
    });
    return {
      ok: false,
      code: 'CREDENTIAL_REVOKED',
      message: 'Agent credential has been revoked by administrator.',
    };
  }

  if (new Date(agent.tokenExpiresAt).getTime() <= now.getTime()) {
    state.auditEvents.unshift({
      id: `aud-${crypto.randomBytes(4).toString('hex')}`,
      timestamp: now.toISOString(),
      actor: `${agent.linuxUser}@${agent.hostname}`,
      eventType: 'HEARTBEAT_REJECTED',
      severity: 'warning',
      summary: `Rejected heartbeat from expired credential (${agent.tokenFingerprint}).`,
      metadata: { reason: 'CREDENTIAL_EXPIRED', agentId: agent.id },
    });
    return {
      ok: false,
      code: 'CREDENTIAL_EXPIRED',
      message: 'Agent credential has expired.',
    };
  }

  if (params.linuxUser.trim().toLowerCase() === 'root' || Number(params.uid) === 0) {
    state.auditEvents.unshift({
      id: `aud-${crypto.randomBytes(4).toString('hex')}`,
      timestamp: now.toISOString(),
      actor: `${params.linuxUser}@${agent.hostname}`,
      eventType: 'HEARTBEAT_REJECTED',
      severity: 'critical',
      summary: 'Rejected heartbeat: agent process attempted to run as root (UID 0).',
      metadata: { reason: 'ROOT_EXECUTION_FORBIDDEN', uid: params.uid },
    });
    return {
      ok: false,
      code: 'ROOT_EXECUTION_FORBIDDEN',
      message: 'Agent heartbeat rejected: running as root is strictly forbidden.',
    };
  }

  agent.lastHeartbeatAt = now.toISOString();
  agent.systemdUnitStatus = params.systemdUnitStatus || 'active (running)';
  if (params.clientIp) {
    agent.lastVerifiedIp = params.clientIp;
  }
  state.wizardChecklist.step6SystemdVerified = agent.systemdUnitStatus === 'active (running)';

  const cleanMessage = sanitizeText(
    params.lastLogLine ||
      `Heartbeat OK from ${agent.linuxUser}@${agent.hostname} (UID ${agent.uid}) · unit=${agent.systemdUnitStatus} · targets=${agent.allowedTargets.length}`
  );

  state.sanitizedLogs.unshift({
    id: `log-${crypto.randomBytes(4).toString('hex')}`,
    timestamp: now.toISOString(),
    level: 'INFO',
    source: 'sentinel-agent.service',
    message: cleanMessage,
  });

  state.auditEvents.unshift({
    id: `aud-${crypto.randomBytes(4).toString('hex')}`,
    timestamp: now.toISOString(),
    actor: `${agent.linuxUser}@${agent.hostname}`,
    eventType: 'HEARTBEAT_VERIFIED',
    severity: 'info',
    summary: `Verified heartbeat from ${agent.linuxUser}@${agent.hostname} (${agent.systemdUnitStatus}).`,
    metadata: { agentId: agent.id, uid: agent.uid, status: agent.systemdUnitStatus },
  });

  return {
    ok: true,
    code: 'HEARTBEAT_VERIFIED',
    message: 'Heartbeat verified and recorded.',
    data: { agent },
  };
}

export function rotateAgentCredential(
  state: SentinelStoreState,
  params: { agentId: string; now?: Date }
): EngineResult<{ rotatedTokenPlaintext: string; agent: RegisteredAgent }> {
  const now = params.now || new Date();
  const agent = state.agents.find((a) => a.id === params.agentId);
  if (!agent) {
    return {
      ok: false,
      code: 'AGENT_NOT_FOUND',
      message: 'Registered agent not found.',
    };
  }
  if (agent.revoked) {
    return {
      ok: false,
      code: 'CREDENTIAL_REVOKED',
      message: 'Cannot rotate a revoked credential. Re-enroll the agent with a new single-use enrollment code.',
    };
  }

  const newToken = `stnl_live_${crypto.randomBytes(24).toString('hex')}`;
  agent.tokenHash = sha256Hex(newToken);
  agent.tokenFingerprint = `stnl_live_••••${newToken.slice(-6)}`;
  agent.tokenIssuedAt = now.toISOString();
  agent.tokenExpiresAt = new Date(now.getTime() + 7 * 24 * 3600_000).toISOString();
  agent.tokenRotationCount += 1;

  state.auditEvents.unshift({
    id: `aud-${crypto.randomBytes(4).toString('hex')}`,
    timestamp: now.toISOString(),
    actor: 'operator',
    eventType: 'TOKEN_ROTATED',
    severity: 'info',
    summary: `Rotated credential for ${agent.linuxUser}@${agent.hostname} (rotation #${agent.tokenRotationCount}, new fingerprint ${agent.tokenFingerprint}).`,
    metadata: { agentId: agent.id, rotationCount: agent.tokenRotationCount },
  });

  return {
    ok: true,
    code: 'TOKEN_ROTATED',
    message: 'Agent credential rotated. Update ~/.config/sentinel-agent/agent.conf on Kali.',
    data: { rotatedTokenPlaintext: newToken, agent },
  };
}

export function revokeAgentCredential(
  state: SentinelStoreState,
  params: { agentId: string; reason?: string; now?: Date }
): EngineResult<{ agent: RegisteredAgent }> {
  const now = params.now || new Date();
  const agent = state.agents.find((a) => a.id === params.agentId);
  if (!agent) {
    return {
      ok: false,
      code: 'AGENT_NOT_FOUND',
      message: 'Registered agent not found.',
    };
  }

  agent.revoked = true;
  agent.revokedReason = (params.reason || 'Operator initiated credential revocation').trim();

  state.sanitizedLogs.unshift({
    id: `log-${crypto.randomBytes(4).toString('hex')}`,
    timestamp: now.toISOString(),
    level: 'WARN',
    source: 'enrollment-authority',
    message: `Credential ${agent.tokenFingerprint} for ${agent.linuxUser}@${agent.hostname} revoked: ${agent.revokedReason}`,
  });

  state.auditEvents.unshift({
    id: `aud-${crypto.randomBytes(4).toString('hex')}`,
    timestamp: now.toISOString(),
    actor: 'operator',
    eventType: 'TOKEN_REVOKED',
    severity: 'critical',
    summary: `Revoked agent credential ${agent.tokenFingerprint}: ${agent.revokedReason}`,
    metadata: { agentId: agent.id, reason: agent.revokedReason },
  });

  return {
    ok: true,
    code: 'TOKEN_REVOKED',
    message: 'Agent credential immediately revoked.',
    data: { agent },
  };
}

export function submitScanJob(
  state: SentinelStoreState,
  params: {
    agentId: string;
    operationId: string;
    target: string;
    rawCommandAttempt?: string;
    approvedByHuman?: boolean;
    approverName?: string;
    approverNote?: string;
    requireImmediateDispatch?: boolean;
    now?: Date;
  }
): EngineResult<{ job: ScanJob }> {
  const now = params.now || new Date();

  // Rule: Never accept arbitrary shell commands or executable scripts from the web API
  if (
    params.rawCommandAttempt ||
    /[;&|`$<>()]/.test(params.operationId || '') ||
    /[;&|`$<>()]/.test(params.target || '')
  ) {
    state.auditEvents.unshift({
      id: `aud-${crypto.randomBytes(4).toString('hex')}`,
      timestamp: now.toISOString(),
      actor: 'policy-guard',
      eventType: 'SCAN_JOB_REJECTED',
      severity: 'critical',
      summary: 'Blocked attempt to pass arbitrary shell command or script payload to Kali agent.',
      metadata: { reason: 'ARBITRARY_COMMAND_FORBIDDEN' },
    });
    return {
      ok: false,
      code: 'ARBITRARY_COMMAND_FORBIDDEN',
      message: 'Security Policy Violation: Arbitrary shell commands and scripts are strictly prohibited. Select a predefined operation.',
    };
  }

  // Rule: Allow only administrator-approved scan jobs and predefined scanner operations
  const opSpec = PREDEFINED_OPERATIONS[params.operationId as PredefinedOperationId];
  if (!opSpec) {
    state.auditEvents.unshift({
      id: `aud-${crypto.randomBytes(4).toString('hex')}`,
      timestamp: now.toISOString(),
      actor: 'policy-guard',
      eventType: 'SCAN_JOB_REJECTED',
      severity: 'warning',
      summary: `Rejected unrecognized scanner operation "${sanitizeText(params.operationId)}".`,
      metadata: { reason: 'UNAPPROVED_OPERATION' },
    });
    return {
      ok: false,
      code: 'UNAPPROVED_OPERATION',
      message: 'Unapproved scanner operation. Only predefined administrator-approved operations are permitted.',
    };
  }

  // Rule: Validate allowed targets on the server and on Kali
  const cleanTarget = (params.target || '').trim();
  if (!isTargetInAllowedScope(cleanTarget, state.allowedTargets)) {
    state.auditEvents.unshift({
      id: `aud-${crypto.randomBytes(4).toString('hex')}`,
      timestamp: now.toISOString(),
      actor: 'policy-guard',
      eventType: 'SCAN_JOB_REJECTED',
      severity: 'critical',
      summary: `Blocked out-of-scope target "${cleanTarget}" for operation ${opSpec.id}.`,
      metadata: { reason: 'TARGET_OUT_OF_SCOPE', target: cleanTarget, operationId: opSpec.id },
    });
    return {
      ok: false,
      code: 'TARGET_OUT_OF_SCOPE',
      message: `Target "${cleanTarget}" is outside the approved lab scope (${state.allowedTargets.join(', ')}).`,
    };
  }

  // Rule: Require human approval for patch deployment and intrusive security tests
  const hasExplicitHumanApproval =
    params.approvedByHuman === true &&
    Boolean(params.approverName?.trim()) &&
    Boolean(params.approverNote?.trim());

  if (opSpec.requiresHumanApproval && !hasExplicitHumanApproval) {
    if (params.requireImmediateDispatch) {
      state.auditEvents.unshift({
        id: `aud-${crypto.randomBytes(4).toString('hex')}`,
        timestamp: now.toISOString(),
        actor: 'policy-guard',
        eventType: 'SCAN_JOB_REJECTED',
        severity: 'warning',
        summary: `Blocked unapproved dispatch of ${opSpec.name} on ${cleanTarget}: explicit human approval is required.`,
        metadata: { reason: 'HUMAN_APPROVAL_REQUIRED', operationId: opSpec.id, target: cleanTarget },
      });
      return {
        ok: false,
        code: 'HUMAN_APPROVAL_REQUIRED',
        message: `Operation "${opSpec.name}" requires explicit human operator approval before dispatch.`,
      };
    }

    const pendingJob: ScanJob = {
      id: `job-${crypto.randomBytes(4).toString('hex')}`,
      agentId: params.agentId,
      operationId: opSpec.id,
      operationName: opSpec.name,
      target: cleanTarget,
      requiresHumanApproval: true,
      status: 'pending_human_approval',
      createdAt: now.toISOString(),
      approvedBy: null,
      approverNote: null,
      approvedAt: null,
      rejectionReason: null,
    };

    state.scanJobs.unshift(pendingJob);
    state.auditEvents.unshift({
      id: `aud-${crypto.randomBytes(4).toString('hex')}`,
      timestamp: now.toISOString(),
      actor: 'operator',
      eventType: 'SCAN_JOB_PENDING_APPROVAL',
      severity: 'warning',
      summary: `Queued "${opSpec.name}" for ${cleanTarget} in pending_human_approval state.`,
      metadata: { jobId: pendingJob.id, operationId: opSpec.id, target: cleanTarget },
    });

    return {
      ok: true,
      code: 'SCAN_JOB_PENDING_APPROVAL',
      message: 'Job requires human approval for intrusive test or patch deployment and is held pending sign-off.',
      data: { job: pendingJob },
    };
  }

  const job: ScanJob = {
    id: `job-${crypto.randomBytes(4).toString('hex')}`,
    agentId: params.agentId,
    operationId: opSpec.id,
    operationName: opSpec.name,
    target: cleanTarget,
    requiresHumanApproval: opSpec.requiresHumanApproval,
    status: opSpec.requiresHumanApproval ? 'approved_dispatched' : 'queued',
    createdAt: now.toISOString(),
    approvedBy: hasExplicitHumanApproval ? params.approverName!.trim() : null,
    approverNote: hasExplicitHumanApproval ? sanitizeText(params.approverNote!.trim()) : null,
    approvedAt: hasExplicitHumanApproval ? now.toISOString() : null,
    rejectionReason: null,
  };

  state.scanJobs.unshift(job);
  state.auditEvents.unshift({
    id: `aud-${crypto.randomBytes(4).toString('hex')}`,
    timestamp: now.toISOString(),
    actor: hasExplicitHumanApproval ? params.approverName!.trim() : 'operator',
    eventType: 'SCAN_JOB_QUEUED',
    severity: 'info',
    summary: `Queued predefined operation "${opSpec.name}" for validated target ${cleanTarget}.`,
    metadata: { jobId: job.id, operationId: opSpec.id, target: cleanTarget },
  });

  return {
    ok: true,
    code: 'SCAN_JOB_QUEUED',
    message: `Predefined job "${opSpec.name}" validated and queued for ${cleanTarget}.`,
    data: { job },
  };
}

export function approveScanJob(
  state: SentinelStoreState,
  params: { jobId: string; approverName: string; approverNote: string; now?: Date }
): EngineResult<{ job: ScanJob }> {
  const now = params.now || new Date();
  const job = state.scanJobs.find((j) => j.id === params.jobId);
  if (!job) {
    return {
      ok: false,
      code: 'JOB_NOT_FOUND',
      message: 'Scan job not found.',
    };
  }
  if (!params.approverName?.trim() || !params.approverNote?.trim()) {
    return {
      ok: false,
      code: 'APPROVER_DETAILS_REQUIRED',
      message: 'Both operator name and approval justification note are required.',
    };
  }

  job.status = 'approved_dispatched';
  job.approvedBy = params.approverName.trim();
  job.approverNote = sanitizeText(params.approverNote.trim());
  job.approvedAt = now.toISOString();

  state.auditEvents.unshift({
    id: `aud-${crypto.randomBytes(4).toString('hex')}`,
    timestamp: now.toISOString(),
    actor: job.approvedBy,
    eventType: 'SCAN_JOB_APPROVED',
    severity: 'info',
    summary: `Human operator (${job.approvedBy}) approved ${job.operationName} on ${job.target}.`,
    metadata: { jobId: job.id, target: job.target },
  });

  return {
    ok: true,
    code: 'SCAN_JOB_APPROVED',
    message: 'Human approval recorded; job marked for agent dispatch.',
    data: { job },
  };
}
