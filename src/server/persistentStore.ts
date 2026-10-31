import fs from 'node:fs';
import path from 'node:path';
import {
  SentinelStoreState,
  createInitialStoreState,
  computeConnectionStatus,
  PREDEFINED_OPERATIONS,
} from '../lib/sentinelEngine';

const DATA_DIR = path.resolve(process.cwd(), 'data');
const DB_FILE = path.join(DATA_DIR, 'sentinel-db.json');
const VAULT_FILE = path.join(DATA_DIR, 'server-agent-vault.json');

interface ServerAgentVault {
  // Server-side-only map of agentId -> live token for local verification tests without exposing secrets to browser JS
  tokensByAgentId: Record<string, string>;
}

function ensureDataDir(): void {
  if (!fs.existsSync(DATA_DIR)) {
    fs.mkdirSync(DATA_DIR, { recursive: true, mode: 0o700 });
  }
}

export function loadStoreState(defaultBackendUrl: string): SentinelStoreState {
  ensureDataDir();
  if (!fs.existsSync(DB_FILE)) {
    const initial = createInitialStoreState(defaultBackendUrl);
    saveStoreState(initial);
    return initial;
  }
  try {
    const raw = fs.readFileSync(DB_FILE, 'utf8');
    const parsed = JSON.parse(raw) as SentinelStoreState;
    if (!parsed.backendUrl && defaultBackendUrl) {
      parsed.backendUrl = defaultBackendUrl;
    }
    return parsed;
  } catch {
    const fallback = createInitialStoreState(defaultBackendUrl);
    saveStoreState(fallback);
    return fallback;
  }
}

export function saveStoreState(state: SentinelStoreState): void {
  ensureDataDir();
  const tmpFile = `${DB_FILE}.tmp`;
  fs.writeFileSync(tmpFile, JSON.stringify(state, null, 2), { encoding: 'utf8', mode: 0o600 });
  fs.renameSync(tmpFile, DB_FILE);
}

export function saveServerVaultToken(agentId: string, tokenPlaintext: string): void {
  ensureDataDir();
  let vault: ServerAgentVault = { tokensByAgentId: {} };
  if (fs.existsSync(VAULT_FILE)) {
    try {
      vault = JSON.parse(fs.readFileSync(VAULT_FILE, 'utf8')) as ServerAgentVault;
    } catch {
      vault = { tokensByAgentId: {} };
    }
  }
  vault.tokensByAgentId[agentId] = tokenPlaintext;
  fs.writeFileSync(VAULT_FILE, JSON.stringify(vault, null, 2), { encoding: 'utf8', mode: 0o600 });
}

export function getServerVaultToken(agentId: string): string | null {
  if (!fs.existsSync(VAULT_FILE)) return null;
  try {
    const vault = JSON.parse(fs.readFileSync(VAULT_FILE, 'utf8')) as ServerAgentVault;
    return vault.tokensByAgentId[agentId] || null;
  } catch {
    return null;
  }
}

export function toPublicStatusPayload(state: SentinelStoreState, now: Date = new Date()) {
  const conn = computeConnectionStatus(state, now);

  // Strip codeHash and tokenHash before sending to frontend
  const sanitizedEnrollments = state.enrollments.slice(0, 10).map((e) => ({
    id: e.id,
    label: e.label,
    codeHint: e.codeHint,
    createdAt: e.createdAt,
    expiresAt: e.expiresAt,
    usedAt: e.usedAt,
    usedByAgentId: e.usedByAgentId,
    revoked: e.revoked,
  }));

  const sanitizedAgents = state.agents.map((a) => ({
    id: a.id,
    hostname: a.hostname,
    linuxUser: a.linuxUser,
    uid: a.uid,
    agentVersion: a.agentVersion,
    configFilePath: a.configFilePath,
    configFileMode: a.configFileMode,
    systemdUnitName: a.systemdUnitName,
    systemdUnitStatus: a.systemdUnitStatus,
    systemdEnabled: a.systemdEnabled,
    tokenFingerprint: a.tokenFingerprint,
    tokenIssuedAt: a.tokenIssuedAt,
    tokenExpiresAt: a.tokenExpiresAt,
    tokenRotationCount: a.tokenRotationCount,
    revoked: a.revoked,
    revokedReason: a.revokedReason,
    enrolledAt: a.enrolledAt,
    lastHeartbeatAt: a.lastHeartbeatAt,
    lastVerifiedIp: a.lastVerifiedIp,
    allowedTargets: a.allowedTargets,
  }));

  return {
    connectionStatus: conn.status,
    connectionReason: conn.reason,
    backendUrl: state.backendUrl,
    allowedTargets: state.allowedTargets,
    setupPackageVersion: state.setupPackageVersion,
    activeAgent: sanitizedAgents[0] || null,
    pendingEnrollment: conn.pendingEnrollment
      ? {
          id: conn.pendingEnrollment.id,
          label: conn.pendingEnrollment.label,
          codeHint: conn.pendingEnrollment.codeHint,
          createdAt: conn.pendingEnrollment.createdAt,
          expiresAt: conn.pendingEnrollment.expiresAt,
        }
      : null,
    enrollments: sanitizedEnrollments,
    sanitizedLogs: state.sanitizedLogs.slice(0, 30),
    auditEvents: state.auditEvents.slice(0, 40),
    scanJobs: state.scanJobs.slice(0, 25),
    predefinedOperations: Object.values(PREDEFINED_OPERATIONS),
    wizardChecklist: state.wizardChecklist,
    serverTimestamp: now.toISOString(),
  };
}
