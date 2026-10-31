import crypto from 'node:crypto';

export type AllowedMvpCategory = 'passive_http_headers' | 'static_code_analysis';
export type GatedCategory = 'intrusive_review_only';
export type ProhibitedCategory =
  | 'arbitrary_shell'
  | 'unrestricted_port_scan'
  | 'exploit_payload'
  | 'credential_attack'
  | 'persistence_install'
  | 'live_system_modification';

export type JobCategory = AllowedMvpCategory | GatedCategory | ProhibitedCategory;

export const PROHIBITED_CATEGORIES: readonly ProhibitedCategory[] = [
  'arbitrary_shell',
  'unrestricted_port_scan',
  'exploit_payload',
  'credential_attack',
  'persistence_install',
  'live_system_modification',
];

export interface OperatorUser {
  id: string;
  email: string;
  displayName: string;
  role: 'lead_researcher' | 'security_reviewer' | 'auditor';
}

export interface AuthorizedAsset {
  id: string;
  name: string;
  targetHost: string;
  ipOrCidr: string;
  environment: 'staging' | 'isolated_lab' | 'production_read_only';
  ownerTeam: string;
  authorizationRef: string;
  verified: boolean;
  verifiedBy: string | null;
  expiresAt: string;
  createdAt: string;
}

export interface ScopePolicy {
  id: string;
  name: string;
  authorizationRef: string;
  permittedHosts: string[];
  permittedCidrs: string[];
  allowedCategories: Array<AllowedMvpCategory | GatedCategory>;
  maxRateLimitRpm: number;
  requireHumanApprovalForIntrusive: boolean;
  expiresAt: string;
  active: boolean;
  createdAt: string;
}

export interface AssessmentPlanStep {
  stepNumber: number;
  title: string;
  category: AllowedMvpCategory | GatedCategory;
  targetHost: string;
  rationale: string;
  safeToolConfig: {
    toolName: 'passive_header_inspector' | 'static_ast_pattern_scanner' | 'architecture_review_gate';
    inspectedControls: string[];
    rateLimitRpm: number;
  };
  requiresHumanApproval: boolean;
}

export interface AssessmentPlan {
  id: string;
  title: string;
  objective: string;
  assetId: string;
  policyId: string;
  generatedBySource: 'gemini_api' | 'deterministic_fallback';
  modelName: string;
  steps: AssessmentPlanStep[];
  safetyAttestation: string;
  createdBy: string;
  createdAt: string;
}

export interface SecurityJob {
  id: string;
  assetId: string;
  policyId: string;
  category: AllowedMvpCategory | GatedCategory;
  targetHost: string;
  codeSnippet?: string;
  codeFilename?: string;
  rateLimitRpm: number;
  status: 'queued' | 'pending_approval' | 'claimed' | 'completed' | 'expired' | 'rejected';
  requiresApproval: boolean;
  approvedBy: string | null;
  approvedAt: string | null;
  claimedByAgentId: string | null;
  idempotencyClaimKey: string | null;
  claimedAt: string | null;
  expiresAt: string;
  resultSummary: {
    checkedItems: number;
    findingsCount: number;
    summaryText: string;
    headersInspected?: Record<string, string>;
  } | null;
  completedAt: string | null;
  createdBy: string;
  createdAt: string;
}

export interface SecurityFinding {
  id: string;
  jobId: string;
  assetId: string;
  targetHost: string;
  title: string;
  severity: 'low' | 'medium' | 'high' | 'critical';
  category: AllowedMvpCategory;
  cweId: string;
  description: string;
  evidence: string;
  status: 'open' | 'remediation_planned' | 'resolved';
  discoveredAt: string;
}

export interface RemediationItem {
  id: string;
  findingId: string;
  findingTitle: string;
  targetHost: string;
  title: string;
  proposedFix: string;
  configOrCodeDiff: string;
  requiresHumanApproval: boolean;
  approvalStatus: 'pending_approval' | 'approved' | 'rejected';
  approvedBy: string | null;
  approvalNote: string | null;
  approvedAt: string | null;
  createdAt: string;
}

export type AgentConnectionStatus =
  | 'pending_heartbeat'
  | 'waiting_poll'
  | 'online'
  | 'paused'
  | 'disconnected'
  | 'revoked'
  | 'uninstalled';

export interface DeviceEnrollmentCode {
  id: string;
  codeHash: string;
  codePreview: string;
  targetHostname: string;
  linuxUser: string;
  issuedBy: string;
  issuedAt: string;
  expiresAt: string;
  consumedAt: string | null;
  consumedByAgentId: string | null;
  status: 'active' | 'consumed' | 'expired' | 'revoked';
}

export interface PollingAgentRecord {
  id: string;
  hostname: string;
  linuxUser: string;
  uid: number;
  version: string;
  osInfo?: string;
  serviceAccount?: string;
  systemdAutostartEnabled?: boolean;
  credentialFingerprint: string;
  credentialHash: string;
  pollingMode: 'outbound_https_poll';
  status: AgentConnectionStatus;
  heartbeatVerifiedLive?: boolean;
  currentJobId?: string | null;
  currentJobStatus?: 'idle' | 'claiming' | 'executing_allowlisted_task' | 'paused' | 'disconnected';
  lastHeartbeatAt: string | null;
  lastPollAt: string | null;
  claimedJobsCount: number;
  completedJobsCount: number;
  enrolledAt: string;
  revokedAt?: string | null;
  uninstalledAt?: string | null;
}

export interface PlatformAuditLog {
  id: string;
  timestamp: string;
  actor: string;
  action: string;
  resourceType: 'auth' | 'asset' | 'policy' | 'plan' | 'job' | 'finding' | 'remediation' | 'agent';
  resourceId: string;
  decision: 'allowed' | 'denied' | 'approval_required';
  summary: string;
  metadata: Record<string, string | number | boolean>;
}

export interface PolicyEvaluationResult {
  allowed: boolean;
  requiresHumanApproval: boolean;
  code:
    | 'POLICY_ALLOWED'
    | 'APPROVAL_REQUIRED'
    | 'ASSET_NOT_FOUND'
    | 'ASSET_UNVERIFIED'
    | 'ASSET_AUTHORIZATION_EXPIRED'
    | 'POLICY_NOT_FOUND_OR_INACTIVE'
    | 'POLICY_EXPIRED'
    | 'AUTHORIZATION_REF_MISMATCH'
    | 'TARGET_HOST_OUT_OF_SCOPE'
    | 'PROHIBITED_TEST_CATEGORY'
    | 'CATEGORY_NOT_IN_POLICY'
    | 'RATE_LIMIT_EXCEEDED'
    | 'SHELL_COMMAND_DETECTED';
  reason: string;
}

function ipToUint32(ip: string): number | null {
  const parts = ip.trim().split('.');
  if (parts.length !== 4) return null;
  let acc = 0;
  for (const part of parts) {
    if (!/^\d+$/.test(part)) return null;
    const n = Number(part);
    if (n < 0 || n > 255) return null;
    acc = ((acc << 8) >>> 0) + n;
  }
  return acc >>> 0;
}

export function isHostOrIpPermitted(
  targetHost: string,
  assetIpOrCidr: string,
  permittedHosts: string[],
  permittedCidrs: string[]
): boolean {
  const cleanHost = (targetHost || '').trim().toLowerCase();
  if (!cleanHost) return false;
  if (/[;&|`$<>()\\/\s]/.test(cleanHost)) return false;

  const hostMatch = permittedHosts.some((h) => {
    const pattern = h.trim().toLowerCase();
    if (!pattern) return false;
    if (pattern.startsWith('*.')) {
      const suffix = pattern.slice(1); // .example.org
      return cleanHost.endsWith(suffix) && cleanHost.length > suffix.length;
    }
    return cleanHost === pattern;
  });

  if (hostMatch) return true;

  // Only check CIDR ranges if targetHost is a direct IPv4 address
  const directTargetIp = ipToUint32(cleanHost);
  if (directTargetIp !== null) {
    for (const cidr of permittedCidrs) {
      const [baseStr, prefixStr] = cidr.trim().split('/');
      const baseIp = ipToUint32(baseStr);
      const prefix = prefixStr !== undefined ? Number(prefixStr) : 32;
      if (baseIp !== null && prefix >= 8 && prefix <= 32) {
        const mask = prefix === 0 ? 0 : (~0 << (32 - prefix)) >>> 0;
        if ((directTargetIp & mask) >>> 0 === (baseIp & mask) >>> 0) {
          return true;
        }
      }
    }
  }

  return false;
}

export function containsExecutableShellSyntax(input: string): boolean {
  if (!input) return false;
  const forbiddenPatterns = [
    /(?:^|\s)(?:bash|sh|zsh|powershell|cmd\.exe)\s+-c/i,
    /(?:^|\s)(?:rm\s+-rf|chmod\s+\+s|nc\s+-e|mkfifo|curl\s+.*\|\s*(?:sh|bash))/i,
    /(?:^|\s)(?:msfconsole|msfvenom|hydra|john|hashcat|sqlmap\s+--os-shell)/i,
    /[;&|`]\s*(?:whoami|id|cat\s+\/etc\/passwd|uname\s+-a)/i,
  ];
  return forbiddenPatterns.some((re) => re.test(input));
}

export function evaluateJobPolicy(params: {
  asset: AuthorizedAsset | undefined;
  policy: ScopePolicy | undefined;
  targetHost: string;
  category: string;
  requestedRateLimitRpm: number;
  rawCommandInput?: string;
  approvedByHuman?: boolean;
  now?: Date;
}): PolicyEvaluationResult {
  const now = params.now || new Date();
  const nowMs = now.getTime();

  // 1. Block any raw shell command payloads
  if (
    params.rawCommandInput ||
    containsExecutableShellSyntax(params.targetHost) ||
    containsExecutableShellSyntax(params.category)
  ) {
    return {
      allowed: false,
      requiresHumanApproval: false,
      code: 'SHELL_COMMAND_DETECTED',
      reason:
        'Policy Violation: Executable shell commands and exploit payloads are strictly prohibited by Sentinel AI.',
    };
  }

  // 2. Block prohibited offensive/destructive categories immediately
  if ((PROHIBITED_CATEGORIES as readonly string[]).includes(params.category)) {
    return {
      allowed: false,
      requiresHumanApproval: false,
      code: 'PROHIBITED_TEST_CATEGORY',
      reason: `Category "${params.category}" is permanently prohibited. MVP allows only passive_http_headers, static_code_analysis, or human-gated intrusive_review_only.`,
    };
  }

  // 3. Verify explicit AuthorizedAsset record
  const { asset, policy } = params;
  if (!asset) {
    return {
      allowed: false,
      requiresHumanApproval: false,
      code: 'ASSET_NOT_FOUND',
      reason: 'Target asset does not have a registered Authorization Record.',
    };
  }

  if (!asset.verified) {
    return {
      allowed: false,
      requiresHumanApproval: false,
      code: 'ASSET_UNVERIFIED',
      reason: `Asset "${asset.name}" (${asset.authorizationRef}) has not been cryptographically/administratively verified yet.`,
    };
  }

  if (new Date(asset.expiresAt).getTime() <= nowMs) {
    return {
      allowed: false,
      requiresHumanApproval: false,
      code: 'ASSET_AUTHORIZATION_EXPIRED',
      reason: `Authorization record ${asset.authorizationRef} for "${asset.name}" expired at ${asset.expiresAt}.`,
    };
  }

  // 4. Verify active, matching, non-expired ScopePolicy
  if (!policy || !policy.active) {
    return {
      allowed: false,
      requiresHumanApproval: false,
      code: 'POLICY_NOT_FOUND_OR_INACTIVE',
      reason: 'Scope policy is missing or inactive.',
    };
  }

  if (new Date(policy.expiresAt).getTime() <= nowMs) {
    return {
      allowed: false,
      requiresHumanApproval: false,
      code: 'POLICY_EXPIRED',
      reason: `Scope policy "${policy.name}" expired at ${policy.expiresAt}.`,
    };
  }

  if (policy.authorizationRef !== asset.authorizationRef) {
    return {
      allowed: false,
      requiresHumanApproval: false,
      code: 'AUTHORIZATION_REF_MISMATCH',
      reason: `Scope policy authorization reference (${policy.authorizationRef}) does not match asset authorization (${asset.authorizationRef}).`,
    };
  }

  // 5. Verify permitted host / IP scope
  if (
    !isHostOrIpPermitted(
      params.targetHost,
      asset.ipOrCidr,
      policy.permittedHosts,
      policy.permittedCidrs
    )
  ) {
    return {
      allowed: false,
      requiresHumanApproval: false,
      code: 'TARGET_HOST_OUT_OF_SCOPE',
      reason: `Target "${params.targetHost}" is not in permitted hosts (${policy.permittedHosts.join(', ')}) or CIDRs (${policy.permittedCidrs.join(', ')}).`,
    };
  }

  // 6. Verify allowed category in policy
  if (!policy.allowedCategories.includes(params.category as AllowedMvpCategory | GatedCategory)) {
    return {
      allowed: false,
      requiresHumanApproval: false,
      code: 'CATEGORY_NOT_IN_POLICY',
      reason: `Category "${params.category}" is not enabled in scope policy "${policy.name}".`,
    };
  }

  // 7. Verify rate limit
  if (
    !Number.isFinite(params.requestedRateLimitRpm) ||
    params.requestedRateLimitRpm <= 0 ||
    params.requestedRateLimitRpm > policy.maxRateLimitRpm
  ) {
    return {
      allowed: false,
      requiresHumanApproval: false,
      code: 'RATE_LIMIT_EXCEEDED',
      reason: `Requested rate limit (${params.requestedRateLimitRpm} req/min) exceeds policy maximum (${policy.maxRateLimitRpm} req/min).`,
    };
  }

  // 8. Check if human approval is required
  const needsApproval =
    params.category === 'intrusive_review_only' && policy.requireHumanApprovalForIntrusive;

  if (needsApproval && !params.approvedByHuman) {
    return {
      allowed: true,
      requiresHumanApproval: true,
      code: 'APPROVAL_REQUIRED',
      reason:
        'Job passed scope and authorization checks, but requires explicit human operator approval before agent claim.',
    };
  }

  return {
    allowed: true,
    requiresHumanApproval: false,
    code: 'POLICY_ALLOWED',
    reason: `Verified against authorization ${asset.authorizationRef} and policy "${policy.name}".`,
  };
}

export function validateAndSanitizeAiPlan(rawSteps: unknown[], asset: AuthorizedAsset, policy: ScopePolicy): AssessmentPlanStep[] {
  const validCategories: Array<AllowedMvpCategory | GatedCategory> = [
    'passive_http_headers',
    'static_code_analysis',
    'intrusive_review_only',
  ];

  const sanitized: AssessmentPlanStep[] = [];

  for (let i = 0; i < rawSteps.length; i++) {
    const item = rawSteps[i] as Record<string, unknown>;
    if (!item || typeof item !== 'object') continue;

    const rawTitle = String(item.title || `Assessment Step ${i + 1}`).trim();
    const rawRationale = String(item.rationale || 'Verify security posture within authorized scope.').trim();

    // Reject any step that tries to sneak executable shell syntax into title or rationale
    if (containsExecutableShellSyntax(rawTitle) || containsExecutableShellSyntax(rawRationale)) {
      continue;
    }

    const candidateCategory = String(item.category || 'passive_http_headers') as AllowedMvpCategory | GatedCategory;
    const category: AllowedMvpCategory | GatedCategory =
      validCategories.includes(candidateCategory) && policy.allowedCategories.includes(candidateCategory)
        ? candidateCategory
        : 'passive_http_headers';

    const toolName =
      category === 'static_code_analysis'
        ? 'static_ast_pattern_scanner'
        : category === 'intrusive_review_only'
        ? 'architecture_review_gate'
        : 'passive_header_inspector';

    sanitized.push({
      stepNumber: sanitized.length + 1,
      title: rawTitle,
      category,
      targetHost: asset.targetHost,
      rationale: rawRationale,
      safeToolConfig: {
        toolName,
        inspectedControls:
          category === 'static_code_analysis'
            ? ['CWE-78 OS Command Injection', 'CWE-798 Hardcoded Secrets', 'CWE-89 SQL Injection', 'CWE-79 XSS']
            : [
                'Strict-Transport-Security',
                'Content-Security-Policy',
                'X-Content-Type-Options',
                'X-Frame-Options',
                'Referrer-Policy',
              ],
        rateLimitRpm: Math.min(15, policy.maxRateLimitRpm),
      },
      requiresHumanApproval: category === 'intrusive_review_only',
    });
  }

  return sanitized;
}

export function runPassiveHttpHeaderCheck(params: {
  jobId: string;
  assetId: string;
  targetHost: string;
  simulatedHeaders?: Record<string, string>;
  now?: Date;
}): {
  headersInspected: Record<string, string>;
  findings: SecurityFinding[];
  remediations: RemediationItem[];
} {
  const now = params.now || new Date();
  const headers: Record<string, string> = params.simulatedHeaders || {
    'content-type': 'text/html; charset=utf-8',
    'x-Frame-Options': 'SAMEORIGIN',
    server: 'nginx/1.18.0 (Ubuntu)',
  };

  const normalized: Record<string, string> = {};
  for (const [k, v] of Object.entries(headers)) {
    normalized[k.toLowerCase()] = v;
  }

  const findings: SecurityFinding[] = [];
  const remediations: RemediationItem[] = [];

  if (!normalized['strict-transport-security']) {
    const findingId = `fnd-${crypto.randomBytes(4).toString('hex')}`;
    findings.push({
      id: findingId,
      jobId: params.jobId,
      assetId: params.assetId,
      targetHost: params.targetHost,
      title: 'Missing HTTP Strict-Transport-Security (HSTS) Header',
      severity: 'medium',
      category: 'passive_http_headers',
      cweId: 'CWE-319',
      description:
        'The target HTTPS endpoint does not emit a Strict-Transport-Security response header, leaving browsers vulnerable to SSL-stripping downgrade attacks on initial connections.',
      evidence: `GET https://${params.targetHost}/ -> Strict-Transport-Security header absent`,
      status: 'remediation_planned',
      discoveredAt: now.toISOString(),
    });
    remediations.push({
      id: `rem-${crypto.randomBytes(4).toString('hex')}`,
      findingId,
      findingTitle: 'Missing HTTP Strict-Transport-Security (HSTS) Header',
      targetHost: params.targetHost,
      title: 'Add Strict-Transport-Security Response Header',
      proposedFix: 'Configure reverse proxy or application middleware to send HSTS with a minimum max-age of 31536000 seconds.',
      configOrCodeDiff: `+ add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;`,
      requiresHumanApproval: true,
      approvalStatus: 'pending_approval',
      approvedBy: null,
      approvalNote: null,
      approvedAt: null,
      createdAt: now.toISOString(),
    });
  }

  if (!normalized['content-security-policy']) {
    const findingId = `fnd-${crypto.randomBytes(4).toString('hex')}`;
    findings.push({
      id: findingId,
      jobId: params.jobId,
      assetId: params.assetId,
      targetHost: params.targetHost,
      title: 'Missing Content-Security-Policy (CSP) Header',
      severity: 'medium',
      category: 'passive_http_headers',
      cweId: 'CWE-693',
      description:
        'No Content-Security-Policy header was observed in passive HTTP response headers, reducing defense-in-depth against Cross-Site Scripting (XSS) and unauthorized script framing.',
      evidence: `GET https://${params.targetHost}/ -> Content-Security-Policy header absent`,
      status: 'remediation_planned',
      discoveredAt: now.toISOString(),
    });
    remediations.push({
      id: `rem-${crypto.randomBytes(4).toString('hex')}`,
      findingId,
      findingTitle: 'Missing Content-Security-Policy (CSP) Header',
      targetHost: params.targetHost,
      title: 'Deploy Restrictive Content-Security-Policy Header',
      proposedFix: 'Add a baseline Content-Security-Policy restricting default-src and script-src to trusted origins.',
      configOrCodeDiff: `+ Content-Security-Policy: default-src 'self'; frame-ancestors 'none'; object-src 'none';`,
      requiresHumanApproval: true,
      approvalStatus: 'pending_approval',
      approvedBy: null,
      approvalNote: null,
      approvedAt: null,
      createdAt: now.toISOString(),
    });
  }

  if (!normalized['x-content-type-options']) {
    const findingId = `fnd-${crypto.randomBytes(4).toString('hex')}`;
    findings.push({
      id: findingId,
      jobId: params.jobId,
      assetId: params.assetId,
      targetHost: params.targetHost,
      title: 'Missing X-Content-Type-Options: nosniff Header',
      severity: 'low',
      category: 'passive_http_headers',
      cweId: 'CWE-16',
      description: 'Browsers may MIME-sniff responses away from the declared Content-Type.',
      evidence: `GET https://${params.targetHost}/ -> X-Content-Type-Options header absent`,
      status: 'open',
      discoveredAt: now.toISOString(),
    });
  }

  return {
    headersInspected: normalized,
    findings,
    remediations,
  };
}

export function runSafeStaticCodeAnalysis(params: {
  jobId: string;
  assetId: string;
  targetHost: string;
  codeSnippet: string;
  filename?: string;
  now?: Date;
}): {
  findings: SecurityFinding[];
  remediations: RemediationItem[];
  rulesChecked: number;
} {
  const now = params.now || new Date();
  const code = params.codeSnippet || '';
  const fileLabel = params.filename || 'submitted_snippet.ts';
  const findings: SecurityFinding[] = [];
  const remediations: RemediationItem[] = [];

  const rules: Array<{
    id: string;
    title: string;
    severity: SecurityFinding['severity'];
    cweId: string;
    regex: RegExp;
    description: string;
    proposedFix: string;
    diffExample: string;
  }> = [
    {
      id: 'SAST-001',
      title: 'Dangerous Dynamic Code / Shell Execution Sink Detected',
      severity: 'critical',
      cweId: 'CWE-78',
      regex: /\b(eval\s*\(|child_process\.exec\s*\(|execSync\s*\(|os\.system\s*\(|subprocess\.(?:Popen|run|call)\s*\([^)]*shell\s*=\s*True)/,
      description:
        'Static analysis identified an unsafe command or dynamic code execution sink that can lead to Remote Code Execution (RCE) if untrusted input reaches it.',
      proposedFix: 'Replace shell execution with parameterized argument arrays (execFile / shell=False) or a strict operation allowlist.',
      diffExample: `- child_process.exec("nmap " + userTarget);\n+ child_process.execFile("/usr/bin/nmap", ["-sT", validatedTarget]);`,
    },
    {
      id: 'SAST-002',
      title: 'Hardcoded Secret or Credential Literal in Source Code',
      severity: 'high',
      cweId: 'CWE-798',
      regex: /(?:api[_-]?key|secret|password|private_key|token)\s*[:=]\s*["'][A-Za-z0-9_\-]{12,}["']/i,
      description:
        'A hardcoded secret or credential string literal was found in the supplied source snippet.',
      proposedFix: 'Move credentials to server-side environment variables injected via a secret manager.',
      diffExample: `- const apiKey = "sk_live_9988776655443322";\n+ const apiKey = process.env.SERVICE_API_KEY;`,
    },
    {
      id: 'SAST-003',
      title: 'Unparameterized SQL String Concatenation',
      severity: 'high',
      cweId: 'CWE-89',
      regex: /(?:SELECT|INSERT|UPDATE|DELETE)\s+[\s\S]{1,80}?(?:\+\s*[a-zA-Z0-9_.]|\$\{[a-zA-Z0-9_.]+\})/i,
      description:
        'SQL query string is constructed using direct variable interpolation or concatenation instead of bound parameters.',
      proposedFix: 'Use parameterized prepared statements ($1, ?) for all user-controlled query values.',
      diffExample: `- db.query(\`SELECT * FROM users WHERE email = '\${email}'\`);\n+ db.query('SELECT * FROM users WHERE email = $1', [email]);`,
    },
    {
      id: 'SAST-004',
      title: 'Disabled TLS Certificate Verification',
      severity: 'medium',
      cweId: 'CWE-295',
      regex: /(?:rejectUnauthorized\s*:\s*false|NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*['"]?0|verify\s*=\s*False)/,
      description:
        'TLS certificate chain validation is explicitly disabled, allowing Man-in-the-Middle (MitM) interception.',
      proposedFix: 'Keep TLS verification enabled and pin the internal CA bundle if using private certificates.',
      diffExample: `- https.Agent({ rejectUnauthorized: false })\n+ https.Agent({ rejectUnauthorized: true, ca: internalCaPem })`,
    },
  ];

  for (const rule of rules) {
    const match = code.match(rule.regex);
    if (match) {
      const findingId = `fnd-${crypto.randomBytes(4).toString('hex')}`;
      findings.push({
        id: findingId,
        jobId: params.jobId,
        assetId: params.assetId,
        targetHost: params.targetHost,
        title: `${rule.title} (${fileLabel})`,
        severity: rule.severity,
        category: 'static_code_analysis',
        cweId: rule.cweId,
        description: rule.description,
        evidence: `Matched pattern in ${fileLabel}: "${match[0].slice(0, 80)}"`,
        status: 'remediation_planned',
        discoveredAt: now.toISOString(),
      });

      remediations.push({
        id: `rem-${crypto.randomBytes(4).toString('hex')}`,
        findingId,
        findingTitle: `${rule.title} (${fileLabel})`,
        targetHost: params.targetHost,
        title: `Remediate ${rule.cweId}: ${rule.title}`,
        proposedFix: rule.proposedFix,
        configOrCodeDiff: rule.diffExample,
        requiresHumanApproval: true,
        approvalStatus: 'pending_approval',
        approvedBy: null,
        approvalNote: null,
        approvedAt: null,
        createdAt: now.toISOString(),
      });
    }
  }

  return {
    findings,
    remediations,
    rulesChecked: rules.length,
  };
}

export function claimJobIdempotently(params: {
  job: SecurityJob | undefined;
  agent: PollingAgentRecord | undefined;
  idempotencyClaimKey: string;
  now?: Date;
}): {
  ok: boolean;
  code:
    | 'JOB_CLAIMED'
    | 'IDEMPOTENT_CLAIM_REPLAY'
    | 'AGENT_UNAUTHORIZED'
    | 'AGENT_PAUSED_OR_DISCONNECTED'
    | 'JOB_NOT_FOUND'
    | 'JOB_EXPIRED'
    | 'JOB_PENDING_HUMAN_APPROVAL'
    | 'JOB_ALREADY_CLAIMED'
    | 'INVALID_CLAIM_KEY';
  message: string;
  job?: SecurityJob;
} {
  const now = params.now || new Date();
  const { job, agent, idempotencyClaimKey } = params;

  if (!agent || agent.status === 'revoked' || agent.status === 'uninstalled') {
    return {
      ok: false,
      code: 'AGENT_UNAUTHORIZED',
      message: 'Polling agent credential is missing, revoked, or uninstalled.',
    };
  }

  if (agent.status === 'paused' || agent.status === 'disconnected') {
    return {
      ok: false,
      code: 'AGENT_PAUSED_OR_DISCONNECTED',
      message: `Agent ${agent.hostname} is currently ${agent.status} and cannot claim new jobs.`,
    };
  }

  if (!idempotencyClaimKey || idempotencyClaimKey.trim().length < 6) {
    return {
      ok: false,
      code: 'INVALID_CLAIM_KEY',
      message: 'A non-empty idempotencyClaimKey (>= 6 chars) is required to claim a job.',
    };
  }

  if (!job) {
    return {
      ok: false,
      code: 'JOB_NOT_FOUND',
      message: 'Requested job ID does not exist.',
    };
  }

  // Check expiry first
  if (new Date(job.expiresAt).getTime() <= now.getTime()) {
    job.status = 'expired';
    return {
      ok: false,
      code: 'JOB_EXPIRED',
      message: `Job ${job.id} expired at ${job.expiresAt} and can no longer be claimed.`,
    };
  }

  if (job.status === 'pending_approval') {
    return {
      ok: false,
      code: 'JOB_PENDING_HUMAN_APPROVAL',
      message: `Job ${job.id} requires explicit human approval before an agent can claim it.`,
    };
  }

  // Idempotent replay check: same agent + same idempotencyClaimKey
  if (job.status === 'claimed') {
    if (job.claimedByAgentId === agent.id && job.idempotencyClaimKey === idempotencyClaimKey.trim()) {
      return {
        ok: true,
        code: 'IDEMPOTENT_CLAIM_REPLAY',
        message: `Idempotent claim confirmed for ${job.id} (already claimed by ${agent.hostname} with key ${idempotencyClaimKey}).`,
        job,
      };
    }
    return {
      ok: false,
      code: 'JOB_ALREADY_CLAIMED',
      message: `Job ${job.id} has already been claimed by another request or key.`,
    };
  }

  if (job.status !== 'queued') {
    return {
      ok: false,
      code: 'JOB_ALREADY_CLAIMED',
      message: `Job ${job.id} is in status "${job.status}" and cannot be claimed.`,
    };
  }

  job.status = 'claimed';
  job.claimedByAgentId = agent.id;
  job.idempotencyClaimKey = idempotencyClaimKey.trim();
  job.claimedAt = now.toISOString();
  agent.claimedJobsCount += 1;
  agent.lastPollAt = now.toISOString();
  agent.currentJobId = job.id;
  agent.currentJobStatus = 'executing_allowlisted_task';

  return {
    ok: true,
    code: 'JOB_CLAIMED',
    message: `Job ${job.id} claimed by ${agent.linuxUser}@${agent.hostname}.`,
    job,
  };
}

function hashEnrollmentOrToken(raw: string): string {
  return crypto.createHash('sha256').update(raw).digest('hex');
}

export function issueDeviceEnrollmentCode(params: {
  targetHostname: string;
  linuxUser: string;
  issuedBy: string;
  ttlMinutes?: number;
  now?: Date;
}): {
  plaintextCode: string;
  record: DeviceEnrollmentCode;
} {
  const now = params.now || new Date();
  const ttlMinutes = Math.max(1, Math.min(60, params.ttlMinutes ?? 10));
  const randomPart = crypto.randomBytes(6).toString('hex').toUpperCase();
  const plaintextCode = `STNL-ENROLL-${randomPart.slice(0, 4)}-${randomPart.slice(4, 8)}-${randomPart.slice(8, 12)}`;
  const expiresAt = new Date(now.getTime() + ttlMinutes * 60_000).toISOString();

  const record: DeviceEnrollmentCode = {
    id: `enr-${crypto.randomBytes(3).toString('hex')}`,
    codeHash: hashEnrollmentOrToken(plaintextCode),
    codePreview: `${plaintextCode.slice(0, 16)}••••`,
    targetHostname: (params.targetHostname || 'kali-research-node').trim().toLowerCase(),
    linuxUser: (params.linuxUser || 'kali').trim().toLowerCase(),
    issuedBy: params.issuedBy || 'Operator',
    issuedAt: now.toISOString(),
    expiresAt,
    consumedAt: null,
    consumedByAgentId: null,
    status: 'active',
  };

  return { plaintextCode, record };
}

export function enrollDeviceWithSingleUseCode(params: {
  enrollmentCodes: DeviceEnrollmentCode[];
  agents: PollingAgentRecord[];
  plaintextCode: string;
  hostname: string;
  linuxUser: string;
  uid: number;
  version?: string;
  osInfo?: string;
  systemdAutostartEnabled?: boolean;
  now?: Date;
}): {
  ok: boolean;
  code:
    | 'ENROLLED_PENDING_HEARTBEAT'
    | 'INVALID_ENROLLMENT_CODE'
    | 'ENROLLMENT_CODE_ALREADY_USED'
    | 'ENROLLMENT_CODE_EXPIRED'
    | 'ROOT_USER_FORBIDDEN';
  message: string;
  deviceToken?: string;
  agent?: PollingAgentRecord;
} {
  const now = params.now || new Date();
  const cleanCode = (params.plaintextCode || '').trim().toUpperCase();
  if (!cleanCode) {
    return {
      ok: false,
      code: 'INVALID_ENROLLMENT_CODE',
      message: 'Single-use enrollment code is required.',
    };
  }

  if (params.uid === 0 || params.uid < 1000) {
    return {
      ok: false,
      code: 'ROOT_USER_FORBIDDEN',
      message: `Security policy violation: agent UID ${params.uid} is privileged. Use a dedicated non-root user (UID >= 1000).`,
    };
  }

  const codeHash = hashEnrollmentOrToken(cleanCode);
  const matched = params.enrollmentCodes.find((c) => c.codeHash === codeHash);
  if (!matched) {
    return {
      ok: false,
      code: 'INVALID_ENROLLMENT_CODE',
      message: 'Unrecognized enrollment code.',
    };
  }

  if (matched.status === 'consumed' || matched.consumedAt) {
    return {
      ok: false,
      code: 'ENROLLMENT_CODE_ALREADY_USED',
      message: `Enrollment code ${matched.codePreview} has already been consumed (single-use only).`,
    };
  }

  if (matched.status === 'revoked' || new Date(matched.expiresAt).getTime() <= now.getTime()) {
    matched.status = 'expired';
    return {
      ok: false,
      code: 'ENROLLMENT_CODE_EXPIRED',
      message: `Enrollment code ${matched.codePreview} expired at ${matched.expiresAt}.`,
    };
  }

  const deviceToken = `stnl_agent_${crypto.randomBytes(18).toString('hex')}`;
  const agentId = `agt-${crypto.randomBytes(3).toString('hex')}`;
  const newAgent: PollingAgentRecord = {
    id: agentId,
    hostname: (params.hostname || matched.targetHostname || 'kali-node').trim().toLowerCase(),
    linuxUser: (params.linuxUser || matched.linuxUser || 'kali').trim(),
    uid: params.uid,
    version: (params.version || '2.1.0').trim(),
    osInfo: (params.osInfo || 'Kali GNU/Linux Rolling 2026.1 (x86_64)').trim(),
    serviceAccount: (params.linuxUser || matched.linuxUser || 'kali').trim(),
    systemdAutostartEnabled: params.systemdAutostartEnabled ?? true,
    credentialFingerprint: `stnl_agent_••••${deviceToken.slice(-6)}`,
    credentialHash: hashEnrollmentOrToken(deviceToken),
    pollingMode: 'outbound_https_poll',
    // CRITICAL INVARIANT: Never mark online at enrollment time! Must wait for real authenticated heartbeat.
    status: 'pending_heartbeat',
    heartbeatVerifiedLive: false,
    currentJobId: null,
    currentJobStatus: 'idle',
    lastHeartbeatAt: null,
    lastPollAt: null,
    claimedJobsCount: 0,
    completedJobsCount: 0,
    enrolledAt: now.toISOString(),
    revokedAt: null,
    uninstalledAt: null,
  };

  matched.status = 'consumed';
  matched.consumedAt = now.toISOString();
  matched.consumedByAgentId = agentId;
  params.agents.unshift(newAgent);

  return {
    ok: true,
    code: 'ENROLLED_PENDING_HEARTBEAT',
    message: `Device ${newAgent.linuxUser}@${newAgent.hostname} registered in pending_heartbeat state. Send an authenticated heartbeat to transition online.`,
    deviceToken,
    agent: newAgent,
  };
}

export function processAuthenticatedAgentHeartbeat(params: {
  agent: PollingAgentRecord | undefined;
  version?: string;
  osInfo?: string;
  jobStatus?: 'idle' | 'claiming' | 'executing_allowlisted_task';
  systemdAutostartEnabled?: boolean;
  now?: Date;
}): {
  ok: boolean;
  code: 'HEARTBEAT_VERIFIED_ONLINE' | 'AGENT_PAUSED' | 'AGENT_DISCONNECTED' | 'AGENT_UNAUTHORIZED';
  message: string;
  agent?: PollingAgentRecord;
} {
  const now = params.now || new Date();
  const { agent } = params;

  if (!agent || agent.status === 'revoked' || agent.status === 'uninstalled') {
    return {
      ok: false,
      code: 'AGENT_UNAUTHORIZED',
      message: 'Device credential is invalid, revoked, or uninstalled.',
    };
  }

  if (params.version) agent.version = params.version.trim();
  if (params.osInfo) agent.osInfo = params.osInfo.trim();
  if (params.systemdAutostartEnabled !== undefined) {
    agent.systemdAutostartEnabled = Boolean(params.systemdAutostartEnabled);
  }

  agent.lastHeartbeatAt = now.toISOString();
  agent.heartbeatVerifiedLive = true;

  if (agent.status === 'paused') {
    agent.currentJobStatus = 'paused';
    return {
      ok: true,
      code: 'AGENT_PAUSED',
      message: `Heartbeat recorded for ${agent.hostname}, but agent is paused by operator control.`,
      agent,
    };
  }

  agent.status = 'online';
  agent.currentJobStatus = params.jobStatus || (agent.currentJobId ? 'executing_allowlisted_task' : 'idle');

  return {
    ok: true,
    code: 'HEARTBEAT_VERIFIED_ONLINE',
    message: `Authenticated heartbeat verified from ${agent.linuxUser}@${agent.hostname} (v${agent.version}). Agent is now online.`,
    agent,
  };
}

export function controlAgentDeviceState(params: {
  agent: PollingAgentRecord | undefined;
  jobs: SecurityJob[];
  action: 'pause' | 'resume' | 'disconnect' | 'revoke' | 'uninstall';
  now?: Date;
}): {
  ok: boolean;
  code: string;
  message: string;
  agent?: PollingAgentRecord;
} {
  const now = params.now || new Date();
  const { agent, jobs, action } = params;

  if (!agent) {
    return { ok: false, code: 'AGENT_NOT_FOUND', message: 'Target agent device not found.' };
  }

  if (action === 'pause') {
    if (agent.status === 'revoked' || agent.status === 'uninstalled') {
      return { ok: false, code: 'INVALID_STATE', message: `Cannot pause a ${agent.status} agent.` };
    }
    agent.status = 'paused';
    agent.currentJobStatus = 'paused';
    return {
      ok: true,
      code: 'AGENT_PAUSED',
      message: `Agent ${agent.hostname} paused. Outbound job polling is suspended until resumed.`,
      agent,
    };
  }

  if (action === 'resume') {
    if (agent.status === 'revoked' || agent.status === 'uninstalled') {
      return { ok: false, code: 'INVALID_STATE', message: `Cannot resume a ${agent.status} agent.` };
    }
    // Only mark online if an authenticated heartbeat was previously verified live
    agent.status = agent.heartbeatVerifiedLive ? 'online' : 'pending_heartbeat';
    agent.currentJobStatus = agent.currentJobId ? 'executing_allowlisted_task' : 'idle';
    return {
      ok: true,
      code: 'AGENT_RESUMED',
      message: `Agent ${agent.hostname} resumed (${agent.status}).`,
      agent,
    };
  }

  if (action === 'disconnect') {
    if (agent.status === 'revoked' || agent.status === 'uninstalled') {
      return { ok: false, code: 'INVALID_STATE', message: `Agent is already ${agent.status}.` };
    }
    agent.status = 'disconnected';
    agent.currentJobStatus = 'disconnected';
    return {
      ok: true,
      code: 'AGENT_DISCONNECTED',
      message: `Agent ${agent.hostname} disconnected from active polling. A fresh authenticated heartbeat is required to reconnect.`,
      agent,
    };
  }

  if (action === 'revoke') {
    agent.status = 'revoked';
    agent.revokedAt = now.toISOString();
    agent.currentJobId = null;
    agent.currentJobStatus = 'disconnected';
    for (const j of jobs) {
      if (j.status === 'claimed' && j.claimedByAgentId === agent.id) {
        j.status = 'queued';
        j.claimedByAgentId = null;
        j.idempotencyClaimKey = null;
        j.claimedAt = null;
      }
    }
    return {
      ok: true,
      code: 'AGENT_REVOKED',
      message: `Device credential for ${agent.hostname} remotely revoked. Any claimed jobs were returned to the queue.`,
      agent,
    };
  }

  // uninstall
  agent.status = 'uninstalled';
  agent.revokedAt = agent.revokedAt || now.toISOString();
  agent.uninstalledAt = now.toISOString();
  agent.currentJobId = null;
  agent.currentJobStatus = 'disconnected';
  for (const j of jobs) {
    if (j.status === 'claimed' && j.claimedByAgentId === agent.id) {
      j.status = 'queued';
      j.claimedByAgentId = null;
      j.idempotencyClaimKey = null;
      j.claimedAt = null;
    }
  }
  return {
    ok: true,
    code: 'AGENT_UNINSTALLED',
    message: `Agent ${agent.hostname} marked uninstalled and credentials invalidated. Run uninstall-sentinel-agent.sh locally on Kali to remove files.`,
    agent,
  };
}

export function rotateDeviceTokenRecord(params: {
  agent: PollingAgentRecord | undefined;
}): {
  ok: boolean;
  code: 'TOKEN_ROTATED' | 'AGENT_NOT_FOUND' | 'AGENT_REVOKED_OR_UNINSTALLED';
  message: string;
  newTokenPlaintext?: string;
  agent?: PollingAgentRecord;
} {
  const { agent } = params;
  if (!agent) {
    return { ok: false, code: 'AGENT_NOT_FOUND', message: 'Agent device not found.' };
  }
  if (agent.status === 'revoked' || agent.status === 'uninstalled') {
    return {
      ok: false,
      code: 'AGENT_REVOKED_OR_UNINSTALLED',
      message: `Cannot rotate token for ${agent.status} device ${agent.hostname}. Enroll a new device instead.`,
    };
  }
  const newTokenPlaintext = `stnl_agent_${crypto.randomBytes(18).toString('hex')}`;
  agent.credentialHash = hashEnrollmentOrToken(newTokenPlaintext);
  agent.credentialFingerprint = `stnl_agent_••••${newTokenPlaintext.slice(-6)}`;
  return {
    ok: true,
    code: 'TOKEN_ROTATED',
    message: `Rotated device token for ${agent.hostname} (${agent.credentialFingerprint}).`,
    newTokenPlaintext,
    agent,
  };
}
