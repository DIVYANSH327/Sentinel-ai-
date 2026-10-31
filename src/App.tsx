/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import React, { useEffect, useState, useCallback } from 'react';
import {
  Shield,
  LayoutDashboard,
  Terminal,
  Server,
  FileCheck2,
  Sparkles,
  Play,
  AlertTriangle,
  Wrench,
  Activity,
  ScrollText,
  UserCheck,
  RefreshCw,
} from 'lucide-react';
import {
  type PlatformBootstrapPayload,
  type PlatformTabId,
  buildClientMockBootstrap,
} from './types/platform';
import {
  evaluateJobPolicy,
  runPassiveHttpHeaderCheck,
  runSafeStaticCodeAnalysis,
  type JobCategory,
  type AllowedMvpCategory,
  type GatedCategory,
} from './lib/policyEngine';
import { OverviewSection } from './components/platform/OverviewSection';
import { KaliAgentSetupSection } from './components/platform/KaliAgentSetupSection';
import {
  AuthorizedAssetsSection,
  ScopePoliciesSection,
} from './components/platform/AssetsAndPoliciesViews';
import {
  AssessmentPlansSection,
  JobQueueSection,
} from './components/platform/PlansAndJobsViews';
import {
  FindingsSection,
  RemediationSection,
} from './components/platform/FindingsAndRemediationViews';
import {
  AgentHealthSection,
  AuditLogsSection,
} from './components/platform/AgentHealthAndAuditViews';

const NAV_TABS: {
  id: PlatformTabId;
  label: string;
  shortLabel: string;
  icon: React.FC<{ className?: string }>;
}[] = [
  { id: 'overview', label: 'Overview', shortLabel: 'Overview', icon: LayoutDashboard },
  { id: 'agent-setup', label: 'Kali Agent Setup', shortLabel: 'Kali Setup', icon: Terminal },
  { id: 'agent-health', label: 'Agent Health & Devices', shortLabel: 'Devices', icon: Activity },
  { id: 'authorized-assets', label: 'Authorized Assets', shortLabel: 'Assets', icon: Server },
  { id: 'scope-policies', label: 'Scope Policies', shortLabel: 'Policies', icon: FileCheck2 },
  { id: 'assessment-plans', label: 'Assessment Plans', shortLabel: 'AI Plans', icon: Sparkles },
  { id: 'job-queue', label: 'Job Queue', shortLabel: 'Jobs', icon: Play },
  { id: 'findings', label: 'Findings', shortLabel: 'Findings', icon: AlertTriangle },
  { id: 'remediation', label: 'Remediation', shortLabel: 'Remediation', icon: Wrench },
  { id: 'audit-logs', label: 'Audit Logs', shortLabel: 'Audit Logs', icon: ScrollText },
];

export default function App() {
  const [activeTab, setActiveTab] = useState<PlatformTabId>('overview');
  const [demoMode, setDemoMode] = useState<boolean>(false);
  const [liveData, setLiveData] = useState<PlatformBootstrapPayload | null>(null);
  const [mockData, setMockData] = useState<PlatformBootstrapPayload>(() =>
    buildClientMockBootstrap()
  );
  const [loading, setLoading] = useState<boolean>(true);
  const [statusBanner, setStatusBanner] = useState<{
    type: 'info' | 'success' | 'error';
    text: string;
  } | null>(null);
  const [operatorModalOpen, setOperatorModalOpen] = useState<boolean>(false);
  const [selectedOperatorId, setSelectedOperatorId] = useState<string>('op-01');
  const [passphraseInput, setPassphraseInput] = useState<string>('demo-switch');

  const fetchBootstrap = useCallback(async () => {
    try {
      const res = await fetch('/api/v1/bootstrap');
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const payload = (await res.json()) as PlatformBootstrapPayload;
      setLiveData(payload);
    } catch {
      setDemoMode(true);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void fetchBootstrap();
  }, [fetchBootstrap]);

  const currentData: PlatformBootstrapPayload =
    demoMode || !liveData ? mockData : liveData;

  const currentOp = currentData.currentOperator || {
    id: 'op-01',
    email: 'neha.raut@sentinel.research.internal',
    displayName: 'Neha Raut',
    role: 'lead_researcher' as const,
  };

  const notify = (type: 'info' | 'success' | 'error', text: string) => {
    setStatusBanner({ type, text });
  };

  const handleOperatorSwitch = async (e: React.FormEvent) => {
    e.preventDefault();
    const chosen = currentData.availableOperators.find((o) => o.id === selectedOperatorId);
    if (demoMode) {
      if (chosen) {
        setMockData((prev) => ({
          ...prev,
          currentOperator: chosen,
          auditLogs: [
            {
              id: `aud-${Date.now()}`,
              timestamp: new Date().toISOString(),
              actor: `${chosen.displayName} (${chosen.role})`,
              action: 'AUTH_SESSION_ESTABLISHED',
              resourceType: 'auth',
              resourceId: chosen.id,
              decision: 'allowed',
              summary: `Authenticated operator session switched to ${chosen.displayName} in Mock Mode.`,
              metadata: { role: chosen.role },
            },
            ...prev.auditLogs,
          ],
        }));
        notify('success', `Switched operator session to ${chosen.displayName} (${chosen.role}).`);
      }
      setOperatorModalOpen(false);
      return;
    }

    try {
      const res = await fetch('/api/v1/auth/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          email: chosen?.email || 'neha.raut@sentinel.research.internal',
          password: passphraseInput || 'demo-switch',
        }),
      });
      const json = await res.json();
      if (!res.ok || !json.ok) {
        notify('error', json.message || 'Authentication failed.');
        return;
      }
      await fetchBootstrap();
      notify('success', json.message || 'Operator session updated.');
      setOperatorModalOpen(false);
    } catch {
      notify('error', 'Failed to reach authentication endpoint.');
    }
  };

  const handleResetDemoState = async () => {
    if (demoMode) {
      setMockData(buildClientMockBootstrap());
      notify('info', 'Mock/Demo workspace reset to initial seed state.');
      return;
    }
    try {
      await fetch('/api/v1/reset', { method: 'POST' });
      await fetchBootstrap();
      notify('info', 'Persistent platform state reset to verified baseline.');
    } catch {
      notify('error', 'Could not reset backend state.');
    }
  };

  // --- Device Enrollment & Management Handlers ---
  const handleIssueEnrollmentCode = async (payload: {
    targetHostname: string;
    linuxUser: string;
    ttlMinutes: number;
  }): Promise<{ ok: boolean; message: string; plaintextCode?: string }> => {
    if (demoMode) {
      const rand = Math.random().toString(16).slice(2, 10).toUpperCase();
      const plaintextCode = `STNL-ENROLL-${rand.slice(0, 4)}-${rand.slice(4, 8)}-MOCK`;
      const now = new Date();
      const expiresAt = new Date(now.getTime() + payload.ttlMinutes * 60_000).toISOString();
      const newRec = {
        id: `enr-${Date.now().toString().slice(-4)}`,
        codePreview: `${plaintextCode.slice(0, 16)}••••`,
        targetHostname: payload.targetHostname,
        linuxUser: payload.linuxUser,
        issuedBy: currentOp.displayName,
        issuedAt: now.toISOString(),
        expiresAt,
        consumedAt: null,
        consumedByAgentId: null,
        status: 'active' as const,
      };
      setMockData((prev) => ({
        ...prev,
        enrollmentCodes: [newRec, ...(prev.enrollmentCodes || [])],
      }));
      return {
        ok: true,
        plaintextCode,
        message: `Issued single-use enrollment code for ${payload.linuxUser}@${payload.targetHostname} in Mock Mode.`,
      };
    }

    const res = await fetch('/api/v1/enrollments/issue', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    });
    const json = await res.json();
    await fetchBootstrap();
    return {
      ok: Boolean(json.ok),
      message: json.message || 'Enrollment code request processed.',
      plaintextCode: json.plaintextCode,
    };
  };

  const handleEnrollDeviceWithCode = async (payload: {
    enrollmentCode: string;
    hostname: string;
    linuxUser: string;
    uid: number;
    version: string;
    osInfo: string;
  }): Promise<{ ok: boolean; code: string; message: string }> => {
    if (demoMode) {
      if (payload.uid === 0 || payload.uid < 1000) {
        return {
          ok: false,
          code: 'ROOT_USER_FORBIDDEN',
          message: `Security policy violation: agent UID ${payload.uid} is privileged. Use a dedicated non-root user (UID >= 1000).`,
        };
      }
      const newAgent = {
        id: `agt-${Date.now().toString().slice(-4)}`,
        hostname: payload.hostname,
        linuxUser: payload.linuxUser,
        uid: payload.uid,
        version: payload.version,
        osInfo: payload.osInfo,
        serviceAccount: payload.linuxUser,
        systemdAutostartEnabled: true,
        credentialFingerprint: `stnl_agent_••••${Math.random().toString(16).slice(2, 8)}`,
        pollingMode: 'outbound_https_poll' as const,
        status: 'pending_heartbeat' as const,
        heartbeatVerifiedLive: false,
        currentJobId: null,
        currentJobStatus: 'idle' as const,
        lastHeartbeatAt: null,
        lastPollAt: null,
        claimedJobsCount: 0,
        completedJobsCount: 0,
        enrolledAt: new Date().toISOString(),
        revokedAt: null,
        uninstalledAt: null,
      };
      setMockData((prev) => ({
        ...prev,
        agents: [newAgent, ...prev.agents],
      }));
      return {
        ok: true,
        code: 'ENROLLED_PENDING_HEARTBEAT',
        message: `Registered ${newAgent.linuxUser}@${newAgent.hostname} in pending_heartbeat state (Mock Mode). Send an authenticated heartbeat to transition online.`,
      };
    }

    const res = await fetch('/api/v1/agent/enroll', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    });
    const json = await res.json();
    await fetchBootstrap();
    return {
      ok: Boolean(json.ok),
      code: json.code || 'ENROLL_RESULT',
      message: json.message || 'Enrollment request processed.',
    };
  };

  const handleSendHeartbeat = async (agentId: string): Promise<{ ok: boolean; message: string }> => {
    if (demoMode) {
      const nowIso = new Date().toISOString();
      setMockData((prev) => ({
        ...prev,
        agents: prev.agents.map((a) =>
          a.id === agentId && a.status !== 'revoked' && a.status !== 'uninstalled'
            ? {
                ...a,
                status: a.status === 'paused' ? 'paused' : 'online',
                heartbeatVerifiedLive: true,
                lastHeartbeatAt: nowIso,
              }
            : a
        ),
        integrationStatus: {
          ...prev.integrationStatus,
          kaliAgentPolledLive: true,
          lastTestedAt: nowIso,
        },
      }));
      return {
        ok: true,
        message: `Authenticated heartbeat verified for ${agentId} in Mock Mode. Device is now online.`,
      };
    }

    const res = await fetch('/api/v1/agent/heartbeat', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ agentId, useServerVault: true, version: '2.1.0' }),
    });
    const json = await res.json();
    await fetchBootstrap();
    return {
      ok: Boolean(json.ok),
      message: json.message || 'Heartbeat processed.',
    };
  };

  const handleControlAgentDevice = async (
    agentId: string,
    action: 'pause' | 'resume' | 'disconnect' | 'revoke' | 'uninstall'
  ): Promise<{ ok: boolean; message: string }> => {
    if (demoMode) {
      setMockData((prev) => ({
        ...prev,
        agents: prev.agents.map((a) => {
          if (a.id !== agentId) return a;
          if (action === 'pause') return { ...a, status: 'paused', currentJobStatus: 'paused' };
          if (action === 'resume') {
            return {
              ...a,
              status: a.heartbeatVerifiedLive ? 'online' : 'pending_heartbeat',
              currentJobStatus: 'idle',
            };
          }
          if (action === 'disconnect') {
            return { ...a, status: 'disconnected', currentJobStatus: 'disconnected' };
          }
          if (action === 'revoke') {
            return { ...a, status: 'revoked', currentJobStatus: 'disconnected' };
          }
          return { ...a, status: 'uninstalled', currentJobStatus: 'disconnected' };
        }),
      }));
      return {
        ok: true,
        message: `Device ${agentId} action "${action}" applied in Mock Mode.`,
      };
    }

    const res = await fetch(`/api/v1/agents/${agentId}/control`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ action }),
    });
    const json = await res.json();
    await fetchBootstrap();
    return {
      ok: Boolean(json.ok),
      message: json.message || `Action ${action} processed.`,
    };
  };

  // --- Asset, Policy, Plan & Job Handlers ---
  const handleRegisterAsset = async (payload: {
    name: string;
    targetHost: string;
    ipOrCidr: string;
    environment: 'staging' | 'isolated_lab' | 'production_read_only';
    ownerTeam: string;
    authorizationRef: string;
    verified: boolean;
  }): Promise<{ ok: boolean; message: string }> => {
    if (demoMode) {
      const newAsset = {
        id: `ast-${Date.now().toString().slice(-4)}`,
        ...payload,
        verifiedBy: payload.verified ? currentOp.displayName : null,
        expiresAt: new Date(Date.now() + 90 * 86400_000).toISOString(),
        createdAt: new Date().toISOString(),
      };
      setMockData((prev) => ({
        ...prev,
        assets: [newAsset, ...prev.assets],
      }));
      return { ok: true, message: `Registered asset ${newAsset.targetHost} in Mock Mode.` };
    }
    const res = await fetch('/api/v1/assets', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    });
    const json = await res.json();
    if (!res.ok || !json.ok) return { ok: false, message: json.message || 'Failed to register asset.' };
    await fetchBootstrap();
    return { ok: true, message: `Registered asset ${json.asset.targetHost}.` };
  };

  const handleVerifyAsset = async (assetId: string): Promise<{ ok: boolean; message: string }> => {
    if (demoMode) {
      setMockData((prev) => ({
        ...prev,
        assets: prev.assets.map((a) =>
          a.id === assetId ? { ...a, verified: true, verifiedBy: currentOp.displayName } : a
        ),
      }));
      return { ok: true, message: `Verified asset ${assetId} in Mock Mode.` };
    }
    const res = await fetch(`/api/v1/assets/${assetId}/verify`, { method: 'POST' });
    const json = await res.json();
    if (!res.ok || !json.ok) return { ok: false, message: json.message || 'Verification failed.' };
    await fetchBootstrap();
    return { ok: true, message: json.message || 'Verified asset authorization.' };
  };

  const handleCreatePolicy = async (payload: {
    name: string;
    authorizationRef: string;
    permittedHosts: string[];
    permittedCidrs: string[];
    maxRateLimitRpm: number;
  }): Promise<{ ok: boolean; message: string }> => {
    if (demoMode) {
      const newPol = {
        id: `pol-${Date.now().toString().slice(-4)}`,
        ...payload,
        allowedCategories: ['passive_http_headers', 'static_code_analysis', 'intrusive_review_only'] as Array<
          AllowedMvpCategory | GatedCategory
        >,
        requireHumanApprovalForIntrusive: true,
        expiresAt: new Date(Date.now() + 90 * 86400_000).toISOString(),
        active: true,
        createdAt: new Date().toISOString(),
      };
      setMockData((prev) => ({
        ...prev,
        policies: [newPol, ...prev.policies],
      }));
      return { ok: true, message: `Created scope policy ${newPol.name} in Mock Mode.` };
    }
    const res = await fetch('/api/v1/policies', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    });
    const json = await res.json();
    if (!res.ok || !json.ok) return { ok: false, message: json.message || 'Failed to create policy.' };
    await fetchBootstrap();
    return { ok: true, message: `Created scope policy ${json.policy.name}.` };
  };

  const handleEvaluatePolicy = async (payload: {
    assetId: string;
    policyId: string;
    targetHost: string;
    category: string;
    requestedRateLimitRpm: number;
  }) => {
    if (demoMode) {
      const asset = mockData.assets.find((a) => a.id === payload.assetId);
      const policy = mockData.policies.find((p) => p.id === payload.policyId);
      const evaluation = evaluateJobPolicy({
        asset,
        policy,
        targetHost: payload.targetHost,
        category: payload.category as JobCategory,
        requestedRateLimitRpm: payload.requestedRateLimitRpm,
      });
      return { evaluation };
    }
    const res = await fetch('/api/v1/policies/evaluate', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    });
    return await res.json();
  };

  const handleGeneratePlan = async (payload: {
    assetId: string;
    policyId: string;
    objective: string;
  }): Promise<{ ok: boolean; notice?: string; message?: string }> => {
    if (demoMode) {
      const asset = mockData.assets.find((a) => a.id === payload.assetId) || mockData.assets[0];
      const policy = mockData.policies.find((p) => p.id === payload.policyId) || mockData.policies[0];
      const plan = {
        id: `pln-${Date.now().toString().slice(-4)}`,
        title: `Structured Assessment Plan: ${asset.targetHost}`,
        objective: payload.objective,
        assetId: asset.id,
        policyId: policy.id,
        generatedBySource: 'deterministic_fallback' as const,
        modelName: 'deterministic-safe-planner-v1',
        steps: [
          {
            stepNumber: 1,
            title: 'Passive HTTP Security-Header Baseline Inspection',
            category: 'passive_http_headers' as const,
            targetHost: asset.targetHost,
            rationale: 'Verify HSTS, CSP, X-Frame-Options, and X-Content-Type-Options without active exploitation.',
            safeToolConfig: {
              toolName: 'passive_header_inspector' as const,
              inspectedControls: ['Strict-Transport-Security', 'Content-Security-Policy', 'X-Frame-Options'],
              rateLimitRpm: Math.min(15, policy.maxRateLimitRpm),
            },
            requiresHumanApproval: false,
          },
          {
            stepNumber: 2,
            title: 'Static Source Code Security Pattern Review',
            category: 'static_code_analysis' as const,
            targetHost: asset.targetHost,
            rationale: 'Scan supplied code snippets for hardcoded credentials and command injection sinks.',
            safeToolConfig: {
              toolName: 'static_ast_pattern_scanner' as const,
              inspectedControls: ['CWE-798', 'CWE-78', 'CWE-89'],
              rateLimitRpm: Math.min(10, policy.maxRateLimitRpm),
            },
            requiresHumanApproval: false,
          },
        ],
        safetyAttestation:
          'Validated structured JSON plan. Zero shell commands or prohibited categories included.',
        createdBy: currentOp.displayName,
        createdAt: new Date().toISOString(),
      };
      setMockData((prev) => ({ ...prev, plans: [plan, ...prev.plans] }));
      return { ok: true, notice: 'Generated structured JSON plan in Mock Mode.' };
    }
    const res = await fetch('/api/v1/plans/generate', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    });
    const json = await res.json();
    if (!res.ok || !json.ok) return { ok: false, message: json.message || 'Failed to generate plan.' };
    await fetchBootstrap();
    return { ok: true, notice: json.notice || 'Structured assessment plan generated.' };
  };

  const handleCreateJob = async (payload: {
    assetId: string;
    policyId: string;
    category: string;
    targetHost: string;
    rateLimitRpm: number;
    codeSnippet?: string;
    codeFilename?: string;
    executeImmediatelyInMvp?: boolean;
  }): Promise<{ ok: boolean; code: string; message: string }> => {
    if (demoMode) {
      const asset = mockData.assets.find((a) => a.id === payload.assetId);
      const policy = mockData.policies.find((p) => p.id === payload.policyId);
      const evalRes = evaluateJobPolicy({
        asset,
        policy,
        targetHost: payload.targetHost,
        category: payload.category as JobCategory,
        requestedRateLimitRpm: payload.rateLimitRpm,
      });
      if (!evalRes.allowed) {
        return { ok: false, code: evalRes.code, message: evalRes.reason };
      }
      const newJobId = `job-${Date.now().toString().slice(-4)}`;
      if (payload.executeImmediatelyInMvp && !evalRes.requiresHumanApproval) {
        const analysis =
          payload.category === 'static_code_analysis'
            ? runSafeStaticCodeAnalysis({
                jobId: newJobId,
                assetId: payload.assetId,
                targetHost: payload.targetHost,
                filename: payload.codeFilename || 'snippet.ts',
                codeSnippet: payload.codeSnippet || '',
              })
            : runPassiveHttpHeaderCheck({
                jobId: newJobId,
                assetId: payload.assetId,
                targetHost: payload.targetHost,
              });
        setMockData((prev) => ({
          ...prev,
          jobs: [
            {
              id: newJobId,
              assetId: payload.assetId,
              policyId: payload.policyId,
              category: payload.category as AllowedMvpCategory,
              targetHost: payload.targetHost,
              rateLimitRpm: payload.rateLimitRpm,
              status: 'completed',
              requiresApproval: false,
              approvedBy: currentOp.displayName,
              approvedAt: new Date().toISOString(),
              claimedByAgentId: 'mvp-safe-runner',
              idempotencyClaimKey: `mvp-${newJobId}`,
              claimedAt: new Date().toISOString(),
              expiresAt: new Date(Date.now() + 3600_000).toISOString(),
              resultSummary: {
                checkedItems: 6,
                findingsCount: analysis.findings.length,
                summaryText: `Executed safe MVP check (${analysis.findings.length} findings).`,
              },
              completedAt: new Date().toISOString(),
              createdBy: currentOp.displayName,
              createdAt: new Date().toISOString(),
            },
            ...prev.jobs,
          ],
          findings: [...analysis.findings, ...prev.findings],
          remediations: [...analysis.remediations, ...prev.remediations],
        }));
        return {
          ok: true,
          code: 'COMPLETED',
          message: `Safe MVP job ${newJobId} executed (${analysis.findings.length} findings).`,
        };
      }
      return { ok: true, code: evalRes.code, message: evalRes.reason };
    }

    const res = await fetch('/api/v1/jobs', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    });
    const json = await res.json();
    await fetchBootstrap();
    if (!res.ok || !json.ok) {
      return {
        ok: false,
        code: json.code || 'POLICY_REJECTED',
        message: json.message || 'Policy engine rejected job.',
      };
    }
    return {
      ok: true,
      code: json.code || 'ALLOWED',
      message: json.message || `Job ${json.job.id} created.`,
    };
  };

  const handleApproveJob = async (jobId: string): Promise<{ ok: boolean; message: string }> => {
    if (demoMode) {
      setMockData((prev) => ({
        ...prev,
        jobs: prev.jobs.map((j) =>
          j.id === jobId ? { ...j, status: 'queued', approvedBy: currentOp.displayName } : j
        ),
      }));
      return { ok: true, message: `Approved job ${jobId} in Mock Mode.` };
    }
    const res = await fetch(`/api/v1/jobs/${jobId}/approve`, { method: 'POST' });
    const json = await res.json();
    if (!res.ok || !json.ok) return { ok: false, message: json.message || 'Failed to approve job.' };
    await fetchBootstrap();
    return { ok: true, message: json.message || `Approved job ${jobId}.` };
  };

  const handleApproveRemediation = async (
    remId: string,
    approvalNote: string
  ): Promise<{ ok: boolean; message: string }> => {
    if (demoMode) {
      setMockData((prev) => ({
        ...prev,
        remediations: prev.remediations.map((r) =>
          r.id === remId
            ? { ...r, approvalStatus: 'approved', approvedBy: currentOp.displayName, approvalNote }
            : r
        ),
      }));
      return { ok: true, message: `Approved remediation ${remId} in Mock Mode.` };
    }
    const res = await fetch(`/api/v1/remediations/${remId}/approve`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ approvalNote }),
    });
    const json = await res.json();
    if (!res.ok || !json.ok) return { ok: false, message: json.message || 'Approval failed.' };
    await fetchBootstrap();
    return { ok: true, message: json.message || 'Remediation approved.' };
  };

  const handlePollJobs = async (
    agentId?: string
  ): Promise<{
    ok: boolean;
    message: string;
    eligibleCount?: number;
  }> => {
    if (demoMode) {
      const queued = mockData.jobs.filter((j) => j.status === 'queued');
      return {
        ok: true,
        eligibleCount: queued.length,
        message: `Mock Outbound Poll complete: ${queued.length} eligible queued job(s).`,
      };
    }
    const res = await fetch('/api/v1/agent/poll', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ agentId, useServerVault: true }),
    });
    const json = await res.json();
    await fetchBootstrap();
    if (!res.ok || !json.ok) return { ok: false, message: json.message || 'Outbound poll failed.' };
    return {
      ok: true,
      eligibleCount: json.eligibleJobs?.length || 0,
      message: `Outbound HTTPS poll verified (${json.eligibleJobs?.length || 0} eligible jobs). Heartbeat updated.`,
    };
  };

  const handleClaimJob = async (
    jobId: string,
    idempotencyClaimKey: string,
    agentId?: string
  ): Promise<{ ok: boolean; code: string; message: string }> => {
    if (demoMode) {
      return {
        ok: true,
        code: 'CLAIMED',
        message: `Claimed job ${jobId} with key ${idempotencyClaimKey} in Mock Mode.`,
      };
    }
    const res = await fetch(`/api/v1/agent/jobs/${jobId}/claim`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        agentId,
        useServerVault: true,
        idempotencyClaimKey,
      }),
    });
    const json = await res.json();
    await fetchBootstrap();
    return {
      ok: Boolean(json.ok),
      code: json.code || (json.ok ? 'CLAIMED' : 'CLAIM_ERROR'),
      message: json.message || 'Claim processed.',
    };
  };

  const handleSubmitJobResult = async (
    jobId: string,
    agentId?: string
  ): Promise<{ ok: boolean; message: string }> => {
    if (demoMode) {
      return { ok: true, message: `Submitted structured result for ${jobId} in Mock Mode.` };
    }
    const res = await fetch(`/api/v1/agent/jobs/${jobId}/result`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ agentId, useServerVault: true }),
    });
    const json = await res.json();
    await fetchBootstrap();
    if (!res.ok || !json.ok) return { ok: false, message: json.message || 'Result submission failed.' };
    return {
      ok: true,
      message: json.message || `Submitted structured result for ${jobId}.`,
    };
  };

  const handleRotateAgentCredential = async (
    agentId: string
  ): Promise<{
    ok: boolean;
    message: string;
  }> => {
    if (demoMode) {
      return { ok: true, message: `Rotated device token for ${agentId} in Mock Mode.` };
    }
    const res = await fetch(`/api/v1/agents/${agentId}/rotate-token`, { method: 'POST' });
    const json = await res.json();
    await fetchBootstrap();
    return { ok: Boolean(json.ok), message: json.message || 'Rotated per-device credential.' };
  };

  return (
    <div className="min-h-screen bg-[#0B1120] text-slate-100 flex flex-col selection:bg-teal-500/30 selection:text-teal-200">
      {/* Two-Tier Control Plane Header */}
      <header className="sticky top-0 z-30 border-b border-slate-800/80 bg-[#0B1120]/95 backdrop-blur">
        <div className="max-w-[1440px] mx-auto px-4 sm:px-6 h-14 flex items-center justify-between gap-2">
          {/* Zone 1: Brand Identity */}
          <div className="flex items-center gap-2.5 min-w-0">
            <div className="w-8 h-8 rounded-lg bg-teal-500/10 border border-teal-500/30 flex items-center justify-center text-teal-400 shrink-0">
              <Shield className="w-4 h-4" />
            </div>
            <div className="min-w-0">
              <div className="flex items-center gap-2">
                <span className="font-semibold text-sm sm:text-base tracking-tight text-slate-100 truncate">
                  Sentinel AI
                </span>
                <span className="hidden md:inline-block text-[11px] font-mono uppercase tracking-wider text-teal-400">
                  · Security Research Platform
                </span>
              </div>
            </div>
          </div>

          {/* Zone 2: Runtime Mode & Operator Auth Control */}
          <div className="flex items-center gap-1.5 sm:gap-2 shrink-0">
            <button
              onClick={() => {
                setDemoMode((prev) => !prev);
                notify(
                  'info',
                  !demoMode
                    ? 'Switched to Mock / Demo Mode (safe offline simulation).'
                    : 'Switched to Live Backend API & Persistent Store.'
                );
              }}
              className={`px-2 sm:px-2.5 py-1.5 rounded-lg border text-[11px] sm:text-xs font-mono transition-colors cursor-pointer whitespace-nowrap ${
                demoMode
                  ? 'border-amber-500/40 bg-amber-500/10 text-amber-300'
                  : 'border-teal-500/40 bg-teal-500/10 text-teal-300'
              }`}
              title="Toggle between Live Node.js Backend and Client Mock/Demo Mode"
            >
              {demoMode ? 'MOCK MODE' : 'LIVE API'}
            </button>

            <button
              onClick={() => setOperatorModalOpen(true)}
              className="px-2 sm:px-2.5 py-1.5 rounded-lg border border-slate-800 bg-slate-900/90 hover:border-slate-700 text-xs text-slate-200 flex items-center gap-1.5 cursor-pointer whitespace-nowrap"
              title="Switch authenticated operator session"
            >
              <UserCheck className="w-3.5 h-3.5 text-teal-400 shrink-0" />
              <span className="font-medium">{currentOp.displayName}</span>
              <span className="hidden sm:inline font-mono text-[11px] text-slate-400">
                · {currentOp.role}
              </span>
            </button>

            <button
              onClick={() => void handleResetDemoState()}
              className="p-1.5 rounded-lg border border-slate-800 bg-slate-900/90 hover:border-slate-700 text-slate-400 hover:text-slate-200 cursor-pointer shrink-0"
              title="Reset platform data to baseline seed"
              aria-label="Reset platform data"
            >
              <RefreshCw className="w-3.5 h-3.5" />
            </button>
          </div>
        </div>

        {/* Dedicated 10-Section Navigation Bar */}
        <div className="border-t border-slate-800/70 bg-slate-950/60">
          <div className="max-w-[1440px] mx-auto px-4 sm:px-6 py-1.5 overflow-x-auto">
            <nav
              aria-label="Primary Platform Sections"
              className="flex items-center gap-1 min-w-max"
            >
              {NAV_TABS.map((tab) => {
                const Icon = tab.icon;
                const isActive = activeTab === tab.id;
                return (
                  <button
                    key={tab.id}
                    onClick={() => setActiveTab(tab.id)}
                    className={`px-3 py-1.5 rounded-md text-xs font-medium transition-colors flex items-center gap-1.5 cursor-pointer whitespace-nowrap ${
                      isActive
                        ? 'bg-teal-500/15 text-teal-300 border border-teal-500/30'
                        : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/60 border border-transparent'
                    }`}
                  >
                    <Icon className="w-3.5 h-3.5" />
                    <span>{tab.label}</span>
                  </button>
                );
              })}
            </nav>
          </div>
        </div>
      </header>

      {/* Optional Status Feedback Toast */}
      {statusBanner && (
        <div className="max-w-[1440px] w-full mx-auto px-4 sm:px-6 pt-4">
          <div
            className={`rounded-lg border px-4 py-2.5 text-xs flex items-center justify-between gap-3 ${
              statusBanner.type === 'error'
                ? 'border-rose-500/40 bg-rose-950/40 text-rose-200'
                : statusBanner.type === 'success'
                  ? 'border-teal-500/40 bg-teal-950/40 text-teal-200'
                  : 'border-slate-700 bg-slate-900/90 text-slate-200'
            }`}
          >
            <span>{statusBanner.text}</span>
            <button
              onClick={() => setStatusBanner(null)}
              className="text-xs font-mono underline opacity-80 hover:opacity-100 cursor-pointer"
            >
              Dismiss
            </button>
          </div>
        </div>
      )}

      {/* Main Content Area */}
      <main className="flex-1 max-w-[1440px] w-full mx-auto px-4 sm:px-6 py-6">
        {loading ? (
          <div className="rounded-xl border border-slate-800 bg-[#0F172A] p-8 text-center text-sm text-slate-400">
            Initializing Sentinel AI Governance &amp; Policy Engine...
          </div>
        ) : (
          <>
            {activeTab === 'overview' && (
              <OverviewSection
                data={currentData}
                demoMode={demoMode}
                onNavigate={setActiveTab}
              />
            )}
            {activeTab === 'agent-setup' && (
              <KaliAgentSetupSection
                data={currentData}
                demoMode={demoMode}
                onIssueEnrollmentCode={handleIssueEnrollmentCode}
                onEnrollDeviceWithCode={handleEnrollDeviceWithCode}
                onNavigate={setActiveTab}
              />
            )}
            {activeTab === 'authorized-assets' && (
              <AuthorizedAssetsSection
                data={currentData}
                onRegisterAsset={handleRegisterAsset}
                onVerifyAsset={handleVerifyAsset}
              />
            )}
            {activeTab === 'scope-policies' && (
              <ScopePoliciesSection
                data={currentData}
                onCreatePolicy={handleCreatePolicy}
                onEvaluatePolicy={handleEvaluatePolicy}
              />
            )}
            {activeTab === 'assessment-plans' && (
              <AssessmentPlansSection
                data={currentData}
                onGeneratePlan={handleGeneratePlan}
                onCreateJobFromPlanStep={(stepPayload) =>
                  handleCreateJob({ ...stepPayload, executeImmediatelyInMvp: false })
                }
              />
            )}
            {activeTab === 'job-queue' && (
              <JobQueueSection
                data={currentData}
                onCreateJob={handleCreateJob}
                onApproveJob={handleApproveJob}
              />
            )}
            {activeTab === 'findings' && (
              <FindingsSection
                data={currentData}
                onNavigateTab={setActiveTab}
              />
            )}
            {activeTab === 'remediation' && (
              <RemediationSection
                data={currentData}
                onApproveRemediation={handleApproveRemediation}
              />
            )}
            {activeTab === 'agent-health' && (
              <AgentHealthSection
                data={currentData}
                onSendHeartbeat={handleSendHeartbeat}
                onPollJobs={handlePollJobs}
                onClaimJob={handleClaimJob}
                onSubmitJobResult={handleSubmitJobResult}
                onRotateAgentCredential={handleRotateAgentCredential}
                onControlAgentDevice={handleControlAgentDevice}
                onNavigateTab={setActiveTab}
              />
            )}
            {activeTab === 'audit-logs' && (
              <AuditLogsSection data={currentData} />
            )}
          </>
        )}
      </main>

      {/* Operator Authentication Modal */}
      {operatorModalOpen && (
        <div className="fixed inset-0 z-50 bg-slate-950/80 backdrop-blur-sm flex items-center justify-center p-4">
          <div className="w-full max-w-md rounded-xl border border-slate-800 bg-[#0F172A] p-6 space-y-4">
            <div className="flex items-center justify-between">
              <h2 className="text-base font-semibold text-slate-100">
                Operator Authentication &amp; Role Session
              </h2>
              <button
                onClick={() => setOperatorModalOpen(false)}
                className="text-xs text-slate-400 hover:text-slate-200 cursor-pointer"
              >
                Close
              </button>
            </div>
            <p className="text-xs text-slate-400">
              Select an operator profile to test role-based permissions across device enrollment, job approval gates, remediation sign-offs, and read-only auditor views.
            </p>
            <form onSubmit={(e) => void handleOperatorSwitch(e)} className="space-y-3">
              <div>
                <label className="block text-xs font-medium text-slate-300 mb-1">
                  Operator Identity
                </label>
                <select
                  value={selectedOperatorId}
                  onChange={(e) => setSelectedOperatorId(e.target.value)}
                  className="w-full rounded-lg border border-slate-700 bg-slate-900 px-3 py-2 text-xs text-slate-100"
                >
                  {currentData.availableOperators.map((op) => (
                    <option key={op.id} value={op.id}>
                      {op.displayName} — {op.role} ({op.email})
                    </option>
                  ))}
                </select>
              </div>
              <div>
                <label className="block text-xs font-medium text-slate-300 mb-1">
                  Operator Passphrase
                </label>
                <input
                  type="password"
                  value={passphraseInput}
                  onChange={(e) => setPassphraseInput(e.target.value)}
                  className="w-full rounded-lg border border-slate-700 bg-slate-900 px-3 py-2 text-xs font-mono text-slate-100"
                />
                <span className="block text-[11px] text-slate-400 mt-1">
                  Default test passphrase: <code className="font-mono text-teal-400">demo-switch</code>
                </span>
              </div>
              <div className="flex items-center justify-end gap-2 pt-2">
                <button
                  type="button"
                  onClick={() => setOperatorModalOpen(false)}
                  className="px-3 py-1.5 rounded-lg border border-slate-700 text-xs text-slate-300 cursor-pointer"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  className="px-3.5 py-1.5 rounded-lg bg-teal-500 hover:bg-teal-400 text-slate-950 font-semibold text-xs cursor-pointer"
                >
                  Authenticate Operator
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
}
