import React, { useState } from 'react';
import {
  RefreshCw,
  CheckCircle2,
  KeyRound,
  Download,
  Terminal,
  Search,
  PauseCircle,
  PlayCircle,
  PowerOff,
  ShieldOff,
  Trash2,
  HeartPulse,
  Plus,
} from 'lucide-react';
import { PlatformBootstrapPayload, PlatformTabId } from '../../types/platform';

interface AgentHealthSectionProps {
  data: PlatformBootstrapPayload;
  onSendHeartbeat: (agentId: string) => Promise<{ ok: boolean; message: string }>;
  onPollJobs: (agentId?: string) => Promise<{ ok: boolean; message: string; eligibleCount?: number }>;
  onClaimJob: (jobId: string, idempotencyClaimKey: string, agentId?: string) => Promise<{
    ok: boolean;
    code: string;
    message: string;
  }>;
  onSubmitJobResult: (jobId: string, agentId?: string) => Promise<{ ok: boolean; message: string }>;
  onRotateAgentCredential: (agentId: string) => Promise<{ ok: boolean; message: string }>;
  onControlAgentDevice: (
    agentId: string,
    action: 'pause' | 'resume' | 'disconnect' | 'revoke' | 'uninstall'
  ) => Promise<{ ok: boolean; message: string }>;
  onNavigateTab?: (tab: PlatformTabId) => void;
}

export const AgentHealthSection: React.FC<AgentHealthSectionProps> = ({
  data,
  onSendHeartbeat,
  onPollJobs,
  onClaimJob,
  onSubmitJobResult,
  onRotateAgentCredential,
  onControlAgentDevice,
  onNavigateTab,
}) => {
  const [selectedAgentId, setSelectedAgentId] = useState<string>(data.agents[0]?.id || 'agt-kali-01');
  const agent = data.agents.find((a) => a.id === selectedAgentId) || data.agents[0] || null;
  const claimableOrClaimedJobs = data.jobs.filter((j) => j.status === 'queued' || j.status === 'claimed');
  const [selectedJobId, setSelectedJobId] = useState(
    claimableOrClaimedJobs[0]?.id || data.jobs[0]?.id || 'job-402'
  );
  const [claimKey, setClaimKey] = useState('kali-claim-key-2026-01');
  const [protocolFeedback, setProtocolFeedback] = useState<{ ok: boolean; text: string } | null>(null);

  const statusColor = (status?: string) => {
    switch (status) {
      case 'online':
        return 'text-teal-300';
      case 'pending_heartbeat':
      case 'waiting_poll':
        return 'text-amber-300';
      case 'paused':
      case 'disconnected':
        return 'text-amber-400';
      case 'revoked':
      case 'uninstalled':
        return 'text-rose-400';
      default:
        return 'text-slate-300';
    }
  };

  return (
    <div className="space-y-8">
      <section className="bg-[#0F172A] border border-slate-800 rounded-xl p-6 flex flex-col lg:flex-row lg:items-center lg:justify-between gap-4">
        <div className="space-y-1.5">
          <div className="flex flex-wrap items-center gap-2 text-xs text-slate-400">
            <span>Device Management &amp; Outbound Polling</span>
            <span aria-hidden="true">·</span>
            <span>Heartbeat-Gated Online Status</span>
            <span aria-hidden="true">·</span>
            <span>Token Rotation &amp; Remote Revocation</span>
          </div>
          <h1 className="text-2xl font-semibold text-slate-100 tracking-tight">
            Kali Linux Device Management &amp; Outbound Polling Protocol
          </h1>
          <p className="text-sm text-slate-300 max-w-3xl leading-relaxed">
            Monitor registered Kali devices, verify authenticated heartbeats, pause or disconnect job dispatch, rotate
            or remotely revoke device credentials, and trigger safe uninstallation. Devices are{' '}
            <strong className="text-teal-300 font-medium">
              never displayed as ONLINE until a real authenticated heartbeat is received
            </strong>
            .
          </p>
        </div>

        <div className="flex flex-wrap items-center gap-2.5 self-start">
          {onNavigateTab && (
            <button
              type="button"
              onClick={() => onNavigateTab('agent-setup')}
              className="px-3.5 py-2.5 text-xs font-semibold bg-teal-500 text-slate-950 rounded-lg hover:bg-teal-400 transition-colors flex items-center gap-1.5 cursor-pointer"
            >
              <Plus className="w-3.5 h-3.5" />
              <span>Enroll New Kali Device</span>
            </button>
          )}
          <a
            href="/api/v1/agent-package/bundle.tar.gz"
            className="px-3.5 py-2.5 text-xs font-medium bg-slate-900 border border-slate-700 text-slate-200 rounded-lg hover:border-teal-500/40 transition-colors flex items-center gap-2 whitespace-nowrap shrink-0"
          >
            <Download className="w-3.5 h-3.5 text-teal-400" aria-hidden="true" />
            <span>Download Installer Bundle (v2.1.0)</span>
          </a>
        </div>
      </section>

      {protocolFeedback && (
        <div
          role="status"
          className={`p-4 rounded-lg border text-sm flex items-center justify-between ${
            protocolFeedback.ok
              ? 'bg-teal-950/40 border-teal-800/80 text-teal-200'
              : 'bg-rose-950/40 border-rose-800/80 text-rose-200'
          }`}
        >
          <span className="font-mono text-xs">{protocolFeedback.text}</span>
          <button
            type="button"
            onClick={() => setProtocolFeedback(null)}
            className="text-xs underline ml-4 cursor-pointer"
          >
            Dismiss
          </button>
        </div>
      )}

      {/* Registered Devices Selector Bar */}
      <section className="bg-[#0F172A] border border-slate-800 rounded-xl p-5 space-y-4">
        <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-2">
          <h2 className="text-sm font-semibold text-slate-100">
            Registered Kali Linux Devices ({data.agents.length})
          </h2>
          <span className="text-xs font-mono text-slate-400">
            Select a device to inspect telemetry or execute operator controls
          </span>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3">
          {data.agents.map((dev) => {
            const selected = agent?.id === dev.id;
            return (
              <button
                key={dev.id}
                type="button"
                onClick={() => setSelectedAgentId(dev.id)}
                className={`text-left rounded-lg border p-3.5 transition-colors cursor-pointer ${
                  selected
                    ? 'border-teal-500/50 bg-teal-950/20'
                    : 'border-slate-800 bg-[#0B1120] hover:border-slate-700'
                }`}
              >
                <div className="flex items-center justify-between gap-2">
                  <span className="font-mono text-xs font-semibold text-slate-100 truncate">
                    {dev.linuxUser}@{dev.hostname}
                  </span>
                  <span className={`font-mono text-[11px] uppercase ${statusColor(dev.status)}`}>
                    {dev.status}
                  </span>
                </div>
                <div className="mt-1.5 text-[11px] font-mono text-slate-400">
                  v{dev.version} · UID {dev.uid} · Job: {dev.currentJobStatus || 'idle'}
                </div>
                <div className="mt-1 text-[11px] text-slate-400">
                  Last Heartbeat:{' '}
                  <span className="font-mono text-slate-300">
                    {dev.lastHeartbeatAt ? new Date(dev.lastHeartbeatAt).toLocaleTimeString() : 'Never (Unverified)'}
                  </span>
                </div>
              </button>
            );
          })}
        </div>
      </section>

      <section className="grid grid-cols-1 lg:grid-cols-12 gap-6 items-stretch">
        {/* Left 6 cols: Device Telemetry, Lifecycle Controls, Token Rotation & Safe Uninstall */}
        <div className="lg:col-span-6 bg-[#0F172A] border border-slate-800 rounded-xl p-6 space-y-5 flex flex-col justify-between">
          {agent ? (
            <div className="space-y-4">
              <div className="flex items-center justify-between border-b border-slate-800 pb-3">
                <div>
                  <h2 className="text-lg font-semibold text-slate-100">
                    01. Device Telemetry &amp; Operator Controls
                  </h2>
                  <p className="text-xs text-slate-400 font-mono mt-0.5">
                    Device ID: {agent.id} · Service Account: {agent.serviceAccount || agent.linuxUser} (UID {agent.uid})
                  </p>
                </div>
                <span className={`text-xs font-mono uppercase font-semibold ${statusColor(agent.status)}`}>
                  {agent.status === 'online' && agent.heartbeatVerifiedLive
                    ? 'ONLINE (HEARTBEAT VERIFIED)'
                    : agent.status.toUpperCase()}
                </span>
              </div>

              <div className="p-4 bg-[#0B1120] border border-slate-800 rounded-lg space-y-2.5 text-xs">
                <div className="flex items-center justify-between">
                  <span className="text-slate-400">Host &amp; Least-Privilege User</span>
                  <span className="font-mono text-slate-100">
                    {agent.linuxUser}@{agent.hostname} (UID {agent.uid})
                  </span>
                </div>
                <div className="flex items-center justify-between">
                  <span className="text-slate-400">Operating System &amp; Agent Version</span>
                  <span className="font-mono text-slate-200">
                    v{agent.version} · {agent.osInfo || 'Kali GNU/Linux Rolling'}
                  </span>
                </div>
                <div className="flex items-center justify-between">
                  <span className="text-slate-400">Systemd Login Autostart</span>
                  <span className="font-mono text-teal-300">
                    {agent.systemdAutostartEnabled !== false
                      ? 'Enabled (systemd --user + XDG autostart)'
                      : 'Manual Start'}
                  </span>
                </div>
                <div className="flex items-center justify-between">
                  <span className="text-slate-400">Device Credential Fingerprint</span>
                  <span className="font-mono text-teal-300 tabular-nums">{agent.credentialFingerprint}</span>
                </div>
                <div className="flex items-center justify-between">
                  <span className="text-slate-400">Last Authenticated Heartbeat</span>
                  <span className="font-mono text-slate-200 tabular-nums">
                    {agent.lastHeartbeatAt
                      ? new Date(agent.lastHeartbeatAt).toLocaleString()
                      : 'Awaiting first authenticated heartbeat'}
                  </span>
                </div>
                <div className="flex items-center justify-between">
                  <span className="text-slate-400">Current Job Status &amp; Counters</span>
                  <span className="font-mono text-slate-200 tabular-nums">
                    {agent.currentJobStatus || 'idle'} · {agent.claimedJobsCount} claimed / {agent.completedJobsCount}{' '}
                    completed
                  </span>
                </div>
              </div>

              {/* Primary Heartbeat & Pause / Disconnect / Resume Controls */}
              <div className="space-y-2.5">
                <div className="text-xs font-semibold text-slate-300">
                  Connection &amp; Dispatch Controls
                </div>
                <div className="grid grid-cols-1 sm:grid-cols-2 gap-2.5">
                  <button
                    type="button"
                    onClick={async () => {
                      const res = await onSendHeartbeat(agent.id);
                      setProtocolFeedback({ ok: res.ok, text: res.message });
                    }}
                    className="py-2.5 px-3 text-xs font-semibold bg-teal-500 text-slate-950 rounded-lg hover:bg-teal-400 transition-colors flex items-center justify-center gap-1.5 cursor-pointer"
                  >
                    <HeartPulse className="w-3.5 h-3.5" />
                    <span>Send Authenticated Heartbeat</span>
                  </button>

                  {agent.status === 'paused' ? (
                    <button
                      type="button"
                      onClick={async () => {
                        const res = await onControlAgentDevice(agent.id, 'resume');
                        setProtocolFeedback({ ok: res.ok, text: res.message });
                      }}
                      className="py-2.5 px-3 text-xs font-medium bg-slate-800 text-teal-300 border border-teal-500/40 rounded-lg hover:bg-slate-700 transition-colors flex items-center justify-center gap-1.5 cursor-pointer"
                    >
                      <PlayCircle className="w-3.5 h-3.5" />
                      <span>Resume Agent Polling</span>
                    </button>
                  ) : (
                    <button
                      type="button"
                      onClick={async () => {
                        const res = await onControlAgentDevice(agent.id, 'pause');
                        setProtocolFeedback({ ok: res.ok, text: res.message });
                      }}
                      className="py-2.5 px-3 text-xs font-medium bg-slate-800 text-amber-300 border border-amber-500/40 rounded-lg hover:bg-slate-700 transition-colors flex items-center justify-center gap-1.5 cursor-pointer"
                    >
                      <PauseCircle className="w-3.5 h-3.5" />
                      <span>Pause Agent</span>
                    </button>
                  )}

                  <button
                    type="button"
                    onClick={async () => {
                      const res = await onControlAgentDevice(agent.id, 'disconnect');
                      setProtocolFeedback({ ok: res.ok, text: res.message });
                    }}
                    className="py-2 px-3 text-xs font-medium bg-[#0B1120] text-slate-200 border border-slate-700 rounded-lg hover:bg-slate-800 transition-colors flex items-center justify-center gap-1.5 cursor-pointer"
                  >
                    <PowerOff className="w-3.5 h-3.5 text-amber-400" />
                    <span>Disconnect Agent</span>
                  </button>

                  <button
                    type="button"
                    onClick={async () => {
                      const res = await onRotateAgentCredential(agent.id);
                      setProtocolFeedback({ ok: res.ok, text: res.message });
                    }}
                    className="py-2 px-3 text-xs font-medium bg-[#0B1120] text-slate-200 border border-slate-700 rounded-lg hover:bg-slate-800 transition-colors flex items-center justify-center gap-1.5 cursor-pointer"
                  >
                    <KeyRound className="w-3.5 h-3.5 text-teal-400" />
                    <span>Rotate Device Token</span>
                  </button>
                </div>
              </div>

              {/* Security Revocation & Safe Uninstall Controls */}
              <div className="border-t border-slate-800 pt-4 space-y-2.5">
                <div className="text-xs font-semibold text-slate-300">
                  Remote Token Revocation &amp; Safe Uninstallation
                </div>
                <div className="grid grid-cols-1 sm:grid-cols-2 gap-2.5">
                  <button
                    type="button"
                    onClick={async () => {
                      const res = await onControlAgentDevice(agent.id, 'revoke');
                      setProtocolFeedback({ ok: res.ok, text: res.message });
                    }}
                    className="py-2 px-3 text-xs font-medium bg-rose-950/30 text-rose-300 border border-rose-700/50 rounded-lg hover:bg-rose-950/50 transition-colors flex items-center justify-center gap-1.5 cursor-pointer"
                  >
                    <ShieldOff className="w-3.5 h-3.5" />
                    <span>Remote Revoke Token</span>
                  </button>

                  <button
                    type="button"
                    onClick={async () => {
                      const res = await onControlAgentDevice(agent.id, 'uninstall');
                      setProtocolFeedback({ ok: res.ok, text: res.message });
                    }}
                    className="py-2 px-3 text-xs font-medium bg-rose-950/30 text-rose-200 border border-rose-700/50 rounded-lg hover:bg-rose-950/50 transition-colors flex items-center justify-center gap-1.5 cursor-pointer"
                  >
                    <Trash2 className="w-3.5 h-3.5" />
                    <span>Safe Uninstall Deregister</span>
                  </button>
                </div>
              </div>
            </div>
          ) : (
            <div className="text-sm text-slate-400">No Kali agent device registered.</div>
          )}
        </div>

        {/* Right 6 cols: Interactive Outbound Polling Protocol Simulator */}
        <div className="lg:col-span-6 bg-[#0F172A] border border-slate-800 rounded-xl p-6 space-y-5 flex flex-col justify-between">
          <div className="space-y-4">
            <h2 className="text-lg font-semibold text-slate-100">
              02. Outbound Polling &amp; Idempotent Claim Verifier
            </h2>
            <p className="text-xs text-slate-300 leading-relaxed">
              Test the 3-step outbound polling lifecycle (<code className="text-teal-300">POST /api/v1/agent/poll</code>{' '}
              → <code className="text-teal-300">/claim</code> → <code className="text-teal-300">/result</code>) for{' '}
              <span className="font-mono text-slate-100">{agent ? `${agent.linuxUser}@${agent.hostname}` : 'agent'}</span>.
              If the device is paused, disconnected, or revoked, polling and job claims are automatically rejected.
            </p>

            <div className="space-y-3 text-xs">
              <div className="p-3.5 bg-[#0B1120] border border-slate-800 rounded-lg flex items-center justify-between gap-3">
                <div>
                  <div className="font-semibold text-slate-100">Step 1: Outbound HTTPS Poll for Queued Jobs</div>
                  <div className="text-slate-400">
                    Authenticates with per-agent token, expires stale jobs, and returns eligible queued jobs.
                  </div>
                </div>
                <button
                  type="button"
                  onClick={async () => {
                    const res = await onPollJobs(agent?.id);
                    setProtocolFeedback({ ok: res.ok, text: res.message });
                  }}
                  className="px-3 py-2 text-xs font-medium bg-teal-500 text-slate-950 rounded-md hover:bg-teal-400 transition-colors flex items-center gap-1.5 whitespace-nowrap shrink-0 cursor-pointer"
                >
                  <RefreshCw className="w-3.5 h-3.5" aria-hidden="true" />
                  <span>1. Outbound Poll</span>
                </button>
              </div>

              <div className="p-3.5 bg-[#0B1120] border border-slate-800 rounded-lg space-y-3">
                <div className="font-semibold text-slate-100">
                  Step 2: Idempotent Job Claim (Enforces Expiry &amp; Claim Key)
                </div>
                <div className="grid grid-cols-1 sm:grid-cols-2 gap-2.5">
                  <div>
                    <label htmlFor="claim-job-select" className="block text-slate-400 mb-1">
                      Target Job ID
                    </label>
                    <select
                      id="claim-job-select"
                      value={selectedJobId}
                      onChange={(e) => setSelectedJobId(e.target.value)}
                      className="w-full bg-[#0F172A] border border-slate-700 rounded-md px-2.5 py-1.5 text-slate-100 font-mono"
                    >
                      {data.jobs.map((j) => (
                        <option key={j.id} value={j.id}>
                          {j.id} ({j.status} · {j.category})
                        </option>
                      ))}
                    </select>
                  </div>
                  <div>
                    <label htmlFor="claim-key-input" className="block text-slate-400 mb-1">
                      Idempotency Claim Key
                    </label>
                    <input
                      id="claim-key-input"
                      type="text"
                      value={claimKey}
                      onChange={(e) => setClaimKey(e.target.value)}
                      className="w-full bg-[#0F172A] border border-slate-700 rounded-md px-2.5 py-1.5 text-slate-100 font-mono tabular-nums"
                    />
                  </div>
                </div>
                <button
                  type="button"
                  onClick={async () => {
                    const res = await onClaimJob(selectedJobId, claimKey, agent?.id);
                    setProtocolFeedback({ ok: res.ok, text: `${res.code}: ${res.message}` });
                  }}
                  className="w-full py-2 px-3 text-xs font-medium bg-slate-800 text-teal-300 border border-teal-700/70 rounded-md hover:bg-slate-700 transition-colors cursor-pointer"
                >
                  2. Claim Job Idempotently (Replay Safe)
                </button>
              </div>

              <div className="p-3.5 bg-[#0B1120] border border-slate-800 rounded-lg flex items-center justify-between gap-3">
                <div>
                  <div className="font-semibold text-slate-100">Step 3: Submit Allowlisted Task Result</div>
                  <div className="text-slate-400">
                    Submits passive header or static code findings for claimed job{' '}
                    <code className="text-teal-300">{selectedJobId}</code>.
                  </div>
                </div>
                <button
                  type="button"
                  onClick={async () => {
                    const res = await onSubmitJobResult(selectedJobId, agent?.id);
                    setProtocolFeedback({ ok: res.ok, text: res.message });
                  }}
                  className="px-3 py-2 text-xs font-medium bg-slate-800 text-slate-100 border border-slate-700 rounded-md hover:bg-slate-700 transition-colors flex items-center gap-1.5 whitespace-nowrap shrink-0 cursor-pointer"
                >
                  <CheckCircle2 className="w-3.5 h-3.5 text-teal-400" aria-hidden="true" />
                  <span>3. Submit Result</span>
                </button>
              </div>
            </div>
          </div>

          <div className="border-t border-slate-800 pt-4 text-xs text-slate-400 flex items-center gap-2">
            <Terminal className="w-4 h-4 text-teal-400 shrink-0" aria-hidden="true" />
            <span>
              Local Kali systemd command:{' '}
              <code className="text-slate-200 font-mono">systemctl --user status sentinel-agent.service</code>
            </span>
          </div>
        </div>
      </section>
    </div>
  );
};

interface AuditLogsSectionProps {
  data: PlatformBootstrapPayload;
}

export const AuditLogsSection: React.FC<AuditLogsSectionProps> = ({ data }) => {
  const [query, setQuery] = useState('');
  const [decisionFilter, setDecisionFilter] = useState<'all' | 'allowed' | 'denied' | 'approval_required'>('all');

  const filtered = data.auditLogs.filter((entry) => {
    const matchesDecision = decisionFilter === 'all' ? true : entry.decision === decisionFilter;
    const matchesQuery =
      !query.trim() ||
      entry.action.toLowerCase().includes(query.toLowerCase()) ||
      entry.summary.toLowerCase().includes(query.toLowerCase()) ||
      entry.actor.toLowerCase().includes(query.toLowerCase());
    return matchesDecision && matchesQuery;
  });

  return (
    <div className="space-y-8">
      <section className="bg-[#0F172A] border border-slate-800 rounded-xl p-6 flex flex-col lg:flex-row lg:items-center lg:justify-between gap-4">
        <div className="space-y-1.5">
          <div className="flex flex-wrap items-center gap-2 text-xs text-slate-400">
            <span>Immutable Security Ledger</span>
            <span aria-hidden="true">·</span>
            <span>Every Action Logged</span>
            <span aria-hidden="true">·</span>
            <span>Sanitized Telemetry</span>
          </div>
          <h1 className="text-2xl font-semibold text-slate-100 tracking-tight">
            Platform Audit Logs ({filtered.length})
          </h1>
          <p className="text-sm text-slate-300 max-w-3xl">
            Every authentication event, device enrollment, heartbeat, policy evaluation, AI plan generation, job claim,
            and human approval is recorded with actor attribution and policy decision.
          </p>
        </div>

        <div className="flex flex-wrap items-center gap-2">
          <div className="relative">
            <Search className="w-3.5 h-3.5 text-slate-400 absolute left-3 top-1/2 -translate-y-1/2" aria-hidden="true" />
            <input
              type="text"
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              placeholder="Filter action, actor, or host..."
              aria-label="Filter audit logs"
              className="bg-[#0B1120] border border-slate-700 rounded-lg pl-8 pr-3 py-1.5 text-xs text-slate-100"
            />
          </div>

          <div className="flex items-center gap-1 p-1 bg-[#0B1120] border border-slate-800 rounded-lg">
            {(['all', 'allowed', 'approval_required', 'denied'] as const).map((dec) => (
              <button
                key={dec}
                type="button"
                onClick={() => setDecisionFilter(dec)}
                className={`px-2.5 py-1 text-xs font-medium rounded transition-colors cursor-pointer ${
                  decisionFilter === dec
                    ? 'bg-teal-500 text-slate-950'
                    : 'text-slate-400 hover:text-slate-200'
                }`}
              >
                {dec}
              </button>
            ))}
          </div>
        </div>
      </section>

      <section className="bg-[#0F172A] border border-slate-800 rounded-xl p-6">
        <div className="overflow-x-auto">
          <table className="w-full text-left border-collapse text-xs">
            <thead>
              <tr className="border-b border-slate-800 text-slate-400">
                <th className="py-2.5 pr-3 font-medium">Timestamp</th>
                <th className="py-2.5 px-3 font-medium">Actor</th>
                <th className="py-2.5 px-3 font-medium">Action</th>
                <th className="py-2.5 px-3 font-medium">Decision</th>
                <th className="py-2.5 pl-3 font-medium">Summary</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/70">
              {filtered.map((entry) => (
                <tr key={entry.id}>
                  <td className="py-3 pr-3 font-mono text-slate-400 tabular-nums whitespace-nowrap">
                    {new Date(entry.timestamp).toLocaleTimeString()}
                  </td>
                  <td className="py-3 px-3 font-mono text-slate-300 whitespace-nowrap">{entry.actor}</td>
                  <td className="py-3 px-3 font-mono text-teal-300 whitespace-nowrap">{entry.action}</td>
                  <td className="py-3 px-3 font-mono whitespace-nowrap">
                    <span
                      className={
                        entry.decision === 'denied'
                          ? 'text-rose-400 font-semibold'
                          : entry.decision === 'approval_required'
                          ? 'text-amber-300 font-semibold'
                          : 'text-teal-300'
                      }
                    >
                      {entry.decision}
                    </span>
                  </td>
                  <td className="py-3 pl-3 text-slate-200">{entry.summary}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>
    </div>
  );
};
