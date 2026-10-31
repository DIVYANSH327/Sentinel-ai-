import React, { useState } from 'react';
import {
  Copy,
  Check,
  RefreshCw,
  ShieldCheck,
  Terminal,
  UserCheck,
} from 'lucide-react';
import {
  ControlPlaneStatus,
  PredefinedOperationSpec,
} from '../types/sentinel';

interface AgentManagerViewProps {
  status: ControlPlaneStatus;
  isDemoMode: boolean;
  onSendVerifiedHeartbeat: () => Promise<{ ok: boolean; message: string }>;
  onSubmitScanJob: (params: {
    operationId: string;
    target: string;
    approvedByHuman?: boolean;
    approverName?: string;
    approverNote?: string;
  }) => Promise<{ ok: boolean; code: string; message: string }>;
  onApproveScanJob: (jobId: string, approverName: string, approverNote: string) => Promise<{
    ok: boolean;
    message: string;
  }>;
}

export const AgentManagerView: React.FC<AgentManagerViewProps> = ({
  status,
  isDemoMode,
  onSendVerifiedHeartbeat,
  onSubmitScanJob,
  onApproveScanJob,
}) => {
  const [selectedOpId, setSelectedOpId] = useState<PredefinedOperationSpec['id']>('passive_port_inventory');
  const [targetInput, setTargetInput] = useState<string>(
    status.allowedTargets[0]?.replace(/\.0\/\d+$/, '.15') || '10.24.0.15'
  );
  const [approverName, setApproverName] = useState<string>('Neha Raut');
  const [approverNote, setApproverNote] = useState<string>('Approved lab window verification');
  const [includeHumanApprovalNow, setIncludeHumanApprovalNow] = useState<boolean>(false);
  const [copiedCmd, setCopiedCmd] = useState<string | null>(null);
  const [feedback, setFeedback] = useState<{ type: 'success' | 'error'; text: string } | null>(null);

  const selectedOp =
    status.predefinedOperations.find((op) => op.id === selectedOpId) || status.predefinedOperations[0];

  const copyCli = (key: string, cmd: string) => {
    navigator.clipboard?.writeText(cmd).catch(() => {});
    setCopiedCmd(key);
    setTimeout(() => setCopiedCmd(null), 1800);
  };

  const handleQueueJob = async (e: React.FormEvent) => {
    e.preventDefault();
    const res = await onSubmitScanJob({
      operationId: selectedOpId,
      target: targetInput,
      approvedByHuman: selectedOp?.requiresHumanApproval ? includeHumanApprovalNow : false,
      approverName: includeHumanApprovalNow ? approverName : undefined,
      approverNote: includeHumanApprovalNow ? approverNote : undefined,
    });
    setFeedback({ type: res.ok ? 'success' : 'error', text: `${res.message} (${res.code})` });
  };

  const localSystemdCommands = [
    {
      id: 'start',
      label: 'Start Service (Local Kali CLI)',
      cmd: 'systemctl --user start sentinel-agent.service',
      desc: 'Starts the non-root agent service inside your Kali user session.',
    },
    {
      id: 'stop',
      label: 'Stop Service (Local Kali CLI)',
      cmd: 'systemctl --user stop sentinel-agent.service',
      desc: 'Cleanly stops the user-level systemd unit on Kali Linux.',
    },
    {
      id: 'restart',
      label: 'Restart Service (Local Kali CLI)',
      cmd: 'systemctl --user restart sentinel-agent.service',
      desc: 'Reloads ~/.config/sentinel-agent/agent.conf after credential rotation.',
    },
    {
      id: 'logs',
      label: 'Inspect Local Journal (Kali CLI)',
      cmd: 'journalctl --user -u sentinel-agent.service -n 50 --no-pager',
      desc: 'Displays local systemd stdout/stderr logs on Kali Linux.',
    },
  ];

  return (
    <div className="space-y-8">
      <section className="bg-[#0F172A] border border-slate-800 rounded-xl p-6 flex flex-col lg:flex-row lg:items-center lg:justify-between gap-4">
        <div className="space-y-1.5">
          <div className="flex items-center gap-2 text-xs text-slate-400">
            <span>Authenticated Agent Telemetry</span>
            <span aria-hidden="true">·</span>
            <span>Non-Root User Service</span>
            <span aria-hidden="true">·</span>
            <span>{isDemoMode ? 'Simulated Demo View' : 'Live Backend API'}</span>
          </div>
          <h1 className="text-2xl font-semibold text-slate-100 tracking-tight">
            Kali Linux Agent Manager &amp; Predefined Operations
          </h1>
          <p className="text-sm text-slate-300 max-w-3xl">
            Monitor verified service heartbeats, inspect sanitized logs, copy local <code className="text-teal-300">systemctl --user</code>{' '}
            lifecycle commands, and queue administrator-approved scanner operations.
          </p>
        </div>

        <button
          type="button"
          onClick={async () => {
            const res = await onSendVerifiedHeartbeat();
            setFeedback({ type: res.ok ? 'success' : 'error', text: res.message });
          }}
          className="px-4 py-2.5 text-xs font-medium bg-slate-800 text-slate-100 border border-slate-700 rounded-lg hover:bg-slate-700 transition-colors flex items-center gap-2 whitespace-nowrap shrink-0 cursor-pointer"
        >
          <RefreshCw className="w-4 h-4 text-teal-400" aria-hidden="true" />
          <span>Verify Agent Heartbeat Now</span>
        </button>
      </section>

      {feedback && (
        <div
          role="status"
          className={`p-4 rounded-lg border text-sm flex items-center justify-between ${
            feedback.type === 'success'
              ? 'bg-teal-950/40 border-teal-800/80 text-teal-200'
              : 'bg-rose-950/40 border-rose-800/80 text-rose-200'
          }`}
        >
          <span>{feedback.text}</span>
          <button
            type="button"
            onClick={() => setFeedback(null)}
            className="text-xs underline ml-4 whitespace-nowrap shrink-0 cursor-pointer"
          >
            Dismiss
          </button>
        </div>
      )}

      {/* Service Status & Local CLI Lifecycle Instructions */}
      <section className="grid grid-cols-1 lg:grid-cols-12 gap-6 items-stretch">
        <div className="lg:col-span-5 bg-[#0F172A] border border-slate-800 rounded-xl p-6 space-y-5">
          <div className="space-y-1">
            <h2 className="text-lg font-semibold text-slate-100">01. Verified Agent Service Status</h2>
            <p className="text-xs text-slate-400">
              Reported to the backend via authenticated <code className="text-slate-300">POST /api/agent/heartbeat</code>.
            </p>
          </div>

          {status.activeAgent ? (
            <dl className="divide-y divide-slate-800/80 text-xs">
              <div className="py-2.5 flex justify-between gap-4">
                <dt className="text-slate-400">Host &amp; Linux User</dt>
                <dd className="font-mono text-slate-100 tabular-nums">
                  {status.activeAgent.linuxUser}@{status.activeAgent.hostname} (UID {status.activeAgent.uid})
                </dd>
              </div>
              <div className="py-2.5 flex justify-between gap-4">
                <dt className="text-slate-400">User systemd Unit</dt>
                <dd className="font-mono text-teal-300 tabular-nums">
                  {status.activeAgent.systemdUnitName} · {status.activeAgent.systemdUnitStatus}
                </dd>
              </div>
              <div className="py-2.5 flex justify-between gap-4">
                <dt className="text-slate-400">Local Credential File</dt>
                <dd className="font-mono text-slate-200 tabular-nums">
                  {status.activeAgent.configFilePath} (mode {status.activeAgent.configFileMode})
                </dd>
              </div>
              <div className="py-2.5 flex justify-between gap-4">
                <dt className="text-slate-400">Last Verified Heartbeat</dt>
                <dd className="font-mono text-slate-200 tabular-nums">
                  {status.activeAgent.lastHeartbeatAt
                    ? new Date(status.activeAgent.lastHeartbeatAt).toLocaleString()
                    : 'Awaiting first heartbeat'}
                </dd>
              </div>
              <div className="py-2.5 flex justify-between gap-4">
                <dt className="text-slate-400">Credential Fingerprint</dt>
                <dd className="font-mono text-slate-200 tabular-nums">{status.activeAgent.tokenFingerprint}</dd>
              </div>
            </dl>
          ) : (
            <div className="p-5 bg-[#0B1120] border border-slate-800 rounded-lg text-xs text-slate-400 space-y-2">
              <div className="font-medium text-slate-200">No Kali Linux Agent Registered</div>
              <p>
                Complete single-use enrollment in the USB Setup Wizard or Secure Configuration to view live service
                telemetry here.
              </p>
            </div>
          )}
        </div>

        <div className="lg:col-span-7 bg-[#0F172A] border border-slate-800 rounded-xl p-6 space-y-4">
          <div className="space-y-1">
            <h2 className="text-lg font-semibold text-slate-100">
              02. Local systemd Start, Stop &amp; Restart Instructions
            </h2>
            <p className="text-xs text-slate-400">
              Browser buttons cannot directly start, stop, or restart a local service on your Kali Linux computer. Run
              these commands in your non-root Kali terminal:
            </p>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
            {localSystemdCommands.map((item) => (
              <div key={item.id} className="bg-[#0B1120] border border-slate-800 rounded-lg p-3.5 space-y-2">
                <div className="flex items-center justify-between text-xs">
                  <span className="font-medium text-slate-200">{item.label}</span>
                  <button
                    type="button"
                    onClick={() => copyCli(item.id, item.cmd)}
                    className="text-teal-400 hover:text-teal-300 flex items-center gap-1 cursor-pointer"
                    aria-label={`Copy ${item.label}`}
                  >
                    {copiedCmd === item.id ? <Check className="w-3.5 h-3.5" /> : <Copy className="w-3.5 h-3.5" />}
                    <span>{copiedCmd === item.id ? 'Copied' : 'Copy'}</span>
                  </button>
                </div>
                <code className="block text-xs font-mono text-teal-300 break-all">{item.cmd}</code>
                <p className="text-[11px] text-slate-400">{item.desc}</p>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* Predefined Operations & Human Approval Gate */}
      <section className="grid grid-cols-1 lg:grid-cols-12 gap-6 items-stretch">
        <div className="lg:col-span-5 bg-[#0F172A] border border-slate-800 rounded-xl p-6 space-y-5">
          <div className="space-y-1">
            <h2 className="text-lg font-semibold text-slate-100">03. Queue Predefined Scanner Operation</h2>
            <p className="text-xs text-slate-400">
              Arbitrary shell commands are blocked. Only predefined operations targeting approved CIDR/host scopes are
              accepted. Intrusive tests and patch deployments require explicit human approval.
            </p>
          </div>

          <form onSubmit={handleQueueJob} className="space-y-4">
            <div className="space-y-1.5">
              <label htmlFor="scanner-op-select" className="block text-xs font-medium text-slate-300">
                Predefined Scanner Operation
              </label>
              <select
                id="scanner-op-select"
                value={selectedOpId}
                onChange={(e) => setSelectedOpId(e.target.value as PredefinedOperationSpec['id'])}
                className="w-full bg-[#0B1120] border border-slate-700 rounded-lg px-3 py-2 text-xs text-slate-100 focus:outline-none focus:border-teal-500"
              >
                {status.predefinedOperations.map((op) => (
                  <option key={op.id} value={op.id}>
                    {op.name} {op.requiresHumanApproval ? '(Requires Human Approval)' : '(Standard)'}
                  </option>
                ))}
              </select>
            </div>

            {selectedOp && (
              <div className="p-3 bg-[#0B1120] border border-slate-800 rounded-lg text-xs space-y-1.5">
                <div className="text-slate-300">{selectedOp.description}</div>
                <div className="font-mono text-[11px] text-teal-300">
                  Fixed Binary Invocation: {selectedOp.fixedArgumentsPreview}
                </div>
              </div>
            )}

            <div className="space-y-1.5">
              <label htmlFor="scan-target-input" className="block text-xs font-medium text-slate-300">
                Target Host or IP (Validated Against Allowed Scope: {status.allowedTargets.join(', ')})
              </label>
              <input
                id="scan-target-input"
                type="text"
                value={targetInput}
                onChange={(e) => setTargetInput(e.target.value)}
                placeholder="10.24.0.15"
                className="w-full bg-[#0B1120] border border-slate-700 rounded-lg px-3 py-2 text-sm font-mono text-slate-100 focus:outline-none focus:border-teal-500"
              />
            </div>

            {selectedOp?.requiresHumanApproval && (
              <div className="p-3.5 bg-[#0B1120] border border-amber-800/70 rounded-lg space-y-3">
                <label className="flex items-center gap-2 text-xs text-amber-300 font-medium cursor-pointer">
                  <input
                    type="checkbox"
                    checked={includeHumanApprovalNow}
                    onChange={(e) => setIncludeHumanApprovalNow(e.target.checked)}
                    className="rounded border-slate-600"
                  />
                  <span>Sign off human operator approval immediately</span>
                </label>

                {includeHumanApprovalNow && (
                  <div className="grid grid-cols-1 gap-2.5">
                    <div>
                      <label htmlFor="approver-name" className="block text-[11px] text-slate-400 mb-1">
                        Approving Operator Name
                      </label>
                      <input
                        id="approver-name"
                        type="text"
                        value={approverName}
                        onChange={(e) => setApproverName(e.target.value)}
                        className="w-full bg-[#0F172A] border border-slate-700 rounded px-2.5 py-1.5 text-xs text-slate-100"
                      />
                    </div>
                    <div>
                      <label htmlFor="approver-note" className="block text-[11px] text-slate-400 mb-1">
                        Change Ticket / Approval Justification
                      </label>
                      <input
                        id="approver-note"
                        type="text"
                        value={approverNote}
                        onChange={(e) => setApproverNote(e.target.value)}
                        className="w-full bg-[#0F172A] border border-slate-700 rounded px-2.5 py-1.5 text-xs text-slate-100"
                      />
                    </div>
                  </div>
                )}
              </div>
            )}

            <div className="flex flex-wrap gap-2">
              <button
                type="submit"
                className="px-4 py-2 text-xs font-medium bg-teal-500 text-slate-950 rounded-lg hover:bg-teal-400 transition-colors cursor-pointer"
              >
                Validate &amp; Submit Predefined Job
              </button>
              <button
                type="button"
                onClick={() => setTargetInput('8.8.8.8')}
                className="px-3 py-2 text-xs font-medium bg-slate-800 text-slate-300 border border-slate-700 rounded-lg hover:bg-slate-700 transition-colors cursor-pointer"
              >
                Test Out-of-Scope Target (8.8.8.8)
              </button>
            </div>
          </form>
        </div>

        {/* Right 7 cols: Active Scan Jobs & Sanitized Agent Logs */}
        <div className="lg:col-span-7 bg-[#0F172A] border border-slate-800 rounded-xl p-6 space-y-6">
          <div className="space-y-3">
            <h2 className="text-lg font-semibold text-slate-100">04. Scan Job Queue &amp; Human Approval Gate</h2>
            {status.scanJobs.length === 0 ? (
              <p className="text-xs text-slate-400 py-3">
                No scan jobs queued yet. Submit a predefined operation on the left to test scope validation and human
                approval gating.
              </p>
            ) : (
              <div className="overflow-x-auto">
                <table className="w-full text-left border-collapse text-xs">
                  <thead>
                    <tr className="border-b border-slate-800 text-slate-400">
                      <th className="py-2 pr-3 font-medium">Operation</th>
                      <th className="py-2 px-3 font-medium">Target</th>
                      <th className="py-2 px-3 font-medium">Status</th>
                      <th className="py-2 pl-3 font-medium text-right">Action</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-800/70">
                    {status.scanJobs.map((job) => (
                      <tr key={job.id}>
                        <td className="py-2.5 pr-3 text-slate-200 font-medium">{job.operationName}</td>
                        <td className="py-2.5 px-3 font-mono text-teal-300 tabular-nums">{job.target}</td>
                        <td className="py-2.5 px-3 font-mono tabular-nums text-slate-300">
                          {job.status}
                          {job.approvedBy ? ` · by ${job.approvedBy}` : ''}
                        </td>
                        <td className="py-2.5 pl-3 text-right">
                          {job.status === 'pending_human_approval' ? (
                            <button
                              type="button"
                              onClick={async () => {
                                const res = await onApproveScanJob(
                                  job.id,
                                  approverName || 'Operator',
                                  approverNote || 'Explicit operator approval'
                                );
                                setFeedback({ type: res.ok ? 'success' : 'error', text: res.message });
                              }}
                              className="px-2.5 py-1 text-xs font-medium bg-amber-500 text-slate-950 rounded hover:bg-amber-400 transition-colors inline-flex items-center gap-1 whitespace-nowrap cursor-pointer"
                            >
                              <UserCheck className="w-3.5 h-3.5" aria-hidden="true" />
                              <span>Approve Dispatch</span>
                            </button>
                          ) : (
                            <span className="text-slate-500 font-mono">Verified</span>
                          )}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>

          <div className="border-t border-slate-800 pt-5 space-y-3">
            <div className="flex items-center justify-between">
              <h3 className="text-sm font-semibold text-slate-200 flex items-center gap-2">
                <Terminal className="w-4 h-4 text-teal-400" aria-hidden="true" />
                <span>Recent Sanitized Agent &amp; Control Plane Logs</span>
              </h3>
              <span className="text-xs text-slate-400">Secrets automatically redacted</span>
            </div>

            <div className="bg-[#0B1120] border border-slate-800 rounded-lg p-3.5 max-h-56 overflow-y-auto space-y-2 font-mono text-xs">
              {status.sanitizedLogs.map((entry) => (
                <div key={entry.id} className="leading-relaxed text-slate-300">
                  <span className="text-slate-500 tabular-nums">
                    [{new Date(entry.timestamp).toLocaleTimeString()}]
                  </span>{' '}
                  <span
                    className={
                      entry.level === 'ERROR'
                        ? 'text-rose-400'
                        : entry.level === 'WARN'
                        ? 'text-amber-300'
                        : 'text-teal-400'
                    }
                  >
                    {entry.level}
                  </span>{' '}
                  <span className="text-slate-400">({entry.source})</span>: {entry.message}
                </div>
              ))}
            </div>
          </div>
        </div>
      </section>
    </div>
  );
};
