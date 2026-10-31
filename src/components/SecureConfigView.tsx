import React, { useState } from 'react';
import {
  KeyRound,
  RotateCw,
  ShieldOff,
  Lock,
  Terminal,
} from 'lucide-react';
import { ControlPlaneStatus } from '../types/sentinel';

interface SecureConfigViewProps {
  status: ControlPlaneStatus;
  lastIssuedOneTimeCode: string | null;
  onSaveBackendUrl: (url: string, allowedTargets: string[]) => Promise<{ ok: boolean; message: string }>;
  onIssueEnrollmentCode: (label: string, ttlMinutes: number) => Promise<{
    ok: boolean;
    message: string;
    singleUseEnrollmentCode?: string;
  }>;
  onSimulateKaliEnroll: (code: string) => Promise<{ ok: boolean; message: string }>;
  onRotateToken: () => Promise<{ ok: boolean; message: string }>;
  onRevokeToken: (reason: string) => Promise<{ ok: boolean; message: string }>;
}

export const SecureConfigView: React.FC<SecureConfigViewProps> = ({
  status,
  lastIssuedOneTimeCode,
  onSaveBackendUrl,
  onIssueEnrollmentCode,
  onSimulateKaliEnroll,
  onRotateToken,
  onRevokeToken,
}) => {
  const [backendUrlInput, setBackendUrlInput] = useState(status.backendUrl || 'https://sentinel-usb-connect.internal');
  const [allowedTargetsText, setAllowedTargetsText] = useState(status.allowedTargets.join(', '));
  const [enrollLabel, setEnrollLabel] = useState('kali-live-usb-station');
  const [enrollTtl, setEnrollTtl] = useState(15);
  const [revokeReason, setRevokeReason] = useState('Scheduled operator credential revocation');
  const [feedback, setFeedback] = useState<{ type: 'success' | 'error'; text: string } | null>(null);

  const handleSaveConfig = async (e: React.FormEvent) => {
    e.preventDefault();
    const targets = allowedTargetsText
      .split(',')
      .map((s) => s.trim())
      .filter(Boolean);
    const res = await onSaveBackendUrl(backendUrlInput, targets);
    setFeedback({ type: res.ok ? 'success' : 'error', text: res.message });
  };

  const handleIssueCode = async (e: React.FormEvent) => {
    e.preventDefault();
    const res = await onIssueEnrollmentCode(enrollLabel, enrollTtl);
    setFeedback({ type: res.ok ? 'success' : 'error', text: res.message });
  };

  return (
    <div className="space-y-8">
      <section className="bg-[#0F172A] border border-slate-800 rounded-xl p-6 space-y-2">
        <div className="flex items-center gap-2 text-xs text-slate-400">
          <span>Zero-Secret Exposure Architecture</span>
          <span aria-hidden="true">·</span>
          <span>SHA-256 Hashed Credential Store</span>
          <span aria-hidden="true">·</span>
          <span>0600 Local Kali Config</span>
        </div>
        <h1 className="text-2xl font-semibold text-slate-100 tracking-tight">
          Secure Configuration, Enrollment &amp; Credential Lifecycle
        </h1>
        <p className="text-sm text-slate-300 max-w-3xl leading-relaxed">
          Manage the HTTPS control plane endpoint, approved target CIDR/hostname scope, short-lived single-use
          enrollment codes, and live agent token rotation or revocation. Live agent bearer tokens are never stored in{' '}
          <code className="text-teal-300">localStorage</code>, URLs, logs, or downloadable setup packages.
        </p>
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

      <section className="grid grid-cols-1 lg:grid-cols-12 gap-6 items-stretch">
        {/* Left 6 cols: HTTPS Backend URL & Scope Policy */}
        <div className="lg:col-span-6 bg-[#0F172A] border border-slate-800 rounded-xl p-6 space-y-5">
          <div className="space-y-1">
            <h2 className="text-lg font-semibold text-slate-100 flex items-center gap-2">
              <Lock className="w-4 h-4 text-teal-400" aria-hidden="true" />
              <span>01. Backend HTTPS Endpoint &amp; Target Scope</span>
            </h2>
            <p className="text-xs text-slate-400">
              Non-HTTPS URLs and URLs containing query-string tokens (<code className="text-slate-300">?token=</code>)
              are automatically rejected.
            </p>
          </div>

          <form onSubmit={handleSaveConfig} className="space-y-4">
            <div className="space-y-1.5">
              <label htmlFor="secure-backend-url" className="block text-xs font-medium text-slate-300">
                Backend HTTPS URL
              </label>
              <input
                id="secure-backend-url"
                type="text"
                value={backendUrlInput}
                onChange={(e) => setBackendUrlInput(e.target.value)}
                className="w-full bg-[#0B1120] border border-slate-700 rounded-lg px-3 py-2 text-sm font-mono text-slate-100 focus:outline-none focus:border-teal-500"
              />
            </div>

            <div className="space-y-1.5">
              <label htmlFor="allowed-targets-input" className="block text-xs font-medium text-slate-300">
                Approved Lab Targets (Comma-Separated CIDRs or Hostnames)
              </label>
              <input
                id="allowed-targets-input"
                type="text"
                value={allowedTargetsText}
                onChange={(e) => setAllowedTargetsText(e.target.value)}
                className="w-full bg-[#0B1120] border border-slate-700 rounded-lg px-3 py-2 text-xs font-mono text-slate-100 focus:outline-none focus:border-teal-500"
              />
              <p className="text-[11px] text-slate-400">
                Validated both on the Node.js control plane and inside <code className="text-slate-300">sentinel_agent.py</code> on Kali Linux.
              </p>
            </div>

            <button
              type="submit"
              className="px-4 py-2 text-xs font-medium bg-teal-500 text-slate-950 rounded-lg hover:bg-teal-400 transition-colors cursor-pointer"
            >
              Save HTTPS Endpoint &amp; Scope Policy
            </button>
          </form>
        </div>

        {/* Right 6 cols: Short-Lived Single-Use Enrollment Flow */}
        <div className="lg:col-span-6 bg-[#0F172A] border border-slate-800 rounded-xl p-6 space-y-5">
          <div className="space-y-1">
            <h2 className="text-lg font-semibold text-slate-100 flex items-center gap-2">
              <KeyRound className="w-4 h-4 text-teal-400" aria-hidden="true" />
              <span>02. Short-Lived Single-Use Enrollment Flow</span>
            </h2>
            <p className="text-xs text-slate-400">
              Each enrollment code is single-use, expires after the configured TTL, and is stored only as a SHA-256
              digest in the database.
            </p>
          </div>

          <form onSubmit={handleIssueCode} className="grid grid-cols-1 sm:grid-cols-3 gap-3 items-end">
            <div className="sm:col-span-2 space-y-1.5">
              <label htmlFor="enrollment-label" className="block text-xs font-medium text-slate-300">
                Workstation Label
              </label>
              <input
                id="enrollment-label"
                type="text"
                value={enrollLabel}
                onChange={(e) => setEnrollLabel(e.target.value)}
                className="w-full bg-[#0B1120] border border-slate-700 rounded-lg px-3 py-2 text-xs font-mono text-slate-100"
              />
            </div>

            <div className="space-y-1.5">
              <label htmlFor="enrollment-ttl" className="block text-xs font-medium text-slate-300">
                TTL (Minutes)
              </label>
              <input
                id="enrollment-ttl"
                type="number"
                min={1}
                max={60}
                value={enrollTtl}
                onChange={(e) => setEnrollTtl(Number(e.target.value))}
                className="w-full bg-[#0B1120] border border-slate-700 rounded-lg px-3 py-2 text-xs font-mono text-slate-100 tabular-nums"
              />
            </div>

            <div className="sm:col-span-3 flex flex-wrap gap-2.5 pt-1">
              <button
                type="submit"
                className="px-4 py-2 text-xs font-medium bg-teal-500 text-slate-950 rounded-lg hover:bg-teal-400 transition-colors cursor-pointer"
              >
                Issue Single-Use Enrollment Code
              </button>

              {lastIssuedOneTimeCode && (
                <button
                  type="button"
                  onClick={async () => {
                    const res = await onSimulateKaliEnroll(lastIssuedOneTimeCode);
                    setFeedback({ type: res.ok ? 'success' : 'error', text: res.message });
                  }}
                  className="px-4 py-2 text-xs font-medium bg-slate-800 text-teal-300 border border-teal-700/70 rounded-lg hover:bg-slate-700 transition-colors flex items-center gap-1.5 cursor-pointer"
                >
                  <Terminal className="w-3.5 h-3.5" aria-hidden="true" />
                  <span>Enroll Kali Agent with Issued Code</span>
                </button>
              )}
            </div>
          </form>

          {lastIssuedOneTimeCode && (
            <div className="p-3.5 bg-[#0B1120] border border-teal-800/80 rounded-lg space-y-1">
              <div className="text-xs text-teal-300 font-medium">
                Active One-Time Enrollment Code (Shown Once in Memory Only):
              </div>
              <div className="font-mono text-sm text-slate-100 select-all tabular-nums">{lastIssuedOneTimeCode}</div>
            </div>
          )}
        </div>
      </section>

      {/* Token Rotation & Revocation + Audit Trail */}
      <section className="grid grid-cols-1 lg:grid-cols-12 gap-6 items-stretch">
        <div className="lg:col-span-5 bg-[#0F172A] border border-slate-800 rounded-xl p-6 space-y-5">
          <div className="space-y-1">
            <h2 className="text-lg font-semibold text-slate-100">03. Token Rotation &amp; Revocation Status</h2>
            <p className="text-xs text-slate-400">
              Rotate or immediately revoke the credential stored in <code className="text-slate-300">~/.config/sentinel-agent/agent.conf</code>.
            </p>
          </div>

          {status.activeAgent ? (
            <div className="space-y-4">
              <div className="p-4 bg-[#0B1120] border border-slate-800 rounded-lg space-y-2 text-xs">
                <div className="flex justify-between">
                  <span className="text-slate-400">Masked Credential Fingerprint</span>
                  <span className="font-mono text-teal-300 tabular-nums">{status.activeAgent.tokenFingerprint}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-slate-400">Rotation Count</span>
                  <span className="font-mono text-slate-200 tabular-nums">{status.activeAgent.tokenRotationCount}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-slate-400">Expires At</span>
                  <span className="font-mono text-slate-200 tabular-nums">
                    {new Date(status.activeAgent.tokenExpiresAt).toLocaleDateString()}
                  </span>
                </div>
                <div className="flex justify-between">
                  <span className="text-slate-400">Revocation Status</span>
                  <span className={status.activeAgent.revoked ? 'text-rose-400 font-semibold' : 'text-teal-300'}>
                    {status.activeAgent.revoked
                      ? `Revoked (${status.activeAgent.revokedReason})`
                      : 'Active & Valid'}
                  </span>
                </div>
              </div>

              <div className="space-y-2">
                <label htmlFor="revoke-reason-input" className="block text-xs font-medium text-slate-300">
                  Revocation Reason (Recorded in Audit Log)
                </label>
                <input
                  id="revoke-reason-input"
                  type="text"
                  value={revokeReason}
                  onChange={(e) => setRevokeReason(e.target.value)}
                  className="w-full bg-[#0B1120] border border-slate-700 rounded-lg px-3 py-2 text-xs text-slate-100"
                />
              </div>

              <div className="flex flex-wrap gap-3">
                <button
                  type="button"
                  disabled={status.activeAgent.revoked}
                  onClick={async () => {
                    const res = await onRotateToken();
                    setFeedback({ type: res.ok ? 'success' : 'error', text: res.message });
                  }}
                  className="px-4 py-2 text-xs font-medium bg-slate-800 text-slate-100 border border-slate-700 rounded-lg hover:bg-slate-700 disabled:opacity-40 transition-colors flex items-center gap-2 cursor-pointer"
                >
                  <RotateCw className="w-3.5 h-3.5 text-teal-400" aria-hidden="true" />
                  <span>Rotate Agent Credential</span>
                </button>

                <button
                  type="button"
                  disabled={status.activeAgent.revoked}
                  onClick={async () => {
                    const res = await onRevokeToken(revokeReason);
                    setFeedback({ type: res.ok ? 'success' : 'error', text: res.message });
                  }}
                  className="px-4 py-2 text-xs font-medium bg-rose-950/70 text-rose-200 border border-rose-800 rounded-lg hover:bg-rose-900/70 disabled:opacity-40 transition-colors flex items-center gap-2 cursor-pointer"
                >
                  <ShieldOff className="w-3.5 h-3.5 text-rose-400" aria-hidden="true" />
                  <span>Revoke Credential Immediately</span>
                </button>
              </div>
            </div>
          ) : (
            <div className="p-4 bg-[#0B1120] border border-slate-800 rounded-lg text-xs text-slate-400">
              No active agent credential enrolled yet. Issue a single-use enrollment code and enroll your Kali agent to
              manage token rotation or revocation.
            </div>
          )}
        </div>

        {/* Right 7 cols: Persistent Security Audit Log */}
        <div className="lg:col-span-7 bg-[#0F172A] border border-slate-800 rounded-xl p-6 space-y-4">
          <div className="flex items-center justify-between">
            <h2 className="text-lg font-semibold text-slate-100">04. Persistent Security Audit Trail</h2>
            <span className="text-xs font-mono text-slate-400 tabular-nums">
              {status.auditEvents.length} Events Recorded
            </span>
          </div>

          <div className="overflow-x-auto max-h-72 overflow-y-auto">
            <table className="w-full text-left border-collapse text-xs">
              <thead>
                <tr className="border-b border-slate-800 text-slate-400">
                  <th className="py-2 pr-3 font-medium">Timestamp</th>
                  <th className="py-2 px-3 font-medium">Event</th>
                  <th className="py-2 px-3 font-medium">Actor</th>
                  <th className="py-2 pl-3 font-medium">Summary</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/70">
                {status.auditEvents.map((ev) => (
                  <tr key={ev.id}>
                    <td className="py-2.5 pr-3 font-mono text-slate-400 tabular-nums whitespace-nowrap">
                      {new Date(ev.timestamp).toLocaleTimeString()}
                    </td>
                    <td className="py-2.5 px-3 font-mono text-teal-300 whitespace-nowrap">{ev.eventType}</td>
                    <td className="py-2.5 px-3 font-mono text-slate-300 whitespace-nowrap">{ev.actor}</td>
                    <td className="py-2.5 pl-3 text-slate-200">{ev.summary}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      </section>
    </div>
  );
};
