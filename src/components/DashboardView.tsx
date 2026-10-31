import React, { useState } from 'react';
import {
  ShieldCheck,
  AlertTriangle,
  Clock,
  SlidersHorizontal,
  ArrowRight,
  CheckCircle2,
  Circle,
  Terminal,
  RefreshCw,
  HardDrive,
} from 'lucide-react';
import {
  ControlPlaneStatus,
  NavPageId,
  WizardChecklistState,
} from '../types/sentinel';

interface DashboardViewProps {
  status: ControlPlaneStatus;
  isDemoMode: boolean;
  onNavigate: (page: NavPageId) => void;
  onSaveBackendUrl: (url: string, allowedTargets: string[]) => Promise<{ ok: boolean; message: string }>;
  onToggleChecklistStep: (key: keyof WizardChecklistState, value: boolean) => Promise<void>;
  onIssueEnrollmentCode: (label: string, ttlMinutes: number) => Promise<{
    ok: boolean;
    message: string;
    singleUseEnrollmentCode?: string;
  }>;
  onSimulateKaliEnroll: (code: string) => Promise<{ ok: boolean; message: string }>;
  onSendVerifiedHeartbeat: () => Promise<{ ok: boolean; message: string }>;
  lastIssuedOneTimeCode: string | null;
}

export const DashboardView: React.FC<DashboardViewProps> = ({
  status,
  isDemoMode,
  onNavigate,
  onSaveBackendUrl,
  onToggleChecklistStep,
  onIssueEnrollmentCode,
  onSimulateKaliEnroll,
  onSendVerifiedHeartbeat,
  lastIssuedOneTimeCode,
}) => {
  const [urlInput, setUrlInput] = useState(status.backendUrl || 'https://sentinel-usb-connect.internal');
  const [feedback, setFeedback] = useState<{ type: 'success' | 'error'; text: string } | null>(null);
  const [busy, setBusy] = useState(false);

  React.useEffect(() => {
    if (status.backendUrl) {
      setUrlInput(status.backendUrl);
    }
  }, [status.backendUrl]);

  const checklistItems: Array<{
    key: keyof WizardChecklistState;
    stepNum: string;
    title: string;
    verificationSource: string;
    done: boolean;
  }> = [
    {
      key: 'step1WindowsUsbPrepared',
      stepNum: '01',
      title: 'Format 16 GB setup USB drive on Windows (exFAT / FAT32, no autorun)',
      verificationSource: 'Operator verified on Windows host',
      done: status.wizardChecklist.step1WindowsUsbPrepared,
    },
    {
      key: 'step2PackageDownloaded',
      stepNum: '02',
      title: `Download versioned setup package (v${status.setupPackageVersion}) & verify SHA-256`,
      verificationSource: 'Backend package download audit',
      done: status.wizardChecklist.step2PackageDownloaded,
    },
    {
      key: 'step3KaliUsbMounted',
      stepNum: '03',
      title: 'Mount setup USB in Kali Linux Live USB and extract to user home directory',
      verificationSource: 'Operator verified in Kali terminal',
      done: status.wizardChecklist.step3KaliUsbMounted,
    },
    {
      key: 'step4NonRootInstalled',
      stepNum: '04',
      title: 'Install Sentinel agent as non-root Linux user (UID >= 1000, never root)',
      verificationSource: 'Verified during agent enrollment',
      done: status.wizardChecklist.step4NonRootInstalled,
    },
    {
      key: 'step5BackendConfigured',
      stepNum: '05',
      title: 'Configure HTTPS Backend URL & single-use code in ~/.config/sentinel-agent/agent.conf (0600)',
      verificationSource: 'Backend enrollment authority',
      done: status.wizardChecklist.step5BackendConfigured,
    },
    {
      key: 'step6SystemdVerified',
      stepNum: '06',
      title: 'Enable user-level systemd unit (systemctl --user enable --now sentinel-agent.service)',
      verificationSource: 'Verified via authenticated heartbeat',
      done: status.wizardChecklist.step6SystemdVerified,
    },
  ];

  const completedSteps = checklistItems.filter((item) => item.done).length;
  const progressPercent = Math.round((completedSteps / checklistItems.length) * 100);

  const handleUrlSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setBusy(true);
    setFeedback(null);
    try {
      const res = await onSaveBackendUrl(urlInput, status.allowedTargets);
      setFeedback({ type: res.ok ? 'success' : 'error', text: res.message });
    } finally {
      setBusy(false);
    }
  };

  const handleQuickIssueCode = async () => {
    setBusy(true);
    setFeedback(null);
    try {
      const res = await onIssueEnrollmentCode('kali-live-usb-primary', 15);
      setFeedback({ type: res.ok ? 'success' : 'error', text: res.message });
    } finally {
      setBusy(false);
    }
  };

  const handleQuickSimulateHandshake = async () => {
    if (!lastIssuedOneTimeCode) {
      setFeedback({
        type: 'error',
        text: 'Issue a fresh single-use enrollment code first so the Kali agent can authenticate.',
      });
      return;
    }
    setBusy(true);
    setFeedback(null);
    try {
      const res = await onSimulateKaliEnroll(lastIssuedOneTimeCode);
      setFeedback({ type: res.ok ? 'success' : 'error', text: res.message });
    } finally {
      setBusy(false);
    }
  };

  const renderStatusIcon = () => {
    switch (status.connectionStatus) {
      case 'Connected':
        return <ShieldCheck className="w-5 h-5 text-teal-400 shrink-0" aria-hidden="true" />;
      case 'Waiting for Kali':
        return <Clock className="w-5 h-5 text-amber-400 shrink-0" aria-hidden="true" />;
      case 'Error':
        return <AlertTriangle className="w-5 h-5 text-rose-400 shrink-0" aria-hidden="true" />;
      default:
        return <SlidersHorizontal className="w-5 h-5 text-slate-400 shrink-0" aria-hidden="true" />;
    }
  };

  const statusColorClass =
    status.connectionStatus === 'Connected'
      ? 'text-teal-300'
      : status.connectionStatus === 'Waiting for Kali'
      ? 'text-amber-300'
      : status.connectionStatus === 'Error'
      ? 'text-rose-300'
      : 'text-slate-300';

  return (
    <div className="space-y-8">
      {/* Hardware & Verification Honesty Banner */}
      <section className="bg-[#0F172A] border border-slate-800 rounded-xl p-6">
        <div className="flex flex-col lg:flex-row lg:items-center lg:justify-between gap-6">
          <div className="space-y-2 max-w-3xl">
            <div className="flex flex-wrap items-center gap-x-2 gap-y-1 text-xs text-slate-400">
              <span className="whitespace-nowrap">Verification Policy</span>
              <span aria-hidden="true">·</span>
              <span className="whitespace-nowrap">Browser Sandbox Isolation</span>
              <span aria-hidden="true">·</span>
              <span className="whitespace-nowrap">Package v{status.setupPackageVersion}</span>
            </div>
            <h1 className="text-2xl font-semibold text-slate-100 tracking-tight">
              Kali Linux Live USB &amp; Sentinel Agent Control Plane
            </h1>
            <p className="text-sm text-slate-300 leading-relaxed">
              This web application prepares a reviewed setup archive for a second 16 GB USB drive and verifies incoming
              HTTPS enrollments from your Kali Linux system. A browser cannot directly detect physical USB insertion or
              control local <code className="text-teal-300">systemd</code> services—connection states below reflect
              cryptographically authenticated backend handshakes.
            </p>
          </div>
          <div className="flex flex-wrap items-center gap-3 shrink-0">
            <button
              type="button"
              onClick={() => onNavigate('wizard')}
              className="px-4 py-2.5 text-sm font-medium bg-teal-500 text-slate-950 rounded-lg hover:bg-teal-400 transition-colors flex items-center gap-2 whitespace-nowrap shrink-0 cursor-pointer"
            >
              <span>Open USB Setup Wizard</span>
              <ArrowRight className="w-4 h-4" aria-hidden="true" />
            </button>
            <a
              href="/api/setup-package/download"
              className="px-4 py-2.5 text-sm font-medium bg-slate-800 text-slate-100 border border-slate-700 rounded-lg hover:bg-slate-700 transition-colors flex items-center gap-2 whitespace-nowrap shrink-0"
            >
              <HardDrive className="w-4 h-4 text-teal-400" aria-hidden="true" />
              <span>Download Setup Package v{status.setupPackageVersion}</span>
            </a>
          </div>
        </div>
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

      {/* Primary Telemetry Row */}
      <section className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-5">
        <div className="bg-[#0F172A] border border-slate-800 rounded-xl p-5 space-y-3">
          <div className="flex items-center justify-between text-xs text-slate-400">
            <span>Kali Connection Status</span>
            <span>{isDemoMode ? 'Simulated' : 'Live API'}</span>
          </div>
          <div className="flex items-center gap-2.5">
            {renderStatusIcon()}
            <span className={`text-xl font-semibold tracking-tight ${statusColorClass}`} data-testid="connection-status-value">
              {status.connectionStatus}
            </span>
          </div>
          <p className="text-xs text-slate-400 leading-relaxed">{status.connectionReason}</p>
        </div>

        <div className="bg-[#0F172A] border border-slate-800 rounded-xl p-5 space-y-3">
          <div className="flex items-center justify-between text-xs text-slate-400">
            <span>Agent Service &amp; User</span>
            <span className="font-mono tabular-nums">
              {status.activeAgent ? `UID ${status.activeAgent.uid}` : 'Unenrolled'}
            </span>
          </div>
          <div className="text-xl font-semibold text-slate-100 font-mono tabular-nums truncate">
            {status.activeAgent
              ? `${status.activeAgent.linuxUser}@${status.activeAgent.hostname}`
              : 'No Active Agent'}
          </div>
          <p className="text-xs text-slate-400">
            {status.activeAgent
              ? `Unit: ${status.activeAgent.systemdUnitName} · ${status.activeAgent.systemdUnitStatus}`
              : 'Runs strictly as ordinary Linux user (never root).'}
          </p>
        </div>

        <div className="bg-[#0F172A] border border-slate-800 rounded-xl p-5 space-y-3">
          <div className="flex items-center justify-between text-xs text-slate-400">
            <span>Last Verified Heartbeat</span>
            <span className="font-mono tabular-nums">
              {status.activeAgent ? `Mode ${status.activeAgent.configFileMode}` : '—'}
            </span>
          </div>
          <div className="text-xl font-semibold text-slate-100 font-mono tabular-nums">
            {status.activeAgent?.lastHeartbeatAt
              ? new Date(status.activeAgent.lastHeartbeatAt).toLocaleTimeString([], {
                  hour: '2-digit',
                  minute: '2-digit',
                  second: '2-digit',
                })
              : 'None recorded'}
          </div>
          <p className="text-xs text-slate-400 font-mono tabular-nums truncate">
            {status.activeAgent
              ? `Token: ${status.activeAgent.tokenFingerprint}`
              : 'Requires single-use enrollment handshake.'}
          </p>
        </div>

        <div className="bg-[#0F172A] border border-slate-800 rounded-xl p-5 space-y-3">
          <div className="flex items-center justify-between text-xs text-slate-400">
            <span>Setup Progress</span>
            <span className="font-mono tabular-nums">{completedSteps} / 6 Verified</span>
          </div>
          <div className="text-xl font-semibold text-teal-300 font-mono tabular-nums">{progressPercent}% Complete</div>
          <div className="w-full h-2 bg-slate-800 rounded-full overflow-hidden">
            <div
              className="h-full bg-teal-500 transition-all duration-200"
              style={{ width: `${progressPercent}%` }}
            />
          </div>
        </div>
      </section>

      {/* Two-Column Split: USB Setup Checklist + Backend URL & Enrollment Quick Actions */}
      <section className="grid grid-cols-1 lg:grid-cols-12 gap-6 items-stretch">
        {/* Left 7 cols: USB Setup Checklist */}
        <div className="lg:col-span-7 bg-[#0F172A] border border-slate-800 rounded-xl p-6 flex flex-col justify-between space-y-6">
          <div className="space-y-2">
            <div className="flex items-center justify-between">
              <h2 className="text-lg font-semibold text-slate-100">01. USB Preparation &amp; Kali Setup Checklist</h2>
              <button
                type="button"
                onClick={() => onNavigate('wizard')}
                className="text-xs font-medium text-teal-400 hover:text-teal-300 transition-colors whitespace-nowrap shrink-0 cursor-pointer"
              >
                Step-by-Step Commands →
              </button>
            </div>
            <p className="text-xs text-slate-400">
              Steps 01 and 03 are performed locally by you on Windows and Kali Linux; Steps 02, 04, 05, and 06 are
              automatically marked when verified by the backend API (or can be toggled manually).
            </p>
          </div>

          <div className="divide-y divide-slate-800/80">
            {checklistItems.map((item) => (
              <div key={item.key} className="py-3.5 flex items-start justify-between gap-4">
                <label className="flex items-start gap-3 cursor-pointer select-none">
                  <input
                    type="checkbox"
                    checked={item.done}
                    onChange={(e) => onToggleChecklistStep(item.key, e.target.checked)}
                    className="sr-only"
                    aria-label={item.title}
                  />
                  {item.done ? (
                    <CheckCircle2 className="w-5 h-5 text-teal-400 shrink-0 mt-0.5" aria-hidden="true" />
                  ) : (
                    <Circle className="w-5 h-5 text-slate-500 shrink-0 mt-0.5" aria-hidden="true" />
                  )}
                  <div className="space-y-1">
                    <div className="text-sm font-medium text-slate-200">
                      <span className="font-mono text-xs text-teal-400 mr-2 tabular-nums">{item.stepNum}.</span>
                      {item.title}
                    </div>
                    <div className="text-xs text-slate-400">{item.verificationSource}</div>
                  </div>
                </label>
                <span className="text-xs font-mono tabular-nums text-slate-400 whitespace-nowrap shrink-0">
                  {item.done ? 'Verified' : 'Pending'}
                </span>
              </div>
            ))}
          </div>
        </div>

        {/* Right 5 cols: Backend URL Configuration & Live Enrollment Test */}
        <div className="lg:col-span-5 bg-[#0F172A] border border-slate-800 rounded-xl p-6 flex flex-col justify-between space-y-6">
          <div className="space-y-5">
            <div className="space-y-1">
              <h2 className="text-lg font-semibold text-slate-100">02. Backend HTTPS URL &amp; Enrollment</h2>
              <p className="text-xs text-slate-400">
                Configure the control plane endpoint written into <code className="text-slate-300">agent.conf</code> and
                issue a short-lived, single-use enrollment code.
              </p>
            </div>

            <form onSubmit={handleUrlSubmit} className="space-y-3">
              <div className="space-y-1.5">
                <label htmlFor="dashboard-backend-url" className="block text-xs font-medium text-slate-300">
                  Sentinel Control Plane HTTPS URL
                </label>
                <div className="flex gap-2">
                  <input
                    id="dashboard-backend-url"
                    type="text"
                    value={urlInput}
                    onChange={(e) => setUrlInput(e.target.value)}
                    placeholder="https://sentinel.research.internal"
                    className="flex-1 bg-[#0B1120] border border-slate-700 rounded-lg px-3 py-2 text-sm font-mono text-slate-100 focus:outline-none focus:border-teal-500"
                  />
                  <button
                    type="submit"
                    disabled={busy}
                    className="px-4 py-2 text-xs font-medium bg-slate-800 text-slate-100 border border-slate-700 rounded-lg hover:bg-slate-700 transition-colors whitespace-nowrap shrink-0 cursor-pointer"
                  >
                    Save URL
                  </button>
                </div>
              </div>
            </form>

            <div className="border-t border-slate-800 pt-4 space-y-3">
              <div className="flex items-center justify-between text-xs">
                <span className="text-slate-300 font-medium">Single-Use Enrollment Authority</span>
                <span className="text-slate-400 font-mono tabular-nums">
                  {status.pendingEnrollment ? `Active: ${status.pendingEnrollment.codeHint}` : 'No open code'}
                </span>
              </div>

              {lastIssuedOneTimeCode && (
                <div className="p-3 bg-[#0B1120] border border-teal-800/80 rounded-lg space-y-1">
                  <div className="text-xs text-teal-300 font-medium">
                    One-Time Enrollment Code (Copy to Kali ~/.config/sentinel-agent/agent.conf):
                  </div>
                  <div
                    className="font-mono text-sm text-slate-100 select-all break-all tabular-nums"
                    data-testid="issued-enrollment-code"
                  >
                    {lastIssuedOneTimeCode}
                  </div>
                </div>
              )}

              <div className="flex flex-wrap gap-2.5 pt-1">
                <button
                  type="button"
                  disabled={busy}
                  onClick={handleQuickIssueCode}
                  className="px-3.5 py-2 text-xs font-medium bg-teal-500 text-slate-950 rounded-lg hover:bg-teal-400 transition-colors whitespace-nowrap shrink-0 cursor-pointer"
                >
                  Issue Single-Use Enrollment Code
                </button>

                {lastIssuedOneTimeCode && status.connectionStatus !== 'Connected' && (
                  <button
                    type="button"
                    disabled={busy}
                    onClick={handleQuickSimulateHandshake}
                    className="px-3.5 py-2 text-xs font-medium bg-slate-800 text-teal-300 border border-teal-700/70 rounded-lg hover:bg-slate-700 transition-colors flex items-center gap-1.5 whitespace-nowrap shrink-0 cursor-pointer"
                  >
                    <Terminal className="w-3.5 h-3.5" aria-hidden="true" />
                    <span>Verify Kali Enrollment Handshake</span>
                  </button>
                )}

                {status.activeAgent && !status.activeAgent.revoked && (
                  <button
                    type="button"
                    disabled={busy}
                    onClick={onSendVerifiedHeartbeat}
                    className="px-3.5 py-2 text-xs font-medium bg-slate-800 text-slate-200 border border-slate-700 rounded-lg hover:bg-slate-700 transition-colors flex items-center gap-1.5 whitespace-nowrap shrink-0 cursor-pointer"
                  >
                    <RefreshCw className="w-3.5 h-3.5" aria-hidden="true" />
                    <span>Send Verified Heartbeat</span>
                  </button>
                )}
              </div>
            </div>
          </div>

          {/* Troubleshooting Reference */}
          <div className="border-t border-slate-800 pt-4 space-y-2">
            <h3 className="text-xs font-semibold text-slate-300">Quick Troubleshooting</h3>
            <ul className="space-y-1.5 text-xs text-slate-400 leading-relaxed">
              <li>
                · <strong className="text-slate-300">USB not mounting in Kali Live:</strong> Run{' '}
                <code className="text-slate-200">lsblk -f</code> and mount under{' '}
                <code className="text-slate-200">/media/kali/SENTINEL_SETUP</code>.
              </li>
              <li>
                · <strong className="text-slate-300">Enrollment rejected (UID 0):</strong> Do not use{' '}
                <code className="text-slate-200">sudo</code> when running <code className="text-slate-200">install-agent.sh</code> or{' '}
                <code className="text-slate-200">systemctl --user</code>.
              </li>
              <li>
                · <strong className="text-slate-300">Permission check failure:</strong> Run{' '}
                <code className="text-slate-200">chmod 600 ~/.config/sentinel-agent/agent.conf</code>.
              </li>
            </ul>
          </div>
        </div>
      </section>
    </div>
  );
};
