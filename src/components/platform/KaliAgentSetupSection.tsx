import React, { useState } from 'react';
import {
  Terminal,
  Download,
  KeyRound,
  ShieldCheck,
  CheckCircle2,
  Copy,
  FileCode2,
  AlertTriangle,
  ArrowRight,
  Cpu,
  Trash2,
} from 'lucide-react';
import type { PlatformBootstrapPayload, PlatformTabId } from '../../types/platform';

interface KaliAgentSetupSectionProps {
  data: PlatformBootstrapPayload;
  demoMode: boolean;
  onIssueEnrollmentCode: (payload: {
    targetHostname: string;
    linuxUser: string;
    ttlMinutes: number;
  }) => Promise<{
    ok: boolean;
    message: string;
    plaintextCode?: string;
  }>;
  onEnrollDeviceWithCode: (payload: {
    enrollmentCode: string;
    hostname: string;
    linuxUser: string;
    uid: number;
    version: string;
    osInfo: string;
  }) => Promise<{
    ok: boolean;
    code: string;
    message: string;
  }>;
  onNavigate: (tab: PlatformTabId) => void;
}

const INSPECTABLE_FILES: Array<{
  id: string;
  filename: string;
  path: string;
  mode: string;
  summary: string;
  downloadHref: string;
  snippet: string;
}> = [
  {
    id: 'installer',
    filename: 'install-sentinel-agent.sh',
    path: 'scripts/install-sentinel-agent.sh',
    mode: '0755',
    summary:
      'One-time installer: checks OS (/etc/os-release), verifies python3/sha256sum/systemctl, validates SHA256SUMS, enforces non-root UID >= 1000, and configures systemd --user + login autostart.',
    downloadHref: '/api/v1/agent-package/file/install-sentinel-agent.sh',
    snippet: `#!/usr/bin/env bash
set -euo pipefail

# 1. Refuse root execution (must run as dedicated non-root user UID >= 1000)
if [ "$(id -u)" -eq 0 ] || [ "$(id -u)" -lt 1000 ]; then
  echo "[FATAL] Run install-sentinel-agent.sh as an unprivileged user (UID >= 1000)." >&2
  exit 1
fi

# 2. Check OS & required dependencies
. /etc/os-release
for cmd in python3 sha256sum systemctl curl; do
  command -v "$cmd" >/dev/null 2>&1 || { echo "Missing dependency: $cmd" >&2; exit 1; }
done

# 3. Verify cryptographic package integrity
sha256sum -c SHA256SUMS

# 4. Install agent & configure 0600 config permissions + systemd user service
mkdir -p ~/.local/share/sentinel-agent ~/.config/sentinel-agent ~/.config/systemd/user ~/.config/autostart
chmod 0700 ~/.local/share/sentinel-agent ~/.config/sentinel-agent
install -m 0750 agent/sentinel_agent.py ~/.local/share/sentinel-agent/sentinel_agent.py
install -m 0644 systemd/sentinel-agent.service ~/.config/systemd/user/sentinel-agent.service
install -m 0644 systemd/sentinel-agent.desktop ~/.config/autostart/sentinel-agent.desktop
systemctl --user daemon-reload
systemctl --user enable sentinel-agent.service`,
  },
  {
    id: 'python-agent',
    filename: 'sentinel_agent.py',
    path: 'agent/sentinel_agent.py',
    mode: '0755',
    summary:
      'Outbound HTTPS polling Python 3 agent. Executes ONLY typed, allowlisted tasks (passive_http_headers, static_code_analysis). Never executes shell commands.',
    downloadHref: '/api/v1/agent-package/file/sentinel_agent.py',
    snippet: `#!/usr/bin/env python3
"""
Sentinel AI Outbound HTTPS Polling Agent (v2.1.0)
- Refuses UID < 1000 and enforces 0600 permissions on ~/.config/sentinel-agent/agent.conf
- Exchanges single-use enrollment code via POST /api/v1/agent/enroll
- Sends authenticated heartbeat via POST /api/v1/agent/heartbeat
- Executes ONLY allowlisted tasks: passive_http_headers & static_code_analysis
- Zero subprocess shell execution (never runs arbitrary or AI-generated shell scripts)
"""
ALLOWLISTED_CATEGORIES = frozenset({"passive_http_headers", "static_code_analysis"})

def execute_typed_job(job: dict) -> dict:
    category = str(job.get("category", ""))
    if category not in ALLOWLISTED_CATEGORIES:
        raise ValueError(f"Refusing non-allowlisted category: {category}")
    if category == "passive_http_headers":
        return run_allowlisted_passive_http_headers(str(job["targetHost"]))
    return run_allowlisted_static_analysis(str(job.get("codeSnippet", "")), str(job.get("codeFilename", "snippet.ts")))`,
  },
  {
    id: 'systemd-unit',
    filename: 'sentinel-agent.service',
    path: 'systemd/sentinel-agent.service',
    mode: '0644',
    summary:
      'User-level systemd service template with NoNewPrivileges=true, ProtectSystem=strict, and automatic restart on failure.',
    downloadHref: '/api/v1/agent-package/file/sentinel-agent.service',
    snippet: `[Unit]
Description=Sentinel AI Outbound Polling Research Agent (v2.1.0)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/bin/python3 %h/.local/share/sentinel-agent/sentinel_agent.py
Restart=on-failure
RestartSec=20
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ReadWritePaths=%h/.config/sentinel-agent %h/.local/state/sentinel-agent

[Install]
WantedBy=default.target`,
  },
  {
    id: 'autostart-desktop',
    filename: 'sentinel-agent.desktop',
    path: 'systemd/sentinel-agent.desktop',
    mode: '0644',
    summary:
      'XDG desktop autostart entry ensuring automatic agent startup immediately after the Kali user logs in.',
    downloadHref: '/api/v1/agent-package/file/sentinel-agent.desktop',
    snippet: `[Desktop Entry]
Type=Application
Name=Sentinel AI Research Agent
Comment=Starts the user-level Sentinel AI systemd service upon Kali desktop login
Exec=/usr/bin/systemctl --user start sentinel-agent.service
Terminal=false
Hidden=false
X-GNOME-Autostart-enabled=true`,
  },
  {
    id: 'uninstaller',
    filename: 'uninstall-sentinel-agent.sh',
    path: 'scripts/uninstall-sentinel-agent.sh',
    mode: '0755',
    summary:
      'Safe uninstaller script: stops and disables sentinel-agent.service, removes login autostart hooks, and shreds ~/.config/sentinel-agent/agent.conf.',
    downloadHref: '/api/v1/agent-package/file/uninstall-sentinel-agent.sh',
    snippet: `#!/usr/bin/env bash
set -euo pipefail
systemctl --user stop sentinel-agent.service 2>/dev/null || true
systemctl --user disable sentinel-agent.service 2>/dev/null || true
rm -f ~/.config/systemd/user/sentinel-agent.service ~/.config/autostart/sentinel-agent.desktop
systemctl --user daemon-reload 2>/dev/null || true

if [ -f ~/.config/sentinel-agent/agent.conf ]; then
  shred -u -z -n 3 ~/.config/sentinel-agent/agent.conf 2>/dev/null || rm -f ~/.config/sentinel-agent/agent.conf
fi
rm -rf ~/.local/share/sentinel-agent ~/.config/sentinel-agent ~/.local/state/sentinel-agent
echo "Safe uninstallation complete."`,
  },
];

export const KaliAgentSetupSection: React.FC<KaliAgentSetupSectionProps> = ({
  data,
  demoMode,
  onIssueEnrollmentCode,
  onEnrollDeviceWithCode,
  onNavigate,
}) => {
  const [targetHostname, setTargetHostname] = useState('kali-field-laptop01');
  const [linuxUser, setLinuxUser] = useState('kali');
  const [ttlMinutes, setTtlMinutes] = useState(10);
  const [issuedPlaintextCode, setIssuedPlaintextCode] = useState<string>('');
  const [enrollCodeInput, setEnrollCodeInput] = useState<string>('');
  const [enrollUid, setEnrollUid] = useState<number>(1000);
  const [selectedFileId, setSelectedFileId] = useState<string>('installer');
  const [feedback, setFeedback] = useState<{ ok: boolean; text: string } | null>(null);
  const [copied, setCopied] = useState(false);

  const enrollmentCodes = data.enrollmentCodes || [];
  const activeInspectFile =
    INSPECTABLE_FILES.find((f) => f.id === selectedFileId) || INSPECTABLE_FILES[0];

  const handleIssueCode = async (e: React.FormEvent) => {
    e.preventDefault();
    const res = await onIssueEnrollmentCode({
      targetHostname,
      linuxUser,
      ttlMinutes,
    });
    setFeedback({ ok: res.ok, text: res.message });
    if (res.ok && res.plaintextCode) {
      setIssuedPlaintextCode(res.plaintextCode);
      setEnrollCodeInput(res.plaintextCode);
    }
  };

  const handleSimulateEnrollment = async (e: React.FormEvent) => {
    e.preventDefault();
    const res = await onEnrollDeviceWithCode({
      enrollmentCode: enrollCodeInput,
      hostname: targetHostname,
      linuxUser,
      uid: enrollUid,
      version: '2.1.0',
      osInfo: 'Kali GNU/Linux Rolling 2026.1 (x86_64)',
    });
    setFeedback({ ok: res.ok, text: res.message });
  };

  const handleCopyCode = () => {
    if (!issuedPlaintextCode) return;
    void navigator.clipboard?.writeText(issuedPlaintextCode);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <div className="space-y-6">
      {/* Header & Explicit Manual Installation Transparency Notice */}
      <section className="rounded-xl border border-slate-800 bg-[#0F172A] p-6 space-y-4">
        <div className="flex flex-col lg:flex-row lg:items-center lg:justify-between gap-4">
          <div className="space-y-1.5">
            <div className="flex flex-wrap items-center gap-2 text-xs font-mono text-teal-400">
              <span>KALI LINUX AGENT SETUP</span>
              <span>·</span>
              <span>SINGLE-USE ENROLLMENT</span>
              <span>·</span>
              <span>LEAST-PRIVILEGE SYSTEMD USER SERVICE</span>
            </div>
            <h1 className="text-xl sm:text-2xl font-semibold text-slate-100 tracking-tight">
              Kali Linux Agent Installer &amp; Secure Device Registration
            </h1>
            <p className="text-sm text-slate-300 max-w-3xl leading-relaxed">
              Prepare and enroll an unprivileged Kali Linux research workstation using a short-lived, single-use
              enrollment code, a cryptographic SHA-256 verified installer package, and a user-level{' '}
              <code className="font-mono text-teal-300">systemd --user</code> service that starts automatically after
              Kali user login.
            </p>
          </div>

          <div className="flex flex-wrap items-center gap-2.5 self-start">
            <a
              href="/api/v1/agent-package/bundle.tar.gz"
              className="px-3.5 py-2 rounded-lg bg-teal-500 hover:bg-teal-400 text-slate-950 font-semibold text-xs transition-colors flex items-center gap-1.5"
            >
              <Download className="w-3.5 h-3.5" />
              Download Full Bundle (.tar.gz)
            </a>
            <button
              type="button"
              onClick={() => onNavigate('agent-health')}
              className="px-3.5 py-2 rounded-lg border border-slate-700 hover:border-teal-500/50 bg-slate-900 text-slate-200 font-medium text-xs transition-colors flex items-center gap-1.5 cursor-pointer"
            >
              <span>Manage Enrolled Devices ({data.agents.length})</span>
              <ArrowRight className="w-3.5 h-3.5 text-teal-400" />
            </button>
          </div>
        </div>

        {/* Mandatory Browser Boundary Disclosure */}
        <div className="rounded-lg border border-amber-500/30 bg-amber-950/20 p-3.5 flex items-start gap-3">
          <AlertTriangle className="w-4 h-4 text-amber-400 shrink-0 mt-0.5" />
          <div className="text-xs text-slate-200 space-y-1">
            <div className="font-semibold text-amber-300">
              Manual Operator Execution Required — Web Browsers Cannot Silently Install Software
            </div>
            <p className="text-slate-300 leading-relaxed">
              Opening this website in a browser never modifies your local operating system, USB drive, or systemd
              services. You must explicitly download the versioned installer package, verify its{' '}
              <code className="font-mono text-amber-200">SHA256SUMS</code> manifest in your Kali terminal, and run{' '}
              <code className="font-mono text-amber-200">./scripts/install-sentinel-agent.sh</code> as a non-root user
              (<code className="font-mono text-amber-200">UID &gt;= 1000</code>). Enrolled devices remain in{' '}
              <code className="font-mono text-teal-300">pending_heartbeat</code> state and are never shown as{' '}
              <code className="font-mono text-teal-300">online</code> until a real authenticated heartbeat is received.
            </p>
          </div>
        </div>
      </section>

      {feedback && (
        <div
          role="status"
          className={`p-4 rounded-lg border text-xs flex items-center justify-between gap-3 ${
            feedback.ok
              ? 'bg-teal-950/40 border-teal-700/80 text-teal-200'
              : 'bg-rose-950/40 border-rose-700/80 text-rose-200'
          }`}
        >
          <span className="font-mono">{feedback.text}</span>
          <button
            type="button"
            onClick={() => setFeedback(null)}
            className="underline opacity-80 hover:opacity-100 cursor-pointer"
          >
            Dismiss
          </button>
        </div>
      )}

      {/* Step 1 & Step 2 Grid: Single-Use Enrollment Workflow + Package Downloads */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6 items-stretch">
        {/* Left 6 Cols: Issue & Exchange Short-Lived Single-Use Enrollment Code */}
        <section className="lg:col-span-6 rounded-xl border border-slate-800 bg-[#0F172A] p-6 space-y-5 flex flex-col justify-between">
          <div className="space-y-4">
            <div className="flex items-center justify-between gap-2">
              <h2 className="text-base font-semibold text-slate-100 flex items-center gap-2">
                <KeyRound className="w-4 h-4 text-teal-400" />
                1. Issue Short-Lived Single-Use Enrollment Code
              </h2>
              <span className="text-xs font-mono text-slate-400">SHA-256 Hashed at Rest</span>
            </div>
            <p className="text-xs text-slate-400 leading-relaxed">
              Generate a short-lived, single-use enrollment code bound to your Kali hostname and unprivileged Linux
              service account. Once exchanged by the installer or Python agent, the code is permanently marked{' '}
              <code className="font-mono text-teal-300">consumed</code> and cannot be replayed.
            </p>

            <form onSubmit={(e) => void handleIssueCode(e)} className="grid grid-cols-1 sm:grid-cols-3 gap-3 text-xs">
              <div>
                <label htmlFor="enr-hostname" className="block text-slate-300 font-medium mb-1">
                  Target Kali Hostname
                </label>
                <input
                  id="enr-hostname"
                  type="text"
                  value={targetHostname}
                  onChange={(e) => setTargetHostname(e.target.value)}
                  className="w-full rounded-lg border border-slate-700 bg-[#0B1120] px-3 py-2 font-mono text-slate-100"
                  required
                />
              </div>
              <div>
                <label htmlFor="enr-user" className="block text-slate-300 font-medium mb-1">
                  Service Account (UID &gt;= 1000)
                </label>
                <input
                  id="enr-user"
                  type="text"
                  value={linuxUser}
                  onChange={(e) => setLinuxUser(e.target.value)}
                  className="w-full rounded-lg border border-slate-700 bg-[#0B1120] px-3 py-2 font-mono text-slate-100"
                  required
                />
              </div>
              <div>
                <label htmlFor="enr-ttl" className="block text-slate-300 font-medium mb-1">
                  Expiry TTL (Minutes)
                </label>
                <input
                  id="enr-ttl"
                  type="number"
                  min={1}
                  max={60}
                  value={ttlMinutes}
                  onChange={(e) => setTtlMinutes(Number(e.target.value))}
                  className="w-full rounded-lg border border-slate-700 bg-[#0B1120] px-3 py-2 font-mono text-slate-100 tabular-nums"
                />
              </div>
              <div className="sm:col-span-3">
                <button
                  type="submit"
                  className="w-full py-2.5 px-4 rounded-lg bg-teal-500 hover:bg-teal-400 text-slate-950 font-semibold text-xs transition-colors cursor-pointer"
                >
                  Issue Single-Use Enrollment Code
                </button>
              </div>
            </form>

            {issuedPlaintextCode && (
              <div className="rounded-lg border border-teal-500/40 bg-teal-950/30 p-3.5 space-y-2">
                <div className="flex items-center justify-between gap-2">
                  <span className="text-xs font-semibold text-teal-300">
                    One-Time Enrollment Code (Copy now — never stored in plaintext):
                  </span>
                  <button
                    type="button"
                    onClick={handleCopyCode}
                    className="px-2.5 py-1 rounded bg-slate-900 border border-teal-500/40 text-teal-300 text-xs font-mono flex items-center gap-1 cursor-pointer"
                  >
                    <Copy className="w-3 h-3" />
                    {copied ? 'Copied' : 'Copy Code'}
                  </button>
                </div>
                <div className="p-2.5 rounded bg-[#0B1120] border border-slate-800 font-mono text-xs text-teal-200 select-all">
                  {issuedPlaintextCode}
                </div>
              </div>
            )}

            {/* Interactive Enrollment Exchange Simulator / Verifier */}
            <form
              onSubmit={(e) => void handleSimulateEnrollment(e)}
              className="border-t border-slate-800 pt-4 space-y-3 text-xs"
            >
              <div className="flex items-center justify-between">
                <h3 className="text-xs font-semibold text-slate-200">
                  Verify / Test Device Enrollment Exchange (POST /api/v1/agent/enroll)
                </h3>
                <span className="font-mono text-[11px] text-slate-400">
                  Initial State: pending_heartbeat
                </span>
              </div>
              <div className="grid grid-cols-1 sm:grid-cols-3 gap-2.5">
                <div className="sm:col-span-2">
                  <label htmlFor="sim-enroll-code" className="block text-slate-400 mb-1">
                    Single-Use Enrollment Code
                  </label>
                  <input
                    id="sim-enroll-code"
                    type="text"
                    placeholder="STNL-ENROLL-XXXX-XXXX-XXXX"
                    value={enrollCodeInput}
                    onChange={(e) => setEnrollCodeInput(e.target.value)}
                    className="w-full rounded-lg border border-slate-700 bg-[#0B1120] px-3 py-2 font-mono text-slate-100"
                  />
                </div>
                <div>
                  <label htmlFor="sim-uid" className="block text-slate-400 mb-1">
                    Linux UID (&gt;= 1000)
                  </label>
                  <input
                    id="sim-uid"
                    type="number"
                    value={enrollUid}
                    onChange={(e) => setEnrollUid(Number(e.target.value))}
                    className="w-full rounded-lg border border-slate-700 bg-[#0B1120] px-3 py-2 font-mono text-slate-100 tabular-nums"
                  />
                </div>
              </div>
              <div className="flex flex-wrap items-center gap-2">
                <button
                  type="submit"
                  className="px-3.5 py-2 rounded-lg bg-slate-800 hover:bg-slate-700 border border-teal-500/40 text-teal-300 font-medium text-xs cursor-pointer"
                >
                  Exchange Code &amp; Register Device (Starts Pending Heartbeat)
                </button>
                <button
                  type="button"
                  onClick={() => setEnrollUid(0)}
                  className="px-3 py-2 rounded-lg bg-slate-900 hover:bg-slate-800 border border-slate-700 text-slate-300 text-xs cursor-pointer"
                >
                  Test UID 0 (Root Rejection)
                </button>
              </div>
            </form>
          </div>

          {/* Active & Consumed Enrollment Codes Ledger */}
          <div className="border-t border-slate-800 pt-4 space-y-2">
            <div className="text-xs font-semibold text-slate-300">
              Recent Single-Use Enrollment Codes ({enrollmentCodes.length})
            </div>
            <div className="space-y-1.5 max-h-40 overflow-y-auto pr-1">
              {enrollmentCodes.map((c) => (
                <div
                  key={c.id}
                  className="rounded-lg border border-slate-800 bg-[#0B1120] px-3 py-2 text-xs flex items-center justify-between gap-2"
                >
                  <div className="min-w-0">
                    <div className="font-mono text-slate-200 truncate">
                      {c.codePreview} · <span className="text-teal-400">{c.linuxUser}@{c.targetHostname}</span>
                    </div>
                    <div className="text-[11px] text-slate-400 font-mono">
                      Expires: {new Date(c.expiresAt).toLocaleTimeString()} · Issued by {c.issuedBy}
                    </div>
                  </div>
                  <span
                    className={`font-mono text-[11px] uppercase shrink-0 ${
                      c.status === 'active'
                        ? 'text-teal-400'
                        : c.status === 'consumed'
                        ? 'text-amber-300'
                        : 'text-rose-400'
                    }`}
                  >
                    {c.status}
                  </span>
                </div>
              ))}
            </div>
          </div>
        </section>

        {/* Right 6 Cols: Downloadable Linux Installer & Python Agent Package + Inspector */}
        <section className="lg:col-span-6 rounded-xl border border-slate-800 bg-[#0F172A] p-6 space-y-5 flex flex-col justify-between">
          <div className="space-y-4">
            <div className="flex items-center justify-between gap-2">
              <h2 className="text-base font-semibold text-slate-100 flex items-center gap-2">
                <FileCode2 className="w-4 h-4 text-teal-400" />
                2. Downloadable Linux Installer &amp; Python Agent Package
              </h2>
              <span className="text-xs font-mono text-teal-400">v2.1.0 · Zero Embedded Secrets</span>
            </div>
            <p className="text-xs text-slate-400 leading-relaxed">
              Download the complete <code className="font-mono text-slate-200">.tar.gz</code> archive or individual
              audited scripts below. Inspect every line before running on Kali Linux.
            </p>

            {/* Direct Download Cards */}
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-2.5 text-xs">
              <a
                href="/api/v1/agent-package/file/install-sentinel-agent.sh"
                className="rounded-lg border border-slate-800 hover:border-teal-500/40 bg-[#0B1120] p-3 flex items-center justify-between gap-2 transition-colors"
              >
                <div>
                  <div className="font-mono font-semibold text-slate-100">install-sentinel-agent.sh</div>
                  <div className="text-[11px] text-slate-400">One-time OS, dep &amp; systemd installer</div>
                </div>
                <Download className="w-4 h-4 text-teal-400 shrink-0" />
              </a>

              <a
                href="/api/v1/agent-package/file/sentinel_agent.py"
                className="rounded-lg border border-slate-800 hover:border-teal-500/40 bg-[#0B1120] p-3 flex items-center justify-between gap-2 transition-colors"
              >
                <div>
                  <div className="font-mono font-semibold text-slate-100">sentinel_agent.py</div>
                  <div className="text-[11px] text-slate-400">Python 3 outbound HTTPS polling agent</div>
                </div>
                <Download className="w-4 h-4 text-teal-400 shrink-0" />
              </a>

              <a
                href="/api/v1/agent-package/file/sentinel-agent.service"
                className="rounded-lg border border-slate-800 hover:border-teal-500/40 bg-[#0B1120] p-3 flex items-center justify-between gap-2 transition-colors"
              >
                <div>
                  <div className="font-mono font-semibold text-slate-100">sentinel-agent.service</div>
                  <div className="text-[11px] text-slate-400">User-level systemd service unit</div>
                </div>
                <Download className="w-4 h-4 text-teal-400 shrink-0" />
              </a>

              <a
                href="/api/v1/agent-package/file/uninstall-sentinel-agent.sh"
                className="rounded-lg border border-slate-800 hover:border-teal-500/40 bg-[#0B1120] p-3 flex items-center justify-between gap-2 transition-colors"
              >
                <div>
                  <div className="font-mono font-semibold text-slate-100">uninstall-sentinel-agent.sh</div>
                  <div className="text-[11px] text-slate-400">Safe uninstaller &amp; token shredder</div>
                </div>
                <Download className="w-4 h-4 text-teal-400 shrink-0" />
              </a>
            </div>

            {/* File Code Inspector */}
            <div className="space-y-2 pt-2">
              <div className="flex flex-wrap items-center gap-1.5">
                {INSPECTABLE_FILES.map((file) => (
                  <button
                    key={file.id}
                    type="button"
                    onClick={() => setSelectedFileId(file.id)}
                    className={`px-2.5 py-1 rounded text-xs font-mono transition-colors cursor-pointer ${
                      selectedFileId === file.id
                        ? 'bg-teal-500/20 text-teal-300 border border-teal-500/40'
                        : 'bg-[#0B1120] text-slate-400 hover:text-slate-200 border border-slate-800'
                    }`}
                  >
                    {file.filename}
                  </button>
                ))}
              </div>

              <div className="rounded-lg border border-slate-800 bg-[#0B1120] p-3.5 space-y-2">
                <div className="flex items-center justify-between text-xs">
                  <span className="font-mono text-teal-300">
                    {activeInspectFile.path} (mode {activeInspectFile.mode})
                  </span>
                  <a
                    href={activeInspectFile.downloadHref}
                    className="text-xs font-mono text-slate-300 hover:text-teal-300 underline"
                  >
                    Download raw file
                  </a>
                </div>
                <p className="text-xs text-slate-400">{activeInspectFile.summary}</p>
                <pre className="p-3 rounded bg-slate-950 border border-slate-800/90 text-[11px] font-mono text-slate-200 overflow-x-auto max-h-56 leading-relaxed">
                  {activeInspectFile.snippet}
                </pre>
              </div>
            </div>
          </div>
        </section>
      </div>

      {/* Step-by-Step Manual Kali Terminal Execution & Safe Uninstall Guide */}
      <section className="rounded-xl border border-slate-800 bg-[#0F172A] p-6 space-y-5">
        <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-2">
          <div>
            <h2 className="text-base font-semibold text-slate-100 flex items-center gap-2">
              <Terminal className="w-4 h-4 text-teal-400" />
              3. Manual Kali Linux Installation, Login Autostart &amp; Safe Uninstall Procedure
            </h2>
            <p className="text-xs text-slate-400 mt-0.5">
              Run these commands inside your Kali Linux terminal as your normal unprivileged user (never as root).
            </p>
          </div>
          <span className="text-xs font-mono text-teal-400">
            Allowlisted Tasks Only: passive_http_headers · static_code_analysis
          </span>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-3 gap-4 text-xs">
          <div className="rounded-lg border border-slate-800 bg-[#0B1120] p-4 space-y-2">
            <div className="flex items-center justify-between">
              <span className="font-semibold text-slate-100">
                Step A: Verify &amp; Run One-Time Installer
              </span>
              <ShieldCheck className="w-4 h-4 text-teal-400" />
            </div>
            <p className="text-slate-400 leading-relaxed">
              Extracts the bundle, verifies cryptographic SHA-256 hashes, checks OS &amp; dependencies, and sets{' '}
              <code className="font-mono text-teal-300">0600</code> permissions on{' '}
              <code className="font-mono text-slate-200">~/.config/sentinel-agent/agent.conf</code>.
            </p>
            <pre className="p-2.5 rounded bg-slate-950 border border-slate-800 font-mono text-[11px] text-teal-200 overflow-x-auto">
{`tar -xzf sentinel-kali-agent-v2.1.0.tar.gz
cd sentinel-agent-v2.1.0
sha256sum -c SHA256SUMS
SENTINEL_ENROLLMENT_CODE="${issuedPlaintextCode || 'STNL-ENROLL-XXXX'}" \\
  ./scripts/install-sentinel-agent.sh`}
            </pre>
          </div>

          <div className="rounded-lg border border-slate-800 bg-[#0B1120] p-4 space-y-2">
            <div className="flex items-center justify-between">
              <span className="font-semibold text-slate-100">
                Step B: Automatic Startup on Kali Login
              </span>
              <Cpu className="w-4 h-4 text-teal-400" />
            </div>
            <p className="text-slate-400 leading-relaxed">
              The installer configures both <code className="font-mono text-slate-200">systemd --user</code> (<code className="font-mono text-teal-300">WantedBy=default.target</code>) and{' '}
              <code className="font-mono text-slate-200">~/.config/autostart/sentinel-agent.desktop</code> so the agent starts automatically whenever the Kali user logs in.
            </p>
            <pre className="p-2.5 rounded bg-slate-950 border border-slate-800 font-mono text-[11px] text-teal-200 overflow-x-auto">
{`systemctl --user daemon-reload
systemctl --user enable --now sentinel-agent.service
systemctl --user status sentinel-agent.service
journalctl --user -u sentinel-agent.service -n 20`}
            </pre>
          </div>

          <div className="rounded-lg border border-slate-800 bg-[#0B1120] p-4 space-y-2">
            <div className="flex items-center justify-between">
              <span className="font-semibold text-slate-100">
                Step C: Safe Uninstall &amp; Token Shredding
              </span>
              <Trash2 className="w-4 h-4 text-rose-400" />
            </div>
            <p className="text-slate-400 leading-relaxed">
              Stops and disables the user service, removes the login autostart hook, shreds the local{' '}
              <code className="font-mono text-slate-200">agent.conf</code> credential, and removes all agent files.
            </p>
            <pre className="p-2.5 rounded bg-slate-950 border border-slate-800 font-mono text-[11px] text-rose-200 overflow-x-auto">
{`~/.local/share/sentinel-agent/uninstall-sentinel-agent.sh
# Then revoke or mark uninstalled in
# the Sentinel AI Device Management view.`}
            </pre>
          </div>
        </div>
      </section>
    </div>
  );
};
