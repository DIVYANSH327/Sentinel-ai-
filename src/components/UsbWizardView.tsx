import React, { useEffect, useState } from 'react';
import {
  CheckCircle2,
  Download,
  FileCode2,
  Copy,
  Check,
  Terminal,
  ShieldAlert,
} from 'lucide-react';
import {
  ControlPlaneStatus,
  SetupPackageManifest,
  WizardChecklistState,
} from '../types/sentinel';

interface UsbWizardViewProps {
  status: ControlPlaneStatus;
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

export const UsbWizardView: React.FC<UsbWizardViewProps> = ({
  status,
  onToggleChecklistStep,
  onIssueEnrollmentCode,
  onSimulateKaliEnroll,
  onSendVerifiedHeartbeat,
  lastIssuedOneTimeCode,
}) => {
  const [activeStep, setActiveStep] = useState<number>(1);
  const [manifest, setManifest] = useState<SetupPackageManifest | null>(null);
  const [selectedFilePath, setSelectedFilePath] = useState<string>('');
  const [copiedKey, setCopiedKey] = useState<string | null>(null);
  const [feedback, setFeedback] = useState<string | null>(null);

  useEffect(() => {
    fetch('/api/setup-package/manifest')
      .then((r) => r.json())
      .then((data: SetupPackageManifest) => {
        setManifest(data);
        if (data.files.length > 0) {
          setSelectedFilePath(data.files[0].path);
        }
      })
      .catch(() => {
        // Ignore transient fetch issues
      });
  }, [status.setupPackageVersion]);

  const copyCommand = (key: string, text: string) => {
    navigator.clipboard?.writeText(text).catch(() => {});
    setCopiedKey(key);
    setTimeout(() => setCopiedKey(null), 1800);
  };

  const steps: Array<{
    num: number;
    key: keyof WizardChecklistState;
    title: string;
    environment: 'Windows Host' | 'Web Control Plane' | 'Kali Linux Terminal (Non-Root)';
    done: boolean;
  }> = [
    {
      num: 1,
      key: 'step1WindowsUsbPrepared',
      title: 'Prepare 16 GB Setup USB on Windows',
      environment: 'Windows Host',
      done: status.wizardChecklist.step1WindowsUsbPrepared,
    },
    {
      num: 2,
      key: 'step2PackageDownloaded',
      title: 'Download Versioned Setup Package',
      environment: 'Web Control Plane',
      done: status.wizardChecklist.step2PackageDownloaded,
    },
    {
      num: 3,
      key: 'step3KaliUsbMounted',
      title: 'Connect & Verify USB on Kali Linux',
      environment: 'Kali Linux Terminal (Non-Root)',
      done: status.wizardChecklist.step3KaliUsbMounted,
    },
    {
      num: 4,
      key: 'step4NonRootInstalled',
      title: 'Install Agent as Non-Root User',
      environment: 'Kali Linux Terminal (Non-Root)',
      done: status.wizardChecklist.step4NonRootInstalled,
    },
    {
      num: 5,
      key: 'step5BackendConfigured',
      title: 'Configure Backend URL & Single-Use Enrollment',
      environment: 'Kali Linux Terminal (Non-Root)',
      done: status.wizardChecklist.step5BackendConfigured,
    },
    {
      num: 6,
      key: 'step6SystemdVerified',
      title: 'Enable & Verify User-Level systemd Service',
      environment: 'Kali Linux Terminal (Non-Root)',
      done: status.wizardChecklist.step6SystemdVerified,
    },
  ];

  const selectedFile = manifest?.files.find((f) => f.path === selectedFilePath) || manifest?.files[0] || null;
  const currentStepObj = steps.find((s) => s.num === activeStep) || steps[0];

  return (
    <div className="space-y-8">
      <section className="bg-[#0F172A] border border-slate-800 rounded-xl p-6 space-y-2">
        <div className="flex items-center gap-2 text-xs text-slate-400">
          <span>6-Step Guided Setup</span>
          <span aria-hidden="true">·</span>
          <span>Second 16 GB USB Drive Workflow</span>
          <span aria-hidden="true">·</span>
          <span>No USB Auto-Execution</span>
        </div>
        <h1 className="text-2xl font-semibold text-slate-100 tracking-tight">
          USB Setup Wizard &amp; Reviewed Package Inspector
        </h1>
        <p className="text-sm text-slate-300 max-w-3xl leading-relaxed">
          Follow each step below to prepare your second 16 GB USB drive on Windows, transfer the versioned setup archive
          to your Kali Linux Live USB computer, and register the non-root systemd service. Every command that must be
          executed locally on Windows or Kali is explicitly labeled.
        </p>
      </section>

      {/* Step Selector Bar */}
      <nav aria-label="Setup Wizard Steps" className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-3">
        {steps.map((s) => {
          const isCurrent = s.num === activeStep;
          return (
            <button
              key={s.num}
              type="button"
              onClick={() => setActiveStep(s.num)}
              className={`text-left p-3.5 rounded-xl border transition-colors cursor-pointer ${
                isCurrent
                  ? 'bg-[#131C31] border-teal-500 text-slate-100'
                  : 'bg-[#0F172A] border-slate-800 text-slate-300 hover:border-slate-700'
              }`}
            >
              <div className="flex items-center justify-between text-xs font-mono tabular-nums mb-1.5">
                <span className={isCurrent ? 'text-teal-300 font-semibold' : 'text-slate-400'}>
                  STEP 0{s.num}
                </span>
                <span className={s.done ? 'text-teal-400' : 'text-slate-500'}>
                  {s.done ? 'Verified' : 'Pending'}
                </span>
              </div>
              <div className="text-xs font-medium leading-snug line-clamp-2">{s.title}</div>
            </button>
          );
        })}
      </nav>

      {feedback && (
        <div
          role="status"
          className="p-4 rounded-lg bg-teal-950/40 border border-teal-800/80 text-teal-200 text-sm flex items-center justify-between"
        >
          <span>{feedback}</span>
          <button
            type="button"
            onClick={() => setFeedback(null)}
            className="text-xs underline ml-4 whitespace-nowrap shrink-0 cursor-pointer"
          >
            Dismiss
          </button>
        </div>
      )}

      {/* Active Step Content */}
      <section className="bg-[#0F172A] border border-slate-800 rounded-xl p-6 space-y-6">
        <div className="flex flex-col md:flex-row md:items-center md:justify-between gap-4 border-b border-slate-800 pb-5">
          <div className="space-y-1">
            <div className="flex items-center gap-2 text-xs text-teal-400 font-mono tabular-nums">
              <span>Step 0{currentStepObj.num} of 06</span>
              <span aria-hidden="true">·</span>
              <span>Execution Environment: {currentStepObj.environment}</span>
            </div>
            <h2 className="text-xl font-semibold text-slate-100">{currentStepObj.title}</h2>
          </div>

          <div className="flex items-center gap-3 shrink-0">
            <button
              type="button"
              onClick={() => onToggleChecklistStep(currentStepObj.key, !currentStepObj.done)}
              className={`px-4 py-2 text-xs font-medium rounded-lg border transition-colors flex items-center gap-2 whitespace-nowrap shrink-0 cursor-pointer ${
                currentStepObj.done
                  ? 'bg-teal-950/50 border-teal-700 text-teal-200'
                  : 'bg-slate-800 border-slate-700 text-slate-200 hover:bg-slate-700'
              }`}
            >
              <CheckCircle2 className="w-4 h-4 text-teal-400" aria-hidden="true" />
              <span>{currentStepObj.done ? 'Step Marked Verified' : 'Mark Step as Completed'}</span>
            </button>
          </div>
        </div>

        {/* STEP 1 */}
        {activeStep === 1 && (
          <div className="space-y-5">
            <p className="text-sm text-slate-300 leading-relaxed">
              Insert your <strong className="text-slate-100">second 16 GB USB flash drive</strong> into your Windows
              workstation (keep your primary Kali Linux Live boot USB untouched). Format the second USB drive as{' '}
              <code className="text-teal-300">exFAT</code> or <code className="text-teal-300">FAT32</code> with the
              volume label <code className="text-teal-300">SENTINEL_SETUP</code>.
            </p>

            <div className="bg-[#0B1120] border border-slate-800 rounded-lg p-4 space-y-3">
              <div className="flex items-center justify-between text-xs text-slate-400">
                <span>Run Locally on Windows PowerShell (Optional CLI Check)</span>
                <button
                  type="button"
                  onClick={() =>
                    copyCommand(
                      'step1-ps',
                      `Get-Volume | Where-Object { $_.DriveType -eq 'Removable' } | Format-Table DriveLetter, FileSystemLabel, FileSystem, SizeRemaining`
                    )
                  }
                  className="text-teal-400 hover:text-teal-300 flex items-center gap-1 cursor-pointer"
                >
                  {copiedKey === 'step1-ps' ? <Check className="w-3.5 h-3.5" /> : <Copy className="w-3.5 h-3.5" />}
                  <span>{copiedKey === 'step1-ps' ? 'Copied' : 'Copy Command'}</span>
                </button>
              </div>
              <pre className="text-xs font-mono text-slate-200 overflow-x-auto leading-relaxed">
                {`# Inspect removable USB drives on Windows before copying setup files:\nGet-Volume | Where-Object { $_.DriveType -eq 'Removable' } | Format-Table DriveLetter, FileSystemLabel, FileSystem, SizeRemaining`}
              </pre>
            </div>

            <div className="p-4 rounded-lg bg-slate-900/90 border border-slate-800 text-xs text-slate-300 space-y-1">
              <div className="font-semibold text-slate-100 flex items-center gap-2">
                <ShieldAlert className="w-4 h-4 text-teal-400 shrink-0" aria-hidden="true" />
                <span>Hardware &amp; Auto-Run Security Notice</span>
              </div>
              <p className="text-slate-400 leading-relaxed">
                Websites cannot directly format or write partition tables to your local USB hardware. In addition,
                Sentinel USB Connect never generates <code className="text-slate-200">autorun.inf</code> or udev
                auto-execution hooks—all scripts require explicit human review and execution.
              </p>
            </div>
          </div>
        )}

        {/* STEP 2 */}
        {activeStep === 2 && (
          <div className="space-y-6">
            <div className="flex flex-col md:flex-row md:items-center md:justify-between gap-4">
              <div className="space-y-1">
                <p className="text-sm text-slate-300">
                  Download the versioned setup archive{' '}
                  <code className="text-teal-300">sentinel-usb-setup-v{status.setupPackageVersion}.tar.gz</code> and save
                  it directly onto your <code className="text-slate-200">SENTINEL_SETUP</code> 16 GB USB drive.
                </p>
                {manifest && (
                  <p className="text-xs font-mono text-slate-400 tabular-nums">
                    Archive SHA-256: {manifest.packageSha256} · Live Secrets Embedded: None (false)
                  </p>
                )}
              </div>

              <a
                href="/api/setup-package/download"
                onClick={() => {
                  setTimeout(() => onToggleChecklistStep('step2PackageDownloaded', true), 400);
                }}
                className="px-4 py-2.5 text-xs font-medium bg-teal-500 text-slate-950 rounded-lg hover:bg-teal-400 transition-colors flex items-center gap-2 whitespace-nowrap shrink-0"
              >
                <Download className="w-4 h-4" aria-hidden="true" />
                <span>Download sentinel-usb-setup-v{status.setupPackageVersion}.tar.gz</span>
              </a>
            </div>

            {manifest && (
              <div className="grid grid-cols-1 lg:grid-cols-12 gap-4">
                <div className="lg:col-span-5 bg-[#0B1120] border border-slate-800 rounded-lg p-4 space-y-2">
                  <div className="text-xs font-semibold text-slate-300 mb-2">
                    Reviewed Files Included in Archive ({manifest.files.length})
                  </div>
                  <div className="space-y-1.5">
                    {manifest.files.map((file) => (
                      <button
                        key={file.path}
                        type="button"
                        onClick={() => setSelectedFilePath(file.path)}
                        className={`w-full text-left p-2.5 rounded-lg border text-xs transition-colors cursor-pointer ${
                          selectedFile?.path === file.path
                            ? 'bg-[#131C31] border-teal-500/80 text-slate-100'
                            : 'bg-[#0F172A] border-slate-800/80 text-slate-300 hover:border-slate-700'
                        }`}
                      >
                        <div className="flex items-center justify-between font-mono tabular-nums">
                          <span className="truncate flex items-center gap-1.5">
                            <FileCode2 className="w-3.5 h-3.5 text-teal-400 shrink-0" aria-hidden="true" />
                            {file.path.replace(`sentinel-usb-setup-v${manifest.version}/`, '')}
                          </span>
                          <span className="text-slate-400 ml-2 shrink-0">mode {file.mode}</span>
                        </div>
                        <div className="text-[11px] text-slate-400 mt-1">{file.description}</div>
                      </button>
                    ))}
                  </div>
                </div>

                <div className="lg:col-span-7 bg-[#0B1120] border border-slate-800 rounded-lg p-4 flex flex-col justify-between space-y-3">
                  {selectedFile && (
                    <>
                      <div className="flex items-center justify-between text-xs border-b border-slate-800 pb-2">
                        <span className="font-mono text-teal-300">{selectedFile.path}</span>
                        <span className="font-mono text-slate-400 tabular-nums">
                          SHA-256: {selectedFile.sha256.slice(0, 16)}… ({selectedFile.sizeBytes} B)
                        </span>
                      </div>
                      <pre className="text-xs font-mono text-slate-200 overflow-x-auto max-h-72 leading-relaxed">
                        {selectedFile.content}
                      </pre>
                    </>
                  )}
                </div>
              </div>
            )}
          </div>
        )}

        {/* STEP 3 */}
        {activeStep === 3 && (
          <div className="space-y-5">
            <p className="text-sm text-slate-300 leading-relaxed">
              Boot your Kali Linux Live USB computer, log in as your normal non-root user (<code className="text-teal-300">kali</code>),
              and plug in the <code className="text-teal-300">SENTINEL_SETUP</code> 16 GB USB drive. Verify the archive
              checksum and extract it into your home directory:
            </p>

            <div className="bg-[#0B1120] border border-slate-800 rounded-lg p-4 space-y-3">
              <div className="flex items-center justify-between text-xs text-slate-400">
                <span>Run Locally in Kali Linux Terminal (Non-Root User)</span>
                <button
                  type="button"
                  onClick={() =>
                    copyCommand(
                      'step3-kali',
                      `lsblk -f\ntar -xzf /media/$USER/SENTINEL_SETUP/sentinel-usb-setup-v${status.setupPackageVersion}.tar.gz -C ~/\ncd ~/sentinel-usb-setup-v${status.setupPackageVersion}\nsha256sum -c SHA256SUMS`
                    )
                  }
                  className="text-teal-400 hover:text-teal-300 flex items-center gap-1 cursor-pointer"
                >
                  {copiedKey === 'step3-kali' ? <Check className="w-3.5 h-3.5" /> : <Copy className="w-3.5 h-3.5" />}
                  <span>{copiedKey === 'step3-kali' ? 'Copied' : 'Copy Commands'}</span>
                </button>
              </div>
              <pre className="text-xs font-mono text-slate-200 overflow-x-auto leading-relaxed">
                {`# 1. Confirm the 16 GB SENTINEL_SETUP drive mount path\nlsblk -f\n\n# 2. Extract the archive into your user home directory\ntar -xzf /media/$USER/SENTINEL_SETUP/sentinel-usb-setup-v${status.setupPackageVersion}.tar.gz -C ~/\n\n# 3. Verify cryptographic integrity of every script before running\ncd ~/sentinel-usb-setup-v${status.setupPackageVersion}\nsha256sum -c SHA256SUMS`}
              </pre>
            </div>
          </div>
        )}

        {/* STEP 4 */}
        {activeStep === 4 && (
          <div className="space-y-5">
            <p className="text-sm text-slate-300 leading-relaxed">
              Run the reviewed installer script as an ordinary Linux user (<strong className="text-slate-100">never as root</strong>).
              The script validates <code className="text-teal-300">id -u &gt;= 1000</code>, installs the Python agent in{' '}
              <code className="text-slate-200">~/.local/share/sentinel-agent/</code>, and creates{' '}
              <code className="text-slate-200">~/.config/sentinel-agent/agent.conf</code> with mode <code className="text-teal-300">0600</code>.
            </p>

            <div className="bg-[#0B1120] border border-slate-800 rounded-lg p-4 space-y-3">
              <div className="flex items-center justify-between text-xs text-slate-400">
                <span>Run Locally in Kali Linux Terminal (Never use sudo)</span>
                <button
                  type="button"
                  onClick={() =>
                    copyCommand(
                      'step4-install',
                      `id -u && id -un   # Must print >= 1000 (e.g. 1000 kali), NEVER 0 (root)\ncd ~/sentinel-usb-setup-v${status.setupPackageVersion}\n./scripts/install-agent.sh`
                    )
                  }
                  className="text-teal-400 hover:text-teal-300 flex items-center gap-1 cursor-pointer"
                >
                  {copiedKey === 'step4-install' ? <Check className="w-3.5 h-3.5" /> : <Copy className="w-3.5 h-3.5" />}
                  <span>{copiedKey === 'step4-install' ? 'Copied' : 'Copy Commands'}</span>
                </button>
              </div>
              <pre className="text-xs font-mono text-slate-200 overflow-x-auto leading-relaxed">
                {`# Confirm you are running as an unprivileged user (UID >= 1000):\nid -u && id -un\n\n# Run the non-root installer:\ncd ~/sentinel-usb-setup-v${status.setupPackageVersion}\n./scripts/install-agent.sh`}
              </pre>
            </div>
          </div>
        )}

        {/* STEP 5 */}
        {activeStep === 5 && (
          <div className="space-y-5">
            <p className="text-sm text-slate-300 leading-relaxed">
              Generate a short-lived, single-use enrollment code below and write it to{' '}
              <code className="text-teal-300">~/.config/sentinel-agent/agent.conf</code> on Kali Linux with strict{' '}
              <code className="text-teal-300">0600</code> permissions. When the agent starts, it exchanges the
              single-use enrollment code for a persistent scoped credential and overwrites the consumed code.
            </p>

            <div className="flex flex-wrap items-center gap-3">
              <button
                type="button"
                onClick={async () => {
                  const res = await onIssueEnrollmentCode('kali-wizard-step5', 15);
                  setFeedback(res.message);
                }}
                className="px-4 py-2 text-xs font-medium bg-teal-500 text-slate-950 rounded-lg hover:bg-teal-400 transition-colors cursor-pointer"
              >
                Issue Single-Use Enrollment Code
              </button>

              {lastIssuedOneTimeCode && (
                <button
                  type="button"
                  onClick={async () => {
                    const res = await onSimulateKaliEnroll(lastIssuedOneTimeCode);
                    setFeedback(res.message);
                  }}
                  className="px-4 py-2 text-xs font-medium bg-slate-800 text-teal-300 border border-teal-700/70 rounded-lg hover:bg-slate-700 transition-colors flex items-center gap-2 cursor-pointer"
                >
                  <Terminal className="w-3.5 h-3.5" aria-hidden="true" />
                  <span>Simulate Kali CLI Enrollment Handshake</span>
                </button>
              )}
            </div>

            <div className="bg-[#0B1120] border border-slate-800 rounded-lg p-4 space-y-3">
              <div className="flex items-center justify-between text-xs text-slate-400">
                <span>Run Locally in Kali Linux Terminal (Configure 0600 Credential File)</span>
                <button
                  type="button"
                  onClick={() =>
                    copyCommand(
                      'step5-conf',
                      `cat > ~/.config/sentinel-agent/agent.conf << 'EOF'\nBACKEND_URL=${status.backendUrl}\nENROLLMENT_CODE=${lastIssuedOneTimeCode || '<PASTE_SINGLE_USE_CODE>'}\nALLOWED_TARGETS=${status.allowedTargets.join(',')}\nEOF\nchmod 600 ~/.config/sentinel-agent/agent.conf\nstat -c '%a %U %n' ~/.config/sentinel-agent/agent.conf`
                    )
                  }
                  className="text-teal-400 hover:text-teal-300 flex items-center gap-1 cursor-pointer"
                >
                  {copiedKey === 'step5-conf' ? <Check className="w-3.5 h-3.5" /> : <Copy className="w-3.5 h-3.5" />}
                  <span>{copiedKey === 'step5-conf' ? 'Copied' : 'Copy Commands'}</span>
                </button>
              </div>
              <pre className="text-xs font-mono text-slate-200 overflow-x-auto leading-relaxed">
                {`cat > ~/.config/sentinel-agent/agent.conf << 'EOF'\nBACKEND_URL=${status.backendUrl}\nENROLLMENT_CODE=${
                  lastIssuedOneTimeCode || '<PASTE_SINGLE_USE_CODE>'
                }\nALLOWED_TARGETS=${status.allowedTargets.join(',')}\nEOF\nchmod 600 ~/.config/sentinel-agent/agent.conf\nstat -c '%a %U %n' ~/.config/sentinel-agent/agent.conf   # Must output: 600 kali`}
              </pre>
            </div>
          </div>
        )}

        {/* STEP 6 */}
        {activeStep === 6 && (
          <div className="space-y-5">
            <p className="text-sm text-slate-300 leading-relaxed">
              Enable and start the user-level <code className="text-teal-300">systemd</code> unit so the Sentinel agent
              starts automatically after your non-root Kali user logs in.
            </p>

            <div className="bg-[#0B1120] border border-slate-800 rounded-lg p-4 space-y-3">
              <div className="flex items-center justify-between text-xs text-slate-400">
                <span>Run Locally in Kali Linux Terminal (Enable User Service)</span>
                <button
                  type="button"
                  onClick={() =>
                    copyCommand(
                      'step6-systemd',
                      `systemctl --user daemon-reload\nsystemctl --user enable --now sentinel-agent.service\nsystemctl --user status sentinel-agent.service`
                    )
                  }
                  className="text-teal-400 hover:text-teal-300 flex items-center gap-1 cursor-pointer"
                >
                  {copiedKey === 'step6-systemd' ? <Check className="w-3.5 h-3.5" /> : <Copy className="w-3.5 h-3.5" />}
                  <span>{copiedKey === 'step6-systemd' ? 'Copied' : 'Copy Commands'}</span>
                </button>
              </div>
              <pre className="text-xs font-mono text-slate-200 overflow-x-auto leading-relaxed">
                {`systemctl --user daemon-reload\nsystemctl --user enable --now sentinel-agent.service\nsystemctl --user status sentinel-agent.service`}
              </pre>
            </div>

            <div className="flex items-center gap-3">
              <button
                type="button"
                onClick={async () => {
                  const res = await onSendVerifiedHeartbeat();
                  setFeedback(res.message);
                }}
                className="px-4 py-2 text-xs font-medium bg-teal-500 text-slate-950 rounded-lg hover:bg-teal-400 transition-colors cursor-pointer"
              >
                Verify Authenticated Agent Heartbeat
              </button>
            </div>
          </div>
        )}

        {/* Wizard Step Footer Navigation */}
        <div className="flex items-center justify-between pt-4 border-t border-slate-800">
          <button
            type="button"
            disabled={activeStep === 1}
            onClick={() => setActiveStep((prev) => Math.max(1, prev - 1))}
            className="px-4 py-2 text-xs font-medium bg-slate-800 text-slate-200 rounded-lg hover:bg-slate-700 disabled:opacity-40 transition-colors cursor-pointer"
          >
            ← Previous Step
          </button>
          <span className="text-xs font-mono text-slate-400 tabular-nums">Step 0{activeStep} / 06</span>
          <button
            type="button"
            disabled={activeStep === 6}
            onClick={() => setActiveStep((prev) => Math.min(6, prev + 1))}
            className="px-4 py-2 text-xs font-medium bg-teal-500 text-slate-950 rounded-lg hover:bg-teal-400 disabled:opacity-40 transition-colors cursor-pointer"
          >
            Next Step →
          </button>
        </div>
      </section>
    </div>
  );
};
