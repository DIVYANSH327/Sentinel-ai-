import React from 'react';
import {
  ShieldCheck,
  Server,
  FileCheck2,
  Cpu,
  Play,
  AlertTriangle,
  Wrench,
  Activity,
  ScrollText,
  ArrowRight,
  Lock,
  CheckCircle2,
  Clock,
  Sparkles,
} from 'lucide-react';
import type { PlatformBootstrapPayload, PlatformTabId } from '../../types/platform';

interface OverviewSectionProps {
  data: PlatformBootstrapPayload;
  demoMode: boolean;
  onNavigate: (tab: PlatformTabId) => void;
}

export const OverviewSection: React.FC<OverviewSectionProps> = ({
  data,
  demoMode,
  onNavigate,
}) => {
  const verifiedAssetsCount = data.assets.filter((a) => a.verified).length;
  const activePoliciesCount = data.policies.filter((p) => p.active).length;
  const pendingApprovalJobs = data.jobs.filter((j) => j.status === 'pending_approval');
  const openFindings = data.findings.filter((f) => f.status === 'open');
  const pendingRemediations = data.remediations.filter(
    (r) => r.approvalStatus === 'pending_approval'
  );
  const connectedAgents = data.agents.filter(
    (a) => a.status === 'online' && a.heartbeatVerifiedLive
  ).length;

  const sections: {
    id: PlatformTabId;
    label: string;
    metric: string;
    desc: string;
    icon: React.FC<{ className?: string }>;
  }[] = [
    {
      id: 'agent-setup',
      label: 'Kali Agent Setup',
      metric: 'v2.1.0 Installer',
      desc: 'Single-use enrollment codes, SHA-256 verified Linux installer, Python agent, and systemd login autostart.',
      icon: Cpu,
    },
    {
      id: 'authorized-assets',
      label: 'Authorized Assets',
      metric: `${verifiedAssetsCount}/${data.assets.length} Verified`,
      desc: 'Signed authorization records, target hostnames, IPv4/CIDR bounds, and expiry timestamps.',
      icon: Server,
    },
    {
      id: 'scope-policies',
      label: 'Scope Policies',
      metric: `${activePoliciesCount} Active`,
      desc: 'Policy engine rules enforcing permitted hosts, allowed safe test categories, and RPM limits.',
      icon: FileCheck2,
    },
    {
      id: 'assessment-plans',
      label: 'Assessment Plans',
      metric: `${data.plans.length} Plans`,
      desc: 'Server-side Gemini structured JSON assessment planner with zero shell command emission.',
      icon: Sparkles,
    },
    {
      id: 'job-queue',
      label: 'Job Queue',
      metric: `${data.jobs.length} Jobs (${pendingApprovalJobs.length} Gate)`,
      desc: 'Passive HTTP header checks, safe static code analysis, and human approval gates.',
      icon: Play,
    },
    {
      id: 'findings',
      label: 'Findings',
      metric: `${openFindings.length} Open`,
      desc: 'CWE-mapped security header and static analysis findings with reproducible evidence.',
      icon: AlertTriangle,
    },
    {
      id: 'remediation',
      label: 'Remediation',
      metric: `${pendingRemediations.length} Awaiting Sign-Off`,
      desc: 'Proposed code and configuration patches requiring explicit human approval.',
      icon: Wrench,
    },
    {
      id: 'agent-health',
      label: 'Agent Health',
      metric: `${connectedAgents}/${data.agents.length} Connected`,
      desc: 'Outbound HTTPS polling protocol for Python Kali agent, idempotent claims, and USB kit.',
      icon: Activity,
    },
    {
      id: 'audit-logs',
      label: 'Audit Logs',
      metric: `${data.auditLogs.length} Events`,
      desc: 'Immutable ledger recording every authorization check, plan generation, job claim, and sign-off.',
      icon: ScrollText,
    },
  ];

  return (
    <div className="space-y-6">
      {/* Top Hero / Executive Posture Banner */}
      <div className="rounded-xl border border-slate-800/80 bg-[#0F172A] p-6">
        <div className="flex flex-col lg:flex-row lg:items-center lg:justify-between gap-4">
          <div className="space-y-1.5">
            <div className="flex items-center gap-2 text-xs font-mono uppercase tracking-wider text-teal-400">
              <ShieldCheck className="w-4 h-4" />
              <span>Authorized AI-Assisted Security Research Platform</span>
              <span>·</span>
              <span>{demoMode ? 'Mock / Demo Sandbox' : 'Live Persistent Runtime'}</span>
            </div>
            <h1 className="text-xl sm:text-2xl font-semibold text-slate-100 tracking-tight">
              Sentinel AI Governance & Safe Research Control Plane
            </h1>
            <p className="text-sm text-slate-400 max-w-3xl">
              Every assessment job is cryptographically and logically gated by an explicit authorization record, scope policy engine, and rate limit check. MVP execution is strictly constrained to passive HTTP security-header inspection and safe static code analysis.
            </p>
          </div>
          <div className="flex flex-wrap items-center gap-2.5">
            <button
              onClick={() => onNavigate('agent-setup')}
              className="px-3.5 py-2 rounded-lg bg-teal-500 hover:bg-teal-400 text-slate-950 font-semibold text-xs transition-colors flex items-center gap-1.5 cursor-pointer"
            >
              <Cpu className="w-3.5 h-3.5" />
              Kali Agent Setup &amp; Installer
            </button>
            <button
              onClick={() => onNavigate('assessment-plans')}
              className="px-3.5 py-2 rounded-lg border border-slate-700 hover:border-teal-500/50 bg-slate-900/90 text-slate-200 font-medium text-xs transition-colors flex items-center gap-1.5 cursor-pointer"
            >
              <Sparkles className="w-3.5 h-3.5 text-teal-400" />
              Generate Structured Plan
            </button>
            <button
              onClick={() => onNavigate('job-queue')}
              className="px-3.5 py-2 rounded-lg border border-slate-700 hover:border-teal-500/50 bg-slate-900/90 text-slate-200 font-medium text-xs transition-colors flex items-center gap-1.5 cursor-pointer"
            >
              <Play className="w-3.5 h-3.5 text-teal-400" />
              Dispatch Safe MVP Job
            </button>
          </div>
        </div>

        {/* 4 Core KPI Strip */}
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4 mt-6 pt-5 border-t border-slate-800/80">
          <div className="rounded-lg bg-slate-900/70 border border-slate-800/70 p-4">
            <div className="text-xs text-slate-400 font-medium">Verified Target Scope</div>
            <div className="mt-1.5 flex items-baseline justify-between">
              <span className="text-2xl font-semibold font-mono tabular-nums text-slate-100">
                {verifiedAssetsCount} <span className="text-xs font-normal text-slate-400">assets</span>
              </span>
              <span className="text-xs font-mono text-teal-400">{activePoliciesCount} active policies</span>
            </div>
            <div className="mt-2 text-xs text-slate-400">
              Unverified or expired targets are automatically blocked.
            </div>
          </div>

          <div className="rounded-lg bg-slate-900/70 border border-slate-800/70 p-4">
            <div className="text-xs text-slate-400 font-medium">Safe MVP Job Queue</div>
            <div className="mt-1.5 flex items-baseline justify-between">
              <span className="text-2xl font-semibold font-mono tabular-nums text-slate-100">
                {data.jobs.length} <span className="text-xs font-normal text-slate-400">total</span>
              </span>
              <span className="text-xs font-mono text-amber-400">
                {pendingApprovalJobs.length} awaiting gate
              </span>
            </div>
            <div className="mt-2 text-xs text-slate-400">
              Passive HTTP headers & static AST/pattern checks only.
            </div>
          </div>

          <div className="rounded-lg bg-slate-900/70 border border-slate-800/70 p-4">
            <div className="text-xs text-slate-400 font-medium">Open Findings & Patches</div>
            <div className="mt-1.5 flex items-baseline justify-between">
              <span className="text-2xl font-semibold font-mono tabular-nums text-slate-100">
                {openFindings.length} <span className="text-xs font-normal text-slate-400">findings</span>
              </span>
              <span className="text-xs font-mono text-teal-400">
                {pendingRemediations.length} pending sign-off
              </span>
            </div>
            <div className="mt-2 text-xs text-slate-400">
              All remediation diffs require human reviewer approval.
            </div>
          </div>

          <div className="rounded-lg bg-slate-900/70 border border-slate-800/70 p-4">
            <div className="text-xs text-slate-400 font-medium">Kali Outbound Agent</div>
            <div className="mt-1.5 flex items-baseline justify-between">
              <span className="text-2xl font-semibold font-mono tabular-nums text-slate-100">
                {connectedAgents}/{data.agents.length} <span className="text-xs font-normal text-slate-400">online</span>
              </span>
              <span className="text-xs font-mono text-slate-300">HTTPS Pull Only</span>
            </div>
            <div className="mt-2 text-xs text-slate-400">
              Per-agent credential vault & idempotent job claims.
            </div>
          </div>
        </div>
      </div>

      {/* Honest Integration Verification Banner + Guardrail Summary */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        <div className="lg:col-span-7 rounded-xl border border-slate-800/80 bg-[#0F172A] p-5 flex flex-col justify-between">
          <div>
            <div className="flex items-center justify-between gap-2 mb-3">
              <h2 className="text-sm font-semibold text-slate-100 flex items-center gap-2">
                <Cpu className="w-4 h-4 text-teal-400" />
                Live Integration Verification Ledger
              </h2>
              <span className="text-xs font-mono text-slate-400">
                Zero Unverified Claims Policy
              </span>
            </div>
            <p className="text-xs text-slate-400 mb-4">
              Sentinel AI never claims an external integration is live until a real round-trip has been executed and recorded during runtime.
            </p>

            <div className="space-y-2.5">
              <div className="rounded-lg border border-slate-800 bg-slate-900/60 p-3 flex items-center justify-between gap-3">
                <div>
                  <div className="text-xs font-medium text-slate-200">
                    Persistent Storage & Policy Engine
                  </div>
                  <div className="text-xs text-slate-400 font-mono mt-0.5">
                    {demoMode
                      ? 'Client-side Mock/Demo State Active (Toggle Live Backend in top bar)'
                      : 'data/sentinel-platform-db.json · SQL schema in src/db/schema.sql'}
                  </div>
                </div>
                <span className="text-xs font-mono text-teal-400 shrink-0 flex items-center gap-1">
                  <CheckCircle2 className="w-3.5 h-3.5" />
                  {demoMode ? 'MOCK ACTIVE' : data.integrationStatus.databasePersisted ? 'VERIFIED' : 'UNTESTED'}
                </span>
              </div>

              <div className="rounded-lg border border-slate-800 bg-slate-900/60 p-3 flex items-center justify-between gap-3">
                <div>
                  <div className="text-xs font-medium text-slate-200">
                    Server-Side Gemini AI Structured Planner
                  </div>
                  <div className="text-xs text-slate-400 font-mono mt-0.5">
                    {data.integrationStatus.geminiSecretConfigured
                      ? 'GEMINI_API_KEY present server-side · gemini-3.8-flash JSON schema'
                      : 'GEMINI_API_KEY not set · Using verified deterministic structured planner'}
                  </div>
                </div>
                <div className="flex items-center gap-2 shrink-0">
                  <span className="text-xs font-mono text-slate-300">
                    {data.integrationStatus.geminiTestedLive
                      ? 'TESTED LIVE'
                      : data.integrationStatus.geminiSecretConfigured
                        ? 'READY TO TEST'
                        : 'FALLBACK MODE'}
                  </span>
                  <button
                    onClick={() => onNavigate('assessment-plans')}
                    className="px-2.5 py-1 rounded bg-slate-800 hover:bg-slate-700 text-xs text-teal-300 font-medium cursor-pointer"
                  >
                    Test
                  </button>
                </div>
              </div>

              <div className="rounded-lg border border-slate-800 bg-slate-900/60 p-3 flex items-center justify-between gap-3">
                <div>
                  <div className="text-xs font-medium text-slate-200">
                    Python Kali Agent Outbound HTTPS Polling Protocol
                  </div>
                  <div className="text-xs text-slate-400 font-mono mt-0.5">
                    POST /api/v1/agent/poll · /claim · /result (Per-agent SHA-256 token)
                  </div>
                </div>
                <div className="flex items-center gap-2 shrink-0">
                  <span className="text-xs font-mono text-slate-300">
                    {data.integrationStatus.kaliAgentPolledLive ? 'POLL VERIFIED' : 'AWAITING POLL'}
                  </span>
                  <button
                    onClick={() => onNavigate('agent-health')}
                    className="px-2.5 py-1 rounded bg-slate-800 hover:bg-slate-700 text-xs text-teal-300 font-medium cursor-pointer"
                  >
                    Verify Poll
                  </button>
                </div>
              </div>
            </div>
          </div>
        </div>

        {/* Hard Security Prohibitions Card */}
        <div className="lg:col-span-5 rounded-xl border border-slate-800/80 bg-[#0F172A] p-5 flex flex-col justify-between">
          <div>
            <div className="flex items-center justify-between gap-2 mb-3">
              <h2 className="text-sm font-semibold text-slate-100 flex items-center gap-2">
                <Lock className="w-4 h-4 text-teal-400" />
                Enforced Safety Boundaries
              </h2>
              <span className="text-xs font-mono text-teal-400">Hard-Coded Invariants</span>
            </div>
            <p className="text-xs text-slate-400 mb-3.5">
              The policy engine and AI plan sanitizer permanently reject prohibited offensive operations before any job can enter the queue:
            </p>
            <ul className="space-y-2 text-xs text-slate-300">
              <li className="flex items-start justify-between gap-2 py-1 border-b border-slate-800/70">
                <span>Arbitrary Shell / Raw Command Execution</span>
                <span className="font-mono text-rose-400">BLOCKED</span>
              </li>
              <li className="flex items-start justify-between gap-2 py-1 border-b border-slate-800/70">
                <span>Unrestricted Port Scanning & Discovery</span>
                <span className="font-mono text-rose-400">BLOCKED</span>
              </li>
              <li className="flex items-start justify-between gap-2 py-1 border-b border-slate-800/70">
                <span>Exploit Payloads & Weaponized Modules</span>
                <span className="font-mono text-rose-400">BLOCKED</span>
              </li>
              <li className="flex items-start justify-between gap-2 py-1 border-b border-slate-800/70">
                <span>Credential Stuffing / Brute-Force Attacks</span>
                <span className="font-mono text-rose-400">BLOCKED</span>
              </li>
              <li className="flex items-start justify-between gap-2 py-1">
                <span>Intrusive Review & Remediation Deployment</span>
                <span className="font-mono text-amber-400">HUMAN GATE</span>
              </li>
            </ul>
          </div>
          <div className="mt-4 pt-3 border-t border-slate-800/80 flex items-center justify-between text-xs text-slate-400">
            <span>Test any target or category in the dry-run evaluator</span>
            <button
              onClick={() => onNavigate('scope-policies')}
              className="text-teal-400 hover:text-teal-300 font-medium flex items-center gap-1 cursor-pointer"
            >
              Scope Evaluator <ArrowRight className="w-3.5 h-3.5" />
            </button>
          </div>
        </div>
      </div>

      {/* 8-Module Directory Grid */}
      <div>
        <div className="flex items-center justify-between mb-3">
          <h2 className="text-sm font-semibold text-slate-200">
            Platform Control Modules
          </h2>
          <span className="text-xs text-slate-400">
            Select any module to inspect records, run validations, or review audit trails
          </span>
        </div>
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
          {sections.map((sec) => {
            const Icon = sec.icon;
            return (
              <button
                key={sec.id}
                onClick={() => onNavigate(sec.id)}
                className="text-left rounded-xl border border-slate-800/80 bg-[#0F172A] hover:border-teal-500/50 p-4 transition-all flex flex-col justify-between group cursor-pointer"
              >
                <div>
                  <div className="flex items-center justify-between gap-2">
                    <div className="w-8 h-8 rounded-lg bg-slate-900 border border-slate-800 flex items-center justify-center text-teal-400 group-hover:text-teal-300">
                      <Icon className="w-4 h-4" />
                    </div>
                    <span className="text-xs font-mono text-slate-300 tabular-nums">
                      {sec.metric}
                    </span>
                  </div>
                  <h3 className="mt-3 text-sm font-semibold text-slate-100 group-hover:text-teal-300 transition-colors">
                    {sec.label}
                  </h3>
                  <p className="mt-1 text-xs text-slate-400 leading-relaxed">
                    {sec.desc}
                  </p>
                </div>
                <div className="mt-4 pt-2.5 border-t border-slate-800/60 flex items-center justify-between text-xs text-teal-400 font-medium">
                  <span>Open {sec.label}</span>
                  <ArrowRight className="w-3.5 h-3.5 group-hover:translate-x-0.5 transition-transform" />
                </div>
              </button>
            );
          })}
        </div>
      </div>

      {/* Recent Activity & Pending Approvals */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <div className="rounded-xl border border-slate-800/80 bg-[#0F172A] p-5">
          <div className="flex items-center justify-between mb-3">
            <h2 className="text-sm font-semibold text-slate-100 flex items-center gap-2">
              <Clock className="w-4 h-4 text-amber-400" />
              Pending Human Approval Gates
            </h2>
            <button
              onClick={() => onNavigate('job-queue')}
              className="text-xs text-teal-400 hover:text-teal-300 cursor-pointer"
            >
              View Queue
            </button>
          </div>
          <div className="space-y-2.5">
            {pendingApprovalJobs.length === 0 && pendingRemediations.length === 0 ? (
              <div className="text-xs text-slate-400 py-4 text-center">
                No jobs or remediations currently awaiting human sign-off.
              </div>
            ) : (
              <>
                {pendingApprovalJobs.map((job) => (
                  <div
                    key={job.id}
                    className="rounded-lg border border-slate-800 bg-slate-900/60 p-3 flex items-center justify-between gap-3"
                  >
                    <div>
                      <div className="text-xs font-medium text-slate-200">
                        Job {job.id} · {job.category}
                      </div>
                      <div className="text-xs text-slate-400 font-mono mt-0.5">
                        Target: {job.targetHost} · Rate: {job.rateLimitRpm} RPM
                      </div>
                    </div>
                    <button
                      onClick={() => onNavigate('job-queue')}
                      className="px-2.5 py-1 rounded bg-amber-500/15 border border-amber-500/40 text-amber-300 text-xs font-medium cursor-pointer shrink-0"
                    >
                      Review Gate
                    </button>
                  </div>
                ))}
                {pendingRemediations.map((rem) => (
                  <div
                    key={rem.id}
                    className="rounded-lg border border-slate-800 bg-slate-900/60 p-3 flex items-center justify-between gap-3"
                  >
                    <div>
                      <div className="text-xs font-medium text-slate-200">
                        {rem.title}
                      </div>
                      <div className="text-xs text-slate-400 font-mono mt-0.5">
                        Remediation {rem.id} · Finding {rem.findingId}
                      </div>
                    </div>
                    <button
                      onClick={() => onNavigate('remediation')}
                      className="px-2.5 py-1 rounded bg-teal-500/15 border border-teal-500/40 text-teal-300 text-xs font-medium cursor-pointer shrink-0"
                    >
                      Approve Diff
                    </button>
                  </div>
                ))}
              </>
            )}
          </div>
        </div>

        <div className="rounded-xl border border-slate-800/80 bg-[#0F172A] p-5">
          <div className="flex items-center justify-between mb-3">
            <h2 className="text-sm font-semibold text-slate-100 flex items-center gap-2">
              <ScrollText className="w-4 h-4 text-teal-400" />
              Latest Immutable Audit Events
            </h2>
            <button
              onClick={() => onNavigate('audit-logs')}
              className="text-xs text-teal-400 hover:text-teal-300 cursor-pointer"
            >
              Full Ledger
            </button>
          </div>
          <div className="space-y-2">
            {data.auditLogs.slice(0, 4).map((entry) => (
              <div
                key={entry.id}
                className="rounded-lg border border-slate-800 bg-slate-900/60 p-2.5 flex items-start justify-between gap-3"
              >
                <div className="min-w-0">
                  <div className="text-xs font-mono text-slate-200 truncate">
                    {entry.action} · <span className="text-slate-400">{entry.actor}</span>
                  </div>
                  <div className="text-xs text-slate-400 truncate mt-0.5">
                    {entry.summary}
                  </div>
                </div>
                <span
                  className={`text-[11px] font-mono shrink-0 ${
                    entry.decision === 'denied'
                      ? 'text-rose-400'
                      : entry.decision === 'approval_required'
                        ? 'text-amber-400'
                        : 'text-teal-400'
                  }`}
                >
                  {(entry.decision || 'allowed').toUpperCase()}
                </span>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
};
