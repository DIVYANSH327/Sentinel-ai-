import React, { useState } from 'react';
import {
  CheckCircle2,
  UserCheck,
  ArrowRight,
  Clock,
} from 'lucide-react';
import { PlatformBootstrapPayload, PlatformTabId } from '../../types/platform';

interface FindingsSectionProps {
  data: PlatformBootstrapPayload;
  onNavigateTab: (tab: PlatformTabId) => void;
}

export const FindingsSection: React.FC<FindingsSectionProps> = ({
  data,
  onNavigateTab,
}) => {
  const [categoryFilter, setCategoryFilter] = useState<'all' | 'passive_http_headers' | 'static_code_analysis'>('all');

  const filtered = data.findings.filter((f) =>
    categoryFilter === 'all' ? true : f.category === categoryFilter
  );

  return (
    <div className="space-y-8">
      <section className="bg-[#0F172A] border border-slate-800 rounded-xl p-6 flex flex-col lg:flex-row lg:items-center lg:justify-between gap-4">
        <div className="space-y-1.5">
          <div className="flex flex-wrap items-center gap-2 text-xs text-slate-400">
            <span>Verified Assessment Output</span>
            <span aria-hidden="true">·</span>
            <span>CWE Mapped</span>
            <span aria-hidden="true">·</span>
            <span>Read-Only Evidence Capture</span>
          </div>
          <h1 className="text-2xl font-semibold text-slate-100 tracking-tight">
            Security Findings ({filtered.length})
          </h1>
          <p className="text-sm text-slate-300 max-w-3xl">
            Structured findings produced by passive HTTP response header checks and safe static code analysis.
          </p>
        </div>

        <div className="flex items-center gap-1 p-1 bg-[#0B1120] border border-slate-800 rounded-lg self-start">
          {(['all', 'passive_http_headers', 'static_code_analysis'] as const).map((cat) => (
            <button
              key={cat}
              type="button"
              onClick={() => setCategoryFilter(cat)}
              className={`px-3 py-1.5 text-xs font-medium rounded-md transition-colors whitespace-nowrap shrink-0 cursor-pointer ${
                categoryFilter === cat
                  ? 'bg-teal-500 text-slate-950'
                  : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              {cat === 'all'
                ? 'All Findings'
                : cat === 'passive_http_headers'
                ? 'Passive HTTP Headers'
                : 'Static Code Analysis'}
            </button>
          ))}
        </div>
      </section>

      <section className="bg-[#0F172A] border border-slate-800 rounded-xl p-6 space-y-4">
        {filtered.length === 0 ? (
          <div className="py-8 text-center text-sm text-slate-400 space-y-3">
            <p>No findings match the current filter.</p>
            <button
              type="button"
              onClick={() => onNavigateTab('job-queue')}
              className="px-4 py-2 text-xs font-medium bg-teal-500 text-slate-950 rounded-lg hover:bg-teal-400 transition-colors cursor-pointer"
            >
              Run Safe Assessment Job
            </button>
          </div>
        ) : (
          <div className="divide-y divide-slate-800">
            {filtered.map((finding) => (
              <div key={finding.id} className="py-5 first:pt-0 last:pb-0 space-y-3">
                <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-2">
                  <div className="space-y-1">
                    <div className="flex flex-wrap items-center gap-2 text-xs font-mono tabular-nums">
                      <span
                        className={
                          finding.severity === 'critical' || finding.severity === 'high'
                            ? 'text-rose-400 font-semibold uppercase'
                            : finding.severity === 'medium'
                            ? 'text-amber-300 font-semibold uppercase'
                            : 'text-teal-300 font-semibold uppercase'
                        }
                      >
                        {finding.severity}
                      </span>
                      <span aria-hidden="true" className="text-slate-600">·</span>
                      <span className="text-teal-300">{finding.cweId}</span>
                      <span aria-hidden="true" className="text-slate-600">·</span>
                      <span className="text-slate-400">{finding.category}</span>
                      <span aria-hidden="true" className="text-slate-600">·</span>
                      <span className="text-slate-300">{finding.targetHost}</span>
                    </div>
                    <h2 className="text-base font-semibold text-slate-100">{finding.title}</h2>
                  </div>

                  <div className="flex items-center gap-3 shrink-0">
                    <span className="text-xs font-mono text-slate-400 tabular-nums">{finding.status}</span>
                    <button
                      type="button"
                      onClick={() => onNavigateTab('remediation')}
                      className="px-3 py-1.5 text-xs font-medium bg-slate-800 text-teal-300 border border-slate-700 rounded-md hover:bg-slate-700 transition-colors flex items-center gap-1.5 whitespace-nowrap cursor-pointer"
                    >
                      <span>View Remediation</span>
                      <ArrowRight className="w-3.5 h-3.5" aria-hidden="true" />
                    </button>
                  </div>
                </div>

                <p className="text-xs text-slate-300 leading-relaxed">{finding.description}</p>

                <div className="p-3 bg-[#0B1120] border border-slate-800 rounded-lg font-mono text-xs text-slate-200 overflow-x-auto">
                  Evidence: {finding.evidence}
                </div>
              </div>
            ))}
          </div>
        )}
      </section>
    </div>
  );
};

interface RemediationSectionProps {
  data: PlatformBootstrapPayload;
  onApproveRemediation: (remId: string, approvalNote: string) => Promise<{ ok: boolean; message: string }>;
}

export const RemediationSection: React.FC<RemediationSectionProps> = ({
  data,
  onApproveRemediation,
}) => {
  const [noteByRemId, setNoteByRemId] = useState<Record<string, string>>({});
  const [feedback, setFeedback] = useState<{ ok: boolean; text: string } | null>(null);

  return (
    <div className="space-y-8">
      <section className="bg-[#0F172A] border border-slate-800 rounded-xl p-6 space-y-2">
        <div className="flex flex-wrap items-center gap-2 text-xs text-slate-400">
          <span>Human-in-the-Loop Remediation</span>
          <span aria-hidden="true">·</span>
          <span>Zero Live-System Auto-Mutation</span>
          <span aria-hidden="true">·</span>
          <span>Full Audit Trail</span>
        </div>
        <h1 className="text-2xl font-semibold text-slate-100 tracking-tight">
          Remediation Proposals &amp; Operator Sign-Off
        </h1>
        <p className="text-sm text-slate-300 max-w-3xl leading-relaxed">
          Sentinel AI generates concrete configuration and source code diffs for every finding, but never modifies live
          production systems directly. Every remediation requires explicit human operator approval.
        </p>
      </section>

      {feedback && (
        <div
          role="status"
          className={`p-4 rounded-lg border text-sm flex items-center justify-between ${
            feedback.ok
              ? 'bg-teal-950/40 border-teal-800/80 text-teal-200'
              : 'bg-rose-950/40 border-rose-800/80 text-rose-200'
          }`}
        >
          <span>{feedback.text}</span>
          <button
            type="button"
            onClick={() => setFeedback(null)}
            className="text-xs underline ml-4 whitespace-nowrap cursor-pointer"
          >
            Dismiss
          </button>
        </div>
      )}

      <section className="space-y-4">
        {data.remediations.map((rem) => (
          <div key={rem.id} className="bg-[#0F172A] border border-slate-800 rounded-xl p-6 space-y-4">
            <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-2 border-b border-slate-800 pb-4">
              <div className="space-y-1">
                <div className="flex items-center gap-2 text-xs font-mono text-slate-400">
                  <span>{rem.id}</span>
                  <span aria-hidden="true">·</span>
                  <span className="text-teal-300">{rem.targetHost}</span>
                  <span aria-hidden="true">·</span>
                  <span>Finding: {rem.findingTitle}</span>
                </div>
                <h2 className="text-lg font-semibold text-slate-100">{rem.title}</h2>
              </div>

              <div className="shrink-0">
                {rem.approvalStatus === 'approved' ? (
                  <span className="inline-flex items-center gap-1.5 text-xs font-medium text-teal-300">
                    <CheckCircle2 className="w-4 h-4 text-teal-400" aria-hidden="true" />
                    <span>Approved by {rem.approvedBy}</span>
                  </span>
                ) : (
                  <span className="inline-flex items-center gap-1.5 text-xs font-medium text-amber-300">
                    <Clock className="w-4 h-4 text-amber-400" aria-hidden="true" />
                    <span>Pending Human Approval</span>
                  </span>
                )}
              </div>
            </div>

            <p className="text-xs text-slate-300 leading-relaxed">{rem.proposedFix}</p>

            <pre className="p-3.5 bg-[#0B1120] border border-slate-800 rounded-lg font-mono text-xs text-teal-300 overflow-x-auto leading-relaxed">
              {rem.configOrCodeDiff}
            </pre>

            {rem.approvalStatus === 'pending_approval' ? (
              <div className="flex flex-col sm:flex-row items-stretch sm:items-center gap-3 pt-2">
                <input
                  type="text"
                  aria-label={`Approval justification for ${rem.title}`}
                  value={noteByRemId[rem.id] ?? 'Reviewed diff; approved for staged deployment.'}
                  onChange={(e) => setNoteByRemId({ ...noteByRemId, [rem.id]: e.target.value })}
                  className="flex-1 bg-[#0B1120] border border-slate-700 rounded-lg px-3 py-2 text-xs text-slate-100"
                />
                <button
                  type="button"
                  onClick={async () => {
                    const note = noteByRemId[rem.id] ?? 'Reviewed diff; approved for staged deployment.';
                    const res = await onApproveRemediation(rem.id, note);
                    setFeedback({ ok: res.ok, text: res.message });
                  }}
                  className="px-4 py-2 text-xs font-medium bg-teal-500 text-slate-950 rounded-lg hover:bg-teal-400 transition-colors inline-flex items-center justify-center gap-1.5 whitespace-nowrap shrink-0 cursor-pointer"
                >
                  <UserCheck className="w-4 h-4" aria-hidden="true" />
                  <span>Approve Remediation Plan</span>
                </button>
              </div>
            ) : (
              <div className="text-xs text-slate-400">
                Sign-off note: <span className="text-slate-200">{rem.approvalNote}</span>
              </div>
            )}
          </div>
        ))}
      </section>
    </div>
  );
};
