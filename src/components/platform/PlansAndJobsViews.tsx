import React, { useState } from 'react';
import {
  FileJson,
  ArrowRight,
  UserCheck,
  Code2,
  Globe,
  ShieldAlert,
} from 'lucide-react';
import { PlatformBootstrapPayload } from '../../types/platform';

interface AssessmentPlansSectionProps {
  data: PlatformBootstrapPayload;
  onGeneratePlan: (payload: {
    assetId: string;
    policyId: string;
    objective: string;
  }) => Promise<{ ok: boolean; notice?: string; message?: string }>;
  onCreateJobFromPlanStep: (payload: {
    assetId: string;
    policyId: string;
    category: string;
    targetHost: string;
    rateLimitRpm: number;
  }) => Promise<{ ok: boolean; message: string }>;
}

export const AssessmentPlansSection: React.FC<AssessmentPlansSectionProps> = ({
  data,
  onGeneratePlan,
  onCreateJobFromPlanStep,
}) => {
  const verifiedAssets = data.assets.filter((a) => a.verified);
  const [assetId, setAssetId] = useState(verifiedAssets[0]?.id || data.assets[0]?.id || '');
  const [policyId, setPolicyId] = useState(data.policies[0]?.id || '');
  const [objective, setObjective] = useState(
    'Perform a non-intrusive HTTP security-header baseline check and static source code review of authentication handlers.'
  );
  const [busy, setBusy] = useState(false);
  const [feedback, setFeedback] = useState<{ ok: boolean; text: string } | null>(null);

  const handleGenerate = async (e: React.FormEvent) => {
    e.preventDefault();
    setBusy(true);
    setFeedback(null);
    try {
      const res = await onGeneratePlan({ assetId, policyId, objective });
      setFeedback({ ok: res.ok, text: res.notice || res.message || 'Plan processed.' });
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="space-y-8">
      <section className="bg-[#0F172A] border border-slate-800 rounded-xl p-6 space-y-2">
        <div className="flex flex-wrap items-center gap-2 text-xs text-slate-400">
          <span>Server-Side Gemini AI Planner</span>
          <span aria-hidden="true">·</span>
          <span>Strict JSON Response Schema</span>
          <span aria-hidden="true">·</span>
          <span>Zero Shell Commands Permitted</span>
        </div>
        <h1 className="text-2xl font-semibold text-slate-100 tracking-tight">
          Structured AI Assessment Plans
        </h1>
        <p className="text-sm text-slate-300 max-w-3xl leading-relaxed">
          The Sentinel AI planner calls Gemini (<code className="text-teal-300">gemini-3.8-flash</code>) on the
          Node.js server with a strict <code className="text-teal-300">Type.OBJECT</code> schema and passes every step
          through the Policy Engine validator. Executable shell commands and exploit payloads are stripped automatically.
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

      <section className="grid grid-cols-1 lg:grid-cols-12 gap-6 items-stretch">
        {/* Left 5 cols: Plan Generator Form */}
        <div className="lg:col-span-5 bg-[#0F172A] border border-slate-800 rounded-xl p-6 space-y-5">
          <div className="space-y-1">
            <h2 className="text-lg font-semibold text-slate-100">01. Generate Structured Assessment Plan</h2>
            <p className="text-xs text-slate-400">
              Integration status:{' '}
              <span className="font-mono text-teal-300">
                {data.integrationStatus.geminiSecretConfigured
                  ? 'Server GEMINI_API_KEY configured'
                  : 'Deterministic Policy Fallback active (GEMINI_API_KEY not set)'}
              </span>
            </p>
          </div>

          <form onSubmit={handleGenerate} className="space-y-4 text-xs">
            <div>
              <label htmlFor="plan-asset-select" className="block font-medium text-slate-300 mb-1">
                Authorized Target Asset
              </label>
              <select
                id="plan-asset-select"
                value={assetId}
                onChange={(e) => {
                  const nextAssetId = e.target.value;
                  setAssetId(nextAssetId);
                  const matchedAsset = data.assets.find((a) => a.id === nextAssetId);
                  const matchingPolicy = data.policies.find((p) => p.authorizationRef === matchedAsset?.authorizationRef);
                  if (matchingPolicy) setPolicyId(matchingPolicy.id);
                }}
                className="w-full bg-[#0B1120] border border-slate-700 rounded-lg px-3 py-2 text-slate-100"
              >
                {data.assets.map((a) => (
                  <option key={a.id} value={a.id}>
                    {a.name} — {a.targetHost} ({a.verified ? 'Verified' : 'Unverified'})
                  </option>
                ))}
              </select>
            </div>

            <div>
              <label htmlFor="plan-policy-select" className="block font-medium text-slate-300 mb-1">
                Governing Scope Policy
              </label>
              <select
                id="plan-policy-select"
                value={policyId}
                onChange={(e) => setPolicyId(e.target.value)}
                className="w-full bg-[#0B1120] border border-slate-700 rounded-lg px-3 py-2 text-slate-100"
              >
                {data.policies.map((p) => (
                  <option key={p.id} value={p.id}>
                    {p.name} ({p.authorizationRef}, max {p.maxRateLimitRpm} req/min)
                  </option>
                ))}
              </select>
            </div>

            <div>
              <label htmlFor="plan-objective-input" className="block font-medium text-slate-300 mb-1">
                Assessment Objective
              </label>
              <textarea
                id="plan-objective-input"
                rows={4}
                value={objective}
                onChange={(e) => setObjective(e.target.value)}
                className="w-full bg-[#0B1120] border border-slate-700 rounded-lg px-3 py-2 text-slate-100 leading-relaxed"
              />
            </div>

            <button
              type="submit"
              disabled={busy}
              className="w-full py-2.5 px-4 text-xs font-medium bg-teal-500 text-slate-950 rounded-lg hover:bg-teal-400 transition-colors cursor-pointer"
            >
              {busy ? 'Generating & Validating Structured Plan…' : 'Generate Validated JSON Assessment Plan'}
            </button>
          </form>
        </div>

        {/* Right 7 cols: Validated Structured JSON Plans */}
        <div className="lg:col-span-7 bg-[#0F172A] border border-slate-800 rounded-xl p-6 space-y-5">
          <div className="flex items-center justify-between">
            <h2 className="text-lg font-semibold text-slate-100 flex items-center gap-2">
              <FileJson className="w-5 h-5 text-teal-400" aria-hidden="true" />
              <span>02. Validated Structured Plans ({data.plans.length})</span>
            </h2>
          </div>

          <div className="space-y-4">
            {data.plans.map((plan) => (
              <div key={plan.id} className="p-4 bg-[#0B1120] border border-slate-800 rounded-lg space-y-3 text-xs">
                <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-2 border-b border-slate-800 pb-3">
                  <div>
                    <div className="text-sm font-semibold text-slate-100">{plan.title}</div>
                    <div className="text-slate-400 mt-0.5">
                      Source: <code className="text-teal-300">{plan.generatedBySource}</code> · Model:{' '}
                      <code className="text-slate-300">{plan.modelName}</code>
                    </div>
                  </div>
                  <span className="font-mono text-slate-400 tabular-nums">
                    {new Date(plan.createdAt).toLocaleTimeString()}
                  </span>
                </div>

                <p className="text-slate-300">{plan.safetyAttestation}</p>

                <div className="space-y-2.5">
                  {plan.steps.map((step) => (
                    <div
                      key={step.stepNumber}
                      className="p-3 bg-[#0F172A] border border-slate-800/90 rounded-lg flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3"
                    >
                      <div className="space-y-1">
                        <div className="font-medium text-slate-100">
                          <span className="font-mono text-teal-400 mr-1.5 tabular-nums">0{step.stepNumber}.</span>
                          {step.title}
                        </div>
                        <div className="text-slate-400">{step.rationale}</div>
                        <div className="font-mono text-[11px] text-slate-400 tabular-nums">
                          category={step.category} · tool={step.safeToolConfig.toolName} · rateLimit=
                          {step.safeToolConfig.rateLimitRpm}rpm
                        </div>
                      </div>

                      <button
                        type="button"
                        onClick={async () => {
                          const res = await onCreateJobFromPlanStep({
                            assetId: plan.assetId,
                            policyId: plan.policyId,
                            category: step.category,
                            targetHost: step.targetHost,
                            rateLimitRpm: step.safeToolConfig.rateLimitRpm,
                          });
                          setFeedback({ ok: res.ok, text: res.message });
                        }}
                        className="px-3 py-1.5 text-xs font-medium bg-slate-800 text-teal-300 border border-teal-700/70 rounded-md hover:bg-slate-700 transition-colors flex items-center gap-1.5 whitespace-nowrap shrink-0 cursor-pointer"
                      >
                        <span>Queue Step as Job</span>
                        <ArrowRight className="w-3.5 h-3.5" aria-hidden="true" />
                      </button>
                    </div>
                  ))}
                </div>
              </div>
            ))}
          </div>
        </div>
      </section>
    </div>
  );
};

interface JobQueueSectionProps {
  data: PlatformBootstrapPayload;
  onCreateJob: (payload: {
    assetId: string;
    policyId: string;
    category: string;
    targetHost: string;
    rateLimitRpm: number;
    codeSnippet?: string;
    codeFilename?: string;
    executeImmediatelyInMvp?: boolean;
  }) => Promise<{ ok: boolean; code: string; message: string }>;
  onApproveJob: (jobId: string) => Promise<{ ok: boolean; message: string }>;
}

export const JobQueueSection: React.FC<JobQueueSectionProps> = ({
  data,
  onCreateJob,
  onApproveJob,
}) => {
  const [assetId, setAssetId] = useState(data.assets[0]?.id || 'ast-101');
  const [policyId, setPolicyId] = useState(data.policies[0]?.id || 'pol-201');
  const [category, setCategory] = useState<'passive_http_headers' | 'static_code_analysis' | 'intrusive_review_only'>(
    'passive_http_headers'
  );
  const [targetHost, setTargetHost] = useState(data.assets[0]?.targetHost || 'auth.staging.sentinel.internal');
  const [rateLimitRpm, setRateLimitRpm] = useState(15);
  const [executeImmediatelyInMvp, setExecuteImmediatelyInMvp] = useState(false);
  const [codeFilename, setCodeFilename] = useState('oauthTokenService.ts');
  const [codeSnippet, setCodeSnippet] = useState(
    `// User-supplied source snippet for safe static analysis (never executed)\nconst fallbackApiKey = "sk_live_998877665544332211";\nexport function verifyHost(host: string) {\n  return child_process.exec("ping -c 1 " + host);\n}\nexport function lookupUser(email: string, db: any) {\n  return db.query(\`SELECT * FROM users WHERE email = '\${email}'\`);\n}`
  );
  const [feedback, setFeedback] = useState<{ ok: boolean; text: string } | null>(null);

  const handleSubmitJob = async (e: React.FormEvent) => {
    e.preventDefault();
    const res = await onCreateJob({
      assetId,
      policyId,
      category,
      targetHost,
      rateLimitRpm,
      codeSnippet: category === 'static_code_analysis' ? codeSnippet : undefined,
      codeFilename: category === 'static_code_analysis' ? codeFilename : undefined,
      executeImmediatelyInMvp,
    });
    setFeedback({ ok: res.ok, text: `${res.message} (${res.code})` });
  };

  return (
    <div className="space-y-8">
      <section className="bg-[#0F172A] border border-slate-800 rounded-xl p-6 space-y-2">
        <div className="flex flex-wrap items-center gap-2 text-xs text-slate-400">
          <span>MVP Safe Tooling Only</span>
          <span aria-hidden="true">·</span>
          <span>Passive HTTP Header Checks &amp; Static Code Analysis</span>
          <span aria-hidden="true">·</span>
          <span>Human Approval for Intrusive Reviews</span>
        </div>
        <h1 className="text-2xl font-semibold text-slate-100 tracking-tight">
          Policy-Enforced Job Queue &amp; Safe Analyzer Dispatch
        </h1>
        <p className="text-sm text-slate-300 max-w-3xl leading-relaxed">
          Every submitted job is checked against an explicit authorization record, scope policy, rate limit, and
          expiry. For the MVP, only passive HTTP security-header checks and static code analysis are enabled; intrusive
          reviews are held in <code className="text-amber-300">pending_approval</code> until human operator sign-off.
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

      <section className="grid grid-cols-1 lg:grid-cols-12 gap-6 items-stretch">
        {/* Left 5 cols: Create Safe Assessment Job */}
        <div className="lg:col-span-5 bg-[#0F172A] border border-slate-800 rounded-xl p-6 space-y-5">
          <h2 className="text-lg font-semibold text-slate-100">01. Dispatch Safe Assessment Job</h2>

          <form onSubmit={handleSubmitJob} className="space-y-3.5 text-xs">
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
              <div>
                <label htmlFor="job-asset-select" className="block font-medium text-slate-300 mb-1">
                  Authorized Asset
                </label>
                <select
                  id="job-asset-select"
                  value={assetId}
                  onChange={(e) => {
                    const nextId = e.target.value;
                    setAssetId(nextId);
                    const found = data.assets.find((a) => a.id === nextId);
                    if (found) {
                      setTargetHost(found.targetHost);
                      const pol = data.policies.find((p) => p.authorizationRef === found.authorizationRef);
                      if (pol) setPolicyId(pol.id);
                    }
                  }}
                  className="w-full bg-[#0B1120] border border-slate-700 rounded-lg px-3 py-2 text-slate-100"
                >
                  {data.assets.map((a) => (
                    <option key={a.id} value={a.id}>
                      {a.name} ({a.verified ? 'Verified' : 'Unverified'})
                    </option>
                  ))}
                </select>
              </div>

              <div>
                <label htmlFor="job-policy-select" className="block font-medium text-slate-300 mb-1">
                  Scope Policy
                </label>
                <select
                  id="job-policy-select"
                  value={policyId}
                  onChange={(e) => setPolicyId(e.target.value)}
                  className="w-full bg-[#0B1120] border border-slate-700 rounded-lg px-3 py-2 text-slate-100"
                >
                  {data.policies.map((p) => (
                    <option key={p.id} value={p.id}>
                      {p.name} ({p.authorizationRef})
                    </option>
                  ))}
                </select>
              </div>
            </div>

            <div>
              <label htmlFor="job-category-select" className="block font-medium text-slate-300 mb-1">
                MVP Assessment Category
              </label>
              <select
                id="job-category-select"
                value={category}
                onChange={(e) => setCategory(e.target.value as typeof category)}
                className="w-full bg-[#0B1120] border border-slate-700 rounded-lg px-3 py-2 text-slate-100"
              >
                <option value="passive_http_headers">
                  passive_http_headers — Passive HTTP Security-Header Inspection
                </option>
                <option value="static_code_analysis">
                  static_code_analysis — Safe Static Analysis of User-Supplied Code
                </option>
                <option value="intrusive_review_only">
                  intrusive_review_only — Gated Review (Requires Human Approval)
                </option>
              </select>
            </div>

            <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
              <div>
                <label htmlFor="job-target-input" className="block font-medium text-slate-300 mb-1">
                  Target Host
                </label>
                <input
                  id="job-target-input"
                  type="text"
                  value={targetHost}
                  onChange={(e) => setTargetHost(e.target.value)}
                  className="w-full bg-[#0B1120] border border-slate-700 rounded-lg px-3 py-2 font-mono text-slate-100"
                />
              </div>

              <div>
                <label htmlFor="job-rpm-input" className="block font-medium text-slate-300 mb-1">
                  Rate Limit (req/min)
                </label>
                <input
                  id="job-rpm-input"
                  type="number"
                  min={1}
                  max={120}
                  value={rateLimitRpm}
                  onChange={(e) => setRateLimitRpm(Number(e.target.value))}
                  className="w-full bg-[#0B1120] border border-slate-700 rounded-lg px-3 py-2 font-mono text-slate-100 tabular-nums"
                />
              </div>
            </div>

            {category === 'static_code_analysis' && (
              <div className="space-y-2 pt-1">
                <div>
                  <label htmlFor="job-code-filename" className="block font-medium text-slate-300 mb-1">
                    Source Filename Label
                  </label>
                  <input
                    id="job-code-filename"
                    type="text"
                    value={codeFilename}
                    onChange={(e) => setCodeFilename(e.target.value)}
                    className="w-full bg-[#0B1120] border border-slate-700 rounded-lg px-3 py-1.5 font-mono text-slate-100"
                  />
                </div>
                <div>
                  <label htmlFor="job-code-snippet" className="block font-medium text-slate-300 mb-1">
                    User-Supplied Source Code Snippet (Inspected Statically, Never Executed)
                  </label>
                  <textarea
                    id="job-code-snippet"
                    rows={5}
                    value={codeSnippet}
                    onChange={(e) => setCodeSnippet(e.target.value)}
                    className="w-full bg-[#0B1120] border border-slate-700 rounded-lg px-3 py-2 font-mono text-slate-100 text-[11px] leading-relaxed"
                  />
                </div>
              </div>
            )}

            <label className="flex items-center gap-2 text-slate-300 cursor-pointer pt-1">
              <input
                type="checkbox"
                checked={executeImmediatelyInMvp}
                onChange={(e) => setExecuteImmediatelyInMvp(e.target.checked)}
                className="rounded border-slate-600"
              />
              <span>Execute safe analyzer immediately on server (unchecked queues for Kali agent polling)</span>
            </label>

            <button
              type="submit"
              className="w-full py-2.5 px-4 text-xs font-medium bg-teal-500 text-slate-950 rounded-lg hover:bg-teal-400 transition-colors cursor-pointer"
            >
              Validate &amp; Submit Job
            </button>
          </form>
        </div>

        {/* Right 7 cols: Active Job Queue Table */}
        <div className="lg:col-span-7 bg-[#0F172A] border border-slate-800 rounded-xl p-6 space-y-4">
          <div className="flex items-center justify-between">
            <h2 className="text-lg font-semibold text-slate-100">02. Job Queue &amp; Claim State</h2>
            <span className="text-xs font-mono text-slate-400 tabular-nums">{data.jobs.length} Jobs</span>
          </div>

          <div className="overflow-x-auto">
            <table className="w-full text-left border-collapse text-xs">
              <thead>
                <tr className="border-b border-slate-800 text-slate-400">
                  <th className="py-2.5 pr-3 font-medium">Job ID &amp; Category</th>
                  <th className="py-2.5 px-3 font-medium">Target Host</th>
                  <th className="py-2.5 px-3 font-medium">Status &amp; Claim Key</th>
                  <th className="py-2.5 px-3 font-medium">Expiry</th>
                  <th className="py-2.5 pl-3 font-medium text-right">Action</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/70">
                {data.jobs.map((job) => (
                  <tr key={job.id}>
                    <td className="py-3 pr-3">
                      <div className="font-mono text-slate-200 tabular-nums">{job.id}</div>
                      <div className="flex items-center gap-1.5 text-slate-400 mt-0.5">
                        {job.category === 'static_code_analysis' ? (
                          <Code2 className="w-3.5 h-3.5 text-teal-400" aria-hidden="true" />
                        ) : job.category === 'intrusive_review_only' ? (
                          <ShieldAlert className="w-3.5 h-3.5 text-amber-400" aria-hidden="true" />
                        ) : (
                          <Globe className="w-3.5 h-3.5 text-teal-400" aria-hidden="true" />
                        )}
                        <span className="font-mono">{job.category}</span>
                      </div>
                    </td>
                    <td className="py-3 px-3 font-mono text-teal-300">
                      <div>{job.targetHost}</div>
                      <div className="text-slate-500 tabular-nums">{job.rateLimitRpm} req/min</div>
                    </td>
                    <td className="py-3 px-3 font-mono tabular-nums">
                      <div
                        className={
                          job.status === 'completed'
                            ? 'text-teal-300'
                            : job.status === 'pending_approval'
                            ? 'text-amber-300'
                            : job.status === 'claimed'
                            ? 'text-sky-300'
                            : 'text-slate-200'
                        }
                      >
                        {job.status}
                      </div>
                      {job.idempotencyClaimKey && (
                        <div className="text-[11px] text-slate-400 truncate max-w-[160px]">
                          key: {job.idempotencyClaimKey}
                        </div>
                      )}
                    </td>
                    <td className="py-3 px-3 font-mono text-slate-400 tabular-nums whitespace-nowrap">
                      {new Date(job.expiresAt).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}
                    </td>
                    <td className="py-3 pl-3 text-right">
                      {job.status === 'pending_approval' ? (
                        <button
                          type="button"
                          onClick={async () => {
                            const res = await onApproveJob(job.id);
                            setFeedback({ ok: res.ok, text: res.message });
                          }}
                          className="px-3 py-1.5 text-xs font-medium bg-amber-500 text-slate-950 rounded-md hover:bg-amber-400 transition-colors inline-flex items-center gap-1 whitespace-nowrap cursor-pointer"
                        >
                          <UserCheck className="w-3.5 h-3.5" aria-hidden="true" />
                          <span>Approve Job</span>
                        </button>
                      ) : (
                        <span className="font-mono text-slate-500">
                          {job.resultSummary ? `${job.resultSummary.findingsCount} finding(s)` : 'Ready'}
                        </span>
                      )}
                    </td>
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
