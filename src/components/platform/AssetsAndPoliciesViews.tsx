import React, { useState } from 'react';
import {
  CheckCircle2,
  Clock,
  ShieldCheck,
  Plus,
  Play,
  AlertTriangle,
} from 'lucide-react';
import { PlatformBootstrapPayload } from '../../types/platform';

interface AuthorizedAssetsSectionProps {
  data: PlatformBootstrapPayload;
  onRegisterAsset: (payload: {
    name: string;
    targetHost: string;
    ipOrCidr: string;
    environment: 'staging' | 'isolated_lab' | 'production_read_only';
    ownerTeam: string;
    authorizationRef: string;
    verified: boolean;
  }) => Promise<{ ok: boolean; message: string }>;
  onVerifyAsset: (assetId: string) => Promise<{ ok: boolean; message: string }>;
}

export const AuthorizedAssetsSection: React.FC<AuthorizedAssetsSectionProps> = ({
  data,
  onRegisterAsset,
  onVerifyAsset,
}) => {
  const [name, setName] = useState('');
  const [targetHost, setTargetHost] = useState('');
  const [ipOrCidr, setIpOrCidr] = useState('10.24.0.55');
  const [environment, setEnvironment] = useState<'staging' | 'isolated_lab' | 'production_read_only'>('staging');
  const [ownerTeam, setOwnerTeam] = useState('Platform Security');
  const [authorizationRef, setAuthorizationRef] = useState('AUTH-2026-9104');
  const [verified, setVerified] = useState(true);
  const [feedback, setFeedback] = useState<{ ok: boolean; text: string } | null>(null);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    const res = await onRegisterAsset({
      name,
      targetHost,
      ipOrCidr,
      environment,
      ownerTeam,
      authorizationRef,
      verified,
    });
    setFeedback({ ok: res.ok, text: res.message });
    if (res.ok) {
      setName('');
      setTargetHost('');
    }
  };

  return (
    <div className="space-y-8">
      <section className="bg-[#0F172A] border border-slate-800 rounded-xl p-6 space-y-2">
        <div className="flex flex-wrap items-center gap-2 text-xs text-slate-400">
          <span>Explicit Authorization Registry</span>
          <span aria-hidden="true">·</span>
          <span>Fail-Closed Verification</span>
          <span aria-hidden="true">·</span>
          <span>Expiry Enforced</span>
        </div>
        <h1 className="text-2xl font-semibold text-slate-100 tracking-tight">
          Authorized Research Assets &amp; Signed Authorization Records
        </h1>
        <p className="text-sm text-slate-300 max-w-3xl leading-relaxed">
          Every security assessment job must reference an explicitly registered, verified, and non-expired asset
          authorization record. Unverified assets are blocked by the Policy Engine until a lead researcher or security
          reviewer signs off.
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
        {/* Left 7 cols: Asset Registry Table */}
        <div className="lg:col-span-7 bg-[#0F172A] border border-slate-800 rounded-xl p-6 space-y-4">
          <div className="flex items-center justify-between">
            <h2 className="text-lg font-semibold text-slate-100">01. Registered Asset Inventory</h2>
            <span className="text-xs font-mono text-slate-400 tabular-nums">{data.assets.length} Assets</span>
          </div>

          <div className="overflow-x-auto">
            <table className="w-full text-left border-collapse text-xs">
              <thead>
                <tr className="border-b border-slate-800 text-slate-400">
                  <th className="py-2.5 pr-3 font-medium">Asset &amp; Host</th>
                  <th className="py-2.5 px-3 font-medium">IP / CIDR</th>
                  <th className="py-2.5 px-3 font-medium">Authorization Ref</th>
                  <th className="py-2.5 px-3 font-medium">Status</th>
                  <th className="py-2.5 pl-3 font-medium text-right">Action</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/70">
                {data.assets.map((asset) => (
                  <tr key={asset.id}>
                    <td className="py-3 pr-3">
                      <div className="font-medium text-slate-100">{asset.name}</div>
                      <div className="font-mono text-teal-300 mt-0.5">{asset.targetHost}</div>
                    </td>
                    <td className="py-3 px-3 font-mono text-slate-300 tabular-nums">{asset.ipOrCidr}</td>
                    <td className="py-3 px-3 font-mono text-slate-200 tabular-nums">{asset.authorizationRef}</td>
                    <td className="py-3 px-3">
                      {asset.verified ? (
                        <span className="inline-flex items-center gap-1.5 text-teal-300 font-medium">
                          <CheckCircle2 className="w-3.5 h-3.5 text-teal-400" aria-hidden="true" />
                          <span>Verified ({asset.verifiedBy})</span>
                        </span>
                      ) : (
                        <span className="inline-flex items-center gap-1.5 text-amber-300 font-medium">
                          <Clock className="w-3.5 h-3.5 text-amber-400" aria-hidden="true" />
                          <span>Pending Verification</span>
                        </span>
                      )}
                    </td>
                    <td className="py-3 pl-3 text-right">
                      {!asset.verified ? (
                        <button
                          type="button"
                          onClick={async () => {
                            const res = await onVerifyAsset(asset.id);
                            setFeedback({ ok: res.ok, text: res.message });
                          }}
                          className="px-3 py-1.5 text-xs font-medium bg-teal-500 text-slate-950 rounded-md hover:bg-teal-400 transition-colors whitespace-nowrap cursor-pointer"
                        >
                          Verify Authorization
                        </button>
                      ) : (
                        <span className="font-mono text-slate-500 tabular-nums">
                          Exp {new Date(asset.expiresAt).toLocaleDateString()}
                        </span>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>

        {/* Right 5 cols: Register New Authorized Asset */}
        <div className="lg:col-span-5 bg-[#0F172A] border border-slate-800 rounded-xl p-6 space-y-5">
          <div className="space-y-1">
            <h2 className="text-lg font-semibold text-slate-100 flex items-center gap-2">
              <Plus className="w-4 h-4 text-teal-400" aria-hidden="true" />
              <span>02. Register New Authorized Asset</span>
            </h2>
            <p className="text-xs text-slate-400">
              Bind a hostname and IP/CIDR to a signed authorization ticket reference.
            </p>
          </div>

          <form onSubmit={handleSubmit} className="space-y-3.5 text-xs">
            <div className="space-y-1">
              <label htmlFor="asset-name-input" className="block font-medium text-slate-300">
                Asset Name
              </label>
              <input
                id="asset-name-input"
                type="text"
                value={name}
                onChange={(e) => setName(e.target.value)}
                placeholder="e.g. Internal Vault API (Staging)"
                className="w-full bg-[#0B1120] border border-slate-700 rounded-lg px-3 py-2 text-slate-100"
              />
            </div>

            <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
              <div className="space-y-1">
                <label htmlFor="asset-host-input" className="block font-medium text-slate-300">
                  Target Hostname
                </label>
                <input
                  id="asset-host-input"
                  type="text"
                  value={targetHost}
                  onChange={(e) => setTargetHost(e.target.value)}
                  placeholder="vault.staging.sentinel.internal"
                  className="w-full bg-[#0B1120] border border-slate-700 rounded-lg px-3 py-2 font-mono text-slate-100"
                />
              </div>

              <div className="space-y-1">
                <label htmlFor="asset-ip-input" className="block font-medium text-slate-300">
                  IPv4 or CIDR
                </label>
                <input
                  id="asset-ip-input"
                  type="text"
                  value={ipOrCidr}
                  onChange={(e) => setIpOrCidr(e.target.value)}
                  className="w-full bg-[#0B1120] border border-slate-700 rounded-lg px-3 py-2 font-mono text-slate-100 tabular-nums"
                />
              </div>
            </div>

            <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
              <div className="space-y-1">
                <label htmlFor="asset-authref-input" className="block font-medium text-slate-300">
                  Authorization Reference
                </label>
                <input
                  id="asset-authref-input"
                  type="text"
                  value={authorizationRef}
                  onChange={(e) => setAuthorizationRef(e.target.value)}
                  className="w-full bg-[#0B1120] border border-slate-700 rounded-lg px-3 py-2 font-mono text-slate-100 tabular-nums"
                />
              </div>

              <div className="space-y-1">
                <label htmlFor="asset-env-select" className="block font-medium text-slate-300">
                  Environment
                </label>
                <select
                  id="asset-env-select"
                  value={environment}
                  onChange={(e) => setEnvironment(e.target.value as typeof environment)}
                  className="w-full bg-[#0B1120] border border-slate-700 rounded-lg px-3 py-2 text-slate-100"
                >
                  <option value="staging">staging</option>
                  <option value="isolated_lab">isolated_lab</option>
                  <option value="production_read_only">production_read_only</option>
                </select>
              </div>
            </div>

            <div className="space-y-1">
              <label htmlFor="asset-owner-input" className="block font-medium text-slate-300">
                Asset Owner Team
              </label>
              <input
                id="asset-owner-input"
                type="text"
                value={ownerTeam}
                onChange={(e) => setOwnerTeam(e.target.value)}
                className="w-full bg-[#0B1120] border border-slate-700 rounded-lg px-3 py-2 text-slate-100"
              />
            </div>

            <label className="flex items-center gap-2 text-slate-300 cursor-pointer pt-1">
              <input
                type="checkbox"
                checked={verified}
                onChange={(e) => setVerified(e.target.checked)}
                className="rounded border-slate-600"
              />
              <span>Mark authorization record verified immediately by current operator</span>
            </label>

            <button
              type="submit"
              className="w-full py-2.5 px-4 text-xs font-medium bg-teal-500 text-slate-950 rounded-lg hover:bg-teal-400 transition-colors cursor-pointer"
            >
              Register Authorized Asset
            </button>
          </form>
        </div>
      </section>
    </div>
  );
};

interface ScopePoliciesSectionProps {
  data: PlatformBootstrapPayload;
  onCreatePolicy: (payload: {
    name: string;
    authorizationRef: string;
    permittedHosts: string[];
    permittedCidrs: string[];
    maxRateLimitRpm: number;
  }) => Promise<{ ok: boolean; message: string }>;
  onEvaluatePolicy: (payload: {
    assetId: string;
    policyId: string;
    targetHost: string;
    category: string;
    requestedRateLimitRpm: number;
    rawCommandInput?: string;
  }) => Promise<{
    ok: boolean;
    evaluation: {
      allowed: boolean;
      requiresHumanApproval: boolean;
      code: string;
      reason: string;
    };
  }>;
}

export const ScopePoliciesSection: React.FC<ScopePoliciesSectionProps> = ({
  data,
  onCreatePolicy,
  onEvaluatePolicy,
}) => {
  const [policyName, setPolicyName] = useState('');
  const [authRef, setAuthRef] = useState('AUTH-2026-9012');
  const [hostsText, setHostsText] = useState('*.staging.sentinel.internal');
  const [cidrsText, setCidrsText] = useState('10.24.0.0/24');
  const [maxRpm, setMaxRpm] = useState(30);

  // Policy Evaluator Test Bench state
  const [evalAssetId, setEvalAssetId] = useState(data.assets[0]?.id || 'ast-101');
  const [evalPolicyId, setEvalPolicyId] = useState(data.policies[0]?.id || 'pol-201');
  const [evalHost, setEvalHost] = useState(data.assets[0]?.targetHost || 'auth.staging.sentinel.internal');
  const [evalCategory, setEvalCategory] = useState('passive_http_headers');
  const [evalRpm, setEvalRpm] = useState(15);
  const [evalResult, setEvalResult] = useState<{
    allowed: boolean;
    requiresHumanApproval: boolean;
    code: string;
    reason: string;
  } | null>(null);

  const handleCreate = async (e: React.FormEvent) => {
    e.preventDefault();
    const res = await onCreatePolicy({
      name: policyName,
      authorizationRef: authRef,
      permittedHosts: hostsText.split(',').map((s) => s.trim()).filter(Boolean),
      permittedCidrs: cidrsText.split(',').map((s) => s.trim()).filter(Boolean),
      maxRateLimitRpm: maxRpm,
    });
    if (res.ok) setPolicyName('');
  };

  const handleRunEvaluation = async (e: React.FormEvent) => {
    e.preventDefault();
    const res = await onEvaluatePolicy({
      assetId: evalAssetId,
      policyId: evalPolicyId,
      targetHost: evalHost,
      category: evalCategory,
      requestedRateLimitRpm: evalRpm,
    });
    setEvalResult(res.evaluation);
  };

  return (
    <div className="space-y-8">
      <section className="bg-[#0F172A] border border-slate-800 rounded-xl p-6 space-y-2">
        <div className="flex flex-wrap items-center gap-2 text-xs text-slate-400">
          <span>Deterministic Policy Engine</span>
          <span aria-hidden="true">·</span>
          <span>Permitted Hosts &amp; CIDRs</span>
          <span aria-hidden="true">·</span>
          <span>Rate Limit &amp; Category Guardrails</span>
        </div>
        <h1 className="text-2xl font-semibold text-slate-100 tracking-tight">
          Scope Policies &amp; Real-Time Policy Engine Evaluator
        </h1>
        <p className="text-sm text-slate-300 max-w-3xl leading-relaxed">
          Scope policies bind an authorization reference to permitted hostnames, IPv4 CIDR blocks, allowed test
          categories (<code className="text-teal-300">passive_http_headers</code> and{' '}
          <code className="text-teal-300">static_code_analysis</code>), maximum request rate limits, and expiry dates.
        </p>
      </section>

      <section className="grid grid-cols-1 lg:grid-cols-12 gap-6 items-stretch">
        {/* Left 6 cols: Active Scope Policies & Create Form */}
        <div className="lg:col-span-6 bg-[#0F172A] border border-slate-800 rounded-xl p-6 space-y-6">
          <div className="space-y-3">
            <h2 className="text-lg font-semibold text-slate-100">01. Active Scope Policies</h2>
            <div className="space-y-3">
              {data.policies.map((pol) => (
                <div key={pol.id} className="p-4 bg-[#0B1120] border border-slate-800 rounded-lg space-y-2 text-xs">
                  <div className="flex items-center justify-between">
                    <span className="font-semibold text-slate-100 text-sm">{pol.name}</span>
                    <span className="font-mono text-teal-300 tabular-nums">{pol.authorizationRef}</span>
                  </div>
                  <div className="text-slate-400 font-mono">
                    Hosts: {pol.permittedHosts.join(', ')} · CIDRs: {pol.permittedCidrs.join(', ')}
                  </div>
                  <div className="text-slate-300">
                    Allowed Categories: <code className="text-teal-300">{pol.allowedCategories.join(', ')}</code> · Max
                    Rate: <span className="font-mono tabular-nums">{pol.maxRateLimitRpm} req/min</span>
                  </div>
                </div>
              ))}
            </div>
          </div>

          <form onSubmit={handleCreate} className="border-t border-slate-800 pt-5 space-y-3 text-xs">
            <h3 className="text-sm font-semibold text-slate-200">Create Scope Policy</h3>
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
              <div>
                <label htmlFor="pol-name" className="block text-slate-400 mb-1">
                  Policy Name
                </label>
                <input
                  id="pol-name"
                  type="text"
                  value={policyName}
                  onChange={(e) => setPolicyName(e.target.value)}
                  placeholder="Staging Read-Only Policy"
                  className="w-full bg-[#0B1120] border border-slate-700 rounded-lg px-3 py-2 text-slate-100"
                />
              </div>
              <div>
                <label htmlFor="pol-authref" className="block text-slate-400 mb-1">
                  Authorization Reference
                </label>
                <input
                  id="pol-authref"
                  type="text"
                  value={authRef}
                  onChange={(e) => setAuthRef(e.target.value)}
                  className="w-full bg-[#0B1120] border border-slate-700 rounded-lg px-3 py-2 font-mono text-slate-100"
                />
              </div>
            </div>
            <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
              <div>
                <label htmlFor="pol-hosts" className="block text-slate-400 mb-1">
                  Permitted Hosts
                </label>
                <input
                  id="pol-hosts"
                  type="text"
                  value={hostsText}
                  onChange={(e) => setHostsText(e.target.value)}
                  className="w-full bg-[#0B1120] border border-slate-700 rounded-lg px-3 py-2 font-mono text-slate-100"
                />
              </div>
              <div>
                <label htmlFor="pol-cidrs" className="block text-slate-400 mb-1">
                  Permitted CIDRs
                </label>
                <input
                  id="pol-cidrs"
                  type="text"
                  value={cidrsText}
                  onChange={(e) => setCidrsText(e.target.value)}
                  className="w-full bg-[#0B1120] border border-slate-700 rounded-lg px-3 py-2 font-mono text-slate-100"
                />
              </div>
              <div>
                <label htmlFor="pol-rpm" className="block text-slate-400 mb-1">
                  Max Rate (req/min)
                </label>
                <input
                  id="pol-rpm"
                  type="number"
                  min={1}
                  max={120}
                  value={maxRpm}
                  onChange={(e) => setMaxRpm(Number(e.target.value))}
                  className="w-full bg-[#0B1120] border border-slate-700 rounded-lg px-3 py-2 font-mono text-slate-100 tabular-nums"
                />
              </div>
            </div>
            <button
              type="submit"
              className="px-4 py-2 text-xs font-medium bg-teal-500 text-slate-950 rounded-lg hover:bg-teal-400 transition-colors cursor-pointer"
            >
              Save Scope Policy
            </button>
          </form>
        </div>

        {/* Right 6 cols: Interactive Policy Engine Dry-Run Evaluator */}
        <div className="lg:col-span-6 bg-[#0F172A] border border-slate-800 rounded-xl p-6 space-y-5">
          <div className="space-y-1">
            <h2 className="text-lg font-semibold text-slate-100 flex items-center gap-2">
              <ShieldCheck className="w-5 h-5 text-teal-400" aria-hidden="true" />
              <span>02. Policy Engine Dry-Run Evaluator</span>
            </h2>
            <p className="text-xs text-slate-400">
              Test any candidate job against the server-side Policy Engine to verify how out-of-scope hosts, unverified
              assets, excessive rate limits, or prohibited categories are blocked.
            </p>
          </div>

          <form onSubmit={handleRunEvaluation} className="space-y-3.5 text-xs">
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
              <div>
                <label htmlFor="eval-asset-select" className="block font-medium text-slate-300 mb-1">
                  Target Asset Record
                </label>
                <select
                  id="eval-asset-select"
                  value={evalAssetId}
                  onChange={(e) => setEvalAssetId(e.target.value)}
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
                <label htmlFor="eval-policy-select" className="block font-medium text-slate-300 mb-1">
                  Scope Policy
                </label>
                <select
                  id="eval-policy-select"
                  value={evalPolicyId}
                  onChange={(e) => setEvalPolicyId(e.target.value)}
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

            <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
              <div>
                <label htmlFor="eval-host-input" className="block font-medium text-slate-300 mb-1">
                  Candidate Target Host or IP
                </label>
                <input
                  id="eval-host-input"
                  type="text"
                  value={evalHost}
                  onChange={(e) => setEvalHost(e.target.value)}
                  className="w-full bg-[#0B1120] border border-slate-700 rounded-lg px-3 py-2 font-mono text-slate-100"
                />
              </div>

              <div>
                <label htmlFor="eval-rpm-input" className="block font-medium text-slate-300 mb-1">
                  Requested Rate Limit (req/min)
                </label>
                <input
                  id="eval-rpm-input"
                  type="number"
                  value={evalRpm}
                  onChange={(e) => setEvalRpm(Number(e.target.value))}
                  className="w-full bg-[#0B1120] border border-slate-700 rounded-lg px-3 py-2 font-mono text-slate-100 tabular-nums"
                />
              </div>
            </div>

            <div>
              <label htmlFor="eval-category-select" className="block font-medium text-slate-300 mb-1">
                Test Category (Includes Prohibited Offensive Categories to Verify Rejection)
              </label>
              <select
                id="eval-category-select"
                value={evalCategory}
                onChange={(e) => setEvalCategory(e.target.value)}
                className="w-full bg-[#0B1120] border border-slate-700 rounded-lg px-3 py-2 text-slate-100"
              >
                <option value="passive_http_headers">passive_http_headers (Allowed MVP)</option>
                <option value="static_code_analysis">static_code_analysis (Allowed MVP)</option>
                <option value="intrusive_review_only">intrusive_review_only (Requires Human Approval)</option>
                <option value="arbitrary_shell">arbitrary_shell (Prohibited — Must Reject)</option>
                <option value="unrestricted_port_scan">unrestricted_port_scan (Prohibited — Must Reject)</option>
                <option value="exploit_payload">exploit_payload (Prohibited — Must Reject)</option>
                <option value="credential_attack">credential_attack (Prohibited — Must Reject)</option>
                <option value="persistence_install">persistence_install (Prohibited — Must Reject)</option>
                <option value="live_system_modification">live_system_modification (Prohibited — Must Reject)</option>
              </select>
            </div>

            <div className="flex flex-wrap gap-2 pt-1">
              <button
                type="submit"
                className="px-4 py-2 text-xs font-medium bg-teal-500 text-slate-950 rounded-lg hover:bg-teal-400 transition-colors flex items-center gap-1.5 cursor-pointer"
              >
                <Play className="w-3.5 h-3.5" aria-hidden="true" />
                <span>Evaluate Policy Decision</span>
              </button>

              <button
                type="button"
                onClick={() => {
                  setEvalCategory('exploit_payload');
                  setEvalHost('unapproved.external.org');
                }}
                className="px-3 py-2 text-xs font-medium bg-slate-800 text-slate-300 border border-slate-700 rounded-lg hover:bg-slate-700 transition-colors cursor-pointer"
              >
                Load Prohibited Exploit Preset
              </button>
            </div>
          </form>

          {evalResult && (
            <div
              data-testid="policy-eval-result"
              className={`p-4 rounded-lg border text-xs space-y-1.5 ${
                evalResult.allowed
                  ? 'bg-teal-950/40 border-teal-800 text-teal-200'
                  : 'bg-rose-950/40 border-rose-800 text-rose-200'
              }`}
            >
              <div className="font-mono font-semibold flex items-center gap-2">
                {evalResult.allowed ? (
                  <CheckCircle2 className="w-4 h-4 text-teal-400" aria-hidden="true" />
                ) : (
                  <AlertTriangle className="w-4 h-4 text-rose-400" aria-hidden="true" />
                )}
                <span>
                  Decision: {evalResult.allowed ? 'ALLOWED' : 'DENIED'} · Code: {evalResult.code}
                  {evalResult.requiresHumanApproval ? ' (Requires Human Approval)' : ''}
                </span>
              </div>
              <p className="text-slate-200 leading-relaxed">{evalResult.reason}</p>
            </div>
          )}
        </div>
      </section>
    </div>
  );
};
