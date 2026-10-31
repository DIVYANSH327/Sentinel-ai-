import crypto from 'node:crypto';
import { GoogleGenAI, Type } from '@google/genai';
import {
  AuthorizedAsset,
  ScopePolicy,
  AssessmentPlan,
  validateAndSanitizeAiPlan,
} from '../lib/policyEngine';

export async function generateStructuredAssessmentPlan(params: {
  objective: string;
  asset: AuthorizedAsset;
  policy: ScopePolicy;
  createdBy: string;
}): Promise<{
  plan: AssessmentPlan;
  geminiTestedLive: boolean;
  notice: string;
}> {
  const { objective, asset, policy, createdBy } = params;
  const apiKey = process.env.GEMINI_API_KEY;
  const hasRealKey = Boolean(apiKey && apiKey !== 'MY_GEMINI_API_KEY' && apiKey.trim().length > 10);

  if (hasRealKey) {
    try {
      const ai = new GoogleGenAI({
        apiKey,
        httpOptions: {
          headers: {
            'User-Agent': 'aistudio-build',
          },
        },
      });

      const prompt = [
        `You are the Sentinel AI Authorized Security Research Planner.`,
        `Generate a structured, non-destructive security assessment plan in JSON for:`,
        `- Asset Name: ${asset.name}`,
        `- Target Host: ${asset.targetHost} (${asset.ipOrCidr})`,
        `- Authorization Reference: ${asset.authorizationRef}`,
        `- Scope Policy: ${policy.name} (Max Rate Limit: ${policy.maxRateLimitRpm} req/min)`,
        `- Allowed Categories: ${policy.allowedCategories.join(', ')}`,
        `- Research Objective: ${objective}`,
        `CRITICAL SAFETY RULES:`,
        `1. Return ONLY structured JSON matching the schema.`,
        `2. NEVER include executable shell commands, exploit payloads, or CLI syntax.`,
        `3. Use only 'passive_http_headers', 'static_code_analysis', or 'intrusive_review_only' as step categories.`,
      ].join('\n');

      const response = await ai.models.generateContent({
        model: 'gemini-3.8-flash',
        contents: prompt,
        config: {
          responseMimeType: 'application/json',
          responseSchema: {
            type: Type.OBJECT,
            properties: {
              title: {
                type: Type.STRING,
                description: 'Concise title of the authorized assessment plan.',
              },
              safetyAttestation: {
                type: Type.STRING,
                description: 'Statement confirming zero shell commands and adherence to authorization scope.',
              },
              steps: {
                type: Type.ARRAY,
                items: {
                  type: Type.OBJECT,
                  properties: {
                    title: { type: Type.STRING },
                    category: {
                      type: Type.STRING,
                      description: 'Must be passive_http_headers, static_code_analysis, or intrusive_review_only',
                    },
                    rationale: { type: Type.STRING },
                  },
                  required: ['title', 'category', 'rationale'],
                },
              },
            },
            required: ['title', 'safetyAttestation', 'steps'],
          },
        },
      });

      const rawText = response.text || '{}';
      const parsed = JSON.parse(rawText) as {
        title?: string;
        safetyAttestation?: string;
        steps?: unknown[];
      };

      const steps = validateAndSanitizeAiPlan(Array.isArray(parsed.steps) ? parsed.steps : [], asset, policy);
      if (steps.length > 0) {
        const plan: AssessmentPlan = {
          id: `pln-${crypto.randomBytes(4).toString('hex')}`,
          title: String(parsed.title || `Authorized Assessment Plan: ${asset.name}`).slice(0, 120),
          objective,
          assetId: asset.id,
          policyId: policy.id,
          generatedBySource: 'gemini_api',
          modelName: 'gemini-3.8-flash',
          steps,
          safetyAttestation: String(
            parsed.safetyAttestation ||
              `Validated against ${asset.authorizationRef}. Contains zero executable shell commands.`
          ),
          createdBy,
          createdAt: new Date().toISOString(),
        };

        return {
          plan,
          geminiTestedLive: true,
          notice: 'Generated via live server-side Gemini API (gemini-3.8-flash) and validated against Scope Policy.',
        };
      }
    } catch (err) {
      const errMsg = err instanceof Error ? err.message : 'Unknown Gemini API error';
      return buildDeterministicPlan({
        objective,
        asset,
        policy,
        createdBy,
        notice: `Gemini API call did not complete (${errMsg}); generated validated deterministic plan instead.`,
      });
    }
  }

  return buildDeterministicPlan({
    objective,
    asset,
    policy,
    createdBy,
    notice:
      'GEMINI_API_KEY not configured in environment; generated validated structured JSON plan via deterministic policy engine (no shell commands).',
  });
}

function buildDeterministicPlan(params: {
  objective: string;
  asset: AuthorizedAsset;
  policy: ScopePolicy;
  createdBy: string;
  notice: string;
}): {
  plan: AssessmentPlan;
  geminiTestedLive: boolean;
  notice: string;
} {
  const { objective, asset, policy, createdBy, notice } = params;
  const rawSteps = [
    {
      title: `Passive HTTP Response Security-Header Baseline on ${asset.targetHost}`,
      category: 'passive_http_headers',
      rationale:
        'Inspect HSTS, Content-Security-Policy, X-Frame-Options, X-Content-Type-Options, and Referrer-Policy headers without sending intrusive traffic.',
    },
    {
      title: `Static Source Code Pattern & Sink Audit for ${asset.name}`,
      category: 'static_code_analysis',
      rationale:
        'Analyze user-supplied application source code for command execution sinks (CWE-78), hardcoded secrets (CWE-798), SQL concatenation (CWE-89), and TLS bypasses (CWE-295).',
    },
    {
      title: `Human-Gated Architecture & Boundary Verification (${asset.authorizationRef})`,
      category: 'intrusive_review_only',
      rationale:
        'Hold any deeper configuration validation behind explicit human security reviewer sign-off.',
    },
  ];

  const steps = validateAndSanitizeAiPlan(rawSteps, asset, policy);
  const plan: AssessmentPlan = {
    id: `pln-${crypto.randomBytes(4).toString('hex')}`,
    title: `Structured Assessment Plan: ${asset.name}`,
    objective,
    assetId: asset.id,
    policyId: policy.id,
    generatedBySource: 'deterministic_fallback',
    modelName: 'policy-structured-planner-v1',
    steps,
    safetyAttestation: `Verified against authorization ${asset.authorizationRef} (${policy.name}). Zero executable shell commands emitted.`,
    createdBy,
    createdAt: new Date().toISOString(),
  };

  return {
    plan,
    geminiTestedLive: false,
    notice,
  };
}
