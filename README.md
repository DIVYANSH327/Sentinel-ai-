# Sentinel AI — Authorized AI-Assisted Security Research Platform

Sentinel AI is a defense-in-depth security research control plane that pairs a React + TypeScript operator workspace with a Node.js policy and orchestration backend, server-side Gemini AI structured assessment planning, and an outbound HTTPS polling protocol for non-root Python Kali Linux agents.

## Core Security Invariants

1. **Explicit Authorization & Scope Policy Engine**:
   - Every job is validated against an active, non-expired `AuthorizedAsset` record (`verified = true`) and a matching `ScopePolicy` record (`active = true`, `expiresAt > now`).
   - Targets must match permitted hostnames or IPv4/CIDR ranges.
   - Rate limits (`rateLimitRpm`) must not exceed the policy's `maxRateLimitRpm`.
2. **MVP Safe Tooling Boundary**:
   - Only two execution categories are enabled in the MVP:
     - `passive_http_headers`: Non-intrusive inspection of HTTP response security headers (`Strict-Transport-Security`, `Content-Security-Policy`, `X-Content-Type-Options`, `X-Frame-Options`, `Referrer-Policy`, `Permissions-Policy`) against explicitly authorized targets.
     - `static_code_analysis`: Safe static AST/pattern analysis of user-supplied source code snippets without executing the code.
   - Prohibited categories (`arbitrary_shell`, `unrestricted_port_scan`, `exploit_payload`, `credential_attack`, `persistence_install`, `live_system_modification`) are unconditionally rejected by the Policy Engine and logged as security violations.
3. **Structured AI Planner (No Shell Commands)**:
   - Server-side Gemini API (`gemini-3.8-flash` via `@google/genai`) uses a strict `Type.OBJECT` JSON `responseSchema`.
   - Every AI-generated plan step is validated and scrubbed by the policy engine to ensure it references only allowed categories (`passive_http_headers` or `static_code_analysis`) and never emits raw shell commands.
4. **Outbound HTTPS Agent Polling Protocol**:
   - The Kali Linux Python agent runs as an ordinary non-root user (`UID >= 1000`) and initiates outbound HTTPS polls (`POST /api/v1/agent/poll`), claims non-expired jobs idempotently (`POST /api/v1/agent/jobs/:jobId/claim`), sends heartbeats (`POST /api/v1/agent/heartbeat`), and submits structured results (`POST /api/v1/agent/jobs/:jobId/result`).
5. **Human-in-the-Loop Approval**:
   - Intrusive assessment reviews and remediation proposals require explicit human operator sign-off before status transitions.

## API Routes

- `GET /api/v1/bootstrap` — Returns operator session, full dashboard state, and integration test status.
- `POST /api/v1/auth/login` / `POST /api/v1/auth/logout` — Operator session authentication.
- `POST /api/v1/assets` / `POST /api/v1/assets/:id/verify` — Manage and verify authorized assets.
- `POST /api/v1/policies` / `POST /api/v1/policies/evaluate` — Create scope policies and test candidate jobs against the Policy Engine.
- `POST /api/v1/plans/generate` — Server-side Gemini structured JSON assessment planner with automatic validation.
- `POST /api/v1/jobs` — Validates and queues a job (or executes built-in safe passive header / static code analysis).
- `POST /api/v1/jobs/:jobId/approve` — Human operator approval for gated jobs.
- `POST /api/v1/remediations/:id/approve` — Human operator approval for remediation plans.
- `POST /api/v1/agent/poll` — Outbound HTTPS polling endpoint for Python Kali agents.
- `POST /api/v1/agent/jobs/:jobId/claim` — Idempotent job claim with `idempotencyClaimKey` and expiry enforcement.
- `POST /api/v1/agent/jobs/:jobId/result` — Structured finding and telemetry submission from the Kali agent.
- `GET /api/setup-package/download` — Downloads the versioned non-root Kali agent & USB setup archive (`v1.4.2`).

## Running Tests

```bash
npx --yes tsx --test src/lib/policyEngine.test.ts
npx --yes tsx --test src/lib/sentinelEngine.test.ts
```
