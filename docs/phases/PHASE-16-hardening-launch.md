# Phase 16 — Profile validation, hardening, launch

**Estimated: 3 weeks** · Depends on all prior phases.

## Read first

1. `docs/STATE.md` — **especially the gaps and debt table**
2. `docs/05-SECURITY-MODEL.md` — in full
3. `docs/08-OPERATIONS.md` §5 (observability), §7 (production)
4. `docs/06-COMPLIANCE-PROFILES.md` §8, §10

## Goal

Production readiness: the compliance profile validated end to end, security reviewed by someone external, performance measured under real load, and a deployment that survives a node loss.

This is **not** where security gets added — every control landed in the phase that introduced its risk. This is where it gets *verified* by an adversary.

## Preconditions

All five BOM types produce reports. Every prior phase's exit criteria pass.

## Deliverables

All created by this phase — none are preconditions.

```
deploy/k8s/                Helm charts, incl. an isolated engine node pool
.github/workflows/         load test, security scan
docs/RUNBOOKS.md           NEW — expanded from 08-OPERATIONS §6
docs/COMPLIANCE-REPORT.md  the coverage evidence pack
services/auth/oidc/        SAML/OIDC enterprise SSO
cmd/axebom/audit.go     audit-log export
perf/                      k6 or vegeta scenarios
```

## Work

### 16.1 Compliance validation

Re-verify every profile entry against the source PDF page it cites — a transcription check, not a re-read. Confirm `all_entries_verified: true` still holds and that no `assumed` entry has crept in.

Then produce the evidence pack: for each BOM type, a report demonstrating every minimum element present or explicitly `not-provided`, with both coverage numbers and the Engine Coverage table. **This is the artifact a customer's auditor will actually ask for**, and producing it is a good test of whether the product does what it claims.

Confirm the guardrails still hold: no hardcoded field count anywhere (grep for the literals), the word "compliant" absent from generated output, and the weights-are-our-judgement footnote present.

### 16.2 Security review

External penetration test focused on the two things that would end the company: **the sandbox boundary** and **tenancy isolation**. Give the testers the threat model and the escape suite — tell them what you already defend against so they spend their time on what you have not thought of.

Re-run the full escape suite. Verify RLS on every table including any added since Phase 1. Re-assert the app role is non-superuser and non-`BYPASSRLS`. Rotate every secret and confirm rotation works without downtime. Review dependency licenses again; confirm zero GPL.

### 16.3 Performance

Load-test the paths that will break first:

- A 50k-component monorepo, end to end.
- 100 concurrent scans.
- The dependencies endpoint at 200k findings — this is where `OFFSET` would have killed you, so confirm keyset pagination holds.
- A Complete-BOM PDF render at the page cap.
- Alias-graph recomputation at scale — incremental, never full.

Fix what the numbers show, not what you assume. Record the baselines in `docs/RUNBOOKS.md` so a future regression is visible as a regression rather than as "it feels slow."

### 16.4 Enterprise

SAML/OIDC SSO with SCIM provisioning where the identity provider supports it. Audit-log export in a machine-readable format (CERT-In §5.3.6 asks for review; export is what makes review practical). API keys with scopes for CI integration.

### 16.5 Deployment

Helm charts. Services scale horizontally and are stateless.

**Engine workers get a dedicated node pool** — they execute untrusted code and must not share a kernel with anything holding credentials. gVisor or Firecracker where available; at minimum a separate pool with strict network policy and **no service-account token mounted**.

Postgres PITR with a 30-day window. Object storage versioned with lifecycle rules — but **raw scan artifacts are never expired**; they are the evidence that makes reports defensible and re-normalization possible.

Then **run a restore drill**. An untested backup is not a backup, and the time to discover that is not during an incident.

### 16.6 Observability

Every metric, alert and dashboard from `08-OPERATIONS.md §5`. The three that matter most in production:

- **`scan_engine_status_total{status="unavailable"}`** — silent coverage loss is the failure mode that hurts a compliance product, because nothing appears broken.
- **`alias_cluster_size`** — a rising tail is early warning of over-merge, which under-reports vulnerabilities.
- **any cross-tenant access attempt** — should be exactly zero; one occurrence is an incident, not a metric.

### 16.7 Documentation

User-facing docs; API reference from the OpenAPI spec; the error-code reference the taxonomy's `docs` links point at; deployment guide; the compliance evidence pack.

## Test requirements

- Full E2E across all five BOM types.
- Escape suite green.
- `TestRLSCoverage` and `TestAuthzMatrix` green over the final schema and route set.
- SPDX and CycloneDX conformance against official validators.
- Load tests meet the recorded targets.
- Restore drill succeeds from a real backup.
- Chaos: kill a worker, kill the scheduler leader, kill a database replica — the system degrades visibly and recovers without data loss.
- Pen-test findings closed or explicitly accepted with a documented rationale.

## Exit criteria

```
task verify
task test:golden
npx playwright test
go test ./... -run 'TestRLSCoverage|TestAuthzMatrix|TestEscape' -v
task profile:lint
helm template deploy/k8s | kubectl apply --dry-run=server -f -
```

Plus: pen-test report with findings closed, load-test baselines recorded, restore drill documented, and the compliance evidence pack generated for all five BOM types.

## Before you finish

Update `docs/STATE.md`: **mark GA.** Record load-test baselines, pen-test outcome, accepted risks with rationale, and what is deliberately deferred to post-launch.

Then write the honest list — what AxeBOM does not do, and what a customer should not expect it to do. That list is a feature. The alternative is discovering it together during an incident.
