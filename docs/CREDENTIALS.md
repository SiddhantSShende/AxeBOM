# Credentials — every key AxeBOM can use, and how to get it free

Nothing here costs money. Every integration below either has a genuinely free
tier or is free outright.

**You do not need any of these to run AxeBOM.** The stack comes up, scans
local source, and produces SBOM, CBOM, QBOM, AIBOM and HBOM output with no
credentials at all. Each key unlocks one specific capability, and a key you do
not supply produces a **stated gap** — the engine reports `unavailable` with a
reason that appears in the report's Engine Coverage section.

That distinction is the whole point. A missing key never silently narrows a
scan. An SBOM that quietly omits an ecosystem is worse than no SBOM, because it
converts an unknown into a false negative the reader trusts.

---

## At a glance

| Key | Cost | Unlocks | Without it |
|---|---|---|---|
| `NVD_API_KEY` | Free | `dependency-check` (NVD/CPE matching) | Engine reports `unavailable`; the other four vulnerability engines still run |
| `GITHUB_CLIENT_ID` / `SECRET` | Free | GitHub SSO login, private repo import | Local accounts and manual/upload projects only |
| `MOUSER_API_KEY` | Free with account | HBOM part enrichment | HBOM import works; parts are not enriched |
| `NEXAR_TOKEN` | Free tier | HBOM part enrichment | As above |
| `HUGGINGFACE_TOKEN` | Free | `aibom-generator` model metadata | Code-level AI discovery still works; model cards are not fetched |

Put them in `.env` at the repository root. That file is gitignored;
`.env.example` is the committed template. **Never commit a real key** — and
note that `.env` is excluded from every Docker build context by
`.dockerignore`, so a key cannot be baked into an image layer by accident.

After editing `.env`:

```bash
task dev            # recreates the containers with the new environment
```

---

## 1. NVD API key — unlocks `dependency-check`

**Free. No payment details. Issued by NIST.**

### Get it

1. Go to <https://nvd.nist.gov/developers/request-an-api-key>
2. Fill in the form (name, email, organisation — a personal name is fine).
3. Accept the terms of use.
4. The key arrives by email, usually within minutes. It is a UUID.

### Install it

```bash
# .env
NVD_API_KEY=xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
```

### Then provision the database

Dependency-Check cannot run until its NVD data is downloaded and stamped:

```bash
task osint:dbsync -- nvd
```

> ⚠ **This takes 30–60 minutes on a cold start** and downloads several GB. It
> is a one-off; afterwards the data is reused and only refreshed when you ask.

### Why the key is required rather than optional

Without a key the NVD throttles requests hard enough that the first sync can run
for many hours. That presents as a hang, not an error. The provisioner therefore
**refuses to start** without one rather than appearing to work — you get a clear
message naming the missing variable instead of a process that looks alive and
never finishes.

### Why the key never reaches a scan

The key is used **only** during provisioning, which is an operator action that
mounts no user repository. Scans run with `--noupdate` against the already
downloaded data, inside a sandbox with `--network=none`. Putting a credential
into an engine container is forbidden outright — see ADR-0008 — and the sandbox
escape suite asserts that no credential-shaped variable reaches one.

---

## 2. GitHub OAuth app — unlocks SSO and repository import

**Free for any GitHub account.**

### Get it

1. Go to <https://github.com/settings/developers> → **OAuth Apps** → **New OAuth App**.
   (For an organisation: *Settings → Developer settings → OAuth Apps*.)
2. Fill in:

   | Field | Value for local development |
   |---|---|
   | Application name | `AxeBOM (local)` |
   | Homepage URL | `http://localhost:5173` |
   | Authorization callback URL | `http://localhost:5173/api/v1/auth/github/` |

   ⚠ **The path must start with `/api/v1`, not `/auth/github/...` directly.**
   Only nginx's (and the Vite dev proxy's) `/api/` prefix location routes to
   the gateway — a bare `/auth/github/...` path has no proxy rule anywhere
   and falls through to the SPA's own router, which 404s it before the
   backend ever sees the OAuth code. This callback URL is also the PARENT of
   both real callback paths (`/api/v1/auth/github/callback` for sign-in,
   `/api/v1/auth/github/connect/callback` for the project wizard's repo
   picker) — one OAuth App backs both flows, and a classic GitHub OAuth App
   registers exactly one "Authorization callback URL". After creating the
   app, find the **wildcard matching** checkbox on its settings page
   (enabled by default for apps created from 2026-08-03 onward) and make
   sure it's on — that's what lets a subdirectory of the registered URL,
   like the two real callback paths above, count as a match. With wildcard
   matching off, GitHub requires an exact match and only one of the two
   flows can ever work.

3. **Register application**, then **Generate a new client secret**. Copy it
   immediately — GitHub shows it once.

### Install it

```bash
# .env
GITHUB_CLIENT_ID=Iv1.xxxxxxxxxxxxxxxx
GITHUB_CLIENT_SECRET=xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
GITHUB_REDIRECT_URL=http://localhost:5173/api/v1/auth/github/callback
GITHUB_CONNECT_REDIRECT_URL=http://localhost:5173/api/v1/auth/github/connect/callback
```

> Both callback URLs must be subdirectories of whatever you registered above
> (see the wildcard-matching note in step 2) or GitHub's own
> `redirect_uri_mismatch` error page appears instead of anything AxeBOM logs.
>
> Note the variables are `GITHUB_REDIRECT_URL` (sign-in) and
> `GITHUB_CONNECT_REDIRECT_URL` (the project wizard's "Connect GitHub" repo
> picker, scope `repo` — a separate consent from sign-in, deliberately never
> requested by the sign-in flow). Earlier templates called the first one
> `GITHUB_CALLBACK_URL`, which no code ever read.

### Scopes

Requested at authorization time, not configured here:

- `read:user`, `user:email` — identity
- `repo` — **only** if you need private repositories. Public repositories need
  no repository scope at all. Ask for it only when you actually need it.

### Where the token goes

Into Vault, never into Postgres. The database stores a **path** to the secret,
derived server-side from (tenant, kind, id) and re-derived on every read — so a
row that has been tampered with is refused before Vault is contacted. Only the
fetcher can use it; no component that runs a scanner holds any credential.

---

## 3. Mouser API key — HBOM part enrichment

**Free with a Mouser account.**

### Get it

1. Create an account at <https://www.mouser.com/>
2. Go to <https://www.mouser.com/api-hub/> and request a **Search API** key.
3. Approval is typically immediate or same-day. The key is a UUID.

### Install it

```bash
# .env
PART_DATA_PROVIDER=mouser
MOUSER_API_KEY=xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
```

---

## 4. Nexar token — HBOM part enrichment (Octopart's successor)

**Free tier available.** Nexar caps free queries per month; check the current
limit when you sign up, as it changes.

### Get it

1. Sign up at <https://nexar.com/> and open the developer portal at
   <https://portal.nexar.com/>
2. Create an **Application**. Note the Client ID and Client Secret.
3. Exchange them for an access token:

```bash
curl -s -X POST https://identity.nexar.com/connect/token \
  -d grant_type=client_credentials \
  -d client_id=YOUR_CLIENT_ID \
  -d client_secret=YOUR_CLIENT_SECRET \
  -d scope=supply.domain
```

### Install it

```bash
# .env
PART_DATA_PROVIDER=nexar
NEXAR_TOKEN=eyJhbGciOi...
```

> The code reads a single **`NEXAR_TOKEN`** — the access token from the call
> above, not the client id and secret. Earlier templates listed
> `NEXAR_CLIENT_ID` and `NEXAR_CLIENT_SECRET`, which nothing read.
>
> Access tokens expire. For anything beyond experimentation, refresh it on a
> schedule rather than pasting a token that will silently stop working.

### Octopart

Octopart is now part of Nexar and its standalone API is **paid**. It sits in the
`rejected:` section of `OSINT/tools.manifest.yaml` with that reason recorded, and
is not used.

---

## 5. Hugging Face token — AIBOM model metadata

**Free.** Only needed for `aibom-generator`, which fetches model cards. Public
models can be read anonymously, but an unauthenticated client is rate-limited
aggressively enough to fail on a repository referencing many models.

### Get it

1. Sign in at <https://huggingface.co/>
2. Go to <https://huggingface.co/settings/tokens> → **New token**.
3. Choose type **Read**. A write token is never needed and should not be used.

### Install it

```bash
# .env
HUGGINGFACE_TOKEN=hf_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
```

---

## What stays unavailable no matter what you pay

Being explicit, because "we could integrate it if you bought X" is a different
statement from "this does not exist":

- **There is no open-source HBOM scanner.** HBOM is a structured CSV/form import
  plus a data model. The providers above enrich parts you have already declared;
  none of them discovers hardware. No key changes this.
- **There is no quantum-hardware scanner.** QBOM is derived from CBOM crypto
  discovery with quantum-vulnerability rules applied, plus device metadata
  captured by form.
- **`sonar-cryptography`** is a SonarQube *plugin*, not a CLI, so it needs a
  SonarQube server (~4 GB). It is deferred past MVP; `cbomkit-theia` covers CBOM
  discovery without it. Free, but heavy.
- **Dependency-Track** is an optional *export target*, not a scanner, and needs
  ~6 GB. Free, and in the `heavy` compose profile if you want it.

---

## Checking what a missing key actually costs you

```bash
task osint:dbstatus     # which vulnerability databases are provisioned
task osint:verify       # which engines resolve, and why the others do not
```

Every generated report carries an **Engine Coverage** section listing each
requested engine, its terminal status, the ecosystems it covered, and any
ecosystem detected with no available engine. That section is mandatory and is
the honest answer to "what did this scan not see".
