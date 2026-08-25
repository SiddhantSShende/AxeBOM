package config

import (
	"fmt"
	"sort"
	"strings"
	"time"
)

// Env is the deployment environment.
type Env string

const (
	EnvDevelopment Env = "development"
	EnvStaging     Env = "staging"
	EnvProduction  Env = "production"
)

func (e Env) IsProduction() bool { return e == EnvProduction }

// Service is the configuration every AxeBOM service shares.
type Service struct {
	Name        string
	Env         Env
	LogLevel    string
	LogFormat   string
	HTTPPort    int
	MetricsPort int

	ShutdownGrace time.Duration
	ReadTimeout   time.Duration
	WriteTimeout  time.Duration
	IdleTimeout   time.Duration

	Postgres Postgres
	NATS     NATS
	Redis    Redis
	S3       S3
	OTel     OTel
	Auth     Auth
	OIDC     OIDC
	Vault    Vault
	Report   Report
	SMTP     SMTP
	Services Services
}

// Services are the base URLs of sibling services.
//
// ⚠ CONFIGURED, NEVER DISCOVERED FROM A REQUEST. A base URL taken from a header
// or a database row turns any cross-service call into an SSRF: the campaign
// service holds a service token, and pointing it at an attacker's host hands
// that token over.
type Services struct {
	Auth             string
	Project          string
	ScanOrchestrator string
	Report           string
	Campaign         string
	Comment          string
	Notification     string
}

// Postgres carries TWO identities, and the separation is load-bearing.
//
//	User / Password      the OWNER. Runs migrations. Creates objects.
//	AppRole / AppPassword the APPLICATION. Runs every request.
//
// The application role must not be superuser and must not have BYPASSRLS.
// Row-Level Security is the only tenancy boundary (ADR-0006), and either
// privilege disables every policy silently — the queries keep working and the
// rows keep coming back. platform/db asserts this on every boot, because a
// later GRANT can reintroduce it long after the migration that got it right.
type Postgres struct {
	Host     string
	Port     int
	Database string

	// Owner — migrations only.
	User     string
	Password Secret

	// Application — everything else.
	AppRole     string
	AppPassword Secret

	SSLMode  string
	MaxConns int
}

// AdminDSN connects as the owner. Migrations only.
//
// Never log the result — it contains a password. Use Redacted().
func (p Postgres) AdminDSN() string {
	return fmt.Sprintf("postgres://%s:%s@%s:%d/%s?sslmode=%s",
		p.User, p.Password.Reveal(), p.Host, p.Port, p.Database, p.SSLMode)
}

// AppDSN connects as the non-superuser application role. Everything at runtime
// uses this, so RLS is always in force.
func (p Postgres) AppDSN() string {
	return fmt.Sprintf("postgres://%s:%s@%s:%d/%s?sslmode=%s",
		p.AppRole, p.AppPassword.Reveal(), p.Host, p.Port, p.Database, p.SSLMode)
}

// Redacted is the safe form for logs and error messages.
func (p Postgres) Redacted() string {
	return fmt.Sprintf("postgres://%s:[REDACTED]@%s:%d/%s?sslmode=%s",
		p.AppRole, p.Host, p.Port, p.Database, p.SSLMode)
}

type NATS struct {
	URL           string
	StreamJobs    string
	StreamEvents  string
	StreamResults string
}

type Redis struct {
	URL Secret // may embed a password
}

type S3 struct {
	Endpoint       string
	Region         string
	Bucket         string
	AccessKey      Secret
	SecretKey      Secret
	ForcePathStyle bool
}

type OTel struct {
	Endpoint  string
	Namespace string
	Enabled   bool
}

// Vault configures the credential store.
//
// Credentials for third-party systems (repository tokens, webhook secrets)
// live here and NEVER in Postgres — a database row holds only the path. See
// libs/go-shared/vault.
type Vault struct {
	Address string
	Token   Secret
	// Mount is the KV v2 mount point.
	Mount string
}

// Report configures report signing.
//
// ⚠ THE SIGNING KEY LIVES IN VAULT TRANSIT AND ONLY ITS NAME IS HERE. The
// private key never reaches this process, so a memory disclosure in the
// renderer leaks reports rather than the ability to forge every future one.
type Report struct {
	// SigningKey is the Vault Transit key NAME, not key material. Empty means
	// reports are stored unsigned — degraded loudly at startup, never silently,
	// because an unsigned report that looks signed is worse than either.
	SigningKey string
	// TransitMount is the transit mount point. Separate from Vault.Mount, which
	// is the KV v2 mount: sharing one field would send signing requests to
	// `secret/sign/...`, which 404s in a way that reads like a missing key.
	TransitMount string
}

// SMTP configures the notification service's email sender.
//
// ⚠ USERNAME/PASSWORD ARE OFTEN BOTH EMPTY, AND THAT IS A VALID CONFIGURATION.
// Mailpit (this repo's dev SMTP target) accepts unauthenticated mail; a real
// provider needs both. net/smtp.SendMail skips PLAIN auth entirely when no
// credentials are given, rather than sending an empty-password AUTH the
// server would reject.
type SMTP struct {
	Host     string
	Port     int
	Username string
	Password Secret
	// From is the envelope and header From address. Mirrors ZITADEL_SMTP_FROM's
	// own convention (a fixed, non-secret sender identity for this platform,
	// distinct from a customer's own address).
	From string
}

// Auth configures identity. Only the auth service consumes all of it; the
// gateway needs the JWT fields to verify tokens it forwards.
type Auth struct {
	// JWTSigningKey is the HMAC key. Shared by auth (signs) and gateway
	// (verifies), which is why it lives in the common config rather than one
	// service's. Minimum length is enforced by auth.NewIssuer, not here — a
	// config package should not own a cryptographic rule.
	JWTSigningKey Secret
	JWTIssuer     string
	AccessTTL     time.Duration
	RefreshTTL    time.Duration

	GitHubClientID     string
	GitHubClientSecret Secret
	GitHubRedirectURL  string

	// FrontendURL is where the OAuth callback lands the browser. Empty means
	// the callback answers with JSON instead of redirecting, which is what
	// integration tests want.
	FrontendURL string
}

// OIDC configures the ZITADEL identity tier.
//
// ⚠ Issuer AND InternalURL ARE TWO DIFFERENT ADDRESSES FOR ONE SERVER, and
// keeping them apart is the whole reason this struct exists.
//
// Issuer is the PUBLIC origin — what the browser calls, and therefore what
// ZITADEL bakes into the `iss` claim of every token it mints. Services must
// validate against exactly that string.
//
// InternalURL is how a service REACHES ZITADEL from inside the network, where
// the public origin does not resolve. It is used to fetch the key set, and by
// the service-token minter, which overrides the Host header so the token it
// gets back still carries the public issuer.
//
// Collapsing the two means either that services cannot reach the IdP, or that
// they validate `iss` against an address only they can see — and then every
// token the browser presents is rejected.
type OIDC struct {
	Issuer      string
	InternalURL string

	// JWKSURL is where signing keys are fetched. Defaults to InternalURL +
	// /oauth/v2/keys, which is the in-network path.
	JWKSURL string

	// ProjectID is both the expected audience and the key of the roles claim.
	// No default: it is produced by `axebom iam bootstrap` and differs per
	// instance. A wrong value fails at startup with a message naming this
	// variable, which is better than a fleet that answers 401 to everything.
	ProjectID string

	// SPAClientID is the browser application's OIDC client id.
	//
	// ⚠ IT IS PUBLIC, AND THAT IS NOT A COMPROMISE. The SPA is a PKCE client
	// with auth method "none" — it holds no secret, because a secret shipped
	// in a JavaScript bundle is readable by everyone who loads the page and
	// merely looks like security. Proof of possession comes from the code
	// verifier, which is generated per login and never leaves the tab.
	//
	// The gateway publishes this at GET /v1/auth/config so one container image
	// serves every environment; baking it into the bundle would mean a rebuild
	// per deployment and a login that silently breaks when the two drift.
	SPAClientID string

	// ServiceKeyPath is the machine-user JSON key used by the components that
	// call other services. Only campaign and fetcher need one; every other
	// service verifies tokens and mints none.
	ServiceKeyPath string

	// ProvisioningKeyPath is the ZITADEL bootstrap machine-user key
	// (services/gateway/internal/signup) used to create a brand-new
	// organisation and its Owner for self-service signup.
	//
	// ⚠ EMPTY BY DEFAULT, DELIBERATELY. This is the SAME credential
	// `axebom iam bootstrap` uses — creating a ZITADEL organisation is an
	// instance-level operation and there is no narrower permission for it —
	// so a service that holds it can provision ANY organisation. Leaving the
	// default empty means a deployment that never sets ZITADEL_BOOTSTRAP_KEY
	// or mounts the key gets the feature turned off rather than a gateway
	// silently holding a credential nobody meant to give it.
	ProvisioningKeyPath string

	// IdentityTTL bounds how long a resolved principal is cached in-process.
	// It is a SECOND control after the token lifetime, not a substitute:
	// setting it longer than the access-token TTL would let a role outlive the
	// token that carried it.
	IdentityTTL time.Duration
}

// LoadService reads the shared configuration for a named service.
//
// HTTP and metrics ports default per service so `task dev` brings up all
// thirteen without a port collision and without thirteen env vars.
func LoadService(name string) (*Service, error) {
	l := New("")

	env := Env(l.Enum("AXEBOM_ENV",
		[]string{"development", "staging", "production"}, "development"))

	svc := &Service{
		Name:        name,
		Env:         env,
		LogLevel:    l.Enum("LOG_LEVEL", []string{"debug", "info", "warn", "error"}, "info"),
		LogFormat:   l.Enum("LOG_FORMAT", []string{"json", "text"}, "json"),
		HTTPPort:    l.Int("HTTP_PORT", defaultPort(name)),
		MetricsPort: l.Int("METRICS_PORT", defaultMetricsPort(name)),

		ShutdownGrace: l.Duration("SHUTDOWN_GRACE", 20*time.Second),
		ReadTimeout:   l.Duration("HTTP_READ_TIMEOUT", 15*time.Second),
		WriteTimeout:  l.Duration("HTTP_WRITE_TIMEOUT", 30*time.Second),
		IdleTimeout:   l.Duration("HTTP_IDLE_TIMEOUT", 120*time.Second),

		Postgres: Postgres{
			Host:     l.StringOr("POSTGRES_HOST", "localhost"),
			Port:     l.Int("POSTGRES_PORT", 55432),
			Database: l.StringOr("POSTGRES_DB", "axebom"),
			User:     l.StringOr("POSTGRES_USER", "axebom"),
			AppRole:  l.StringOr("POSTGRES_APP_ROLE", "axebom_app"),
			SSLMode:  l.StringOr("POSTGRES_SSLMODE", sslDefault(env)),
			MaxConns: l.Int("POSTGRES_MAX_CONNS", 20),
		},
		NATS: NATS{
			URL:           l.StringOr("NATS_URL", "nats://localhost:54222"),
			StreamJobs:    l.StringOr("NATS_STREAM_JOBS", "SCAN_JOBS"),
			StreamEvents:  l.StringOr("NATS_STREAM_EVENTS", "SCAN_EVENTS"),
			StreamResults: l.StringOr("NATS_STREAM_RESULTS", "SCAN_RESULTS"),
		},
		Redis: Redis{
			URL: l.SecretOr("REDIS_URL", "redis://localhost:56379/0"),
		},
		S3: S3{
			Endpoint:       l.StringOr("S3_ENDPOINT", "http://localhost:59000"),
			Region:         l.StringOr("S3_REGION", "us-east-1"),
			Bucket:         l.StringOr("S3_BUCKET", "axebom"),
			ForcePathStyle: l.Bool("S3_FORCE_PATH_STYLE", true),
		},
		OTel: OTel{
			Endpoint:  l.StringOr("OTEL_EXPORTER_OTLP_ENDPOINT", ""),
			Namespace: l.StringOr("OTEL_SERVICE_NAMESPACE", "axebom"),
		},
		Vault: Vault{
			Address: l.StringOr("VAULT_ADDR", "http://localhost:58200"),
			Mount:   l.StringOr("VAULT_MOUNT", "secret"),
		},
		Services: Services{
			// The defaults mirror servicePorts below. A URL that does not match
			// a listening service fails at the first cross-service call, which
			// for a scheduler is at 02:30 rather than at startup — so a test
			// asserts the two stay in step.
			Auth:             l.StringOr("AUTH_URL", localURL("auth")),
			Project:          l.StringOr("PROJECT_URL", localURL("project")),
			ScanOrchestrator: l.StringOr("SCAN_ORCHESTRATOR_URL", localURL("scan-orchestrator")),
			Report:           l.StringOr("REPORT_URL", localURL("report")),
			Campaign:         l.StringOr("CAMPAIGN_URL", localURL("campaign")),
			Comment:          l.StringOr("COMMENT_URL", localURL("comment")),
			Notification:     l.StringOr("NOTIFICATION_URL", localURL("notification")),
		},
		Report: Report{
			// No default. A default key NAME would have every deployment sign
			// with whatever happens to exist at that path — including nothing,
			// which fails at render time rather than at startup.
			SigningKey:   l.StringOr("REPORT_SIGNING_KEY", ""),
			TransitMount: l.StringOr("VAULT_TRANSIT_MOUNT", "transit"),
		},
		SMTP: SMTP{
			// Host-perspective default (Mailpit's PUBLISHED port), matching
			// every other default in this file — docker-compose.app.yml
			// overrides both to the internal mailpit:1025 for containerized
			// services, the same relationship POSTGRES_HOST/PORT already has.
			Host:     l.StringOr("SMTP_HOST", "localhost"),
			Port:     l.Int("SMTP_PORT", 51025),
			Username: l.StringOr("SMTP_USERNAME", ""),
			Password: l.SecretOr("SMTP_PASSWORD", ""),
			From:     l.StringOr("SMTP_FROM", "noreply@axebom.test"),
		},
		Auth: Auth{
			JWTIssuer: l.StringOr("JWT_ISSUER", "axebom"),
			// 15 minutes: long enough that clients are not refreshing
			// constantly, short enough that a stolen access token is stale
			// before it is useful. Revocation is by refresh family, so the
			// access TTL is the real exposure window.
			AccessTTL:  l.Duration("JWT_ACCESS_TTL", 15*time.Minute),
			RefreshTTL: l.Duration("JWT_REFRESH_TTL", 30*24*time.Hour),

			GitHubClientID:    l.StringOr("GITHUB_CLIENT_ID", ""),
			GitHubRedirectURL: l.StringOr("GITHUB_REDIRECT_URL", ""),
			FrontendURL:       l.StringOr("FRONTEND_URL", ""),
		},
		OIDC: OIDC{
			// The public origin, and the default matches the reverse proxy in
			// deploy/docker/nginx.conf. Change one without the other and every
			// token fails its issuer check.
			Issuer: l.StringOr("ZITADEL_ISSUER", "http://localhost:5173"),
			// The published API port, for a service running on the host.
			// Compose overrides this with http://zitadel-api:8080.
			InternalURL: l.StringOr("ZITADEL_INTERNAL_URL", "http://localhost:58080"),
			JWKSURL:     l.StringOr("ZITADEL_JWKS_URL", ""),
			ProjectID:   l.StringOr("ZITADEL_PROJECT_ID", ""),
			SPAClientID: l.StringOr("ZITADEL_SPA_CLIENT_ID", ""),
			// Derived from the service NAME so it matches what
			// `axebom iam bootstrap` writes (iam.ensureServiceKey) without
			// a second list to keep in step. Only campaign and fetcher read
			// it; for every other service the file is simply never opened.
			ServiceKeyPath: l.StringOr("ZITADEL_SERVICE_KEY_PATH",
				fmt.Sprintf("deploy/compose/.data/zitadel-bootstrap/service-keys/svc-%s.json", name)),
			// No default — see the field comment. Only the gateway's compose
			// entry sets this.
			ProvisioningKeyPath: l.StringOr("ZITADEL_BOOTSTRAP_KEY", ""),
			IdentityTTL:         l.Duration("ZITADEL_IDENTITY_CACHE_TTL", 60*time.Second),
		},
	}
	svc.OTel.Enabled = svc.OTel.Endpoint != ""

	// Keys are fetched over the INTERNAL address, and the issuer is still
	// validated against the public one. Deriving the default here rather than
	// in oidcauth keeps the split in the one place that knows both addresses.
	if svc.OIDC.JWKSURL == "" {
		svc.OIDC.JWKSURL = strings.TrimRight(svc.OIDC.InternalURL, "/") + "/oauth/v2/keys"
	}

	// Secrets are required in production and defaulted in development, so a
	// fresh clone runs with `task dev` but a production deploy cannot start
	// with a default credential.
	if env.IsProduction() {
		svc.Postgres.Password = l.Secret("POSTGRES_PASSWORD")
		svc.Postgres.AppPassword = l.Secret("POSTGRES_APP_PASSWORD")
		svc.S3.AccessKey = l.Secret("S3_ACCESS_KEY")
		svc.S3.SecretKey = l.Secret("S3_SECRET_KEY")
		// A default signing key in production means anyone who has read this
		// repository can mint a token for any tenant. There is no fallback.
		svc.Auth.JWTSigningKey = l.Secret("JWT_SIGNING_KEY")
		// Same reasoning: a default Vault token in production is a master key
		// to every stored credential.
		svc.Vault.Token = l.Secret("VAULT_TOKEN")
	} else {
		svc.Postgres.Password = l.SecretOr("POSTGRES_PASSWORD", "axebom")
		svc.Postgres.AppPassword = l.SecretOr("POSTGRES_APP_PASSWORD", "axebom_app")
		svc.S3.AccessKey = l.SecretOr("S3_ACCESS_KEY", "minioadmin")
		svc.S3.SecretKey = l.SecretOr("S3_SECRET_KEY", "minioadmin")
		// The name states what it is, so a value found in a running process
		// cannot be mistaken for a real key.
		svc.Auth.JWTSigningKey = l.SecretOr("JWT_SIGNING_KEY",
			"dev-only-insecure-signing-key-do-not-use-in-production")
		// Matches VAULT_DEV_ROOT_TOKEN_ID in deploy/compose/docker-compose.yml.
		svc.Vault.Token = l.SecretOr("VAULT_TOKEN", "dev-root-token")
	}
	svc.Auth.GitHubClientSecret = l.SecretOr("GITHUB_CLIENT_SECRET", "")

	if err := l.Err(); err != nil {
		return nil, err
	}
	return svc, nil
}

func sslDefault(env Env) string {
	if env.IsProduction() {
		return "require"
	}
	return "disable"
}

// defaultPort assigns each service a stable port so the local stack has no
// collisions and no per-service env vars.
//
// Infrastructure defaults (Postgres 55432, NATS 54222, Redis 56379, MinIO
// 59000) are deliberately NOT the upstream defaults: this development machine
// already runs other projects on 5432, 4222, 6379 and 9000. Colliding means
// silently connecting to somebody else's database and getting an auth failure
// that looks like a credential bug rather than a port clash.
// localURL is the development address of a sibling service, derived from the
// same port map its own process reads. Two hand-maintained lists of ports would
// drift, and the symptom would be a cross-service call to a closed port.
func localURL(name string) string {
	return fmt.Sprintf("http://localhost:%d", defaultPort(name))
}

func defaultPort(name string) int {
	if p, ok := servicePorts[name]; ok {
		return p
	}
	return 8080
}

// ServicePorts returns a copy of the service port registry.
//
// Exported so operator tooling (axebom health) probes the same table the
// services themselves bind, rather than a second list that would drift the
// first time a port changed.
func ServicePorts() map[string]int {
	out := make(map[string]int, len(servicePorts))
	for k, v := range servicePorts {
		out[k] = v
	}
	return out
}

var servicePorts = map[string]int{
	"gateway":           8080,
	"auth":              8091,
	"project":           8092,
	"scan-orchestrator": 8093,
	"report":            8094,
	"campaign":          8095,
	"comment":           8096,
	"notification":      8097,
	"fetcher":           8098,
}

// defaultMetricsPort gives each service its OWN metrics port.
//
// TWO defects were fixed here, both found by actually running two services at
// once rather than by reading the config:
//
//  1. Every service defaulted to a SHARED 9090. The HTTP ports above were
//     assigned per service precisely to avoid collisions, but the metrics
//     listener was left common, so the second service to start died with
//     "Only one usage of each socket address" — which reads as a mysterious
//     crash rather than a port clash, and would have taken down `task dev`.
//
//  2. The obvious fix, 9091/9092, collides with Docker Desktop's WSL relay on
//     this machine, which already listens on 9090-9092. That is the same
//     reason the infrastructure ports were moved into the 5xxxx range.
//
// So: HTTP port + 10000 (8091 -> 18091). The mapping is obvious in a process
// list, there is no second table to keep in sync, and the range is clear of
// both the common Prometheus convention and Docker's relays.
func defaultMetricsPort(name string) int {
	http, ok := servicePorts[name]
	if !ok {
		return 18080
	}
	return http + 10000
}

// KnownServices lists every Go service. Used by the generator and by preflight.
func KnownServices() []string {
	// DERIVED from servicePorts, not a second literal.
	//
	// It used to be its own hardcoded slice, which is precisely the drift
	// TestRegistryMatchesConfig exists to catch — and it caught it: adding the
	// fetcher to the port map left this list at eight, so the ninth service
	// would have fallen back to defaultPort's 8080 and collided with the
	// gateway. That presents as "the gateway is flaky", not as "two lists
	// disagree".
	out := make([]string, 0, len(servicePorts))
	for name := range servicePorts {
		out = append(out, name)
	}
	sort.Strings(out) // map order is randomised; callers deserve stability
	return out
}

// IsKnownService reports whether name is a registered service.
func IsKnownService(name string) bool {
	for _, s := range KnownServices() {
		if s == name {
			return true
		}
	}
	return false
}

// String renders the config for startup logging. Secrets are already redacted
// by their own String method; Postgres is rendered via Redacted for the DSN.
func (s *Service) String() string {
	var b strings.Builder
	fmt.Fprintf(&b, "service=%s env=%s log=%s/%s http=:%d metrics=:%d",
		s.Name, s.Env, s.LogLevel, s.LogFormat, s.HTTPPort, s.MetricsPort)
	fmt.Fprintf(&b, " postgres=%s nats=%s s3=%s/%s otel=%v",
		s.Postgres.Redacted(), s.NATS.URL, s.S3.Endpoint, s.S3.Bucket, s.OTel.Enabled)
	return b.String()
}
