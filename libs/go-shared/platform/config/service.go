package config

import (
	"fmt"
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

// Service is the configuration every EncoreBOM service shares.
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
}

type Postgres struct {
	Host     string
	Port     int
	Database string
	User     string
	Password Secret
	// AppRole must not be superuser and must not have BYPASSRLS. Row-Level
	// Security is the only tenancy boundary (ADR-0006); a superuser connection
	// silently disables every policy. Asserted at startup in Phase 1.
	AppRole  string
	SSLMode  string
	MaxConns int
}

// DSN builds a connection string. Never log the result — it contains the
// password. Use Redacted() for anything human-visible.
func (p Postgres) DSN() string {
	return fmt.Sprintf("postgres://%s:%s@%s:%d/%s?sslmode=%s",
		p.User, p.Password.Reveal(), p.Host, p.Port, p.Database, p.SSLMode)
}

// Redacted is the safe form for logs and error messages.
func (p Postgres) Redacted() string {
	return fmt.Sprintf("postgres://%s:[REDACTED]@%s:%d/%s?sslmode=%s",
		p.User, p.Host, p.Port, p.Database, p.SSLMode)
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

// LoadService reads the shared configuration for a named service.
//
// HTTP and metrics ports default per service so `task dev` brings up all
// thirteen without a port collision and without thirteen env vars.
func LoadService(name string) (*Service, error) {
	l := New("")

	env := Env(l.Enum("ENCOREBOM_ENV",
		[]string{"development", "staging", "production"}, "development"))

	svc := &Service{
		Name:        name,
		Env:         env,
		LogLevel:    l.Enum("LOG_LEVEL", []string{"debug", "info", "warn", "error"}, "info"),
		LogFormat:   l.Enum("LOG_FORMAT", []string{"json", "text"}, "json"),
		HTTPPort:    l.Int("HTTP_PORT", defaultPort(name)),
		MetricsPort: l.Int("METRICS_PORT", 9090),

		ShutdownGrace: l.Duration("SHUTDOWN_GRACE", 20*time.Second),
		ReadTimeout:   l.Duration("HTTP_READ_TIMEOUT", 15*time.Second),
		WriteTimeout:  l.Duration("HTTP_WRITE_TIMEOUT", 30*time.Second),
		IdleTimeout:   l.Duration("HTTP_IDLE_TIMEOUT", 120*time.Second),

		Postgres: Postgres{
			Host:     l.StringOr("POSTGRES_HOST", "localhost"),
			Port:     l.Int("POSTGRES_PORT", 5432),
			Database: l.StringOr("POSTGRES_DB", "encorebom"),
			User:     l.StringOr("POSTGRES_USER", "encorebom"),
			AppRole:  l.StringOr("POSTGRES_APP_ROLE", "encorebom_app"),
			SSLMode:  l.StringOr("POSTGRES_SSLMODE", sslDefault(env)),
			MaxConns: l.Int("POSTGRES_MAX_CONNS", 20),
		},
		NATS: NATS{
			URL:           l.StringOr("NATS_URL", "nats://localhost:4222"),
			StreamJobs:    l.StringOr("NATS_STREAM_JOBS", "SCAN_JOBS"),
			StreamEvents:  l.StringOr("NATS_STREAM_EVENTS", "SCAN_EVENTS"),
			StreamResults: l.StringOr("NATS_STREAM_RESULTS", "SCAN_RESULTS"),
		},
		Redis: Redis{
			URL: l.SecretOr("REDIS_URL", "redis://localhost:6379/0"),
		},
		S3: S3{
			Endpoint:       l.StringOr("S3_ENDPOINT", "http://localhost:9000"),
			Region:         l.StringOr("S3_REGION", "us-east-1"),
			Bucket:         l.StringOr("S3_BUCKET", "encorebom"),
			ForcePathStyle: l.Bool("S3_FORCE_PATH_STYLE", true),
		},
		OTel: OTel{
			Endpoint:  l.StringOr("OTEL_EXPORTER_OTLP_ENDPOINT", ""),
			Namespace: l.StringOr("OTEL_SERVICE_NAMESPACE", "encorebom"),
		},
	}
	svc.OTel.Enabled = svc.OTel.Endpoint != ""

	// Secrets are required in production and defaulted in development, so a
	// fresh clone runs with `task dev` but a production deploy cannot start
	// with a default credential.
	if env.IsProduction() {
		svc.Postgres.Password = l.Secret("POSTGRES_PASSWORD")
		svc.S3.AccessKey = l.Secret("S3_ACCESS_KEY")
		svc.S3.SecretKey = l.Secret("S3_SECRET_KEY")
	} else {
		svc.Postgres.Password = l.SecretOr("POSTGRES_PASSWORD", "encorebom")
		svc.S3.AccessKey = l.SecretOr("S3_ACCESS_KEY", "minioadmin")
		svc.S3.SecretKey = l.SecretOr("S3_SECRET_KEY", "minioadmin")
	}

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
func defaultPort(name string) int {
	ports := map[string]int{
		"gateway":           8080,
		"auth":              8091,
		"project":           8092,
		"scan-orchestrator": 8093,
		"report":            8094,
		"campaign":          8095,
		"comment":           8096,
		"notification":      8097,
	}
	if p, ok := ports[name]; ok {
		return p
	}
	return 8080
}

// KnownServices lists every Go service. Used by the generator and by preflight.
func KnownServices() []string {
	return []string{
		"gateway", "auth", "project", "scan-orchestrator",
		"report", "campaign", "comment", "notification",
	}
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
