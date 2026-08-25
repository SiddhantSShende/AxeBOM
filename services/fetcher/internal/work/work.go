// Package work consumes scan.job.fetch and materializes source exactly once.
//
// # The one job this service has
//
// A scan begins with a single fetch. Only when it completes does the
// orchestrator pin `source_commit_sha` and fan out one job per engine, all
// pointing at the same content-addressed archive. Six engines cloning
// independently could land on six different commits and produce a report
// describing a codebase that never existed (ADR-0008).
//
// So this is the narrow waist of a scan, and nothing downstream can start
// without it. Until this consumer existed, scan.job.fetch had no subscriber at
// all: `CreateScan` published a job, nothing consumed it, and the scan sat at
// `queued` until the reaper timed it out half an hour later.
//
// # Why this is a separate service
//
// It holds a git credential. Every other component is denied one — an engine
// container gets a content-addressed archive and nothing else, so compromising
// a scanner yields the code it was already scanning rather than access to the
// customer's repository. Putting this consumer inside the orchestrator would
// have given a gateway-reachable service a Vault token with repository access.
package work

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"time"

	"github.com/nats-io/nats.go/jetstream"

	"github.com/axebom/axebom/libs/go-shared/bus"
	"github.com/axebom/axebom/libs/go-shared/events"
	"github.com/axebom/axebom/libs/go-shared/fetcher"
	"github.com/axebom/axebom/libs/go-shared/platform/blob"
	"github.com/axebom/axebom/libs/go-shared/sandbox"
	"github.com/axebom/axebom/libs/go-shared/vault"
	"github.com/axebom/axebom/services/fetcher/internal/source"
)

// Resolver finds where a project's code lives.
type Resolver interface {
	Resolve(ctx context.Context, tenantID, projectID string) (source.Source, error)
}

// Secrets exchanges a credential reference for the token itself.
type Secrets interface {
	Get(ctx context.Context, ref vault.Ref, stored string) (map[string]string, error)
}

// Worker consumes fetch jobs.
type Worker struct {
	bus      *bus.Bus
	runner   sandbox.Runner
	store    *blob.Store
	resolver Resolver
	secrets  Secrets
	log      *slog.Logger

	// workspaceRoot is where a clone lands before it is archived.
	workspaceRoot string
	// version is reported as engine_version, for provenance.
	version string
}

// Options configures a Worker.
type Options struct {
	Bus           *bus.Bus
	Runner        sandbox.Runner
	Store         *blob.Store
	Resolver      Resolver
	Secrets       Secrets
	Log           *slog.Logger
	WorkspaceRoot string
	Version       string
}

func New(opts Options) (*Worker, error) {
	switch {
	case opts.Bus == nil:
		return nil, errors.New("fetcher: no bus")
	case opts.Runner == nil:
		return nil, errors.New("fetcher: no sandbox runner")
	case opts.Store == nil:
		return nil, errors.New("fetcher: no object store")
	case opts.Resolver == nil:
		return nil, errors.New("fetcher: no source resolver")
	}

	log := opts.Log
	if log == nil {
		log = slog.Default()
	}
	root := opts.WorkspaceRoot
	if root == "" {
		root = filepath.Join(os.TempDir(), "axebom-fetch")
	}
	version := opts.Version
	if version == "" {
		version = "dev"
	}

	return &Worker{
		bus: opts.Bus, runner: opts.Runner, store: opts.Store,
		resolver: opts.Resolver, secrets: opts.Secrets, log: log,
		workspaceRoot: root, version: version,
	}, nil
}

// Run consumes scan.job.fetch until the context is cancelled.
func (w *Worker) Run(ctx context.Context) error {
	consumer, err := w.bus.EnsureConsumer(ctx, bus.ConsumerConfig{
		Stream:        bus.StreamJobs,
		Durable:       "fetcher",
		FilterSubject: "scan.job." + string(events.FamilyFetch),
		// ⚠ NOT 1, AND THE REASON IS OPERATIONAL RATHER THAN THROUGHPUT.
		//
		// A clone is network-bound, so one at a time is tempting: it bounds
		// disk and bandwidth, and a replica cannot usefully run many at once.
		//
		// But max_ack_pending=1 combined with ack_wait=30m — which a clone
		// genuinely needs — means ONE stuck fetch halts EVERY scan in the
		// system for half an hour. Observed exactly that: a worker restarted
		// while holding a message, and because a message held by a dead
		// consumer is only released at ack_wait, the whole fetch queue stopped
		// dead with "Outstanding Acks: 1 out of maximum 1" and no log line to
		// explain it.
		//
		// Four gives head-of-line failures somewhere to go while still bounding
		// concurrent clones. Disk is bounded separately by the archive limits.
		MaxAckPending: 4,
	})
	if err != nil {
		return err
	}

	w.log.Info("fetcher consuming", "subject", "scan.job."+string(events.FamilyFetch))

	return w.bus.Consume(ctx, consumer, "scan.dlq."+string(events.FamilyFetch),
		func(ctx context.Context, msg jetstream.Msg) error {
			// The handler takes raw bytes, not the message: acking,
			// redelivery and DLQ routing are bus.Consume's decisions, and
			// keeping them out of handle() is what makes it testable without
			// a broker.
			return w.handle(ctx, msg.Data())
		})
}

// handle processes one fetch job.
//
// ⚠ THE RETURN VALUE DECIDES THE MESSAGE'S FATE, and the distinction matters.
//
//	nil       acked. The result is published; the orchestrator takes it from here.
//	ErrRetry  transient — a broker or storage blip, worth another attempt.
//	other     PERMANENT — to the DLQ without burning the retry budget.
//
// A malformed job or a project with no repository will never succeed, so
// retrying it three times costs ten minutes of backoff and delays every scan
// behind it before failing anyway.
func (w *Worker) handle(ctx context.Context, data []byte) error {
	var job events.ScanJobV1
	if err := json.Unmarshal(data, &job); err != nil {
		return fmt.Errorf("fetch job is not valid JSON: %w", err)
	}
	if err := job.Validate(); err != nil {
		return fmt.Errorf("fetch job failed validation: %w", err)
	}

	log := w.log.With("scan_id", job.ScanID, "job_id", job.JobID)
	started := time.Now().UTC()

	// Logged on ENTRY, not only on completion. A fetch can take minutes, and
	// without this a stalled clone is indistinguishable from a worker that
	// never received the job — the queue shows one outstanding ack and the log
	// shows nothing at all.
	log.Info("fetch started", "project_id", job.ProjectID)

	src, err := w.resolver.Resolve(ctx, job.TenantID, job.ProjectID)
	if err != nil {
		if errors.Is(err, source.ErrNoSource) {
			// NOT a failure of this service, and not retryable. Report it as a
			// failed fetch with a stated reason so the orchestrator fails the
			// scan now, with a cause, instead of leaving every engine run
			// queued for the reaper to time out in half an hour.
			log.Warn("project has no repository connection; nothing to fetch")
			return w.publish(ctx, w.failure(job, started,
				"FETCH_NO_SOURCE",
				"the project has no repository connection, so there is nothing to clone"))
		}
		// A broker, network or project-service blip. Worth retrying.
		//
		// LOGGED, because a silent retry is invisible: the message is naked
		// with a delay, redelivered, and naked again, and the only symptom is a
		// consumer holding one outstanding ack forever while every scan behind
		// it waits. Nothing in bus.dispatch logs the retry path.
		log.Warn("could not resolve the source; will retry", "cause", err.Error())
		return fmt.Errorf("%w: resolving source: %w", bus.ErrRetry, err)
	}

	token, err := w.credential(ctx, job.TenantID, src)
	if err != nil {
		// A credential that cannot be read is not transient in any useful
		// sense: the ref is wrong, or the token was never stored. Retrying
		// three times changes nothing.
		log.Error("could not read the repository credential", "cause", err.Error())
		return w.publish(ctx, w.failure(job, started, "FETCH_CREDENTIAL_UNAVAILABLE",
			"the repository credential could not be read; the connection may need reauthorizing"))
	}

	dest := filepath.Join(w.workspaceRoot, job.ScanID)
	if err := os.MkdirAll(dest, 0o750); err != nil {
		log.Warn("could not prepare the workspace; will retry", "cause", err.Error())
		return fmt.Errorf("%w: preparing workspace: %w", bus.ErrRetry, err)
	}
	// The clone is scratch. The ARCHIVE is the durable artifact, and it is
	// content-addressed in object storage; leaving hundreds of megabytes of
	// working tree behind on every scan fills the disk within a day.
	defer func() { _ = os.RemoveAll(dest) }()

	res, err := fetcher.Clone(ctx, w.runner, fetcher.CloneRequest{
		RepoURL: src.RepoURL,
		Ref:     src.DefaultBranch,
		Token:   token,
		Timeout: time.Duration(job.Limits.WallClockSec) * time.Second,
		// Without DestDir the clone leaves no files: /workspace is a tmpfs that
		// dies with the container. See CloneRequest.DestDir.
		DestDir: dest,
	}, fetcher.FetcherPolicy(), sandbox.DefaultLimits())
	if err != nil {
		log.Error("clone failed", "cause", err.Error())
		return w.publish(ctx, w.failure(job, started, "FETCH_CLONE_FAILED",
			"the repository could not be cloned"))
	}

	archive, err := fetcher.CreateArchive(ctx, w.store, res.WorkspacePath,
		job.Output.Prefix, fetcher.DefaultArchiveLimits())
	if err != nil {
		// Storage, not the repository. Retryable — the clone succeeded and a
		// second attempt re-does work rather than losing it.
		log.Warn("could not archive the source; will retry", "cause", err.Error())
		return fmt.Errorf("%w: archiving source: %w", bus.ErrRetry, err)
	}

	log.Info("source materialized",
		"commit_sha", res.CommitSHA,
		"archive_key", archive.Key,
		"files", archive.FileCount,
		"deduplicated", archive.Deduplicated)

	return w.publish(ctx, w.success(job, started, res, archive))
}

// credential exchanges the stored reference for the token.
//
// ⚠ THE STORED PATH IS NOT TRUSTED. The Ref is rebuilt from
// (tenant, kind, connection id) and vault.Get refuses a stored value that does
// not match the derived one before Vault is contacted. This service holds ONE
// token with access to the whole mount, so a path taken at face value would
// turn any bug that lets an attacker influence a stored ref into a read of
// another tenant's secret.
func (w *Worker) credential(ctx context.Context, tenantID string, src source.Source) (string, error) {
	if src.CredentialRef == "" {
		// A public repository. Not an error — most open-source scanning needs
		// no credential at all, and demanding one would block the common case.
		return "", nil
	}
	if w.secrets == nil {
		return "", errors.New("a credential is required but no secret store is configured")
	}

	ref := vault.Ref{
		TenantID: tenantID,
		Kind:     vault.KindRepoToken,
		ID:       src.ConnectionID,
	}
	secret, err := w.secrets.Get(ctx, ref, src.CredentialRef)
	if err != nil {
		return "", err
	}
	return secret["token"], nil
}

func (w *Worker) publish(ctx context.Context, result events.ScanResultV1) error {
	payload, err := json.Marshal(result)
	if err != nil {
		return fmt.Errorf("marshalling fetch result: %w", err)
	}
	// The job id is the dedup key, so a worker that crashes between publishing
	// and acking republishes harmlessly.
	return w.bus.Publish(ctx, "scan.result."+string(events.FamilyFetch), result.JobID, payload)
}

func (w *Worker) base(job events.ScanJobV1, started time.Time) events.ScanResultV1 {
	finished := time.Now().UTC()
	return events.ScanResultV1{
		SchemaVersion: events.SchemaScanResultV1,
		JobID:         job.JobID,
		ScanID:        job.ScanID,
		TenantID:      job.TenantID,
		Engine:        job.Engine,
		EngineVersion: w.version,
		Invocation: events.Invocation{
			// The clone argv carries no credential by construction — the token
			// travels in the environment and is consumed by a credential
			// helper, because argv is world-readable via /proc/<pid>/cmdline.
			ArgvRedacted: []string{"git", "clone"},
			StartedAt:    started,
			FinishedAt:   finished,
			DurationMS:   finished.Sub(started).Milliseconds(),
		},
	}
}

func (w *Worker) failure(job events.ScanJobV1, started time.Time, code, msg string) events.ScanResultV1 {
	r := w.base(job, started)
	r.Status = events.StatusFailed
	r.Diagnostics = []events.Diagnostic{{Severity: "error", Code: code, Message: msg}}
	r.Error = &events.ResultError{Code: code, Message: msg}
	return r
}

func (w *Worker) success(job events.ScanJobV1, started time.Time,
	res fetcher.CloneResult, archive fetcher.Archive,
) events.ScanResultV1 {
	r := w.base(job, started)
	r.Status = events.StatusSucceeded

	// The commit sha travels in SourceMeta, which exists for exactly this.
	// The orchestrator previously read it out of EngineDBVersion — a field
	// documented as the vulnerability-database vintage — which made a fetch
	// result claim a database it had never consulted.
	r.SourceMeta = &events.SourceMeta{
		Kind:      job.SourceMeta.Kind,
		CommitSHA: res.CommitSHA,
	}

	r.Artifacts = []events.Artifact{{
		Role:      "source_archive",
		URI:       archive.Key,
		SHA256:    archive.SHA256,
		SizeBytes: archive.SizeBytes,
		MediaType: "application/zstd",
	}}
	return r
}
