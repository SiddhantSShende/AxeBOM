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
// "Materializing source" means two different things depending on where the
// project's code lives — a git clone, or an already-stored upload extracted
// into the workspace — but both converge on the SAME archiving step, so every
// engine downstream reads an identical content-addressed archive regardless of
// which path produced it. See handle's dispatch on src.Kind.
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
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/nats-io/nats.go/jetstream"

	"github.com/axebom/axebom/libs/go-shared/bus"
	"github.com/axebom/axebom/libs/go-shared/events"
	"github.com/axebom/axebom/libs/go-shared/fetcher"
	"github.com/axebom/axebom/libs/go-shared/platform/blob"
	"github.com/axebom/axebom/libs/go-shared/platform/errs"
	"github.com/axebom/axebom/libs/go-shared/projectsource"
	"github.com/axebom/axebom/libs/go-shared/sandbox"
	"github.com/axebom/axebom/libs/go-shared/vault"
)

// Resolver finds where a project's code lives.
type Resolver interface {
	Resolve(ctx context.Context, tenantID, projectID string) (projectsource.Source, error)
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
	// httpClient backs the GitHub Dependency Graph call, the only plain
	// (non-clone) outbound request this service makes. Injectable so tests can
	// point it at a local server: SafeHTTPClient's own dialer blocks loopback by
	// design, with no bypass, the same reason FetchDependencyGraphSBOM takes a
	// *http.Client rather than building one internally. Defaults to
	// fetcher.SafeHTTPClient(nil) in New.
	httpClient *http.Client

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
	// HTTPClient overrides the default SafeHTTPClient(nil) — tests only; a
	// live deployment should never set this.
	HTTPClient *http.Client
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
	httpClient := opts.HTTPClient
	if httpClient == nil {
		httpClient = fetcher.SafeHTTPClient(nil)
	}

	return &Worker{
		bus: opts.Bus, runner: opts.Runner, store: opts.Store,
		resolver: opts.Resolver, secrets: opts.Secrets, log: log,
		httpClient:    httpClient,
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
		if errors.Is(err, projectsource.ErrNoSource) {
			// NOT a failure of this service, and not retryable. Report it as a
			// failed fetch with a stated reason so the orchestrator fails the
			// scan now, with a cause, instead of leaving every engine run
			// queued for the reaper to time out in half an hour.
			log.Warn("project has no source connected or uploaded; nothing to fetch")
			return w.publish(ctx, w.failure(job, started,
				"FETCH_NO_SOURCE",
				"the project has no repository connection or uploaded file, "+
					"so there is nothing to fetch"))
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

	// Credential lookup is unconditional and safe for every kind: an upload
	// source's CredentialRef is always empty (nothing about an upload is ever
	// authenticated), and credential() already treats an empty ref as "no
	// credential needed" rather than an error.
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
	// The clone (or extracted upload) is scratch. The ARCHIVE is the durable
	// artifact, and it is content-addressed in object storage; leaving hundreds
	// of megabytes of working tree behind on every scan fills the disk within a
	// day.
	defer func() { _ = os.RemoveAll(dest) }()

	// workspacePath is where CreateArchive reads from. It is NOT always dest
	// itself: a git clone's materialized tree can land in a subdirectory of
	// dest (see fetcher.Clone's DestDir handling), so the git branch trusts
	// what Clone reports rather than assuming dest.
	var workspacePath, commitSHA string
	// extraArtifacts rides alongside the source archive in the success result.
	// Today: at most one entry, the GitHub Dependency Graph SBOM — a
	// reconciliation source, never required, so nothing here can turn a
	// successful clone into a failed fetch.
	var extraArtifacts []events.Artifact

	switch src.Kind {
	case events.SourceUpload:
		if err := w.materializeUpload(ctx, src, dest); err != nil {
			var fail *fetchFailure
			if errors.As(err, &fail) {
				log.Error("could not materialize the upload", "cause", err.Error())
				return w.publish(ctx, w.failure(job, started, fail.code, fail.message))
			}
			// Storage or filesystem blip. Retryable — nothing about the upload
			// itself has been judged bad yet.
			log.Warn("could not materialize the upload; will retry", "cause", err.Error())
			return fmt.Errorf("%w: materializing upload: %w", bus.ErrRetry, err)
		}
		workspacePath = dest

	case events.SourceURL:
		// ⚠ SHOULD NEVER HAPPEN. A url-sourced scan's job is published to
		// services/webrecon (scan.job.webrecon), never here — see
		// orchestr.CreateScan's publishFetchJob/publishWebreconJob split. If
		// this fires, the orchestrator's routing invariant broke; failing loud
		// and specific beats silently attempting a git clone with no RepoURL
		// (what the pre-webrecon default case did — see docs/STATE.md, the
		// Milestone 5 entry, for why this case moved out of the fetcher).
		log.Error("a url-sourced job reached the fetcher; it belongs to services/webrecon")
		return w.publish(ctx, w.failure(job, started, "FETCH_MISROUTED_URL_SOURCE",
			"a url-sourced scan was routed to the fetcher instead of services/webrecon"))

	default: // events.SourceGit, and anything an older caller left unset
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
		workspacePath, commitSHA = res.WorkspacePath, res.CommitSHA

		if artifact, ok := w.fetchDependencyGraphSBOM(ctx, job, src, token, log); ok {
			extraArtifacts = append(extraArtifacts, artifact)
		}
	}

	archive, err := fetcher.CreateArchive(ctx, w.store, workspacePath,
		job.Output.Prefix, fetcher.DefaultArchiveLimits())
	if err != nil {
		// Storage, not the source. Retryable — materialization succeeded and a
		// second attempt re-does work rather than losing it.
		log.Warn("could not archive the source; will retry", "cause", err.Error())
		return fmt.Errorf("%w: archiving source: %w", bus.ErrRetry, err)
	}

	log.Info("source materialized",
		"kind", src.Kind,
		"commit_sha", commitSHA,
		"archive_key", archive.Key,
		"files", archive.FileCount,
		"deduplicated", archive.Deduplicated)

	return w.publish(ctx, w.success(job, started, src.Kind, commitSHA, archive, extraArtifacts))
}

// fetchDependencyGraphSBOM tries to reconcile against the repo's own
// CI-published SBOM, staging it as a second raw artifact if one exists.
//
// ⚠ SOFT FAILURE, ALWAYS. Every return path here is either (artifact, true)
// or (zero value, false) — never an error the caller has to decide about.
// This is a reconciliation source, not a required input: most repositories
// are not on GitHub, most GitHub repos do not have Dependency Graph enabled,
// and both are ordinary, expected outcomes, not failures worth a WARN-level
// log line on every scan.
func (w *Worker) fetchDependencyGraphSBOM(
	ctx context.Context, job events.ScanJobV1, src projectsource.Source, token string, log *slog.Logger,
) (events.Artifact, bool) {
	if src.Provider != "github" || token == "" {
		return events.Artifact{}, false
	}

	raw, err := fetcher.FetchDependencyGraphSBOM(ctx, w.httpClient, "", src.RepoURL, token)
	if err != nil {
		log.Info("no GitHub Dependency Graph SBOM available; continuing without it",
			"scan_id", job.ScanID, "cause", err.Error())
		return events.Artifact{}, false
	}

	key := strings.TrimRight(job.Output.Prefix, "/") + "/dependency-graph-sbom.json"
	obj, err := w.store.Put(ctx, key, bytes.NewReader(raw), blob.PutOptions{
		ContentType: "application/spdx+json",
	})
	if err != nil {
		log.Warn("fetched a Dependency Graph SBOM but could not store it; continuing without it",
			"scan_id", job.ScanID, "cause", err.Error())
		return events.Artifact{}, false
	}

	log.Info("staged the repository's own Dependency Graph SBOM as a reconciliation source",
		"scan_id", job.ScanID, "artifact_key", obj.Key, "size_bytes", obj.Size)

	return events.Artifact{
		Role:      "native_output",
		URI:       obj.Key,
		SHA256:    obj.SHA256,
		SizeBytes: obj.Size,
		MediaType: "application/spdx+json",
	}, true
}

// fetchFailure signals a TERMINAL materialization failure carrying a specific
// taxonomy code, as opposed to a plain error — which handle() treats as
// transient and retries. Mirrors the distinction the git-clone branch already
// makes inline (FETCH_CLONE_FAILED vs. a wrapped bus.ErrRetry).
type fetchFailure struct {
	code    string
	message string
}

func (f *fetchFailure) Error() string { return f.code + ": " + f.message }

// materializeUpload downloads a stored upload and places it into dest —
// extracting a source_archive, or writing a single manifest/lockfile/sbom/
// hbom_csv file as-is. This is the upload analogue of fetcher.Clone: after it
// returns, dest holds exactly the tree CreateArchive will tar, the only
// difference being where the bytes came from.
func (w *Worker) materializeUpload(ctx context.Context, src projectsource.Source, dest string) error {
	rc, err := w.store.Get(ctx, src.StorageRef)
	if err != nil {
		if errors.Is(err, blob.ErrNotFound) {
			return &fetchFailure{code: "FETCH_NO_SOURCE",
				message: "the uploaded file could not be found in storage"}
		}
		return fmt.Errorf("read upload: %w", err) // a storage blip; retryable
	}
	defer func() { _ = rc.Close() }()

	if src.UploadKind != "source_archive" {
		// A single file — manifest, lockfile, sbom or hbom_csv. No extraction:
		// it is placed into the workspace under its own name, and one file is a
		// perfectly valid (if tiny) source tree for CreateArchive to tar.
		name := src.OriginalFilename
		if name == "" {
			name = "source"
		}
		// #nosec G304 -- dest is this job's own freshly created workspace
		// directory (see handle), and name was already sanitized to a safe
		// alphabet by the project service before it was ever stored.
		f, err := os.OpenFile(filepath.Join(dest, name), os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
		if err != nil {
			return fmt.Errorf("create workspace file: %w", err)
		}
		defer func() { _ = f.Close() }()
		if _, err := io.Copy(f, rc); err != nil {
			return fmt.Errorf("write workspace file: %w", err)
		}
		return nil
	}

	// A source_archive needs extraction, and zip needs random access — so it is
	// staged to a local temp file first rather than extracted straight from the
	// object-store stream.
	lim := fetcher.DefaultExtractLimits()
	tmp, err := os.CreateTemp("", "axebom-upload-*")
	if err != nil {
		return fmt.Errorf("stage upload: %w", err)
	}
	tmpPath := tmp.Name()
	defer func() {
		_ = tmp.Close()
		_ = os.Remove(tmpPath)
	}()

	// +1 byte, same trick DefaultMaxBytes uses elsewhere: reading exactly the
	// limit cannot distinguish "exactly at the limit" from "truncated here."
	// The project service already caps an upload at 256 MiB, well under this;
	// the copy is bounded again here in depth, not because it is expected to
	// bite.
	written, err := io.Copy(tmp, io.LimitReader(rc, lim.MaxBytes+1))
	if err != nil {
		return fmt.Errorf("stage upload: %w", err)
	}
	if written > lim.MaxBytes {
		return &fetchFailure{code: "FETCH_ARCHIVE_TOO_LARGE",
			message: fmt.Sprintf("upload exceeds the %d MiB limit", lim.MaxBytes>>20)}
	}
	if _, err := tmp.Seek(0, io.SeekStart); err != nil {
		return fmt.Errorf("stage upload: %w", err)
	}

	if _, err := fetcher.ExtractArchive(src.OriginalFilename, tmp, written, dest, lim); err != nil {
		var taxonomy *errs.Error
		if errors.As(err, &taxonomy) {
			return &fetchFailure{code: string(taxonomy.Code), message: taxonomy.Message}
		}
		return fmt.Errorf("extract upload: %w", err)
	}
	return nil
}

// credential exchanges the stored reference for the token.
//
// ⚠ THE STORED PATH IS NOT TRUSTED. The Ref is rebuilt from
// (tenant, kind, connection id) and vault.Get refuses a stored value that does
// not match the derived one before Vault is contacted. This service holds ONE
// token with access to the whole mount, so a path taken at face value would
// turn any bug that lets an attacker influence a stored ref into a read of
// another tenant's secret.
func (w *Worker) credential(ctx context.Context, tenantID string, src projectsource.Source) (string, error) {
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

// argvFor names what actually ran, for provenance — never a credential:
// whatever travels here is world-readable via /proc/<pid>/cmdline and reaches
// a stored manifest, so a git clone's token lives in the environment and a
// credential helper instead.
func argvFor(kind events.SourceKind) []string {
	switch kind {
	case events.SourceUpload:
		return []string{"axebom-fetcher", "materialize-upload"}
	default:
		return []string{"git", "clone"}
	}
}

func (w *Worker) base(job events.ScanJobV1, started time.Time, argv []string) events.ScanResultV1 {
	finished := time.Now().UTC()
	return events.ScanResultV1{
		SchemaVersion: events.SchemaScanResultV1,
		JobID:         job.JobID,
		ScanID:        job.ScanID,
		TenantID:      job.TenantID,
		Engine:        job.Engine,
		EngineVersion: w.version,
		Invocation: events.Invocation{
			ArgvRedacted: argv,
			StartedAt:    started,
			FinishedAt:   finished,
			DurationMS:   finished.Sub(started).Milliseconds(),
		},
	}
}

func (w *Worker) failure(job events.ScanJobV1, started time.Time, code, msg string) events.ScanResultV1 {
	r := w.base(job, started, argvFor(job.SourceMeta.Kind))
	r.Status = events.StatusFailed
	r.Diagnostics = []events.Diagnostic{{Severity: "error", Code: code, Message: msg}}
	r.Error = &events.ResultError{Code: code, Message: msg}
	return r
}

func (w *Worker) success(job events.ScanJobV1, started time.Time,
	kind events.SourceKind, commitSHA string, archive fetcher.Archive, extra []events.Artifact,
) events.ScanResultV1 {
	r := w.base(job, started, argvFor(kind))
	r.Status = events.StatusSucceeded

	// The commit sha travels in SourceMeta, which exists for exactly this.
	// The orchestrator previously read it out of EngineDBVersion — a field
	// documented as the vulnerability-database vintage — which made a fetch
	// result claim a database it had never consulted.
	//
	// commitSHA is empty for an upload: there is no commit, and SourceMeta's
	// CommitSHA is `omitempty` for exactly this reason — an upload-sourced
	// report has nothing dishonest to say here, it simply says nothing.
	r.SourceMeta = &events.SourceMeta{
		Kind:      kind,
		CommitSHA: commitSHA,
	}

	r.Artifacts = append([]events.Artifact{{
		Role:      "source_archive",
		URI:       archive.Key,
		SHA256:    archive.SHA256,
		SizeBytes: archive.SizeBytes,
		MediaType: "application/zstd",
	}}, extra...)
	return r
}
