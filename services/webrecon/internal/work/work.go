// Package work consumes scan.job.webrecon and produces a url source's
// discovery + JS-fingerprint document.
//
// publishFetchJob's sibling (services/fetcher/internal/work): the fetcher
// materializes a git/upload source exactly once; this materializes a url
// source's INPUT exactly once — subdomain discovery plus per-host JS
// fingerprinting — and stages the result as a single native_output artifact
// that webrecon-fingerprint (services/scan-orchestrator/internal/policy/
// registry.go) is the only engine ever wired to read.
//
// # Why this is a separate service, not a fetcher extension
//
// libs/go-shared/sandbox/policy.go states flatly that no ENGINE may have
// network egress. subfinder needs it, and so does every page/script fetch.
// Both run here, inside a component that — like the fetcher — is a
// deliberate, named, narrow exception, never inside a normal sandboxed
// engine container. It holds NO credential: a url source is never
// authenticated, so there is nothing to protect the way ADR-0008 protects
// git tokens.
package work

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"sync/atomic"
	"time"

	"github.com/nats-io/nats.go/jetstream"

	"github.com/axebom/axebom/libs/go-shared/bus"
	"github.com/axebom/axebom/libs/go-shared/events"
	"github.com/axebom/axebom/libs/go-shared/fetcher"
	"github.com/axebom/axebom/libs/go-shared/platform/blob"
	"github.com/axebom/axebom/libs/go-shared/projectsource"
	"github.com/axebom/axebom/libs/go-shared/sandbox"
	"github.com/axebom/axebom/services/webrecon/internal/discover"
	"github.com/axebom/axebom/services/webrecon/internal/fingerprint"
)

// Resolver finds where a project's code lives — the same interface the
// fetcher's Worker depends on, satisfied by the same shared
// projectsource.Client.
type Resolver interface {
	Resolve(ctx context.Context, tenantID, projectID string) (projectsource.Source, error)
}

// Worker consumes webrecon jobs.
type Worker struct {
	// seq numbers this worker's own scan.event.* frames. Monotonic across
	// every job this process handles, same shape as
	// scan-orchestrator's Orchestrator.seq — see events.PublishScanEvent's
	// own doc comment for why that is sufficient.
	seq      atomic.Int64
	bus      *bus.Bus
	runner   sandbox.Runner
	store    *blob.Store
	resolver Resolver
	matcher  *fingerprint.Matcher
	// httpClient is the SSRF-hardened client every page/script fetch uses —
	// injectable so tests can point it at a local server, same reasoning as
	// the fetcher's own Options.HTTPClient.
	httpClient *http.Client
	log        *slog.Logger
	version    string
}

// Options configures a Worker.
type Options struct {
	Bus        *bus.Bus
	Runner     sandbox.Runner
	Store      *blob.Store
	Resolver   Resolver
	Signatures []byte // the vendored retire.js signature database, read by deps.go
	Log        *slog.Logger
	Version    string
	// HTTPClient overrides the default SafeHTTPClient(nil) — tests only.
	HTTPClient *http.Client
}

func New(opts Options) (*Worker, error) {
	switch {
	case opts.Bus == nil:
		return nil, errors.New("webrecon: no bus")
	case opts.Runner == nil:
		return nil, errors.New("webrecon: no sandbox runner")
	case opts.Store == nil:
		return nil, errors.New("webrecon: no object store")
	case opts.Resolver == nil:
		return nil, errors.New("webrecon: no source resolver")
	case len(opts.Signatures) == 0:
		return nil, errors.New("webrecon: no signature database")
	}

	matcher, stats, err := fingerprint.LoadSignatures(opts.Signatures)
	if err != nil {
		return nil, fmt.Errorf("webrecon: load signature database: %w", err)
	}

	log := opts.Log
	if log == nil {
		log = slog.Default()
	}
	log.Info("signature database loaded",
		"libraries", stats.Libraries, "patterns_compiled", stats.PatternsCompiled,
		"skipped_incompatible", stats.SkippedIncompatible, "capped_repeat", stats.CappedRepeat)

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
		resolver: opts.Resolver, matcher: matcher, httpClient: httpClient,
		log: log, version: version,
	}, nil
}

// Run consumes scan.job.webrecon until the context is cancelled.
func (w *Worker) Run(ctx context.Context) error {
	consumer, err := w.bus.EnsureConsumer(ctx, bus.ConsumerConfig{
		Stream:        bus.StreamJobs,
		Durable:       "webrecon",
		FilterSubject: "scan.job." + string(events.FamilyWebrecon),
		// A discovery + multi-host fetch pass can genuinely take a few
		// minutes at max_hosts; more than one in flight per replica risks the
		// same "one stuck job halts everything for ack_wait" failure mode the
		// fetcher's own MaxAckPending comment documents — matching its value.
		MaxAckPending: 4,
	})
	if err != nil {
		return err
	}

	w.log.Info("webrecon consuming", "subject", "scan.job."+string(events.FamilyWebrecon))

	return w.bus.Consume(ctx, consumer, "scan.dlq."+string(events.FamilyWebrecon),
		func(ctx context.Context, msg jetstream.Msg) error {
			return w.handle(ctx, msg.Data())
		})
}

// handle processes one webrecon job. Same return-value contract as the
// fetcher's handle(): nil acks and publishes a result, bus.ErrRetry is
// transient, anything else is permanent (to the DLQ).
func (w *Worker) handle(ctx context.Context, data []byte) error {
	var job events.ScanJobV1
	if err := json.Unmarshal(data, &job); err != nil {
		return fmt.Errorf("webrecon job is not valid JSON: %w", err)
	}
	if err := job.Validate(); err != nil {
		return fmt.Errorf("webrecon job failed validation: %w", err)
	}

	log := w.log.With("scan_id", job.ScanID, "job_id", job.JobID)
	started := time.Now().UTC()
	log.Info("webrecon started", "project_id", job.ProjectID)

	src, err := w.resolver.Resolve(ctx, job.TenantID, job.ProjectID)
	if err != nil {
		if errors.Is(err, projectsource.ErrNoSource) {
			log.Warn("project has no url source; nothing to discover")
			return w.publish(ctx, w.failure(job, started, "WEBRECON_NO_SOURCE",
				"the project has no URL source, so there is nothing to discover"))
		}
		log.Warn("could not resolve the source; will retry", "cause", err.Error())
		return fmt.Errorf("%w: resolving source: %w", bus.ErrRetry, err)
	}
	if src.Kind != events.SourceURL {
		// ⚠ SHOULD NEVER HAPPEN — the mirror of the fetcher's own defensive
		// events.SourceURL case. CreateScan only ever publishes scan.job.
		// webrecon for a url-sourced scan.
		log.Error("a non-url-sourced job reached webrecon", "kind", src.Kind)
		return w.publish(ctx, w.failure(job, started, "WEBRECON_MISROUTED_SOURCE",
			"a non-url-sourced scan was routed to services/webrecon"))
	}

	hosts, err := w.resolveHosts(ctx, src, log)
	if err != nil {
		// A network/API blip resolving hosts (e.g. Docker unreachable for the
		// discovery container) is retryable; the fingerprint pass itself
		// never returns an error — every per-host failure is recorded IN the
		// document instead, exactly like ecosystems_detected records a gap.
		log.Warn("could not resolve hosts to fingerprint; will retry", "cause", err.Error())
		return fmt.Errorf("%w: resolving hosts: %w", bus.ErrRetry, err)
	}
	w.publishEvent(ctx, job, events.PhaseRunning,
		fmt.Sprintf("discovered %d host(s) to fingerprint", len(hosts)))

	doc := w.fingerprintAll(ctx, job, src, hosts)

	payload, err := json.Marshal(doc)
	if err != nil {
		return fmt.Errorf("marshal webrecon document: %w", err)
	}

	key := strings.TrimRight(job.Output.Prefix, "/") + "/webrecon.json"
	obj, err := w.store.Put(ctx, key, bytes.NewReader(payload), blob.PutOptions{
		ContentType: "application/json",
	})
	if err != nil {
		log.Warn("could not store the webrecon document; will retry", "cause", err.Error())
		return fmt.Errorf("%w: storing document: %w", bus.ErrRetry, err)
	}

	log.Info("webrecon complete",
		"hosts", len(doc.Hosts), "libraries", countLibraries(doc), "artifact_key", obj.Key)

	return w.publish(ctx, w.success(job, started, events.Artifact{
		Role: "native_output", URI: obj.Key, SHA256: obj.SHA256,
		SizeBytes: obj.Size, MediaType: "application/json",
	}))
}

// resolveHosts builds the list of hosts to fingerprint: the root URL's own
// host always; subfinder's passive discovery, capped at MaxHosts, only when
// DiscoveryEnabled and there is room left in the cap.
//
// A discovery FAILURE (Docker unreachable, the subfinder image missing)
// degrades to root-only rather than failing the whole job — discovery is an
// enhancement over the one page the tenant explicitly registered, not a
// precondition for fingerprinting it.
func (w *Worker) resolveHosts(ctx context.Context, src projectsource.Source, log *slog.Logger) ([]string, error) {
	rootHost := fingerprint.HostOf(src.RootURL)
	if rootHost == "" {
		return nil, fmt.Errorf("resolve hosts: %q has no host", src.RootURL)
	}
	hosts := []string{rootHost}

	if !src.DiscoveryEnabled {
		return hosts, nil
	}
	maxHosts := src.MaxHosts
	if maxHosts <= 0 {
		maxHosts = 25 // matches project.web_sources' own column default
	}
	if len(hosts) >= maxHosts {
		return hosts, nil
	}

	discovered, err := discover.Discover(ctx, w.runner, rootHost, maxHosts-len(hosts))
	if err != nil {
		log.Warn("subdomain discovery failed; fingerprinting only the registered root page",
			"cause", err.Error())
		return hosts, nil
	}
	return append(hosts, discovered...), nil
}

// fingerprintAll fetches and fingerprints every host. Never returns an
// error: a per-host failure (unreachable, HTTP error) is recorded in that
// host's own entry, exactly the "declared, not omitted" doctrine
// ecosystems_detected already applies to engine coverage.
//
// ⚠ ONE EVENT PER HOST, LIVE, AS IT HAPPENS — the actual "what is it
// reaching right now" signal a connected browser sees, not derived or
// guessed at afterward. hosts is typically 1 (discovery off or failed) up
// to max_hosts (25 by default), so for a project with real subdomains this
// is the one place in the whole product where a scan's progress view has
// more than two states (dispatched, done) to show while it runs.
func (w *Worker) fingerprintAll(
	ctx context.Context, job events.ScanJobV1, src projectsource.Source, hosts []string,
) webreconDoc {
	doc := webreconDoc{
		SchemaVersion:    "axebom-webrecon-json-1",
		RootURL:          src.RootURL,
		DiscoveryEnabled: src.DiscoveryEnabled,
	}

	for i, host := range hosts {
		pageURL := src.RootURL
		if host != fingerprint.HostOf(src.RootURL) {
			pageURL = "https://" + host + "/"
		}

		w.publishEvent(ctx, job, events.PhaseRunning,
			fmt.Sprintf("fingerprinting %s (%d of %d)", host, i+1, len(hosts)))

		result := fingerprint.FetchAndFingerprint(w.httpClient, w.matcher, pageURL)
		doc.Hosts = append(doc.Hosts, toHostDoc(result))
	}
	return doc
}

// publishEvent emits an advisory scan.event.* frame. Best-effort, like every
// other advisory publish in this product (events.PublishScanEvent's own doc
// comment) — a message the browser missed is never a reason to fail or slow
// the actual scan.
func (w *Worker) publishEvent(ctx context.Context, job events.ScanJobV1, phase events.Phase, message string) {
	events.PublishScanEvent(ctx, w.bus, &w.seq, w.log, events.ScanEventV1{
		ScanID: job.ScanID, TenantID: job.TenantID, JobID: job.JobID,
		Engine: "webrecon-fingerprint", Phase: phase, Message: message,
	})
}

func (w *Worker) publish(ctx context.Context, result events.ScanResultV1) error {
	payload, err := json.Marshal(result)
	if err != nil {
		return fmt.Errorf("marshalling webrecon result: %w", err)
	}
	return w.bus.Publish(ctx, "scan.result."+string(events.FamilyWebrecon), result.JobID, payload)
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
			ArgvRedacted: []string{"axebom-webrecon", "discover-and-fingerprint"},
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

func (w *Worker) success(job events.ScanJobV1, started time.Time, artifact events.Artifact) events.ScanResultV1 {
	r := w.base(job, started)
	r.Status = events.StatusSucceeded
	r.Artifacts = []events.Artifact{artifact}
	return r
}

func countLibraries(doc webreconDoc) int {
	n := 0
	for _, h := range doc.Hosts {
		n += len(h.Libraries)
	}
	return n
}
