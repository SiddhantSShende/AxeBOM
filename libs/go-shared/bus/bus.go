// Package bus is the NATS JetStream layer.
//
// It implements the topology in docs/02-CONTRACTS.md §2, which is the SSOT:
//
//	SCAN_JOBS    scan.job.<family>     WorkQueue  pull, max_deliver=4, ack_wait=30m
//	SCAN_EVENTS  scan.event.<scan_id>  Limits 24h push, ephemeral — ADVISORY ONLY
//	SCAN_RESULTS scan.result.<family>  WorkQueue  pull
//	SCAN_DLQ     scan.dlq.<family>     Limits 30d manual — poison messages
//
// THE MOST IMPORTANT PROPERTY HERE IS THAT NONE OF IT IS REQUIRED FOR
// CORRECTNESS. Postgres is the source of truth. If the bus loses a message, a
// job is redelivered (jobs are idempotent) or the reaper times it out; if it
// loses an EVENT, a page refresh reads the database and is correct. Progress
// logic that depends on receiving every event is a bug.
package bus

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
)

// Stream names.
const (
	StreamJobs    = "SCAN_JOBS"
	StreamEvents  = "SCAN_EVENTS"
	StreamResults = "SCAN_RESULTS"
	StreamDLQ     = "SCAN_DLQ"
	StreamNotify  = "NOTIFY"
	// StreamReports carries render jobs.
	//
	// ⚠ A SEPARATE STREAM FROM SCAN_JOBS, not another subject on it. Scan jobs
	// run third-party scanners in a sandbox for minutes; render jobs build a
	// document in-process in seconds. Sharing a stream would make them share
	// AckWait — 30 minutes, sized for a container — so a render worker that
	// died would hold its report hostage for half an hour.
	StreamReports = "REPORT_JOBS"
)

// SubjectRender is the render-job subject.
//
// One subject, not one per format: a WorkQueue stream permits ONE consumer per
// filter subject (Phase 6), so per-format subjects would mean per-format
// consumer groups and a PDF backlog could not be drained by an idle worker.
const SubjectRender = "report.render.requested"

// Delivery policy, from the contract.
const (
	// MaxDeliver is the total number of attempts, so three RETRIES after the
	// first. Four is chosen against the backoff schedule below: a job that has
	// failed at 30s, 2m and 8m is not going to succeed at 30m either, and
	// holding it longer delays everything behind it.
	MaxDeliver = 4

	// AckWait matches the sandbox wall-clock ceiling. A job that exceeds it is
	// redelivered, which is safe ONLY because jobs are idempotent — the worker
	// HEADs its manifest first and re-emits rather than re-running.
	AckWait = 30 * time.Minute
)

// backoff is the redelivery schedule.
//
// Deliberately not exponential-with-jitter: these are minutes-long container
// jobs, not HTTP calls. 30s covers a restarting worker, 2m covers a node
// rolling, 8m covers a dependency being redeployed.
var backoff = []time.Duration{30 * time.Second, 2 * time.Minute, 8 * time.Minute}

// Bus is a JetStream connection.
type Bus struct {
	nc  *nats.Conn
	js  jetstream.JetStream
	cfg Config
}

// Config configures the connection.
type Config struct {
	URL  string
	Name string
	// ConnectTimeout bounds the initial connection.
	ConnectTimeout time.Duration
}

// Connect opens a connection and ensures the streams exist.
func Connect(ctx context.Context, cfg Config) (*Bus, error) {
	if cfg.URL == "" {
		return nil, errors.New("bus: no NATS URL configured")
	}
	if cfg.ConnectTimeout <= 0 {
		cfg.ConnectTimeout = 10 * time.Second
	}

	nc, err := nats.Connect(cfg.URL,
		nats.Name(cfg.Name),
		nats.Timeout(cfg.ConnectTimeout),
		// Reconnect FOREVER. A bus outage must degrade into delayed jobs, not
		// into a service that gave up and needs restarting by hand.
		nats.MaxReconnects(-1),
		nats.ReconnectWait(2*time.Second),
		nats.ReconnectJitter(500*time.Millisecond, 2*time.Second),
	)
	if err != nil {
		return nil, fmt.Errorf("bus: connect to %s: %w", cfg.URL, err)
	}

	js, err := jetstream.New(nc)
	if err != nil {
		nc.Close()
		return nil, fmt.Errorf("bus: jetstream: %w", err)
	}

	b := &Bus{nc: nc, js: js, cfg: cfg}
	if err := b.ensureStreams(ctx); err != nil {
		nc.Close()
		return nil, err
	}
	return b, nil
}

// ensureStreams creates or updates every stream.
//
// Idempotent and run on every start, so a fresh environment works with no
// manual setup and a changed retention policy applies without an operator
// remembering to run something.
func (b *Bus) ensureStreams(ctx context.Context) error {
	streams := []jetstream.StreamConfig{
		{
			Name:     StreamJobs,
			Subjects: []string{"scan.job.>"},
			// WorkQueue: each message is delivered to exactly one consumer and
			// removed on ack. A job must not fan out to every worker.
			Retention: jetstream.WorkQueuePolicy,
			Storage:   jetstream.FileStorage,
			MaxAge:    24 * time.Hour,
			Discard:   jetstream.DiscardOld,
		},
		{
			Name:     StreamEvents,
			Subjects: []string{"scan.event.>"},
			// Limits, not WorkQueue: events are BROADCAST. Every connected
			// browser session gets them, and they expire on their own.
			Retention: jetstream.LimitsPolicy,
			Storage:   jetstream.MemoryStorage, // advisory; losing them on restart is fine
			MaxAge:    24 * time.Hour,
			MaxMsgs:   1_000_000,
			Discard:   jetstream.DiscardOld,
		},
		{
			Name:      StreamResults,
			Subjects:  []string{"scan.result.>"},
			Retention: jetstream.WorkQueuePolicy,
			Storage:   jetstream.FileStorage,
			MaxAge:    7 * 24 * time.Hour,
			Discard:   jetstream.DiscardOld,
		},
		{
			Name:     StreamDLQ,
			Subjects: []string{"scan.dlq.>"},
			// 30 days, because a poison message is a BUG REPORT. Discarding it
			// after an hour means the one artifact that explains a production
			// failure is gone before anyone looks.
			Retention: jetstream.LimitsPolicy,
			Storage:   jetstream.FileStorage,
			MaxAge:    30 * 24 * time.Hour,
			Discard:   jetstream.DiscardOld,
		},
		{
			Name:      StreamNotify,
			Subjects:  []string{"notify.>"},
			Retention: jetstream.WorkQueuePolicy,
			Storage:   jetstream.FileStorage,
			MaxAge:    7 * 24 * time.Hour,
			Discard:   jetstream.DiscardOld,
		},
		{
			Name:     StreamReports,
			Subjects: []string{"report.render.>"},
			// WorkQueue: one worker renders each report. Fanning out would have
			// two workers race for the same storage key — and the conditional
			// `status = queued` transition would make the loser do nothing,
			// which is correct but wasteful at 3000 pages.
			Retention: jetstream.WorkQueuePolicy,
			Storage:   jetstream.FileStorage,
			// 24 hours. A render job older than that describes a report the
			// customer has given up on, and re-rendering it surprises them.
			MaxAge:  24 * time.Hour,
			Discard: jetstream.DiscardOld,
		},
	}

	for _, cfg := range streams {
		if _, err := b.js.CreateOrUpdateStream(ctx, cfg); err != nil {
			return fmt.Errorf("bus: ensure stream %s: %w", cfg.Name, err)
		}
	}
	return nil
}

// Close drains and closes the connection.
//
// Drain, not Close: it lets in-flight publishes complete rather than dropping
// them, which matters on a rolling deploy.
func (b *Bus) Close() error {
	return b.nc.Drain()
}

// Ping reports whether the bus is reachable, for readiness checks.
func (b *Bus) Ping(context.Context) error {
	if !b.nc.IsConnected() {
		return errors.New("bus: not connected")
	}
	return nil
}

// JetStream exposes the underlying handle for callers that need consumer
// management. Named conspicuously so ordinary publish/subscribe goes through
// the typed helpers instead.
func (b *Bus) JetStream() jetstream.JetStream { return b.js }

// ---------------------------------------------------------------------------
// Publishing
// ---------------------------------------------------------------------------

// Publish sends a message with a deduplication id.
//
// ⚠ THE MSG-ID IS WHAT MAKES A DOUBLE PUBLISH HARMLESS.
//
// JetStream deduplicates by Nats-Msg-Id within its duplicate window, so an
// orchestrator that crashes after publishing but before recording the fact can
// republish safely. Without it, a crash-retry loop enqueues the same job
// repeatedly and every one of them runs.
func (b *Bus) Publish(ctx context.Context, subject, msgID string, payload []byte) error {
	opts := []jetstream.PublishOpt{}
	if msgID != "" {
		opts = append(opts, jetstream.WithMsgID(msgID))
	}
	if _, err := b.js.Publish(ctx, subject, payload, opts...); err != nil {
		return fmt.Errorf("bus: publish to %s: %w", subject, err)
	}
	return nil
}

// PublishAdvisory sends a fire-and-forget event.
//
// Errors are RETURNED but callers are expected to log and continue: an event is
// advisory, and failing a scan because a progress message could not be
// published would be the tail wagging the dog.
func (b *Bus) PublishAdvisory(ctx context.Context, subject string, payload []byte) error {
	_, err := b.js.Publish(ctx, subject, payload)
	if err != nil {
		return fmt.Errorf("bus: publish advisory to %s: %w", subject, err)
	}
	return nil
}

// ---------------------------------------------------------------------------
// Consuming
// ---------------------------------------------------------------------------

// ConsumerConfig describes a durable pull consumer.
//
// ⚠ ON A WORKQUEUE STREAM, ONE FILTER SUBJECT ADMITS EXACTLY ONE CONSUMER.
//
// NATS refuses a second with "filtered consumer not unique on workqueue
// stream". That is correct for a work queue and it dictates the deployment
// shape: every worker for a family shares ONE durable name, and NATS
// distributes messages between them. Giving each worker instance its own
// durable would be rejected at startup — which is the failure surfacing early,
// where it should.
type ConsumerConfig struct {
	Stream  string
	Durable string
	// FilterSubject narrows what this consumer receives, e.g. scan.job.sbom.
	FilterSubject string
	// MaxAckPending bounds how many messages one consumer holds unacked. It is
	// the concurrency limit: a worker that can run two containers must not be
	// handed fifty jobs.
	MaxAckPending int
	// AckWait overrides the default. Zero uses AckWait, which is sized for a
	// SANDBOXED SCAN — thirty minutes of container.
	//
	// ⚠ A CONSUMER OF SHORT WORK MUST NOT INHERIT IT. A render is seconds of
	// in-process work; leaving it at thirty minutes means a worker that dies
	// mid-render holds that report hostage for half an hour, and the customer
	// sees `rendering` the whole time.
	AckWait time.Duration
}

// EnsureConsumer creates or updates a durable pull consumer.
func (b *Bus) EnsureConsumer(ctx context.Context, cfg ConsumerConfig) (jetstream.Consumer, error) {
	if cfg.MaxAckPending <= 0 {
		cfg.MaxAckPending = 8
	}
	ackWait := cfg.AckWait
	if ackWait <= 0 {
		ackWait = AckWait
	}

	c, err := b.js.CreateOrUpdateConsumer(ctx, cfg.Stream, jetstream.ConsumerConfig{
		Durable:       cfg.Durable,
		FilterSubject: cfg.FilterSubject,
		AckPolicy:     jetstream.AckExplicitPolicy,
		AckWait:       ackWait,
		MaxDeliver:    MaxDeliver,
		BackOff:       backoff,
		MaxAckPending: cfg.MaxAckPending,
		// DeliverAll: a consumer that starts fresh must pick up work already
		// queued, not only what arrives after it connects.
		DeliverPolicy: jetstream.DeliverAllPolicy,
	})
	if err != nil {
		return nil, fmt.Errorf("bus: ensure consumer %s on %s: %w", cfg.Durable, cfg.Stream, err)
	}
	return c, nil
}

// DeleteConsumer removes a durable consumer.
//
// Used by tests to release a filter subject between runs — see the constraint
// on ConsumerConfig — and by operators retiring a worker fleet.
func (b *Bus) DeleteConsumer(ctx context.Context, stream, durable string) error {
	err := b.js.DeleteConsumer(ctx, stream, durable)
	if err != nil && !errors.Is(err, jetstream.ErrConsumerNotFound) {
		return fmt.Errorf("bus: delete consumer %s: %w", durable, err)
	}
	return nil
}

// PurgeSubject removes every message on a subject.
//
// ⚠ FOR TEST ISOLATION, NOT FOR ROUTINE USE. It DESTROYS UNPROCESSED WORK.
//
// A WorkQueue stream retains a message until it is acked, so a run that was
// killed mid-delivery leaves messages behind. The next run then consumes one of
// those instead of its own, and the symptom is bizarre: a redelivery-backoff
// test that measured 30s starts reporting 2.6ms, because the "redelivery" is
// actually a stale message arriving first.
//
// Deleting the consumer is not enough — that clears the subscription, not the
// backlog. Both are needed to claim a subject deterministically.
func (b *Bus) PurgeSubject(ctx context.Context, stream, subject string) error {
	s, err := b.js.Stream(ctx, stream)
	if err != nil {
		if errors.Is(err, jetstream.ErrStreamNotFound) {
			return nil
		}
		return fmt.Errorf("bus: stream %s: %w", stream, err)
	}
	if err := s.Purge(ctx, jetstream.WithPurgeSubject(subject)); err != nil {
		return fmt.Errorf("bus: purge %s on %s: %w", subject, stream, err)
	}
	return nil
}

// ReleaseFilterSubject deletes every consumer bound to a filter subject.
//
// ⚠ EXISTS BECAUSE OF THE WORKQUEUE CONSTRAINT.
//
// A WorkQueue stream permits exactly ONE consumer per filter subject, so a
// durable left behind by a previous worker fleet — or by a test run — blocks
// the next one from starting with a different durable name. NATS reports
// "filtered consumer not unique on workqueue stream", which is accurate and
// says nothing about what to do.
//
// Used by TESTS to claim a subject deterministically, and by operators retiring
// a fleet. NOT for routine use: deleting a live fleet's consumer drops its
// in-flight deliveries.
func (b *Bus) ReleaseFilterSubject(ctx context.Context, stream, subject string) error {
	s, err := b.js.Stream(ctx, stream)
	if err != nil {
		return fmt.Errorf("bus: stream %s: %w", stream, err)
	}

	names := s.ConsumerNames(ctx)
	var toDelete []string
	for name := range names.Name() {
		info, err := s.Consumer(ctx, name)
		if err != nil {
			continue
		}
		if info.CachedInfo().Config.FilterSubject == subject {
			toDelete = append(toDelete, name)
		}
	}
	if err := names.Err(); err != nil {
		return fmt.Errorf("bus: listing consumers on %s: %w", stream, err)
	}

	for _, name := range toDelete {
		if err := b.DeleteConsumer(ctx, stream, name); err != nil {
			return err
		}
	}
	return nil
}

// Handler processes one message.
//
// The RETURN VALUE decides the message's fate, and getting it wrong is
// expensive in both directions:
//
//	nil        ack — done, remove from the queue
//	ErrRetry   nak with backoff — transient, try again
//	any other  TERMINATE — permanent, send to the DLQ, do NOT burn retries
//
// Terminating on a permanent error is the important half. A config-schema
// violation naked four times costs 10 minutes of backoff and three container
// starts before failing anyway, and it delays every job behind it.
type Handler func(ctx context.Context, msg jetstream.Msg) error

// ErrRetry marks a failure as transient.
var ErrRetry = errors.New("retryable failure")

// Consume runs a handler over a consumer until the context is cancelled.
func (b *Bus) Consume(ctx context.Context, consumer jetstream.Consumer,
	dlqSubject string, handler Handler,
) error {
	cc, err := consumer.Consume(func(msg jetstream.Msg) {
		b.dispatch(ctx, msg, dlqSubject, handler)
	})
	if err != nil {
		return fmt.Errorf("bus: consume: %w", err)
	}
	defer cc.Stop()

	<-ctx.Done()
	return nil
}

// dispatch runs one message through the handler and decides its fate.
func (b *Bus) dispatch(ctx context.Context, msg jetstream.Msg, dlqSubject string, handler Handler) {
	err := handler(ctx, msg)

	switch {
	case err == nil:
		if ackErr := msg.Ack(); ackErr != nil {
			// The work IS done; the ack failed. The message will be
			// redelivered, and idempotency is what makes that harmless — which
			// is exactly why idempotency is not optional.
			_ = ackErr
		}

	case errors.Is(err, ErrRetry):
		meta, metaErr := msg.Metadata()
		if metaErr == nil && meta.NumDelivered >= MaxDeliver {
			// Out of attempts. Route to the DLQ ourselves rather than letting
			// the message expire silently: a poison message that vanishes is a
			// production failure with no artifact to diagnose it from.
			b.toDLQ(ctx, msg, dlqSubject, err)
			_ = msg.Ack()
			return
		}

		// ⚠ NakWithDelay, NOT Nak.
		//
		// A bare Nak() redelivers IMMEDIATELY. The consumer's BackOff setting
		// governs ack_wait EXPIRY — a worker that died silently — not an
		// explicit nak, so a failing job would spin as fast as the consumer can
		// loop: three attempts in milliseconds, all four delivery attempts
		// burned before the dependency it is waiting on has blinked.
		//
		// Measured: the retry test completed in 0.05s against a schedule whose
		// first step is 30 seconds.
		_ = msg.NakWithDelay(backoffFor(metaErr, meta))

	default:
		// Permanent. Terminate immediately — do not burn the retry budget on
		// something that cannot succeed.
		b.toDLQ(ctx, msg, dlqSubject, err)
		if termErr := msg.Term(); termErr != nil {
			_ = msg.Ack()
		}
	}
}

// backoffFor returns the delay before the next attempt.
//
// Indexed by delivery count, so the schedule is 30s, 2m, 8m — matching the
// consumer's BackOff configuration, which covers the other redelivery path
// (ack_wait expiry). Both routes must use the same schedule or the observed
// behaviour depends on how the worker happened to fail.
func backoffFor(metaErr error, meta *jetstream.MsgMetadata) time.Duration {
	if metaErr != nil || meta == nil {
		return backoff[0]
	}
	// NumDelivered is 1 on the first attempt, so the first nak waits backoff[0].
	//
	// Clamped BEFORE the conversion: NumDelivered is uint64, and a value past
	// MaxInt would wrap to a negative index. It cannot realistically get there
	// with max_deliver=4, but a conversion that is only safe because of a
	// setting elsewhere is the kind of thing that breaks when the setting
	// changes.
	delivered := meta.NumDelivered
	if delivered > uint64(len(backoff)) {
		return backoff[len(backoff)-1]
	}
	if delivered == 0 {
		return backoff[0]
	}
	return backoff[delivered-1]
}

// toDLQ copies a message to the dead-letter stream with the reason attached.
func (b *Bus) toDLQ(ctx context.Context, msg jetstream.Msg, subject string, cause error) {
	if subject == "" {
		return
	}

	dlqMsg := nats.NewMsg(subject)
	dlqMsg.Data = msg.Data()
	dlqMsg.Header.Set("Encorebom-Dlq-Reason", truncateHeader(cause.Error()))
	dlqMsg.Header.Set("Encorebom-Original-Subject", msg.Subject())
	if meta, err := msg.Metadata(); err == nil {
		dlqMsg.Header.Set("Encorebom-Delivery-Count", fmt.Sprint(meta.NumDelivered))
	}

	// Best effort: if the DLQ publish fails there is nothing further to do, and
	// failing the handler over it would turn a diagnosis aid into an outage.
	_, _ = b.js.PublishMsg(ctx, dlqMsg)
}

// truncateHeader bounds a header value. Error text is attacker-influenced and
// NATS headers are not a place for unbounded strings.
func truncateHeader(s string) string {
	const max = 512
	s = sanitizeHeader(s)
	if len(s) > max {
		return s[:max] + "…"
	}
	return s
}

// sanitizeHeader strips characters that would break header framing.
func sanitizeHeader(s string) string {
	out := make([]rune, 0, len(s))
	for _, r := range s {
		if r == '\r' || r == '\n' || r == 0 {
			out = append(out, ' ')
			continue
		}
		out = append(out, r)
	}
	return string(out)
}
