package worker

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/nats-io/nats.go/jetstream"

	"github.com/axebom/axebom/libs/go-shared/bus"
	"github.com/axebom/axebom/libs/go-shared/platform/errs"
)

// RenderJobV1 is the render-job envelope.
//
// ⚠ IT CARRIES IDS AND NOTHING ELSE. Not the BOM, not the format options, not a
// pre-resolved storage key. The row is the source of truth, and a job that
// carried a copy of it would render yesterday's request after a retry — the
// message outlives the state it describes.
type RenderJobV1 struct {
	Schema   string `json:"schema"`
	TenantID string `json:"tenant_id"`
	ReportID string `json:"report_id"`
	// RequestedAt is for diagnostics only. Nothing branches on it: a job that
	// has been queued a long time is still the same job.
	RequestedAt string `json:"requested_at"`
}

// RenderJobSchema versions the envelope.
const RenderJobSchema = "axebom.report.render/v1"

// Validate refuses a job that cannot identify a report.
//
// ⚠ UNKNOWN FIELDS ARE IGNORED, the deliberate opposite of the HTTP handlers'
// DisallowUnknownFields. A typo'd field in a user's request is a mistake worth
// reporting; an unrecognized field in a queue message is a NEWER PUBLISHER, and
// rejecting it would mean no envelope could ever gain a field without a
// synchronised deploy (docs/02-CONTRACTS.md §2).
func (j RenderJobV1) Validate() error {
	if j.TenantID == "" {
		return errors.New("render job has no tenant id")
	}
	if j.ReportID == "" {
		return errors.New("render job has no report id")
	}
	return nil
}

// Publisher publishes render jobs. It satisfies service.Queue.
type Publisher struct {
	bus *bus.Bus
	now func() time.Time
}

// NewPublisher builds a publisher. A nil clock uses time.Now.
func NewPublisher(b *bus.Bus, now func() time.Time) *Publisher {
	if now == nil {
		now = time.Now
	}
	return &Publisher{bus: b, now: now}
}

// PublishRender queues one render.
//
// ⚠ THE MESSAGE ID IS THE REPORT ID, which makes the publish idempotent at the
// broker. A retried HTTP request that got as far as writing the row but not as
// far as acknowledging must not queue a second render of the same report —
// JetStream deduplicates on Nats-Msg-Id within its duplicate window.
func (p *Publisher) PublishRender(ctx context.Context, tenantID, reportID string) error {
	job := RenderJobV1{
		Schema:      RenderJobSchema,
		TenantID:    tenantID,
		ReportID:    reportID,
		RequestedAt: p.now().UTC().Format(time.RFC3339),
	}
	if err := job.Validate(); err != nil {
		return err
	}

	payload, err := json.Marshal(job)
	if err != nil {
		return fmt.Errorf("encoding the render job: %w", err)
	}
	return p.bus.Publish(ctx, bus.SubjectRender, reportID, payload)
}

// Consumer drains render jobs.
type Consumer struct {
	bus    *bus.Bus
	worker *Worker
	log    *slog.Logger
}

// NewConsumer builds a consumer.
func NewConsumer(b *bus.Bus, w *Worker, log *slog.Logger) *Consumer {
	if log == nil {
		log = slog.Default()
	}
	return &Consumer{bus: b, worker: w, log: log}
}

// DurableName is the shared consumer name.
//
// ⚠ ONE DURABLE FOR EVERY REPLICA, NOT ONE PER INSTANCE. A WorkQueue stream
// permits exactly one consumer per filter subject; NATS distributes between the
// members. A per-instance durable is rejected at startup — discovered against a
// real server in Phase 6 and recorded in docs/02-CONTRACTS.md §2.
const DurableName = "report-render"

// Run consumes until the context is cancelled.
func (c *Consumer) Run(ctx context.Context) error {
	consumer, err := c.bus.EnsureConsumer(ctx, bus.ConsumerConfig{
		Stream:        bus.StreamReports,
		Durable:       DurableName,
		FilterSubject: bus.SubjectRender,
		// ⚠ MUCH SHORTER THAN A SCAN JOB'S. A render is seconds of in-process
		// work, not minutes of container. Inheriting the 30-minute scan AckWait
		// would leave a report held hostage for half an hour whenever a worker
		// died mid-render.
		AckWait: 5 * time.Minute,
	})
	if err != nil {
		return fmt.Errorf("ensure the render consumer: %w", err)
	}

	c.log.Info("consuming render jobs",
		"stream", bus.StreamReports, "durable", DurableName, "subject", bus.SubjectRender)

	return c.bus.Consume(ctx, consumer, "report.dlq.render", c.handle)
}

// handle renders one job.
//
// ⚠ THE RETRYABLE / TERMINAL DISTINCTION IS THE WHOLE OF THIS FUNCTION.
//
// A malformed job and a Vault outage both fail. Retrying the first wastes three
// deliveries and ends in the DLQ regardless; NOT retrying the second turns a
// thirty-second blip into a failed report the customer has to request again. So
// the classification is explicit rather than "return err and hope".
func (c *Consumer) handle(ctx context.Context, msg jetstream.Msg) error {
	var job RenderJobV1
	if err := json.Unmarshal(msg.Data(), &job); err != nil {
		// Terminal: the same bytes will not parse on the next delivery. Straight
		// to the DLQ, which keeps it for thirty days because a poison message is
		// a bug report.
		c.log.Error("a render job could not be decoded", "error", err)
		return err
	}
	if err := job.Validate(); err != nil {
		c.log.Error("a render job is not usable", "error", err)
		return err
	}

	err := c.worker.Render(ctx, job.TenantID, job.ReportID)
	if err == nil {
		return nil
	}

	if retryable(err) {
		c.log.Warn("render failed on a dependency; it will be retried",
			"report_id", job.ReportID, "error", err)
		return fmt.Errorf("%w: %w", bus.ErrRetry, err)
	}

	// ⚠ THE ROW IS ALREADY `failed` — Worker.Render's deferred marker saw to
	// that before returning. Retrying now would find nothing to claim and log a
	// confusing "already claimed", so the message is acked and the failure lives
	// on the row where the customer can see it.
	c.log.Error("render failed terminally",
		"report_id", job.ReportID, "code", string(errs.From(err).Code), "error", err)
	return nil
}

// retryable reports whether a failure is worth another delivery.
//
// Only infrastructure. A BOM too large for a PDF will be too large next time;
// an object store that was briefly unreachable will not be.
func retryable(err error) bool {
	return errs.Is(err, errs.InternalDependency)
}
