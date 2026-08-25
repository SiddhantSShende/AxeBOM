package bus_test

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"sync/atomic"
	"testing"
	"time"

	"github.com/nats-io/nats.go/jetstream"

	"github.com/axebom/axebom/libs/go-shared/bus"
	"github.com/axebom/axebom/libs/go-shared/platform/config"
)

// Bus tests against a real NATS server.
//
// A mocked queue would prove nothing here: every property under test — dedup by
// message id, redelivery after nak, termination to the DLQ, the delivery
// counter — is a property of JetStream, not of our code calling it.

func newBus(t *testing.T) *bus.Bus {
	t.Helper()
	if os.Getenv("SKIP_BUS_TESTS") != "" {
		t.Skip("SKIP_BUS_TESTS is set")
	}
	cfg, err := config.LoadService("scan-orchestrator")
	if err != nil {
		t.Fatalf("config: %v", err)
	}

	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
	defer cancel()

	b, err := bus.Connect(ctx, bus.Config{URL: cfg.NATS.URL, Name: "bus-test"})
	if err != nil {
		t.Skipf("NATS unavailable (%v) — run `task dev`", err)
	}
	t.Cleanup(func() { _ = b.Close() })
	return b
}

// uniqueDurable is a per-run id used in message payloads, so one run's data is
// distinguishable from another's.
func uniqueDurable(t *testing.T) string {
	t.Helper()
	return fmt.Sprintf("test-%d", time.Now().UnixNano())
}

// exclusiveConsumer creates a consumer for a filter subject, first removing any
// leftover from a previous run.
//
// ⚠ A WORKQUEUE STREAM ALLOWS ONE CONSUMER PER FILTER SUBJECT.
//
// A second is rejected with "filtered consumer not unique on workqueue stream",
// so a durable left behind by an earlier run blocks the next one. Each test
// therefore uses its OWN family subject and a stable durable name, and deletes
// it on cleanup.
//
// ⚠ TESTS USE DEDICATED FAMILIES (scan.job.testpub, testdedup, testretry,
// testdlq), NEVER A PRODUCTION ONE.
//
// A WorkQueue stream permits exactly ONE consumer per filter subject. These
// tests used scan.job.sbom and scan.job.cbom, so the moment a real worker was
// running against the same NATS — which is now the normal state of a dev
// machine — every one of them failed at setup with
//
//	filtered consumer not unique on workqueue stream
//
// The alternative, ReleaseFilterSubject, would pass by DELETING THE LIVE
// WORKER'S CONSUMER and dropping its in-flight deliveries. A test suite that
// only passes when the application is stopped, and whose fix is to break the
// application, is the wrong shape. The stream filter is scan.job.> so any
// suffix is valid, and no worker consumes these.
func exclusiveConsumer(t *testing.T, b *bus.Bus, stream, subject, durable string) jetstream.Consumer {
	t.Helper()

	if err := b.DeleteConsumer(t.Context(), stream, durable); err != nil {
		t.Fatalf("clearing a leftover consumer: %v", err)
	}
	// ⚠ AND THE BACKLOG, not just the subscription.
	//
	// A WorkQueue stream keeps a message until it is acked, so a run killed
	// mid-delivery leaves messages on the subject. The next run consumes one of
	// THOSE instead of its own, and the symptom is baffling: the
	// redelivery-backoff assertion below measured 2.6ms instead of 30s, because
	// the "redelivery" was a stale message arriving first.
	if err := b.PurgeSubject(t.Context(), stream, subject); err != nil {
		t.Fatalf("clearing a leftover backlog: %v", err)
	}
	c, err := b.EnsureConsumer(t.Context(), bus.ConsumerConfig{
		Stream: stream, Durable: durable, FilterSubject: subject,
	})
	if err != nil {
		t.Fatalf("consumer: %v", err)
	}
	t.Cleanup(func() {
		_ = b.DeleteConsumer(context.Background(), stream, durable)
	})
	return c
}

func TestPublishAndConsume(t *testing.T) {
	b := newBus(t)
	durable := uniqueDurable(t)

	consumer := exclusiveConsumer(t, b, bus.StreamJobs, "scan.job.testpub", "test-publish-consume")

	payload, _ := json.Marshal(map[string]string{"job_id": durable})
	if err := b.Publish(t.Context(), "scan.job.testpub", durable, payload); err != nil {
		t.Fatalf("publish: %v", err)
	}

	received := make(chan []byte, 1)
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
	defer cancel()

	go func() {
		_ = b.Consume(ctx, consumer, "scan.dlq.testpub", func(_ context.Context, msg jetstream.Msg) error {
			received <- msg.Data()
			return nil
		})
	}()

	select {
	case data := <-received:
		var got map[string]string
		_ = json.Unmarshal(data, &got)
		if got["job_id"] != durable {
			t.Errorf("received the wrong message: %v", got)
		}
	case <-ctx.Done():
		t.Fatal("no message received within the timeout")
	}
}

// ⚠ THE DEDUPLICATION PROOF.
//
// An orchestrator that crashes after publishing but before recording the fact
// republishes on restart. Without a message id, that enqueues the same job
// twice and BOTH run — two containers, two artifact sets, doubled counts.
func TestDuplicatePublishIsDeduplicatedByMessageID(t *testing.T) {
	b := newBus(t)
	durable := uniqueDurable(t)

	consumer := exclusiveConsumer(t, b, bus.StreamJobs, "scan.job.testdedup", "test-dedup")

	payload := []byte(`{"work":"once"}`)
	msgID := "dedup-" + durable

	// The same message id, published three times — the crash-retry loop.
	for i := 0; i < 3; i++ {
		if err := b.Publish(t.Context(), "scan.job.testdedup", msgID, payload); err != nil {
			t.Fatalf("publish %d: %v", i, err)
		}
	}

	var delivered atomic.Int32
	ctx, cancel := context.WithTimeout(t.Context(), 8*time.Second)
	defer cancel()

	go func() {
		_ = b.Consume(ctx, consumer, "", func(_ context.Context, _ jetstream.Msg) error {
			delivered.Add(1)
			return nil
		})
	}()
	<-ctx.Done()

	if got := delivered.Load(); got != 1 {
		t.Errorf("the same message id was delivered %d times, want 1 — "+
			"a crash-retry loop would run every job repeatedly", got)
	}
}

// A transient failure must be retried; a permanent one must not burn the retry
// budget. Getting this backwards is expensive in both directions.
func TestRetryableFailureIsRedelivered(t *testing.T) {
	b := newBus(t)
	durable := uniqueDurable(t)

	consumer := exclusiveConsumer(t, b, bus.StreamJobs, "scan.job.testretry", "test-retry")

	if err := b.Publish(t.Context(), "scan.job.testretry", durable, []byte(`{"x":1}`)); err != nil {
		t.Fatalf("publish: %v", err)
	}

	var attempts atomic.Int32
	done := make(chan struct{})
	ctx, cancel := context.WithTimeout(t.Context(), 90*time.Second)
	defer cancel()

	go func() {
		_ = b.Consume(ctx, consumer, "scan.dlq.testretry", func(_ context.Context, _ jetstream.Msg) error {
			n := attempts.Add(1)
			if n == 1 {
				return bus.ErrRetry // transient
			}
			close(done)
			return nil
		})
	}()

	start := time.Now()
	select {
	case <-done:
		if attempts.Load() < 2 {
			t.Errorf("attempts = %d, want at least 2", attempts.Load())
		}

		// ⚠ THE BACKOFF MUST ACTUALLY APPLY.
		//
		// A bare Nak() redelivers IMMEDIATELY — the consumer's BackOff setting
		// governs ack_wait expiry, not an explicit nak. Without NakWithDelay a
		// failing job spins as fast as the consumer can loop, burning all four
		// delivery attempts in milliseconds against a dependency that has not
		// had time to recover. This test measured 0.05s before that was fixed.
		elapsed := time.Since(start)
		if elapsed < 20*time.Second {
			t.Errorf("redelivered after %v; the first backoff step is 30s, so an "+
				"immediate redelivery means the schedule is not being applied", elapsed)
		}
		t.Logf("redelivered after %v (first backoff step is 30s)", elapsed)

	case <-ctx.Done():
		t.Fatalf("no redelivery within the timeout (attempts=%d)", attempts.Load())
	}
}

// ⚠ A POISON MESSAGE MUST REACH THE DLQ.
//
// A message that vanishes is a production failure with no artifact to diagnose
// it from. 30-day retention on the DLQ exists because a poison message is a bug
// report.
func TestPermanentFailureGoesStraightToTheDLQ(t *testing.T) {
	b := newBus(t)
	durable := uniqueDurable(t)
	dlqSubject := "scan.dlq.testdlq"

	consumer := exclusiveConsumer(t, b, bus.StreamJobs, "scan.job.testdlq", "test-dlq-source")

	// A DLQ consumer, to observe what lands there. The DLQ is a Limits stream,
	// so it has no one-consumer-per-subject restriction — but the same helper
	// keeps runs from accumulating durables.
	dlqConsumer := exclusiveConsumer(t, b, bus.StreamDLQ, dlqSubject, "test-dlq-sink")

	marker := []byte(`{"poison":"` + durable + `"}`)
	if err := b.Publish(t.Context(), "scan.job.testdlq", durable, marker); err != nil {
		t.Fatalf("publish: %v", err)
	}

	var attempts atomic.Int32
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()

	go func() {
		_ = b.Consume(ctx, consumer, dlqSubject, func(_ context.Context, _ jetstream.Msg) error {
			attempts.Add(1)
			// A PERMANENT error — not ErrRetry.
			return fmt.Errorf("config schema violation: unknown field")
		})
	}()

	landed := make(chan jetstream.Msg, 1)
	go func() {
		_ = b.Consume(ctx, dlqConsumer, "", func(_ context.Context, msg jetstream.Msg) error {
			if string(msg.Data()) == string(marker) {
				landed <- msg
			}
			return nil
		})
	}()

	select {
	case msg := <-landed:
		// ⚠ THE IMPORTANT HALF: it reached the DLQ WITHOUT burning the retry
		// budget. Naking a permanent error four times costs ten minutes of
		// backoff and three container starts to learn nothing.
		if got := attempts.Load(); got != 1 {
			t.Errorf("a permanent failure was attempted %d times, want 1", got)
		}
		if reason := msg.Headers().Get("Axebom-Dlq-Reason"); reason == "" {
			t.Error("the DLQ message carries no reason; it is a bug report with the bug removed")
		}
		if orig := msg.Headers().Get("Axebom-Original-Subject"); orig != "scan.job.testdlq" {
			t.Errorf("original subject = %q", orig)
		}
	case <-ctx.Done():
		t.Fatalf("nothing reached the DLQ (attempts=%d)", attempts.Load())
	}
}

// Streams must be created idempotently: every service calls this on every
// start, so a second call must not fail.
func TestStreamsAreCreatedIdempotently(t *testing.T) {
	b := newBus(t)

	cfg, err := config.LoadService("scan-orchestrator")
	if err != nil {
		t.Fatalf("config: %v", err)
	}
	second, err := bus.Connect(t.Context(), bus.Config{URL: cfg.NATS.URL, Name: "bus-test-2"})
	if err != nil {
		t.Fatalf("a second Connect failed; streams are not created idempotently: %v", err)
	}
	_ = second.Close()

	if err := b.Ping(t.Context()); err != nil {
		t.Errorf("ping: %v", err)
	}
}

// Events are advisory and must not be delivered as work: they are BROADCAST to
// every listener, so the stream is Limits rather than WorkQueue.
func TestEventStreamIsBroadcastNotWorkQueue(t *testing.T) {
	b := newBus(t)

	scanID := uniqueDurable(t)
	subject := "scan.event." + scanID

	if err := b.PublishAdvisory(t.Context(), subject, []byte(`{"seq":1}`)); err != nil {
		t.Fatalf("publish advisory: %v", err)
	}

	// Two independent consumers must BOTH see it. Under WorkQueue retention
	// only one would, and a second browser session would silently see nothing.
	var got atomic.Int32
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()

	for i := 0; i < 2; i++ {
		// TWO consumers on the SAME subject — legal here precisely because the
		// event stream is Limits rather than WorkQueue, which is the property
		// under test.
		consumer, err := b.EnsureConsumer(t.Context(), bus.ConsumerConfig{
			Stream: bus.StreamEvents, Durable: fmt.Sprintf("%s-%d", scanID, i),
			FilterSubject: subject,
		})
		if err != nil {
			t.Fatalf("consumer %d: %v", i, err)
		}
		go func() {
			_ = b.Consume(ctx, consumer, "", func(_ context.Context, _ jetstream.Msg) error {
				got.Add(1)
				return nil
			})
		}()
	}

	deadline := time.After(8 * time.Second)
	for {
		if got.Load() >= 2 {
			return
		}
		select {
		case <-deadline:
			t.Fatalf("only %d of 2 consumers received the event; the event stream "+
				"is behaving as a work queue, so a second browser session sees nothing",
				got.Load())
		case <-time.After(200 * time.Millisecond):
		}
	}
}
