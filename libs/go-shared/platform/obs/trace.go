package obs

import (
	"context"
	"fmt"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.26.0"
	"go.opentelemetry.io/otel/trace"
)

// TraceConfig configures the tracer.
type TraceConfig struct {
	Service   string
	Namespace string
	Endpoint  string // OTLP gRPC. Empty disables tracing entirely.
	Env       string
	// SampleRatio is ignored in development, where everything is sampled.
	SampleRatio float64
}

// InitTracer configures the global tracer provider and returns a shutdown func.
//
// An empty Endpoint returns a no-op shutdown and leaves the global provider as
// OTel's default no-op. Tracing is genuinely optional: local development should
// not require a collector, and a service must never fail to start because a
// telemetry backend is down.
func InitTracer(ctx context.Context, cfg TraceConfig) (func(context.Context) error, error) {
	if cfg.Endpoint == "" {
		return func(context.Context) error { return nil }, nil
	}

	exp, err := otlptracegrpc.New(ctx,
		otlptracegrpc.WithEndpoint(cfg.Endpoint),
		otlptracegrpc.WithInsecure(), // TLS terminates at the collector sidecar
	)
	if err != nil {
		return nil, fmt.Errorf("otlp exporter: %w", err)
	}

	res, err := resource.Merge(resource.Default(), resource.NewWithAttributes(
		semconv.SchemaURL,
		semconv.ServiceName(cfg.Service),
		semconv.ServiceNamespace(cfg.Namespace),
		attribute.String("deployment.environment", cfg.Env),
	))
	if err != nil {
		return nil, fmt.Errorf("otel resource: %w", err)
	}

	sampler := sdktrace.AlwaysSample()
	if cfg.Env == "production" && cfg.SampleRatio > 0 && cfg.SampleRatio < 1 {
		// ParentBased keeps a whole trace together: once the edge decides to
		// sample, every downstream span follows. Sampling per-service
		// independently produces traces with holes, which are worse than none.
		sampler = sdktrace.ParentBased(sdktrace.TraceIDRatioBased(cfg.SampleRatio))
	}

	tp := sdktrace.NewTracerProvider(
		sdktrace.WithBatcher(exp, sdktrace.WithBatchTimeout(5*time.Second)),
		sdktrace.WithResource(res),
		sdktrace.WithSampler(sampler),
	)
	otel.SetTracerProvider(tp)

	// W3C traceparent + baggage. The same propagator is used for HTTP, gRPC and
	// NATS headers so one trace spans the whole scan pipeline.
	otel.SetTextMapPropagator(propagation.NewCompositeTextMapPropagator(
		propagation.TraceContext{},
		propagation.Baggage{},
	))

	return tp.Shutdown, nil
}

// Tracer returns a named tracer.
func Tracer(name string) trace.Tracer { return otel.Tracer(name) }

// Propagator returns the configured propagator, for injecting trace context
// into NATS message headers where there is no HTTP carrier.
func Propagator() propagation.TextMapPropagator { return otel.GetTextMapPropagator() }
