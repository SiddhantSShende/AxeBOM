package obs

import (
	"net/http"
	"strconv"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// Metrics holds the platform-wide collectors.
//
// The service-specific metrics that matter most in production are defined in
// their owning phases (docs/08-OPERATIONS.md §5):
//
//	scan_engine_status_total{engine,status}  — `unavailable` and `partial` rates
//	                                           are the product health signal;
//	                                           silent coverage loss is the
//	                                           failure mode that hurts most.
//	alias_cluster_size (histogram)           — a rising tail means over-merge,
//	                                           which under-reports vulns.
//	tenant_isolation_violation_total         — must be exactly zero. One
//	                                           occurrence is an incident.
type Metrics struct {
	Registry *prometheus.Registry

	HTTPRequests *prometheus.CounterVec
	HTTPDuration *prometheus.HistogramVec
	HTTPInFlight prometheus.Gauge

	// TenantViolations counts cross-tenant access attempts. Alert on any
	// increase; the expected value is zero forever.
	TenantViolations *prometheus.CounterVec
}

// NewMetrics builds a registry with Go runtime and process collectors plus the
// platform HTTP metrics.
func NewMetrics(service string) *Metrics {
	reg := prometheus.NewRegistry()
	reg.MustRegister(
		collectors.NewGoCollector(),
		collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}),
	)

	labels := prometheus.Labels{"service": service}

	m := &Metrics{
		Registry: reg,
		HTTPRequests: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name:        "http_requests_total",
			Help:        "Total HTTP requests by method, route and status.",
			ConstLabels: labels,
		}, []string{"method", "route", "status"}),

		HTTPDuration: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name: "http_request_duration_seconds",
			Help: "HTTP request latency.",
			// Wider than the default: report rendering and scan creation are
			// legitimately slow, and the default buckets top out at 10s.
			Buckets:     []float64{.005, .01, .025, .05, .1, .25, .5, 1, 2.5, 5, 10, 30, 60},
			ConstLabels: labels,
		}, []string{"method", "route"}),

		HTTPInFlight: prometheus.NewGauge(prometheus.GaugeOpts{
			Name:        "http_requests_in_flight",
			Help:        "Requests currently being served.",
			ConstLabels: labels,
		}),

		TenantViolations: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name:        "tenant_isolation_violation_total",
			Help:        "Cross-tenant access attempts. Expected value: zero. Alert on any increase.",
			ConstLabels: labels,
		}, []string{"resource"}),
	}

	reg.MustRegister(m.HTTPRequests, m.HTTPDuration, m.HTTPInFlight, m.TenantViolations)
	return m
}

// Handler serves the Prometheus endpoint.
func (m *Metrics) Handler() http.Handler {
	return promhttp.HandlerFor(m.Registry, promhttp.HandlerOpts{Registry: m.Registry})
}

// ObserveHTTP records one request.
//
// `route` must be the PATTERN ("/projects/{id}"), never the concrete path
// ("/projects/9f2c..."). A concrete path produces unbounded cardinality and
// will take down the metrics backend before it tells you anything useful.
func (m *Metrics) ObserveHTTP(method, route string, status int, d time.Duration) {
	m.HTTPRequests.WithLabelValues(method, route, strconv.Itoa(status)).Inc()
	m.HTTPDuration.WithLabelValues(method, route).Observe(d.Seconds())
}

// ServeMetrics starts the metrics listener on its own port, separate from the
// application listener so it is never exposed publicly by an ingress rule that
// only knows about the app port.
func ServeMetrics(addr string, m *Metrics) *http.Server {
	mux := http.NewServeMux()
	mux.Handle("/metrics", m.Handler())
	return &http.Server{
		Addr:              addr,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}
}
