package work

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/axebom/axebom/libs/go-shared/bus"
	"github.com/axebom/axebom/libs/go-shared/events"
	"github.com/axebom/axebom/libs/go-shared/platform/blob"
	"github.com/axebom/axebom/libs/go-shared/platform/config"
	"github.com/axebom/axebom/libs/go-shared/projectsource"
	"github.com/axebom/axebom/libs/go-shared/sandbox"
	"github.com/axebom/axebom/services/webrecon/internal/fingerprint"
)

// This is package `work` (internal, not `work_test`) specifically so these
// tests can reach resolveHosts/fingerprintAll directly — mirroring the
// fetcher's own work_test.go convention (materializeUpload/materializeURL) —
// rather than round-tripping through NATS, which real infra tests elsewhere
// in this codebase already cover for the publish/consume plumbing itself.

// refusingRunner fails the test if the sandbox is ever invoked — used to
// prove discovery-disabled truly never starts a container.
type refusingRunner struct{ t *testing.T }

func (rr refusingRunner) Run(context.Context, sandbox.Spec) (sandbox.Result, error) {
	rr.t.Fatal("the sandbox runner was invoked with discovery disabled")
	return sandbox.Result{}, nil
}
func (refusingRunner) Ping(context.Context) error { return nil }
func (refusingRunner) Close() error               { return nil }

// failingRunner simulates Docker being unreachable — discovery must degrade
// to the root host, not fail the whole job.
type failingRunner struct{}

func (failingRunner) Run(context.Context, sandbox.Spec) (sandbox.Result, error) {
	return sandbox.Result{}, errors.New("docker unreachable")
}
func (failingRunner) Ping(context.Context) error { return nil }
func (failingRunner) Close() error               { return nil }

type noopResolver struct{}

func (noopResolver) Resolve(context.Context, string, string) (projectsource.Source, error) {
	return projectsource.Source{}, errors.New("not used by these tests")
}

func testWorker(t *testing.T, runner sandbox.Runner) *Worker {
	t.Helper()
	w, err := New(Options{
		Bus:        fakeBus(t),
		Runner:     runner,
		Store:      fakeStore(t),
		Resolver:   noopResolver{},
		Signatures: fingerprint.EmbeddedSignatures,
		HTTPClient: http.DefaultClient, // tests target httptest servers on loopback
	})
	if err != nil {
		t.Fatalf("new worker: %v", err)
	}
	return w
}

// fakeBus/fakeStore connect to the real dev-stack infra (NATS, MinIO) — New
// requires non-nil values, but resolveHosts/fingerprintAll never call a
// method on either, matching the fetcher fixture's own reasoning.
func fakeBus(t *testing.T) *bus.Bus {
	t.Helper()
	if os.Getenv("SKIP_DB_TESTS") != "" {
		t.Skip("SKIP_DB_TESTS is set")
	}
	cfg, err := config.LoadService("webrecon")
	if err != nil {
		t.Fatalf("config: %v", err)
	}
	b, err := bus.Connect(t.Context(), bus.Config{URL: cfg.NATS.URL, Name: "webrecon-work-test"})
	if err != nil {
		t.Skipf("NATS unavailable (%v) — run `task dev`", err)
	}
	t.Cleanup(func() { _ = b.Close() })
	return b
}

func fakeStore(t *testing.T) *blob.Store {
	t.Helper()
	cfg, err := config.LoadService("webrecon")
	if err != nil {
		t.Fatalf("config: %v", err)
	}
	store, err := blob.Open(t.Context(), cfg.S3)
	if err != nil {
		t.Skipf("object storage unavailable (%v) — run `task dev`", err)
	}
	return store
}

func TestNewRequiresEveryDependency(t *testing.T) {
	base := Options{
		Bus: fakeBus(t), Runner: refusingRunner{t: t}, Store: fakeStore(t),
		Resolver: noopResolver{}, Signatures: fingerprint.EmbeddedSignatures,
	}

	tests := []struct {
		name   string
		mutate func(Options) Options
	}{
		{"no bus", func(o Options) Options { o.Bus = nil; return o }},
		{"no runner", func(o Options) Options { o.Runner = nil; return o }},
		{"no store", func(o Options) Options { o.Store = nil; return o }},
		{"no resolver", func(o Options) Options { o.Resolver = nil; return o }},
		{"no signatures", func(o Options) Options { o.Signatures = nil; return o }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := New(tt.mutate(base)); err == nil {
				t.Errorf("%s: expected an error, got none", tt.name)
			}
		})
	}
}

func TestNewRejectsAMalformedSignatureDatabase(t *testing.T) {
	_, err := New(Options{
		Bus: fakeBus(t), Runner: refusingRunner{t: t}, Store: fakeStore(t),
		Resolver: noopResolver{}, Signatures: []byte(`not json`),
	})
	if err == nil {
		t.Fatal("a malformed signature database was accepted")
	}
}

func TestResolveHostsWithDiscoveryDisabledNeverTouchesTheRunner(t *testing.T) {
	w := testWorker(t, refusingRunner{t: t}) // fails the test if Run is ever called

	src := projectsource.Source{RootURL: "https://example.com/", DiscoveryEnabled: false}
	hosts, err := w.resolveHosts(t.Context(), src, w.log)
	if err != nil {
		t.Fatalf("resolveHosts: %v", err)
	}
	if len(hosts) != 1 || hosts[0] != "example.com" {
		t.Errorf("hosts = %v, want exactly [example.com]", hosts)
	}
}

// Docker being unreachable degrades discovery to the root host rather than
// failing the job — discovery is an enhancement over the one page the
// tenant explicitly registered, not a precondition for fingerprinting it.
func TestResolveHostsDegradesToRootWhenDiscoveryFails(t *testing.T) {
	w := testWorker(t, failingRunner{})

	src := projectsource.Source{
		RootURL: "https://example.com/", DiscoveryEnabled: true, MaxHosts: 25,
	}
	hosts, err := w.resolveHosts(t.Context(), src, w.log)
	if err != nil {
		t.Fatalf("resolveHosts: %v", err)
	}
	if len(hosts) != 1 || hosts[0] != "example.com" {
		t.Errorf("hosts = %v, want exactly [example.com] after a discovery failure", hosts)
	}
}

func TestResolveHostsStopsAtMaxHostsBeforeInvokingDiscovery(t *testing.T) {
	// max_hosts=1 and the root host already fills it — subfinder must never
	// run at all, not run and then be truncated.
	w := testWorker(t, refusingRunner{t: t})

	src := projectsource.Source{
		RootURL: "https://example.com/", DiscoveryEnabled: true, MaxHosts: 1,
	}
	hosts, err := w.resolveHosts(t.Context(), src, w.log)
	if err != nil {
		t.Fatalf("resolveHosts: %v", err)
	}
	if len(hosts) != 1 {
		t.Errorf("hosts = %v, want exactly 1 (max_hosts)", hosts)
	}
}

func TestFingerprintAllDetectsALibraryOnTheRootPage(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`<html><body><script>/*! jQuery v3.5.1 */</script></body></html>`))
	}))
	defer srv.Close()

	w := testWorker(t, refusingRunner{t: t})
	src := projectsource.Source{RootURL: srv.URL, DiscoveryEnabled: false}

	job := events.ScanJobV1{ScanID: "scan-1", TenantID: "tenant-1", JobID: "job-1"}
	doc := w.fingerprintAll(t.Context(), job, src, []string{fingerprint.HostOf(srv.URL)})
	if len(doc.Hosts) != 1 {
		t.Fatalf("hosts = %d, want 1", len(doc.Hosts))
	}
	host := doc.Hosts[0]
	if host.Status != "succeeded" {
		t.Errorf("status = %q, want succeeded", host.Status)
	}
	if len(host.Libraries) != 1 || host.Libraries[0].Name != "jquery" {
		t.Errorf("libraries = %+v, want exactly [jquery]", host.Libraries)
	}
	if host.Libraries[0].NPMPurl != "pkg:npm/jquery@3.5.1" {
		t.Errorf("npm_purl = %q, want pkg:npm/jquery@3.5.1", host.Libraries[0].NPMPurl)
	}
}

func TestFingerprintAllRecordsAnUnreachableHostWithoutFailingTheOthers(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`<html><body><script>/*! jQuery v3.5.1 */</script></body></html>`))
	}))
	defer srv.Close()

	w := testWorker(t, refusingRunner{t: t})
	src := projectsource.Source{RootURL: srv.URL, DiscoveryEnabled: false}

	// A second, discovered host on a port nothing listens on — refused
	// immediately, unlike an unrouted address that would wait out
	// perRequestTimeout and make this test slow for no extra coverage
	// (that path is exercised directly, with a controlled client timeout, by
	// fingerprint.TestFetchAndFingerprintReportsUnreachableStatus).
	job := events.ScanJobV1{ScanID: "scan-1", TenantID: "tenant-1", JobID: "job-1"}
	doc := w.fingerprintAll(t.Context(), job, src, []string{fingerprint.HostOf(srv.URL), "127.0.0.1:1"})
	if len(doc.Hosts) != 2 {
		t.Fatalf("hosts = %d, want 2", len(doc.Hosts))
	}
	if doc.Hosts[0].Status != "succeeded" {
		t.Errorf("first host status = %q, want succeeded", doc.Hosts[0].Status)
	}
	if doc.Hosts[1].Status == "succeeded" {
		t.Error("the unreachable second host was reported as succeeded")
	}
}
