package handler

import (
	"bufio"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/coder/websocket"
)

// TestNewParsesOriginHost guards New's frontendURL -> originHost parsing —
// the piece that feeds websocket.AcceptOptions.OriginPatterns in Progress.
// A silently-empty originHost reproduces the real bug (see
// TestOriginPatternsAcceptBrowserShapedMismatch's own doc comment): every
// real browser handshake gets a pre-101 403.
func TestNewParsesOriginHost(t *testing.T) {
	cases := []struct {
		name        string
		frontendURL string
		want        string
	}{
		{"typical dev URL", "https://192.168.30.202:5173", "192.168.30.202:5173"},
		{"localhost with scheme", "http://localhost:5173", "localhost:5173"},
		{"empty is left empty, not defaulted", "", ""},
		{"unparseable is left empty, not defaulted", "://not a url", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := New(nil, nil, nil, nil, nil, tc.frontendURL)
			if h.originHost != tc.want {
				t.Errorf("originHost = %q, want %q", h.originHost, tc.want)
			}
		})
	}
}

// TestOriginPatternsAcceptBrowserShapedMismatch is a regression guard for a
// real bug: services/scan-orchestrator/internal/handler/handler.go's
// Progress handler called websocket.Accept with InsecureSkipVerify:false and
// no OriginPatterns. coder/websocket's own same-origin check only
// auto-authorizes a handshake when the request's Host equals the Origin
// header's host — but in this deployment, services/gateway's reverse proxy
// (proxy.go's Rewrite) deliberately rewrites Host to the upstream's own
// address (scan-orchestrator:8093) before this handler ever sees the
// request, while the browser's real Origin header (the public-facing host,
// e.g. https://192.168.30.202:5173) is forwarded untouched by nginx and
// gateway alike. Host and Origin's host therefore NEVER matched for a real
// browser, and every handshake got a pre-101 403 — exactly Chrome's
// "WebSocket connection ... failed", on every attempt, regardless of scan
// speed. curl never reproduced it because curl sends no Origin header at
// all, which is what made this look fixed during earlier manual testing.
//
// This exercises the exact websocket.AcceptOptions shape Progress now uses,
// against a real hijacked connection (websocket.Accept needs http.Hijacker,
// which httptest.ResponseRecorder does not provide), with Host and Origin
// set independently — mirroring the real proxy topology — rather than
// through h.Progress directly, since that also requires a live-Postgres
// GetScan call this package's other tests don't stand up.
func TestOriginPatternsAcceptBrowserShapedMismatch(t *testing.T) {
	const publicOrigin = "https://192.168.30.202:5173"
	const rewrittenHost = "scan-orchestrator:8093"

	mux := http.NewServeMux()
	mux.HandleFunc("/progress", func(w http.ResponseWriter, r *http.Request) {
		conn, err := websocket.Accept(w, r, &websocket.AcceptOptions{
			InsecureSkipVerify: false,
			OriginPatterns:     []string{"192.168.30.202:5173"},
		})
		if err != nil {
			return // Accept already answered — 403 in the broken case.
		}
		_ = conn.Close(websocket.StatusNormalClosure, "")
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	addr := strings.TrimPrefix(srv.URL, "http://")

	handshake := func(t *testing.T, hostHeader, origin string) int {
		t.Helper()
		conn, err := net.Dial("tcp", addr)
		if err != nil {
			t.Fatalf("dial: %v", err)
		}
		defer conn.Close()

		req := fmt.Sprintf(
			"GET /progress HTTP/1.1\r\n"+
				"Host: %s\r\n"+
				"Origin: %s\r\n"+
				"Upgrade: websocket\r\n"+
				"Connection: Upgrade\r\n"+
				"Sec-WebSocket-Version: 13\r\n"+
				"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"+
				"\r\n", hostHeader, origin)
		if _, err := conn.Write([]byte(req)); err != nil {
			t.Fatalf("write: %v", err)
		}
		resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
		if err != nil {
			t.Fatalf("read response: %v", err)
		}
		defer func() { _ = resp.Body.Close() }()
		return resp.StatusCode
	}

	t.Run("Host rewritten by the proxy, Origin the real browser's — must succeed", func(t *testing.T) {
		got := handshake(t, rewrittenHost, publicOrigin)
		if got != http.StatusSwitchingProtocols {
			t.Errorf("status = %d, want %d (101) — this is the browser-shaped "+
				"mismatch OriginPatterns exists to authorize", got, http.StatusSwitchingProtocols)
		}
	})

	t.Run("a genuinely foreign Origin is still rejected — the check is not weakened", func(t *testing.T) {
		got := handshake(t, rewrittenHost, "https://evil.example.com")
		if got == http.StatusSwitchingProtocols {
			t.Errorf("status = %d, an unrelated origin must not be authorized", got)
		}
	})
}
