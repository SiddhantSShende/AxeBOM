package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/encorebom/encorebom/libs/go-shared/platform/config"
)

// runHealth reports the readiness of every service in the stack.
//
// This exists because `docker compose ps` cannot answer the question. The Go
// services run on distroless/static — no shell, no curl — so they carry no
// HEALTHCHECK directive and compose can only report "Up", meaning the process
// has not exited. A service whose database connection is gone is still "Up".
//
// /readyz is where the truth is, and it distinguishes three states that matter:
//
//	up        every critical dependency answered
//	degraded  an OPTIONAL dependency is down; the service still serves
//	down      a critical dependency is gone; take it out of the load balancer
//
// The gateway reports its upstreams as optional on purpose, so "degraded" on
// the gateway names exactly which service is missing — see services/gateway/health.go.
func runHealth(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("health", flag.ContinueOnError)
	var (
		timeout = fs.Duration("timeout", 5*time.Second, "per-service timeout")
		asJSON  = fs.Bool("json", false, "emit machine-readable output")
		host    = fs.String("host", "localhost", "host the services are published on")
		inClus  = fs.Bool("in-cluster", false, "address each service by its own name (run inside the compose network)")
	)
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "Usage: encorebom health [--timeout 5s] [--json] [--host localhost] [--in-cluster]")
		fmt.Fprintln(os.Stderr, "\nProbes /readyz on every service and reports up | degraded | down.")
		fmt.Fprintln(os.Stderr, "\nOnly the gateway is published to the host in the compose stack, so from a")
		fmt.Fprintln(os.Stderr, "shell outside it every other service reads as unreachable. Use --in-cluster")
		fmt.Fprintln(os.Stderr, "from inside the compose network to address each service by its own name.")
	}
	if err := fs.Parse(args); err != nil {
		return exitError{code: 2, err: err}
	}

	targets := config.ServicePorts()
	names := make([]string, 0, len(targets))
	for name := range targets {
		names = append(names, name)
	}
	sort.Strings(names)

	results := make([]healthResult, len(names))
	var wg sync.WaitGroup
	for i, name := range names {
		wg.Add(1)
		go func(i int, name string) {
			defer wg.Done()
			// Inside the compose network a service answers on its own name at
			// its real port; from the host only the gateway is published.
			addr := *host
			port := targets[name]
			if *inClus {
				addr = name
			}
			results[i] = probe(ctx, addr, name, port, *timeout)
		}(i, name)
	}
	wg.Wait()

	if *asJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(results); err != nil {
			return err
		}
	} else {
		printHealth(results)
	}

	// Exit non-zero only on `down`. `degraded` is a real, serviceable state —
	// failing on it would make the command useless during a rolling restart,
	// which is exactly when someone runs it.
	for _, r := range results {
		if r.Status == "down" || r.Status == "unreachable" {
			return exitError{code: 1}
		}
	}
	return nil
}

type healthResult struct {
	Service string            `json:"service"`
	Port    int               `json:"port"`
	Status  string            `json:"status"`
	Checks  map[string]string `json:"checks,omitempty"`
	Error   string            `json:"error,omitempty"`
	TookMS  int64             `json:"took_ms"`
}

// readyzBody is the subset of the readiness payload this command reads.
type readyzBody struct {
	Status string `json:"status"`
	Checks map[string]struct {
		Status string `json:"status"`
		Error  string `json:"error"`
	} `json:"checks"`
}

func probe(ctx context.Context, host, name string, port int, timeout time.Duration) healthResult {
	res := healthResult{Service: name, Port: port}
	start := time.Now()
	defer func() { res.TookMS = time.Since(start).Milliseconds() }()

	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	url := fmt.Sprintf("http://%s:%d/readyz", host, port)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		res.Status, res.Error = "unreachable", err.Error()
		return res
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		// Distinguish "not running" from "running and unhealthy". Only the
		// second is a defect; the first is usually just a service you did not
		// start, and reporting it as a failure trains people to ignore this.
		res.Status = "unreachable"
		res.Error = compactDialError(err)
		return res
	}
	defer func() { _ = resp.Body.Close() }()

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))

	var parsed readyzBody
	if err := json.Unmarshal(body, &parsed); err != nil {
		res.Status = "down"
		res.Error = fmt.Sprintf("unparseable /readyz (HTTP %d)", resp.StatusCode)
		return res
	}

	res.Status = parsed.Status
	if len(parsed.Checks) > 0 {
		res.Checks = make(map[string]string, len(parsed.Checks))
		for k, v := range parsed.Checks {
			if v.Error != "" {
				res.Checks[k] = v.Status + ": " + v.Error
				continue
			}
			res.Checks[k] = v.Status
		}
	}
	return res
}

// compactDialError trims Go's verbose dial errors to the part that helps.
func compactDialError(err error) string {
	s := err.Error()
	if i := strings.LastIndex(s, ": "); i >= 0 && i+2 < len(s) {
		return s[i+2:]
	}
	return s
}

func printHealth(results []healthResult) {
	fmt.Println("EncoreBOM service readiness")
	fmt.Println()

	var up, degraded, bad int
	for _, r := range results {
		var mark string
		switch r.Status {
		case "up":
			mark, up = "  ok ", up+1
		case "degraded":
			mark, degraded = " warn", degraded+1
		default:
			mark, bad = " FAIL", bad+1
		}

		fmt.Printf("%s  %-20s :%-6d %s\n", mark, r.Service, r.Port, r.Status)
		if r.Error != "" {
			fmt.Printf("        %s\n", r.Error)
		}

		names := make([]string, 0, len(r.Checks))
		for k := range r.Checks {
			names = append(names, k)
		}
		sort.Strings(names)
		for _, k := range names {
			v := r.Checks[k]
			if strings.HasPrefix(v, "up") {
				continue // only the problems are worth the lines
			}
			fmt.Printf("        %-18s %s\n", k, v)
		}
	}

	fmt.Println()
	fmt.Printf("%d up, %d degraded, %d unavailable\n", up, degraded, bad)
	if degraded > 0 && bad == 0 {
		fmt.Println("degraded means an OPTIONAL dependency is down; the service still serves traffic")
	}
}
