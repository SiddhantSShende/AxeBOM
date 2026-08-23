// Command encorebom is the EncoreBOM operator CLI.
//
// It exists because the primary development machine has no `make` and no
// `task`, and PowerShell 5.1 has no `&&`. Rather than maintain parallel bash
// and PowerShell scripts that drift, anything a script would do lives here as
// a cross-platform Go subcommand. See CLAUDE.md §Conventions.
//
// Subcommands are added by the phase that needs them:
//
//	preflight              Phase 0  what is installed, what is missing
//	health                 Phase 0  per-service readiness across the stack
//	version                Phase 0
//	db migrate|reset|seed  Phase 1
//	profile lint|gen       Phase 1
//	toolctl sync|verify    Phase 2
//	docs lint              Phase 0
//	verify <report>        Phase 9  signature verification for consumers
package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"syscall"
)

// command is one subcommand.
type command struct {
	name    string
	summary string
	// phase records which build phase introduces the command, so `encorebom`
	// with no arguments doubles as an honest status board of what exists.
	phase int
	run   func(ctx context.Context, args []string) error
}

var commands []command

// exitError lets a command choose the process exit code.
//
// It exists so a pipeline can distinguish a failed CHECK from a failed RUN:
// `encorebom verify` exits 3 when a signature does not verify and 1 when the
// file is missing, and conflating the two would have a broken path read as a
// forgery.
type exitError struct {
	code int
	// err is optional. When nil, the command has already reported the failure
	// with the detail the user needs and main prints nothing further.
	err error
}

func (e exitError) Error() string {
	if e.err == nil {
		return fmt.Sprintf("exit %d", e.code)
	}
	return e.err.Error()
}

func (e exitError) Unwrap() error { return e.err }

func init() {
	commands = []command{
		{"preflight", "Report toolchain status and known environment gaps", 0, runPreflight},
		{"health", "Probe /readyz on every service and report up|degraded|down", 0, runHealth},
		{"version", "Print version and build information", 0, runVersion},
		{"docs", "Documentation tooling (lint)", 0, runDocs},
		{"db", "Migrations, reset, seed, RLS verification", 1, runDB},
		{"profile", "Validate and generate from the CERT-In compliance profile", 1, runProfile},
		{"toolctl", "Fetch, verify and probe pinned scanner artifacts", 2, runToolctl},
		{"schema", "Generate the published envelope JSON Schemas", 6, runSchema},
		{"sandbox", "Run a command in the scan sandbox (the bridge Python workers call)", 7, runSandbox},
		{"source", "Materialize a scan's source archive into a worker workspace", 7, runSource},
		{"verify", "Check a report artifact against its detached signature", 9, runVerify},
	}
}

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}

	name := os.Args[1]
	switch name {
	case "-h", "--help", "help":
		usage()
		return
	}

	for _, c := range commands {
		if c.name == name {
			if err := c.run(ctx, os.Args[2:]); err != nil {
				var ee exitError
				if errors.As(err, &ee) {
					// The command has already reported the failure in its own
					// words; a second, blunter line would bury it.
					if ee.err != nil {
						fmt.Fprintf(os.Stderr, "encorebom %s: %v\n", name, ee.err)
					}
					os.Exit(ee.code)
				}
				fmt.Fprintf(os.Stderr, "encorebom %s: %v\n", name, err)
				os.Exit(1)
			}
			return
		}
	}

	fmt.Fprintf(os.Stderr, "encorebom: unknown command %q\n\n", name)
	usage()
	os.Exit(2)
}

func usage() {
	fmt.Fprintf(os.Stderr, "EncoreBOM operator CLI (%s)\n\n", Version)
	fmt.Fprintln(os.Stderr, "Usage: encorebom <command> [flags]")
	fmt.Fprintln(os.Stderr, "\nCommands:")
	for _, c := range commands {
		fmt.Fprintf(os.Stderr, "  %-12s %s\n", c.name, c.summary)
	}
	fmt.Fprintln(os.Stderr, "\nNot yet implemented (see docs/STATE.md):")
	pending := []struct {
		name, summary string
		phase         int
	}{
		{"verify", "Verify a report's detached signature", 9},
	}
	for _, p := range pending {
		fmt.Fprintf(os.Stderr, "  %-12s %s (phase %d)\n", p.name, p.summary, p.phase)
	}
}
