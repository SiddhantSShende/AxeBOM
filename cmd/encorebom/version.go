package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"runtime"
	"runtime/debug"
)

// Build metadata, injected at release time via -ldflags.
//
// ADR-0002 makes this non-cosmetic: for a compliance product, provenance IS the
// product. A report must be able to assert which build produced it, and a
// binary reporting "dev" cannot make that claim. This is the same reason we
// consume upstream scanners as signed release artifacts rather than source
// builds — a locally-built syft reports version "unknown" for exactly this
// reason and breaks the same guarantee.
var (
	Version   = "dev"
	Commit    = "unknown"
	BuildDate = "unknown"
)

type versionInfo struct {
	Version   string `json:"version"`
	Commit    string `json:"commit"`
	BuildDate string `json:"build_date"`
	GoVersion string `json:"go_version"`
	Platform  string `json:"platform"`
}

func buildInfo() versionInfo {
	v := versionInfo{
		Version:   Version,
		Commit:    Commit,
		BuildDate: BuildDate,
		GoVersion: runtime.Version(),
		Platform:  runtime.GOOS + "/" + runtime.GOARCH,
	}
	// `go build` without ldflags still records VCS state, so a developer build
	// is identifiable even though it is not a release.
	if bi, ok := debug.ReadBuildInfo(); ok {
		for _, s := range bi.Settings {
			switch s.Key {
			case "vcs.revision":
				if v.Commit == "unknown" {
					v.Commit = s.Value
				}
			case "vcs.time":
				if v.BuildDate == "unknown" {
					v.BuildDate = s.Value
				}
			case "vcs.modified":
				if s.Value == "true" {
					v.Commit += "-dirty"
				}
			}
		}
	}
	return v
}

func runVersion(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("version", flag.ExitOnError)
	asJSON := fs.Bool("json", false, "emit JSON")
	if err := fs.Parse(args); err != nil {
		return err
	}

	v := buildInfo()
	if *asJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(v)
	}

	fmt.Printf("encorebom %s\n", v.Version)
	fmt.Printf("  commit:     %s\n", v.Commit)
	fmt.Printf("  built:      %s\n", v.BuildDate)
	fmt.Printf("  go:         %s\n", v.GoVersion)
	fmt.Printf("  platform:   %s\n", v.Platform)
	return nil
}
