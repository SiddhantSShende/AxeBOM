package main

import (
	"context"
	"flag"
	"fmt"

	"github.com/encorebom/encorebom/libs/go-shared/events"
)

// schemaCmd generates the published envelope schemas.
//
// They are DERIVED from the Go types rather than hand-written, so a published
// schema cannot describe something the code does not send. The Python workers
// consume them; without a published schema that agreement lives in prose, and
// prose does not fail a build.
func runSchema(ctx context.Context, args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: encorebom schema gen [flags]")
	}
	switch args[0] {
	case "gen":
		return schemaGen(args[1:])
	default:
		return fmt.Errorf("unknown schema subcommand %q (want: gen)", args[0])
	}
}

func schemaGen(args []string) error {
	fs := flag.NewFlagSet("schema", flag.ExitOnError)
	out := fs.String("out", "proto/schemas", "directory to write schemas into")
	if err := fs.Parse(args); err != nil {
		return err
	}

	written, err := events.GenerateSchemas(resolveFromRepoRoot(*out))
	if err != nil {
		return err
	}
	for _, p := range written {
		fmt.Println("  wrote", p)
	}
	fmt.Printf("\n%d envelope schemas generated from libs/go-shared/events\n", len(written))
	return nil
}
