package events

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"time"
)

// JSON Schema generation for the three envelopes.
//
// ⚠ GENERATED FROM THE GO TYPES, NOT HAND-WRITTEN.
//
// A hand-written schema is a second definition of the same thing, and the two
// drift the moment somebody adds a field to one. Deriving from the struct means
// the published schema cannot describe something the code does not send.
//
// The Python workers consume these: without a published schema, the agreement
// between a Python worker and a Go orchestrator lives in prose, and prose does
// not fail a build.

// SchemaDoc is a minimal JSON Schema document.
//
// Hand-rolled rather than pulling a reflection library: we need draft-2020-12
// with three object types, and a dependency for that is more surface than the
// forty lines below.
type SchemaDoc struct {
	Schema      string         `json:"$schema"`
	ID          string         `json:"$id"`
	Title       string         `json:"title"`
	Description string         `json:"description"`
	Type        string         `json:"type"`
	Properties  map[string]any `json:"properties"`
	Required    []string       `json:"required"`

	// ⚠ ALWAYS TRUE. Unknown fields are ignored, never fatal: a newer publisher
	// must not break older consumers, or the schema can never gain a field
	// without a synchronised deploy of every service.
	AdditionalProperties bool `json:"additionalProperties"`
}

// GenerateSchemas writes the three schema files into dir.
func GenerateSchemas(dir string) ([]string, error) {
	docs := []struct {
		file        string
		title       string
		description string
		sample      any
		required    []string
	}{
		{
			file:  "scan-job-v1.schema.json",
			title: "ScanJobV1",
			description: "One unit of scan work: exactly ONE engine against ONE " +
				"content-addressed archive (ADR-0004). There is no credential field " +
				"and there never will be — engine containers receive an archive and " +
				"nothing else (ADR-0008).",
			sample: ScanJobV1{},
			required: []string{
				"schema_version", "job_id", "scan_id", "tenant_id", "project_id",
				"family", "engine", "attempt", "deadline_at", "output",
			},
		},
		{
			file:  "scan-event-v1.schema.json",
			title: "ScanEventV1",
			description: "An ADVISORY progress event. The database is the source of " +
				"truth; no event is ever required for correctness. `seq` is monotonic " +
				"per job_id so consumers can reorder and DETECT gaps. `message` never " +
				"contains a user path, a repository URL, or anything from the scanned " +
				"code — event streams reach browsers and logs.",
			sample:   ScanEventV1{},
			required: []string{"schema_version", "scan_id", "tenant_id", "seq", "ts", "phase"},
		},
		{
			file:  "scan-result-v1.schema.json",
			title: "ScanResultV1",
			description: "What one engine produced. `partial` is a FIRST-CLASS STATUS, " +
				"not an error: 11 of 12 ecosystems covered is useful output plus a " +
				"known gap, and both must survive into the report. " +
				"`engine_db_version` is REQUIRED for vulnerability engines — a finding " +
				"that cannot be dated is not defensible.",
			sample: ScanResultV1{},
			required: []string{
				"schema_version", "job_id", "scan_id", "tenant_id",
				"engine", "engine_version", "status",
			},
		},
	}

	if err := os.MkdirAll(dir, 0o750); err != nil {
		return nil, fmt.Errorf("create schema directory: %w", err)
	}

	written := make([]string, 0, len(docs))
	for _, d := range docs {
		doc := SchemaDoc{
			Schema:      "https://json-schema.org/draft/2020-12/schema",
			ID:          "https://schemas.encorebom.io/" + d.file,
			Title:       d.title,
			Description: d.description,
			Type:        "object",
			Properties:  propertiesOf(reflect.TypeOf(d.sample)),
			Required:    d.required,
			// See the field comment. Never false.
			AdditionalProperties: true,
		}

		data, err := json.MarshalIndent(doc, "", "  ")
		if err != nil {
			return nil, err
		}
		data = append(data, '\n')

		path := filepath.Join(dir, d.file)
		if err := os.WriteFile(path, data, 0o600); err != nil {
			return nil, fmt.Errorf("write %s: %w", path, err)
		}
		written = append(written, path)
	}

	return written, nil
}

// propertiesOf derives JSON Schema properties from a struct type.
func propertiesOf(t reflect.Type) map[string]any {
	props := map[string]any{}
	if t == nil || t.Kind() != reflect.Struct {
		return props
	}

	for i := 0; i < t.NumField(); i++ {
		f := t.Field(i)
		name, ok := jsonName(f)
		if !ok {
			continue
		}
		props[name] = schemaFor(f.Type)
	}
	return props
}

func jsonName(f reflect.StructField) (string, bool) {
	tag := f.Tag.Get("json")
	if tag == "-" || tag == "" {
		return "", false
	}
	name, _, _ := strings.Cut(tag, ",")
	if name == "" {
		return "", false
	}
	return name, true
}

// schemaFor maps a Go type to a JSON Schema fragment.
func schemaFor(t reflect.Type) map[string]any {
	switch t.Kind() {
	case reflect.String:
		return map[string]any{"type": "string"}
	case reflect.Bool:
		return map[string]any{"type": "boolean"}
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		return map[string]any{"type": "integer"}
	case reflect.Float32, reflect.Float64:
		return map[string]any{"type": "number"}
	case reflect.Slice, reflect.Array:
		return map[string]any{"type": "array", "items": schemaFor(t.Elem())}
	case reflect.Map:
		return map[string]any{"type": "object", "additionalProperties": true}
	case reflect.Pointer:
		// A pointer is nullable. Rendering both types is what lets a consumer
		// distinguish "absent" from "explicitly null" — a distinction this
		// product cares about elsewhere too (`not-provided` is not the same as
		// missing).
		inner := schemaFor(t.Elem())
		return map[string]any{"type": []string{typeOf(inner), "null"}}
	case reflect.Struct:
		if t == reflect.TypeOf(time.Time{}) {
			// RFC3339 with a literal Z. No local time anywhere, ever.
			return map[string]any{"type": "string", "format": "date-time"}
		}
		return map[string]any{
			"type":                 "object",
			"properties":           propertiesOf(t),
			"additionalProperties": true,
		}
	case reflect.Interface:
		return map[string]any{}
	default:
		return map[string]any{}
	}
}

func typeOf(fragment map[string]any) string {
	if v, ok := fragment["type"].(string); ok {
		return v
	}
	return "object"
}

// SchemaFiles lists the generated file names, sorted.
func SchemaFiles() []string {
	names := []string{
		"scan-job-v1.schema.json",
		"scan-event-v1.schema.json",
		"scan-result-v1.schema.json",
	}
	sort.Strings(names)
	return names
}
