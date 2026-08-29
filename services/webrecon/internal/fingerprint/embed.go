package fingerprint

import _ "embed"

// EmbeddedSignatures is the vendored retire.js signature database, compiled
// directly into the binary.
//
// ⚠ WHY EMBEDDED, NOT toolctl-RESOLVED AT RUNTIME LIKE A REAL TOOL. This is a
// single ~550 KB JSON data file, not a goreleaser-style multi-platform
// executable release — it does not fit toolctl's binary/container pinning
// machinery (see signatures/PROVENANCE.md). go:embed requires the file to
// live inside this package's own directory tree, which is why the canonical
// copy is signatures/retire-js-jsrepository.json rather than under OSINT/ —
// OSINT/tools.manifest.yaml's `retire-js-signatures` library entry still
// documents it in the roster and points here.
//
//go:embed signatures/retire-js-jsrepository.json
var EmbeddedSignatures []byte
