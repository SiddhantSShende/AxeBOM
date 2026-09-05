// Package pdftext reads the drawn strings back out of a PDF this product wrote.
//
// ⚠ IT EXISTS SO TWO TEST PACKAGES CAN SHARE ONE EXTRACTOR, NOT AS A FEATURE.
//
// `render` has always had this, privately, in pdf_test.go. The (format × BOM
// type) matrix test lives in `worker`, because that is the only package where
// all six formats are reachable — PDF, DOCX, XLSX and JSON through `render`,
// SPDX and CycloneDX through `toExportDocument`. Copying an extractor with
// zlib handling and PDF literal parsing into a second test file is how the two
// copies drift, and a drifted extractor fails open: it returns nothing, and
// every "is this value present" assertion then passes on an empty string.
//
// A full PDF parser would be a dependency added purely to read our own output.
// This inflates each content stream and pulls out the `(literal)` operands,
// which is all fpdf writes for a text-only document.
package pdftext

import (
	"bytes"
	"compress/zlib"
	"io"
	"strings"
)

// Extract returns every string literal drawn in the document, newline
// separated. An empty result means the extractor could not read the file —
// callers must treat that as a failure, never as "the text is not there".
func Extract(data []byte) string {
	var sb strings.Builder
	rest := data
	for {
		i := bytes.Index(rest, []byte("stream"))
		if i < 0 {
			break
		}
		body := bytes.TrimLeft(rest[i+len("stream"):], "\r\n")
		j := bytes.Index(body, []byte("endstream"))
		if j < 0 {
			break
		}
		sb.WriteString(literals(inflate(body[:j])))
		// ⚠ Advance past the WHOLE keyword. Leaving `rest` pointing at
		// `endstream` makes the next search match the `stream` inside it, so the
		// following block starts mid-object, fails to inflate, and is scanned as
		// raw compressed bytes — which yields garbage rather than an error, and
		// silently drops every page after the first.
		rest = body[j+len("endstream"):]
	}

	// Uncompressed literals too, for metadata strings outside content streams.
	sb.WriteString(literals(data))
	return sb.String()
}

// inflate zlib-decompresses a stream, returning it unchanged if it is not
// compressed.
func inflate(stream []byte) []byte {
	zr, err := zlib.NewReader(bytes.NewReader(stream))
	if err != nil {
		return stream
	}
	defer func() { _ = zr.Close() }()
	out, err := io.ReadAll(zr)
	if err != nil {
		return stream
	}
	return out
}

// literals extracts PDF string literals — `(text)` — from a byte range.
func literals(data []byte) string {
	var sb strings.Builder
	for i := 0; i < len(data); i++ {
		if data[i] != '(' {
			continue
		}
		j := i + 1
		var lit []byte
		for j < len(data) {
			if data[j] == '\\' && j+1 < len(data) {
				lit = append(lit, data[j+1])
				j += 2
				continue
			}
			if data[j] == ')' {
				break
			}
			lit = append(lit, data[j])
			j++
		}
		sb.Write(lit)
		sb.WriteByte('\n')
		i = j
	}
	return sb.String()
}
