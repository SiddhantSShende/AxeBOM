package main

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/axebom/axebom/libs/go-shared/reportsig"
)

// runVerify checks a report artifact against its detached signature.
//
// ⚠ THIS COMMAND IS FOR THE PERSON RECEIVING THE REPORT, NOT FOR US.
//
// It therefore reaches nothing: no database, no Vault, no network. Everything
// it needs is the three files a customer was given — the artifact, the
// signature, and the published public key. A verifier that had to call our API
// would be verifying our claim that our claim is true.
func runVerify(_ context.Context, args []string) error {
	fs := flag.NewFlagSet("verify", flag.ContinueOnError)
	sigPath := fs.String("signature", "", "path to the detached signature (default: <artifact>.sig.json)")
	keyPath := fs.String("public-key", "", "path to the published Ed25519 public key")
	keyInline := fs.String("public-key-base64", "", "the published Ed25519 public key, base64")
	quiet := fs.Bool("quiet", false, "print nothing; report the result through the exit code")
	fs.Usage = func() {
		_, _ = fmt.Fprint(os.Stderr, verifyUsage)
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return err
	}

	if fs.NArg() != 1 {
		fs.Usage()
		return errors.New("expected exactly one artifact path")
	}
	artifactPath := fs.Arg(0)

	if *sigPath == "" {
		*sigPath = artifactPath + ".sig.json"
	}

	publicKey, err := loadPublicKey(*keyPath, *keyInline)
	if err != nil {
		return err
	}

	envelope, err := loadEnvelope(*sigPath)
	if err != nil {
		return err
	}

	artifact, err := os.Open(artifactPath) //nolint:gosec // the path is the operator's argument; that is the command
	if err != nil {
		return fmt.Errorf("opening the artifact: %w", err)
	}
	defer func() { _ = artifact.Close() }()

	result, err := reportsig.VerifyReader(envelope, artifact, publicKey)
	if err != nil {
		if !*quiet {
			_, _ = fmt.Fprintf(stderr, "VERIFICATION FAILED\n\n  artifact:  %s\n  signature: %s\n\n%v\n",
				artifactPath, *sigPath, err)
			_, _ = fmt.Fprint(stderr, failureHint(err))
		}
		// ⚠ A DISTINCT EXIT CODE. A pipeline must be able to tell a signature
		// that did not verify from a path that does not exist; treating both as
		// 1 turns a typo into an apparent forgery, and — worse — an operator who
		// learns to ignore exit 1 from a missing file learns to ignore a real
		// verification failure.
		return exitError{code: 3}
	}

	if *quiet {
		return nil
	}
	printResult(stdout, artifactPath, *sigPath, result)
	return nil
}

// stdout and stderr are variables so the tests can capture what a consumer
// actually reads — the wording of a verification result IS the deliverable
// here, and asserting on an error value would not check it.
var (
	stdout io.Writer = os.Stdout
	stderr io.Writer = os.Stderr
)

// failureHint explains what a particular failure means, because "signature does
// not verify" and "artifact does not match" call for completely different
// responses from whoever is holding the file.
func failureHint(err error) string {
	switch {
	case errors.Is(err, reportsig.ErrArtifactMismatch):
		return "\nThe signature is well-formed but describes a different file. Either the\n" +
			"artifact was modified after it was signed, or the signature belongs to a\n" +
			"different download. Do not treat this artifact as the one that was issued.\n"
	case errors.Is(err, reportsig.ErrSignatureInvalid):
		return "\nThe signature does not verify under the supplied public key. Either the\n" +
			"signature was forged, or you are checking against the wrong key — compare\n" +
			"the key id in the signature file against the published key material.\n"
	default:
		return ""
	}
}

// printResult reports what was verified, and how much it is worth.
func printResult(w io.Writer, artifactPath, sigPath string, r reportsig.Result) {
	_, _ = fmt.Fprintf(w, "Signature verified.\n\n")
	_, _ = fmt.Fprintf(w, "  artifact:    %s\n", artifactPath)
	_, _ = fmt.Fprintf(w, "  signature:   %s\n", sigPath)
	_, _ = fmt.Fprintf(w, "  key id:      %s\n", r.KeyID)
	_, _ = fmt.Fprintf(w, "  report:      %s\n", r.Statement.ReportID)
	_, _ = fmt.Fprintf(w, "  format:      %s\n", r.Statement.Format)
	_, _ = fmt.Fprintf(w, "  sha256:      %s\n", r.Statement.SHA256)
	_, _ = fmt.Fprintf(w, "  size:        %d bytes\n", r.Statement.SizeBytes)
	_, _ = fmt.Fprintf(w, "  generated:   %s\n", r.Statement.GeneratedAt)
	_, _ = fmt.Fprintf(w, "  profile:     %s revision %d\n",
		r.Statement.ProfileID, r.Statement.ProfileRevision)
	_, _ = fmt.Fprintf(w, "  produced by: %s %s\n", r.Statement.ToolName, r.Statement.ToolVersion)

	// ⚠ A DEVELOPMENT SIGNATURE MUST NOT READ AS A PRODUCTION ONE.
	//
	// Verification against a locally generated key is a correct cryptographic
	// result and a worthless assurance. Printing the same clean pass would let
	// an unsigned pipeline look signed.
	if !r.Trusted {
		_, _ = fmt.Fprintf(w, "\n  ⚠ THIS IS A DEVELOPMENT SIGNATURE.\n"+
			"    Key id %q marks a key generated locally, not the published\n"+
			"    AxeBOM signing key. It proves the file is unmodified since it\n"+
			"    was signed and nothing about who signed it.\n", r.KeyID)
	}

	_, _ = fmt.Fprintf(w, "\nWhat this proves: the artifact is byte-for-byte the one signed under this\n"+
		"key, for this report, in this format. It says nothing about whether the\n"+
		"report's contents are correct — for that, read the Engine Coverage section,\n"+
		"which states what the scan could not see.\n")
}

// loadPublicKey reads the published key from a file or the command line.
//
// ⚠ IT IS NEVER READ FROM THE SIGNATURE FILE. An attacker who can replace the
// signature can replace an embedded public key just as easily, and the check
// would then pass on every forgery. The envelope deliberately does not carry
// one, so there is nothing here to be tempted by.
func loadPublicKey(path, inline string) (ed25519.PublicKey, error) {
	var raw []byte

	switch {
	case path != "" && inline != "":
		return nil, errors.New("give either -public-key or -public-key-base64, not both")
	case path != "":
		data, err := os.ReadFile(path) //nolint:gosec // an operator-supplied path is the point
		if err != nil {
			return nil, fmt.Errorf("reading the public key: %w", err)
		}
		raw, err = decodeKey(strings.TrimSpace(string(data)))
		if err != nil {
			return nil, err
		}
	case inline != "":
		var err error
		raw, err = decodeKey(strings.TrimSpace(inline))
		if err != nil {
			return nil, err
		}
	default:
		return nil, errors.New(
			"no public key given: pass -public-key <file> or -public-key-base64 <key>.\n" +
				"The key is published alongside the report; it is deliberately NOT " +
				"carried inside the signature file, because a signature that supplies " +
				"its own verification key proves nothing")
	}

	if len(raw) != ed25519.PublicKeySize {
		return nil, fmt.Errorf(
			"the public key is %d bytes; an Ed25519 public key is %d",
			len(raw), ed25519.PublicKeySize)
	}
	return ed25519.PublicKey(raw), nil
}

// decodeKey accepts base64 or hex, because a key copied from a web page arrives
// as whichever the reader's tooling produced.
//
// ⚠ THE TWO ENCODINGS OVERLAP, SO "TRY BASE64 FIRST" IS WRONG.
//
// A 64-character hex string is also valid base64 — every hex digit is in the
// base64 alphabet and 64 is a multiple of 4 — so a hex-encoded Ed25519 key
// decodes cleanly as base64 into 48 meaningless bytes. The first version of
// this did exactly that and rejected correct keys with a length complaint.
//
// The disambiguator is the RESULT: exactly one interpretation yields a 32-byte
// key, so both are tried and the one that produces a usable key wins.
func decodeKey(s string) ([]byte, error) {
	var candidates [][]byte
	if raw, err := hex.DecodeString(s); err == nil {
		candidates = append(candidates, raw)
	}
	if raw, err := base64.StdEncoding.DecodeString(s); err == nil {
		candidates = append(candidates, raw)
	}
	if len(candidates) == 0 {
		return nil, errors.New("the public key is neither base64 nor hex")
	}

	for _, raw := range candidates {
		if len(raw) == ed25519.PublicKeySize {
			return raw, nil
		}
	}
	// None was the right size. Return the first so the caller reports the
	// length, which is the useful complaint.
	return candidates[0], nil
}

func loadEnvelope(path string) (reportsig.Envelope, error) {
	data, err := os.ReadFile(path) //nolint:gosec // an operator-supplied path is the point
	if err != nil {
		return reportsig.Envelope{}, fmt.Errorf("reading the signature: %w", err)
	}
	var env reportsig.Envelope
	if err := json.Unmarshal(data, &env); err != nil {
		return reportsig.Envelope{}, fmt.Errorf("the signature file is not readable: %w", err)
	}
	return env, nil
}

const verifyUsage = `usage: axebom verify [flags] <artifact>

Check a report artifact against its detached signature. Reaches no network, no
database and no Vault — everything it needs is the artifact, the signature file
and the published public key.

Exit codes: 0 verified, 1 usage or I/O error, 3 verification failed.

flags:
`
