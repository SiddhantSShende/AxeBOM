package handler

import (
	"encoding/json"
	"strings"

	"github.com/axebom/axebom/libs/go-shared/platform/errs"
	"github.com/axebom/axebom/services/aibom/internal/store"
)

// MethodModelSigning names the verifier whose output this parses.
//
// Recorded on every row rather than assumed, because a second verification
// method added later must not be indistinguishable from this one in a stored
// record — "verified" alone does not say verified BY WHAT.
const MethodModelSigning = "sigstore-model-signing"

// ParseModelSigningOutput reads a `model_signing verify` result into a record.
//
// ⚠ THE CUSTOMER RAN THE VERIFIER, NOT AxeBOM, AND THE RECORD SAYS SO.
//
// `model_signing verify` recomputes the digest of every model FILE and checks it
// against the signed manifest. AxeBOM never holds customer model weights — the
// scan sandbox sees a source tree and the enrichment plane sees a model
// identifier — so it cannot perform that check, and pretending otherwise would
// be the exact fabrication this product forbids. This is the `hbom-host-report`
// shape: the customer runs the tool where the artifact is, and AxeBOM ingests
// what it returned.
//
// ⚠ WHAT THIS BUYS OVER THE FREE-TEXT ELEMENT 19 FIELD IS REAL. `verified` is
// READ from the tool's output rather than typed by a person; a FAILED
// verification is recorded as a failure instead of being quietly not mentioned;
// and the signer identity, the issuer and the digest land on the record where a
// reviewer can check them against the signature they were shown.
//
// ⚠ IT DOES NOT ESTABLISH THAT THE SIGNATURE IS VALID. Whoever produced this
// JSON could have written anything in it. The record is evidence of a claim, at
// a moment, attributed to the person who uploaded it — which is more than a
// text box and less than a verification, and both halves have to be said.
func ParseModelSigningOutput(raw json.RawMessage) (store.Attestation, error) {
	if len(raw) == 0 {
		return store.Attestation{}, errs.New(errs.ValidationFieldRequired,
			"model_signing_output is required: this endpoint records what a verifier "+
				"returned, and there is nothing to record without it")
	}

	// The shape `model_signing verify --output json` produces. Every field is
	// optional: a failed run carries a reason and no identity, which is the
	// honest shape — a failed check establishes no signer.
	var out struct {
		Verified *bool  `json:"verified"`
		Status   string `json:"status"`
		Identity string `json:"identity"`
		// The tool spells the issuer both ways depending on version; reading one
		// would silently lose it on the other.
		IdentityProvider string `json:"identity_provider"`
		Issuer           string `json:"issuer"`
		Digest           string `json:"digest"`
		ModelDigest      string `json:"model_digest"`
		Error            string `json:"error"`
		Reason           string `json:"reason"`
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		return store.Attestation{}, errs.Wrap(err, errs.ValidationBodyMalformed,
			"model_signing_output is not a JSON object this endpoint can read")
	}

	// ⚠ NEVER DEFAULTS TO TRUE, the rule `normalize.ai_models.verified` already
	// carries. An output with no `verified` field and no recognisable success
	// status has not told us the verification passed, and treating silence as
	// success is how a compliance document ends up asserting something nobody
	// checked.
	verified := false
	switch {
	case out.Verified != nil:
		verified = *out.Verified
	case strings.EqualFold(out.Status, "ok"), strings.EqualFold(out.Status, "verified"),
		strings.EqualFold(out.Status, "success"):
		verified = true
	}

	att := store.Attestation{
		Verified:       verified,
		Method:         MethodModelSigning,
		SignerIdentity: out.Identity,
		SignerIssuer:   firstNonEmpty(out.IdentityProvider, out.Issuer),
		Digest:         firstNonEmpty(out.Digest, out.ModelDigest),
		Raw:            raw,
	}
	if !verified {
		att.FailureReason = firstNonEmpty(out.Error, out.Reason, out.Status,
			"the verifier's output did not report a successful verification")
		// A failed check establishes no signer. Keeping a parsed identity on a
		// failed row would let a reader take it for one that was confirmed.
		att.SignerIdentity = ""
		att.SignerIssuer = ""
	}
	return att, nil
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}
