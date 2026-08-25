// Package signup lets a visitor create their own AxeBOM organisation.
//
// ---------------------------------------------------------------------------
// WHY THIS EXISTS NEXT TO ZITADEL'S OWN (DISABLED) REGISTRATION
//
// libs/go-shared/iam.ensureLoginPolicy turns OFF ZITADEL's built-in "Register
// new user" link, because a user created that way holds a role in NO
// organisation and the OIDC callback then refuses to complete
// (Errors.User.GrantRequired) — see the comment there for the full story.
// This package is the flow that was missing: it creates the ORGANISATION
// first, grants it the AxeBOM project, creates the user as that
// organisation's Owner, and only then hands the visitor to the normal
// Authorization Code + PKCE login. A visitor who finishes this form arrives
// at ZITADEL's password screen already holding a role, so the callback that
// used to fail now succeeds.
//
// ⚠ THIS ENDPOINT HOLDS THE SAME CREDENTIAL `axebom iam bootstrap` DOES.
// Creating a ZITADEL organisation is an instance-level operation and there is
// no narrower ZITADEL permission that grants "can create orgs" alone. The
// bootstrap machine key is mounted read-only into the gateway
// (deploy/compose/docker-compose.app.yml) and used ONLY through this package.
// That is a development-appropriate trade, made explicit here rather than
// silently: a deployment that wants this endpoint anywhere but a demo/dev
// stack needs a ZITADEL permission-model decision, not a code change — see
// config.OIDC.ProvisioningKeyPath, which defaults to unset (feature off).
package signup

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/mail"
	"strings"

	"github.com/axebom/axebom/libs/go-shared/authz"
	"github.com/axebom/axebom/libs/go-shared/iam"
	"github.com/axebom/axebom/libs/go-shared/platform/errs"
)

// maxBodyBytes bounds the request body. Five short strings need nothing close
// to this; it exists to reject an oversized payload before it is parsed.
const maxBodyBytes = 8 << 10

// request is the wire shape of POST /v1/auth/signup.
type request struct {
	OrganisationName string `json:"organisation_name"`
	Email            string `json:"email"`
	Password         string `json:"password"`
	GivenName        string `json:"given_name"`
	FamilyName       string `json:"family_name"`
}

// response is deliberately minimal: no ZITADEL id, no AxeBOM tenant id — that
// mapping is created lazily on the visitor's first sign-in (auth.identity_for,
// migrations/auth/0003_zitadel_identity.sql), so none of it exists yet at the
// moment this responds.
type response struct {
	OrganisationName string `json:"organisation_name"`
	Email            string `json:"email"`
}

// Handler returns the self-service signup endpoint.
//
// client is nil when ZITADEL_BOOTSTRAP_KEY is unset or the connection at
// startup failed — see buildIAMClient in ../../deps.go. The handler still
// exists in that case so the response is the same structured error every
// other half-configured endpoint gives (see services/gateway/internal/
// authconfig), not a 404 that reads like the route was never wired.
func Handler(client *iam.Client, projectID string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if client == nil || projectID == "" {
			errs.Write(w, r, errs.New(errs.InternalDependency,
				"self-service signup is not configured on this deployment"))
			return
		}

		var req request
		dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxBodyBytes))
		if err := dec.Decode(&req); err != nil {
			errs.Write(w, r, errs.Wrap(err, errs.ValidationBodyMalformed, "request body is not valid JSON"))
			return
		}

		if field := firstMissingField(req); field != "" {
			errs.Write(w, r, errs.New(errs.ValidationFieldRequired, field+" is required"))
			return
		}
		if _, err := mail.ParseAddress(req.Email); err != nil {
			errs.Write(w, r, errs.New(errs.ValidationFieldInvalid, "email is not a valid address"))
			return
		}

		orgName := strings.TrimSpace(req.OrganisationName)
		spec := iam.UserSpec{
			Email:      req.Email,
			GivenName:  req.GivenName,
			FamilyName: req.FamilyName,
			Password:   req.Password,
			// The person who creates the organisation owns it. Every other
			// member is invited by an Owner or Admin afterward — invite-only
			// beyond this one bootstrapping step (docs/05-SECURITY-MODEL.md).
			Role: authz.RoleOwner,
		}

		_, err := client.Signup(r.Context(), projectID, orgName, spec)
		switch {
		case err == nil:
			errs.WriteJSON(w, http.StatusCreated, response{
				OrganisationName: orgName,
				Email:            req.Email,
			})
		case errors.Is(err, iam.ErrOrgNameTaken):
			errs.Write(w, r, errs.New(errs.AuthOrgNameTaken,
				"an organisation named \""+orgName+"\" already exists"))
		case errors.Is(err, iam.ErrEmailTaken):
			errs.Write(w, r, errs.New(errs.AuthEmailTaken, "this email is already registered"))
		case isPasswordPolicy(err):
			// Surfaced from ZITADEL rather than duplicated here: the policy
			// (upper, lower, digit, symbol, minimum length) is configured on
			// the instance, and restating it here is how the two drift.
			errs.Write(w, r, errs.Wrap(err, errs.ValidationFieldInvalid,
				"password does not meet the password policy (upper case, lower case, a digit and a symbol)"))
		default:
			errs.Write(w, r, errs.Wrap(err, errs.InternalDependency, "could not create the organisation"))
		}
	}
}

// firstMissingField returns the first required field that is blank, or "" if
// none are.
func firstMissingField(req request) string {
	switch {
	case strings.TrimSpace(req.OrganisationName) == "":
		return "organisation_name"
	case strings.TrimSpace(req.Email) == "":
		return "email"
	case req.Password == "":
		return "password"
	case strings.TrimSpace(req.GivenName) == "":
		return "given_name"
	case strings.TrimSpace(req.FamilyName) == "":
		return "family_name"
	default:
		return ""
	}
}

// isPasswordPolicy reports whether ZITADEL rejected the password itself,
// rather than some other step of provisioning.
func isPasswordPolicy(err error) bool {
	return err != nil && strings.Contains(strings.ToLower(err.Error()), "password")
}
