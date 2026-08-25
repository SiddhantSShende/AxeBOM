package oidcauth

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	jose "github.com/go-jose/go-jose/v4"
)

// ServiceTokenSource mints access tokens for one of our own components.
//
// It replaces auth.Issuer.MintService. The shape of the problem is unchanged —
// campaign calls scan-orchestrator, fetcher calls project, and both need a
// credential — but the credential is now issued by ZITADEL against a private
// key rather than signed with the HMAC secret every service shared.
//
// ---------------------------------------------------------------------------
// ⚠ THE HOST HEADER IS LOAD-BEARING, AND THIS IS THE SUBTLEST PART OF THE
// WHOLE INTEGRATION.
//
// ZITADEL builds the `iss` claim from the host of the request that asked for
// the token. A token minted by calling the container directly on :58080 carries
// `iss: http://localhost:58080`; the browser, arriving through the reverse
// proxy, gets `iss: http://localhost:5173`. Those are two different issuers and
// a verifier configured for one rejects the other.
//
// Services live inside the compose network and cannot resolve the public
// origin, so they connect to the container by service name and OVERRIDE the
// Host header to the public value. ZITADEL then mints exactly the issuer the
// browser would have got, and one verifier configuration covers both.
//
// The alternative — accepting two issuers — would mean the check no longer
// pins which ZITADEL minted the token, which is most of what checking `iss` is
// for.
type ServiceTokenSource struct {
	tokenURL string
	audience string
	scopes   []string
	client   *http.Client

	userID string
	keyID  string
	key    *rsa.PrivateKey

	mu      sync.Mutex
	token   string
	expires time.Time
}

// ServiceTokenConfig configures the minter.
type ServiceTokenConfig struct {
	// KeyPath is the machine-user JSON key written by `axebom iam bootstrap`.
	KeyPath string
	// TokenURL is reachable from this process, e.g. http://zitadel-api:8080.
	// The /oauth/v2/token path is appended.
	BaseURL string
	// Issuer is the PUBLIC issuer. It becomes both the assertion audience and
	// the Host header, so the minted token's `iss` matches what verifiers
	// expect. See the type comment.
	Issuer string
	// ProjectID is added to the token audience so our own resource servers
	// accept it.
	ProjectID  string
	HTTPClient *http.Client
}

type machineKeyFile struct {
	Type   string `json:"type"`
	KeyID  string `json:"keyId"`
	Key    string `json:"key"`
	UserID string `json:"userId"`
}

// NewServiceTokenSource loads a machine key and prepares to mint.
func NewServiceTokenSource(cfg ServiceTokenConfig) (*ServiceTokenSource, error) {
	if cfg.KeyPath == "" {
		return nil, errors.New("oidcauth: no service key path configured")
	}
	if cfg.Issuer == "" || cfg.ProjectID == "" {
		return nil, errors.New("oidcauth: service tokens need both an issuer and a project id")
	}

	raw, err := os.ReadFile(cfg.KeyPath) //nolint:gosec // an operator-configured path
	if err != nil {
		return nil, fmt.Errorf("oidcauth: read service key %s: %w", cfg.KeyPath, err)
	}
	var kf machineKeyFile
	if err := json.Unmarshal(raw, &kf); err != nil {
		return nil, fmt.Errorf("oidcauth: parse service key %s: %w", cfg.KeyPath, err)
	}
	if kf.UserID == "" || kf.KeyID == "" || kf.Key == "" {
		return nil, fmt.Errorf("oidcauth: service key %s is missing userId, keyId or key", cfg.KeyPath)
	}

	key, err := parseRSAPrivateKey(kf.Key)
	if err != nil {
		return nil, fmt.Errorf("oidcauth: service key %s: %w", cfg.KeyPath, err)
	}

	issuer := strings.TrimRight(cfg.Issuer, "/")

	base := strings.TrimRight(cfg.BaseURL, "/")
	if base == "" {
		base = issuer
	}

	httpClient := cfg.HTTPClient
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 10 * time.Second}
	}
	// The same override the key fetcher uses, for the same reason and by the
	// same code — see the publicHost transport. Two hand-rolled copies of one
	// rule is how the second call site ends up without it.
	httpClient, err = withPublicHost(httpClient, issuer, base)
	if err != nil {
		return nil, err
	}

	return &ServiceTokenSource{
		tokenURL: base + "/oauth/v2/token",
		audience: issuer,
		scopes: []string{
			"openid",
			// Without the project audience scope our own resource servers
			// reject the token: it is valid, but not for us.
			fmt.Sprintf("urn:zitadel:iam:org:project:id:%s:aud", cfg.ProjectID),
			// ⚠ AND WITHOUT THIS ONE THE TOKEN CARRIES NO ROLES AT ALL.
			//
			// The project has role assertion enabled, which covers users
			// signing in through an application. A machine user authenticating
			// by JWT profile has no application, so the roles claim is only
			// added when it is asked for by scope — and a service token with
			// no roles is one RequireService correctly refuses, which reads as
			// a broken machine user rather than a missing scope.
			"urn:zitadel:iam:org:projects:roles",
		},
		client: httpClient,
		userID: kf.UserID,
		keyID:  kf.KeyID,
		key:    key,
	}, nil
}

// Token returns a cached access token, minting a new one when needed.
func (s *ServiceTokenSource) Token(ctx context.Context) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	// A minute of headroom. A token that expires in flight fails the call it
	// was fetched for, and the retry looks like an intermittent auth fault.
	if s.token != "" && time.Now().Add(time.Minute).Before(s.expires) {
		return s.token, nil
	}

	assertion, err := s.assertion()
	if err != nil {
		return "", err
	}

	form := url.Values{
		"grant_type": {"urn:ietf:params:oauth:grant-type:jwt-bearer"},
		"scope":      {strings.Join(s.scopes, " ")},
		"assertion":  {assertion},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.tokenURL,
		strings.NewReader(form.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := s.client.Do(req)
	if err != nil {
		return "", fmt.Errorf("oidcauth: mint service token: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("oidcauth: mint service token: %s: %s",
			resp.Status, strings.TrimSpace(string(body)))
	}

	var out struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int64  `json:"expires_in"`
	}
	if err := json.Unmarshal(body, &out); err != nil {
		return "", fmt.Errorf("oidcauth: decode token response: %w", err)
	}
	if out.AccessToken == "" {
		return "", errors.New("oidcauth: the token response carried no access_token")
	}

	s.token = out.AccessToken
	s.expires = time.Now().Add(time.Duration(out.ExpiresIn) * time.Second)
	return s.token, nil
}

// assertion builds the private-key JWT that authenticates the machine user.
func (s *ServiceTokenSource) assertion() (string, error) {
	signer, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.RS256, Key: s.key},
		(&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", s.keyID),
	)
	if err != nil {
		return "", fmt.Errorf("oidcauth: build assertion signer: %w", err)
	}

	now := time.Now()
	// ⚠ NEVER MORE THAN AN HOUR. ZITADEL enforces `exp` strictly, and when
	// `exp` is further than an hour out it falls back to `iat` — so a
	// long-lived assertion stops working an hour after it was issued rather
	// than at the expiry it declares. Ten minutes sidesteps the whole rule.
	claims := map[string]any{
		"iss": s.userID,
		"sub": s.userID,
		"aud": s.audience,
		"iat": now.Add(-30 * time.Second).Unix(),
		"exp": now.Add(10 * time.Minute).Unix(),
	}
	payload, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	obj, err := signer.Sign(payload)
	if err != nil {
		return "", fmt.Errorf("oidcauth: sign assertion: %w", err)
	}
	return obj.CompactSerialize()
}

func parseRSAPrivateKey(pemText string) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode([]byte(pemText))
	if block == nil {
		return nil, errors.New("no PEM block found")
	}
	// ZITADEL emits PKCS#1 ("BEGIN RSA PRIVATE KEY"), but accept PKCS#8 too so
	// a re-wrapped key is not a mystery failure.
	if key, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		return key, nil
	}
	any, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("not a PKCS#1 or PKCS#8 private key: %w", err)
	}
	key, ok := any.(*rsa.PrivateKey)
	if !ok {
		return nil, errors.New("the key is not RSA")
	}
	return key, nil
}
