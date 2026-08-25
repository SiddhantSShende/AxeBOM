// Package trigger starts scans on behalf of a campaign.
//
// ⚠ ONE SCAN PER PROJECT, AND PARTIAL SUCCESS IS RECORDED AS PARTIAL SUCCESS.
//
// A campaign over five projects that fails on the third must not discard the
// two scans it already started. Those scans are running; the orchestrator will
// finish them and produce reports whether or not this code returns an error.
// Reporting the whole run as failed would leave the product asserting that
// nothing happened while two scans burn CPU and two reports appear from
// nowhere — the same class of dishonesty as an SBOM that silently omits an
// ecosystem.
//
// So the return is (started scans, error), and both can be non-empty. The
// scheduler records the ids it got.
package trigger

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/axebom/axebom/libs/go-shared/oidcauth"
	"github.com/axebom/axebom/services/campaign/internal/scheduler"
)

// Trigger calls the scan service.
type Trigger struct {
	client  *http.Client
	baseURL string
	// token mints the service-to-service credential.
	//
	// ⚠ IT TAKES NO TENANT. A ZITADEL machine token belongs to the AxeBOM
	// organisation and carries no customer; the tenant this run acts for goes
	// on the request as X-AxeBOM-Tenant, which the middleware honours only
	// for a verified service principal.
	token func(ctx context.Context) (string, error)
}

// Options configure a Trigger.
type Options struct {
	BaseURL string
	Client  *http.Client
	Token   func(ctx context.Context) (string, error)
}

// New builds a Trigger.
func New(opts Options) (*Trigger, error) {
	if opts.BaseURL == "" {
		return nil, fmt.Errorf("trigger: the scan service base URL is required")
	}
	if opts.Token == nil {
		return nil, fmt.Errorf("trigger: a token source is required")
	}
	client := opts.Client
	if client == nil {
		// A bounded timeout, not none. A scan-creation call that hangs holds
		// the scheduler's dispatch loop, and the leader lock with it.
		client = &http.Client{Timeout: 30 * time.Second}
	}
	return &Trigger{
		client:  client,
		baseURL: strings.TrimRight(opts.BaseURL, "/"),
		token:   opts.Token,
	}, nil
}

// Trigger starts one scan per project in the campaign.
//
// ⚠ scheduledFor IS PART OF THE INTERFACE AND IS DELIBERATELY NOT SENT.
//
// The scan carries its campaign as provenance, and the RUN carries the
// occurrence. Putting a formatted timestamp in the scan request as well would
// give the same fact two representations that can disagree — and the one the
// idempotency key depended on would be the formatted copy, which is the fragile
// one. The parameter stays so a future caller cannot be surprised by its
// absence from the contract.
func (t *Trigger) Trigger(
	ctx context.Context, c scheduler.Campaign, runID string, _ time.Time,
) ([]string, error) {
	token, err := t.token(ctx)
	if err != nil {
		return nil, fmt.Errorf("mint service token: %w", err)
	}

	var started []string
	var failures []string

	for _, projectID := range c.ProjectIDs {
		scanID, err := t.startScan(ctx, token, c, runID, projectID)
		if err != nil {
			failures = append(failures, fmt.Sprintf("%s: %v", projectID, err))
			continue
		}
		started = append(started, scanID)
	}

	if len(failures) > 0 {
		// ⚠ THE STARTED SCANS ARE RETURNED ALONGSIDE THE ERROR. See the package
		// comment: they are running regardless of what this function says.
		return started, fmt.Errorf(
			"%d of %d projects could not be scanned: %s",
			len(failures), len(c.ProjectIDs), strings.Join(failures, "; "))
	}
	return started, nil
}

type scanRequest struct {
	ProjectID   string   `json:"project_id"`
	BOMTypes    []string `json:"bom_types"`
	TriggeredBy string   `json:"triggered_by"`
	TriggerRef  string   `json:"trigger_ref"`
}

type scanResponse struct {
	ID string `json:"id"`
}

func (t *Trigger) startScan(
	ctx context.Context, token string, c scheduler.Campaign,
	runID, projectID string,
) (string, error) {
	body, err := json.Marshal(scanRequest{
		ProjectID: projectID,
		BOMTypes:  c.BOMTypes,
		// docs/01-DATA-MODEL.md: triggered_by is CHECKed against this
		// vocabulary, and trigger_ref is the campaign — so a scan's provenance
		// answers "why does this exist?" without a join.
		TriggeredBy: "campaign",
		TriggerRef:  c.ID,
	})
	if err != nil {
		return "", err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		t.baseURL+"/v1/scans", bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	// Which tenant this run acts for. See Trigger.token.
	req.Header.Set(oidcauth.HeaderServiceTenant, c.TenantID)

	// ⚠ THE IDEMPOTENCY KEY IS DERIVED FROM THE RUN AND THE PROJECT, NOT
	// GENERATED. A dispatch that starts three scans and then loses its
	// connection will be retried; a fresh random key each time would create
	// three more. Keying on (run, project) means the retry returns the ORIGINAL
	// scan — which is the same idempotency argument as
	// UNIQUE (campaign_id, scheduled_for), one layer down.
	//
	// scheduled_for is deliberately NOT in the key: the run id already encodes
	// it, and including a formatted timestamp would make the key sensitive to
	// how that timestamp is rendered.
	req.Header.Set("Idempotency-Key", runID+":"+projectID)

	resp, err := t.client.Do(req)
	if err != nil {
		return "", fmt.Errorf("call scan service: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	// A bounded read: an error body from a service that is misbehaving should
	// not be able to exhaust this process's memory.
	payload, err := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	if err != nil {
		return "", fmt.Errorf("read scan response: %w", err)
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", fmt.Errorf("scan service returned %d: %s",
			resp.StatusCode, strings.TrimSpace(string(payload)))
	}

	var out scanResponse
	if err := json.Unmarshal(payload, &out); err != nil {
		return "", fmt.Errorf("decode scan response: %w", err)
	}
	if out.ID == "" {
		return "", fmt.Errorf("scan service accepted the request but returned no scan id")
	}
	return out.ID, nil
}
