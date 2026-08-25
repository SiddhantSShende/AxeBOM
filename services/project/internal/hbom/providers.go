package hbom

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"
)

// Enrichment is what a provider knows about one manufacturer part number.
// Matches workers/hbom/providers/base.py's Enrichment dataclass.
type Enrichment struct {
	MPN                  string
	ManufacturerName     string
	ManufacturerLocation string
	Origin               string
	TechnologyNode       string
	// RoHS, CE, REACH…
	Compliance []string
	// Active, NRND, obsolete. Not a CERT-In element, but the single most
	// useful fact a parts database holds for a BOM that has to stay accurate.
	Lifecycle    string
	DatasheetURL string
	// Which provider said so. Carried into the component's provenance.
	Source string
}

// Provider looks up manufacturer part numbers. Matches
// workers/hbom/providers/base.py's PartDataProvider protocol.
type Provider interface {
	Name() string
	// Configured reports whether this provider can be called. Checked before
	// every batch — an unconfigured provider must be skipped silently rather
	// than called with an empty credential.
	Configured() bool
	// Lookup resolves part numbers. A missing key means "not found", never an
	// error — and a provider failure (network, timeout, malformed response)
	// must not surface as an import failure, so Lookup itself never errors.
	Lookup(ctx context.Context, mpns []string) map[string]Enrichment
}

// ManualProvider looks nothing up. Always configured, because it needs
// nothing — the shipping default and the tested path, per
// workers/hbom/providers/manual.py.
type ManualProvider struct{}

func (ManualProvider) Name() string     { return "manual" }
func (ManualProvider) Configured() bool { return true }
func (ManualProvider) Lookup(context.Context, []string) map[string]Enrichment {
	return map[string]Enrichment{}
}

// Resolve picks the provider to use: the first configured one, or `manual`.
// Matches workers/hbom/providers/base.py's resolve().
func Resolve(providers ...Provider) Provider {
	for _, p := range providers {
		if p != nil && p.Configured() {
			return p
		}
	}
	return ManualProvider{}
}

// Apply fills EMPTY fields on a component and its descendants from a lookup.
//
// ⚠ EMPTY FIELDS ONLY. The customer's value wins, always; every value this
// writes is recorded in EnrichedFields so a report can say where it came
// from. Matches workers/hbom/providers/base.py's apply().
func Apply(root *Component, enrichments map[string]Enrichment) {
	root.Walk(0, func(_ int, node *Component) {
		key := strings.ToLower(strings.TrimSpace(node.ModelNumber))
		if key == "" {
			return
		}
		found, ok := enrichments[key]
		if !ok {
			return
		}

		for _, p := range []struct{ attr, val string }{
			{"manufacturer_name", found.ManufacturerName},
			{"manufacturer_location", found.ManufacturerLocation},
			{"origin", found.Origin},
			{"technology_node", found.TechnologyNode},
		} {
			if p.val != "" && attrValue(node, p.attr) == "" {
				setAttr(node, p.attr, p.val)
				if node.EnrichedFields == nil {
					node.EnrichedFields = map[string]string{}
				}
				node.EnrichedFields[p.attr] = found.Source
			}
		}

		// Compliance is a union rather than a replacement: a customer
		// asserting RoHS and a provider asserting CE are both true.
		if len(found.Compliance) > 0 {
			existing := make(map[string]bool, len(node.Compliance))
			for _, c := range node.Compliance {
				existing[strings.ToLower(c)] = true
			}
			var added []string
			for _, c := range found.Compliance {
				if !existing[strings.ToLower(c)] {
					added = append(added, c)
				}
			}
			if len(added) > 0 {
				node.Compliance = append(node.Compliance, added...)
				if node.EnrichedFields == nil {
					node.EnrichedFields = map[string]string{}
				}
				node.EnrichedFields["compliance"] = found.Source
			}
		}
	})
}

// MPNs returns every distinct part number in a tree, lower-cased.
//
// ⚠ DEDUPED BEFORE THE CALL. The same capacitor appears in four
// sub-assemblies of a real board; looking it up four times burns a
// commercial quota the customer pays for, to learn the same thing.
func MPNs(root *Component) []string {
	seen := make(map[string]bool)
	var out []string
	root.Walk(0, func(_ int, node *Component) {
		key := strings.ToLower(strings.TrimSpace(node.ModelNumber))
		if key == "" || seen[key] {
			return
		}
		seen[key] = true
		out = append(out, key)
	})
	return out
}

// ---------------------------------------------------------------------------
// Nexar
// ---------------------------------------------------------------------------

// NexarProvider looks up parts through Nexar (Altium, formerly Octopart).
//
// ⚠ COMMERCIAL, QUOTA-LIMITED, AND OPTIONAL — resolve() falls back to manual.
//
// ⚠ THIS ADAPTER HAS NEVER BEEN RUN AGAINST THE LIVE API, exactly like its
// Python counterpart in workers/hbom/providers/nexar.py, which this ports
// field-for-field. It is written against Nexar's published GraphQL schema and
// tested against hand-built responses only.
type NexarProvider struct {
	Token   string
	Client  *http.Client
	Timeout time.Duration
}

// NexarFromEnv builds a provider from NEXAR_TOKEN, matching
// NexarProvider.from_env() in Python.
func NexarFromEnv() NexarProvider {
	return NexarProvider{Token: strings.TrimSpace(os.Getenv("NEXAR_TOKEN"))}
}

func (n NexarProvider) Name() string     { return "nexar" }
func (n NexarProvider) Configured() bool { return n.Token != "" }

const (
	nexarURL       = "https://api.nexar.com/graphql"
	nexarBatchSize = 20
)

const nexarQuery = `
query MultiMatch($queries: [SupPartMatchQuery!]!) {
  supMultiMatch(queries: $queries) {
    parts {
      mpn
      manufacturer { name }
      specs { attribute { shortname } displayValue }
      bestDatasheet { url }
    }
  }
}
`

func (n NexarProvider) Lookup(ctx context.Context, mpns []string) map[string]Enrichment {
	out := map[string]Enrichment{}
	if !n.Configured() || len(mpns) == 0 {
		return out
	}
	client := n.Client
	if client == nil {
		client = &http.Client{Timeout: n.timeout()}
	}

	for start := 0; start < len(mpns); start += nexarBatchSize {
		end := start + nexarBatchSize
		if end > len(mpns) {
			end = len(mpns)
		}
		found, err := n.query(ctx, client, mpns[start:end])
		if err != nil {
			// ⚠ ENRICHMENT FAILURE IS NOT IMPORT FAILURE. The customer's own
			// data is already complete and correct; a parts database being
			// unreachable must not lose it.
			continue
		}
		for k, v := range found {
			out[k] = v
		}
	}
	return out
}

func (n NexarProvider) timeout() time.Duration {
	if n.Timeout > 0 {
		return n.Timeout
	}
	return 15 * time.Second
}

type nexarQueryVar struct {
	MPN   string `json:"mpn"`
	Limit int    `json:"limit"`
}

func (n NexarProvider) query(ctx context.Context, client *http.Client, mpns []string) (map[string]Enrichment, error) {
	queries := make([]nexarQueryVar, 0, len(mpns))
	for _, m := range mpns {
		queries = append(queries, nexarQueryVar{MPN: m, Limit: 1})
	}
	payload, err := json.Marshal(map[string]any{
		"query":     nexarQuery,
		"variables": map[string]any{"queries": queries},
	})
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, nexarURL, bytes.NewReader(payload))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+n.Token)

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("nexar: unexpected status %d", resp.StatusCode)
	}

	var body nexarResponseBody
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return nil, err
	}
	return parseNexarResponse(body), nil
}

// nexarResponseBody is Nexar's GraphQL response shape, separated from
// query() so parsing is testable without a network call — the only part of
// this adapter that currently has coverage, matching the split between
// _query and the static parse() method in workers/hbom/providers/nexar.py.
type nexarResponseBody struct {
	Data struct {
		SupMultiMatch []struct {
			Parts []struct {
				MPN          string `json:"mpn"`
				Manufacturer struct {
					Name string `json:"name"`
				} `json:"manufacturer"`
				Specs []struct {
					Attribute struct {
						Shortname string `json:"shortname"`
					} `json:"attribute"`
					DisplayValue string `json:"displayValue"`
				} `json:"specs"`
				BestDatasheet struct {
					URL string `json:"url"`
				} `json:"bestDatasheet"`
			} `json:"parts"`
		} `json:"supMultiMatch"`
	} `json:"data"`
}

// parseNexarResponse turns a decoded Nexar response into enrichments.
// Matches NexarProvider.parse() in workers/hbom/providers/nexar.py.
func parseNexarResponse(body nexarResponseBody) map[string]Enrichment {
	out := map[string]Enrichment{}
	for _, match := range body.Data.SupMultiMatch {
		for _, part := range match.Parts {
			mpn := strings.TrimSpace(part.MPN)
			if mpn == "" {
				continue
			}
			specs := make(map[string]string, len(part.Specs))
			for _, s := range part.Specs {
				specs[s.Attribute.Shortname] = s.DisplayValue
			}
			var compliance []string
			if strings.HasPrefix(strings.ToLower(specs["rohsstatus"]), "rohs") {
				compliance = append(compliance, "RoHS")
			}
			if specs["reachsvhc"] != "" {
				compliance = append(compliance, "REACH")
			}
			out[strings.ToLower(mpn)] = Enrichment{
				MPN:              mpn,
				ManufacturerName: part.Manufacturer.Name,
				TechnologyNode:   specs["processgeometry"],
				Compliance:       compliance,
				Lifecycle:        specs["lifecyclestatus"],
				DatasheetURL:     part.BestDatasheet.URL,
				Source:           "nexar",
			}
		}
	}
	return out
}

// ---------------------------------------------------------------------------
// Mouser
// ---------------------------------------------------------------------------

// MouserProvider looks up parts through Mouser's search API.
//
// ⚠ COMMERCIAL, KEYED, AND OPTIONAL — the same rules as Nexar. Ported from
// workers/hbom/providers/mouser.py; also never run against the live API.
type MouserProvider struct {
	APIKey  string
	Client  *http.Client
	Timeout time.Duration
}

// MouserFromEnv builds a provider from MOUSER_API_KEY.
func MouserFromEnv() MouserProvider {
	return MouserProvider{APIKey: strings.TrimSpace(os.Getenv("MOUSER_API_KEY"))}
}

func (m MouserProvider) Name() string     { return "mouser" }
func (m MouserProvider) Configured() bool { return m.APIKey != "" }

const (
	mouserURL       = "https://api.mouser.com/api/v1/search/keyword"
	mouserMaxLookup = 100
)

func (m MouserProvider) Lookup(ctx context.Context, mpns []string) map[string]Enrichment {
	out := map[string]Enrichment{}
	if !m.Configured() || len(mpns) == 0 {
		return out
	}
	client := m.Client
	if client == nil {
		client = &http.Client{Timeout: m.timeout()}
	}

	// ⚠ CAPPED. A 5,000-line BOM would otherwise issue 5,000 billable calls
	// from one import; the remainder is simply not enriched.
	capped := mpns
	if len(capped) > mouserMaxLookup {
		capped = capped[:mouserMaxLookup]
	}
	for _, mpn := range capped {
		found, err := m.query(ctx, client, mpn)
		if err != nil {
			continue
		}
		for k, v := range found {
			out[k] = v
		}
	}
	return out
}

func (m MouserProvider) timeout() time.Duration {
	if m.Timeout > 0 {
		return m.Timeout
	}
	return 15 * time.Second
}

func (m MouserProvider) query(ctx context.Context, client *http.Client, mpn string) (map[string]Enrichment, error) {
	payload, err := json.Marshal(map[string]any{
		"SearchByKeywordRequest": map[string]any{
			"keyword": mpn, "records": 1, "startingRecord": 0,
		},
	})
	if err != nil {
		return nil, err
	}

	url := fmt.Sprintf("%s?apiKey=%s", mouserURL, m.APIKey)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(payload))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("mouser: unexpected status %d", resp.StatusCode)
	}

	var body mouserResponseBody
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return nil, err
	}
	return parseMouserResponse(body), nil
}

// mouserResponseBody is Mouser's search response shape, separated from
// query() so parsing is testable without a network call. Mirrors the split
// in workers/hbom/providers/mouser.py.
type mouserResponseBody struct {
	SearchResults struct {
		Parts []struct {
			ManufacturerPartNumber string `json:"ManufacturerPartNumber"`
			Manufacturer           string `json:"Manufacturer"`
			ROHSStatus             string `json:"ROHSStatus"`
			LifecycleStatus        string `json:"LifecycleStatus"`
			DataSheetURL           string `json:"DataSheetUrl"`
			ProductAttributes      []struct {
				AttributeName  string `json:"AttributeName"`
				AttributeValue string `json:"AttributeValue"`
			} `json:"ProductAttributes"`
		} `json:"Parts"`
	} `json:"SearchResults"`
}

// parseMouserResponse turns a decoded Mouser response into enrichments.
// Matches MouserProvider.parse() in workers/hbom/providers/mouser.py.
func parseMouserResponse(body mouserResponseBody) map[string]Enrichment {
	out := map[string]Enrichment{}
	for _, part := range body.SearchResults.Parts {
		mpn := strings.TrimSpace(part.ManufacturerPartNumber)
		if mpn == "" {
			continue
		}
		attrs := make(map[string]string, len(part.ProductAttributes))
		for _, a := range part.ProductAttributes {
			attrs[a.AttributeName] = a.AttributeValue
		}
		var compliance []string
		if strings.HasPrefix(strings.ToLower(part.ROHSStatus), "rohs") {
			compliance = append(compliance, "RoHS")
		}
		out[strings.ToLower(mpn)] = Enrichment{
			MPN:              mpn,
			ManufacturerName: part.Manufacturer,
			Compliance:       compliance,
			Lifecycle:        part.LifecycleStatus,
			DatasheetURL:     part.DataSheetURL,
			TechnologyNode:   attrs["Process Geometry"],
			Source:           "mouser",
		}
	}
	return out
}
