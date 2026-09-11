package store_test

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/axebom/axebom/libs/go-shared/platform/db"
	"github.com/axebom/axebom/services/project/internal/store"
)

// seedCryptoAssets inserts one CBOM bom_document with a certificate and a key —
// enough to exercise type-discrimination (CLAUDE.md invariant 5) without
// duplicating every asset_type seedSBOM-style; the four-type case is already
// covered at the normalizer level in workers/cbom/test_crypto_normalize.py.
func seedCryptoAssets(t *testing.T, pool *db.Pool, tenantID, projectID string) (docID string) {
	t.Helper()
	var seededScanID string
	err := pool.WithTenant(t.Context(), tenantID, func(ctx context.Context, tx db.Tx) error {
		var scanID string
		if err := tx.QueryRow(ctx, `
			INSERT INTO scan.scans (tenant_id, project_id, triggered_by, source_kind)
			VALUES ($1, $2, 'user', 'git') RETURNING id`, tenantID, projectID).Scan(&scanID); err != nil {
			return err
		}

		if err := tx.QueryRow(ctx, `
			INSERT INTO normalize.bom_documents
				(tenant_id, scan_id, bom_type, normalization_version,
				 ruleset_version, alias_snapshot_id, spdx_license_list_version, generated_at)
						-- ⚠ alias_snapshot_id IS NULL, NOT app.uuid_v7(). Migration 0012 gave
			-- the column a real FK, so a minted id is now rejected outright.
			-- NULL is also what production writes for this BOM type: CBOM runs
			-- no alias closure, so there is no snapshot to reference.
VALUES ($1, $2, 'CBOM', 1, 'test-1', NULL, '', now())
			RETURNING id`, tenantID, scanID).Scan(&docID); err != nil {
			return err
		}

		// ⚠ SHAPED LIKE A MIGRATION-0020 ROW: an asset key, the rule that made
		// it, evidence and attributes — and, for the key, two engines' worth of
		// provenance, inserted out of order so the sort is what the test sees.
		var certID, keyID string
		if err := tx.QueryRow(ctx, `
			INSERT INTO normalize.crypto_assets
				(tenant_id, bom_document_id, component_key, asset_type, name,
				 asset_key, identity_rule, identity_confidence,
				 cert_subject, cert_issuer, signature_algo_ref,
				 quantum_vulnerable, quantum_family, quantum_readiness_group,
				 deprecation_status, evidence, attributes)
			VALUES ($1, $2, 'cert-ref-1', 'certificate', 'example.com',
			        'cert:example.com;issuer=example.com', 'certificate-subject-issuer-validity', 'medium',
			        'example.com', 'example.com', 'SHA256-RSA',
			        true, 'rsa', 'vulnerable', 'current',
			        '[{"path": "certs/example.pem", "line": null, "engine": "cbomkit-theia"}]',
			        '{"signature_algorithm_key": "algorithm:rsa;digest=sha2-256", "surfaces": ["file"]}')
			RETURNING id`,
			tenantID, docID).Scan(&certID); err != nil {
			return err
		}

		if err := tx.QueryRow(ctx, `
			INSERT INTO normalize.crypto_assets
				(tenant_id, bom_document_id, component_key, asset_type, name,
				 asset_key, identity_rule, identity_confidence,
				 key_size, key_state, quantum_vulnerable, quantum_readiness_group,
				 evidence, attributes, derivations)
			VALUES ($1, $2, 'key-ref-1', 'key', 'RSA-2048',
			        'key:fp:sha256:00ff', 'key-fingerprint', 'high',
			        2048, 'active', true, 'vulnerable',
			        '[{"path": "keys/server.key", "line": null, "engine": "cbomkit-theia"},
			          {"path": "src/Main.java", "line": 42, "engine": "cbomkit-action"}]',
			        '{"material_type": "private-key", "private_key_in_source": true,
			          "nist_quantum_security_level": 0}',
			        '{"key_size": "test-reference"}')
			RETURNING id`,
			tenantID, docID).Scan(&keyID); err != nil {
			return err
		}

		for _, p := range []struct{ assetID, engine string }{
			{keyID, "cbomkit-theia"}, {keyID, "cbomkit-action"}, {certID, "cbomkit-theia"},
		} {
			if _, err := tx.Exec(ctx, `
				INSERT INTO normalize.crypto_asset_provenance
					(tenant_id, crypto_asset_id, engine_id, engine_version, observed_name)
				VALUES ($1, $2, $3, 'test', 'observed')`,
				tenantID, p.assetID, p.engine); err != nil {
				return err
			}
		}
		seededScanID = scanID
		return nil
	})
	if err != nil {
		t.Fatalf("seed CBOM: %v", err)
	}
	cleanupSeededScan(t, pool, tenantID, seededScanID, docID)
	return docID
}

func TestListCryptoAssetsIsTypeDiscriminated(t *testing.T) {
	pool := openPool(t)
	st := store.New(pool)
	projectID := createTestProject(t, st, tenantA)
	seedCryptoAssets(t, pool, tenantA, projectID)

	assets, err := st.ListCryptoAssets(t.Context(), tenantA, projectID)
	if err != nil {
		t.Fatalf("ListCryptoAssets: %v", err)
	}
	if len(assets) != 2 {
		t.Fatalf("assets = %d, want 2", len(assets))
	}

	byType := map[string]store.CryptoAsset{}
	for _, a := range assets {
		byType[a.AssetType] = a
	}

	cert, ok := byType["certificate"]
	if !ok {
		t.Fatalf("missing certificate: %+v", assets)
	}
	// ⚠ THE INVARIANT-5 CASE: a certificate carries no key_size at all.
	if cert.KeySize != nil {
		t.Errorf("certificate KeySize = %v, want nil (not this type's field)", cert.KeySize)
	}
	if cert.CertSubject != "example.com" || cert.SignatureAlgoRef != "SHA256-RSA" {
		t.Errorf("certificate = %+v", cert)
	}
	if !cert.QuantumVulnerable || cert.QuantumReadinessGroup != "vulnerable" {
		t.Errorf("certificate quantum verdict = %+v, want vulnerable", cert)
	}

	key, ok := byType["key"]
	if !ok {
		t.Fatalf("missing key: %+v", assets)
	}
	if key.KeySize == nil || *key.KeySize != 2048 {
		t.Errorf("key KeySize = %v, want 2048", key.KeySize)
	}
	if key.CertSubject != "" {
		t.Errorf("key CertSubject = %q, want empty (not this type's field)", key.CertSubject)
	}
}

// TestListCryptoAssetsCarriesIdentityEvidenceAndEngines round-trips migration
// 0020's columns from real rows: the asset key and its rule, evidence with a
// null line kept null, attributes and derivations as objects, and the engines
// read from normalize.crypto_asset_provenance — distinct and sorted.
func TestListCryptoAssetsCarriesIdentityEvidenceAndEngines(t *testing.T) {
	pool := openPool(t)
	st := store.New(pool)
	projectID := createTestProject(t, st, tenantA)
	seedCryptoAssets(t, pool, tenantA, projectID)

	assets, err := st.ListCryptoAssets(t.Context(), tenantA, projectID)
	if err != nil {
		t.Fatalf("ListCryptoAssets: %v", err)
	}
	byType := map[string]store.CryptoAsset{}
	for _, a := range assets {
		byType[a.AssetType] = a
	}

	key := byType["key"]
	if key.AssetKey != "key:fp:sha256:00ff" || key.IdentityRule != "key-fingerprint" ||
		key.IdentityConfidence != "high" {
		t.Errorf("key identity = %q / %q / %q", key.AssetKey, key.IdentityRule, key.IdentityConfidence)
	}
	if got := strings.Join(key.Engines, ","); got != "cbomkit-action,cbomkit-theia" {
		t.Errorf("key engines = %q, want the provenance rows' engines, sorted", got)
	}
	if len(key.Evidence) != 2 {
		t.Fatalf("key evidence = %+v, want 2 entries", key.Evidence)
	}
	if e := key.Evidence[0]; e.Path != "keys/server.key" || e.Line != nil || e.Engine != "cbomkit-theia" {
		t.Errorf("first evidence = %+v, want keys/server.key with a null line", e)
	}
	if e := key.Evidence[1]; e.Path != "src/Main.java" || e.Line == nil || *e.Line != 42 || e.Engine != "cbomkit-action" {
		t.Errorf("second evidence = %+v", e)
	}
	if key.Attributes["material_type"] != "private-key" || key.Attributes["private_key_in_source"] != true {
		t.Errorf("key attributes = %v", key.Attributes)
	}
	if key.Derivations["key_size"] != "test-reference" {
		t.Errorf("key derivations = %v", key.Derivations)
	}

	cert := byType["certificate"]
	if cert.AssetKey != "cert:example.com;issuer=example.com" {
		t.Errorf("certificate asset key = %q", cert.AssetKey)
	}
	if got := strings.Join(cert.Engines, ","); got != "cbomkit-theia" {
		t.Errorf("certificate engines = %q", got)
	}
	if cert.Attributes["signature_algorithm_key"] != "algorithm:rsa;digest=sha2-256" {
		t.Errorf("certificate attributes = %v", cert.Attributes)
	}

	// ⚠ THE WIRE SHAPE, NOT JUST THE STRUCT: an empty derivations map and a
	// null line must reach the client as `{}` and `null`, never omitted.
	raw, err := json.Marshal(cert)
	if err != nil {
		t.Fatal(err)
	}
	var wire map[string]any
	if err := json.Unmarshal(raw, &wire); err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"asset_key", "identity_rule", "identity_confidence", "evidence", "attributes", "derivations", "engines"} {
		if _, ok := wire[k]; !ok {
			t.Errorf("the crypto asset JSON has no %q key: %s", k, raw)
		}
	}
	if d, ok := wire["derivations"].(map[string]any); !ok || len(d) != 0 {
		t.Errorf("derivations on the wire = %v, want {}", wire["derivations"])
	}
	evidence := wire["evidence"].([]any)[0].(map[string]any)
	if line, ok := evidence["line"]; !ok || line != nil {
		t.Errorf("a null evidence line reached the wire as %v (present=%v)", line, ok)
	}
}

func TestListCryptoAssetsIsEmptyBeforeAnyCBOM(t *testing.T) {
	pool := openPool(t)
	st := store.New(pool)
	projectID := createTestProject(t, st, tenantA)

	assets, err := st.ListCryptoAssets(t.Context(), tenantA, projectID)
	if err != nil {
		t.Fatalf("ListCryptoAssets: %v", err)
	}
	if len(assets) != 0 {
		t.Errorf("assets = %d, want 0 before any CBOM scan", len(assets))
	}
}

// TestListCryptoAssetsIsTenantScoped: a cross-tenant fetch is ErrNotFound,
// never an empty list — RLS makes tenantA's project invisible to tenantB's
// connection, and projectExists reports that as "no such project" rather
// than "no such project has crypto assets" (CLAUDE.md: 404, never 403 — the
// two must be indistinguishable to the caller, matching
// TestListDependenciesIsTenantScoped's identical assertion).
func TestListCryptoAssetsIsTenantScoped(t *testing.T) {
	pool := openPool(t)
	st := store.New(pool)
	projectID := createTestProject(t, st, tenantA)
	seedCryptoAssets(t, pool, tenantA, projectID)

	_, err := st.ListCryptoAssets(t.Context(), tenantB, projectID)
	if !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("ListCryptoAssets cross-tenant error = %v, want ErrNotFound", err)
	}
}
