package store_test

import (
	"context"
	"errors"
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

		if _, err := tx.Exec(ctx, `
			INSERT INTO normalize.crypto_assets
				(tenant_id, bom_document_id, component_key, asset_type, name,
				 cert_subject, cert_issuer, signature_algo_ref,
				 quantum_vulnerable, quantum_family, quantum_readiness_group,
				 deprecation_status)
			VALUES ($1, $2, 'cert-ref-1', 'certificate', 'example.com',
			        'example.com', 'example.com', 'SHA256-RSA',
			        true, 'rsa', 'vulnerable', 'current')`,
			tenantID, docID); err != nil {
			return err
		}

		_, err := tx.Exec(ctx, `
			INSERT INTO normalize.crypto_assets
				(tenant_id, bom_document_id, component_key, asset_type, name,
				 key_size, key_state, quantum_vulnerable, quantum_readiness_group)
			VALUES ($1, $2, 'key-ref-1', 'key', 'RSA-2048',
			        2048, 'active', true, 'vulnerable')`,
			tenantID, docID)
		return err
	})
	if err != nil {
		t.Fatalf("seed CBOM: %v", err)
	}
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
