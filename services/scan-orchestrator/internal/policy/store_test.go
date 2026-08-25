package policy_test

import (
	"context"
	"os"
	"testing"

	"github.com/axebom/axebom/libs/go-shared/events"
	"github.com/axebom/axebom/libs/go-shared/platform/config"
	"github.com/axebom/axebom/libs/go-shared/platform/db"
	"github.com/axebom/axebom/services/scan-orchestrator/internal/policy"
)

// Against real Postgres, same discipline as orchestr's tests: the property
// under test is RLS and upsert-on-conflict, which a mocked store cannot fail.

const (
	tenantA = "01900000-0000-7000-8000-0000000000e1"
	tenantB = "01900000-0000-7000-8000-0000000000e2"
)

func newPoolOrSkip(t *testing.T) *db.Pool {
	t.Helper()
	if os.Getenv("SKIP_DB_TESTS") != "" {
		t.Skip("SKIP_DB_TESTS is set")
	}
	cfg, err := config.LoadService("scan-orchestrator")
	if err != nil {
		t.Fatalf("config: %v", err)
	}
	pool, err := db.Open(t.Context(), cfg.Postgres)
	if err != nil {
		t.Skipf("database unavailable (%v) — run `task dev`", err)
	}
	t.Cleanup(pool.Close)
	return pool
}

func cleanupPolicy(t *testing.T, pool *db.Pool, tenantID string, family events.Family) {
	t.Helper()
	t.Cleanup(func() {
		err := pool.WithTenant(context.Background(), tenantID, func(ctx context.Context, tx db.Tx) error {
			_, err := tx.Exec(ctx, `DELETE FROM scan.engine_policy WHERE family = $1`, string(family))
			return err
		})
		if err != nil {
			t.Logf("cleanup: %v", err)
		}
	})
}

func TestUpsertThenGetRoundTrips(t *testing.T) {
	pool := newPoolOrSkip(t)
	store := policy.NewStore(pool)
	cleanupPolicy(t, pool, tenantA, events.FamilySBOM)

	_, err := store.Upsert(t.Context(), tenantA, events.FamilySBOM,
		[]string{"syft"}, map[string]int{"syft": 5}, true, "pin to syft while evaluating")
	if err != nil {
		t.Fatalf("Upsert: %v", err)
	}

	got, ok, err := store.Get(t.Context(), tenantA, events.FamilySBOM)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if !ok {
		t.Fatal("expected a row, found none")
	}
	if len(got.EngineIDs) != 1 || got.EngineIDs[0] != "syft" {
		t.Errorf("engine_ids = %v, want [syft]", got.EngineIDs)
	}
	if got.Weights["syft"] != 5 {
		t.Errorf("weights[syft] = %d, want 5", got.Weights["syft"])
	}
	if !got.Enabled {
		t.Error("enabled = false, want true")
	}
}

// TestUpsertIsIdempotentOnConflict asserts the second call REPLACES the
// first, matching the migration's own "rows are overrides, not additions"
// framing — two calls must not leave two rows or a merged engine_ids list.
func TestUpsertIsIdempotentOnConflict(t *testing.T) {
	pool := newPoolOrSkip(t)
	store := policy.NewStore(pool)
	cleanupPolicy(t, pool, tenantA, events.FamilyCBOM)

	if _, err := store.Upsert(t.Context(), tenantA, events.FamilyCBOM,
		[]string{"cbomkit-theia", "cbomkit"}, nil, true, ""); err != nil {
		t.Fatalf("first Upsert: %v", err)
	}
	if _, err := store.Upsert(t.Context(), tenantA, events.FamilyCBOM,
		[]string{"cbomkit-theia"}, nil, true, "narrowed to one engine"); err != nil {
		t.Fatalf("second Upsert: %v", err)
	}

	got, ok, err := store.Get(t.Context(), tenantA, events.FamilyCBOM)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if !ok {
		t.Fatal("expected a row")
	}
	if len(got.EngineIDs) != 1 || got.EngineIDs[0] != "cbomkit-theia" {
		t.Errorf("engine_ids = %v, want [cbomkit-theia] (the second Upsert should replace, not merge)", got.EngineIDs)
	}
}

// TestEmptyEngineIDsMeansRunNothing, not "no override" — the migration's own
// documented distinction. A round trip through Upsert must preserve an empty,
// non-nil slice, not silently become an absent row.
func TestEmptyEngineIDsMeansRunNothing(t *testing.T) {
	pool := newPoolOrSkip(t)
	store := policy.NewStore(pool)
	cleanupPolicy(t, pool, tenantA, events.FamilyAIBOM)

	if _, err := store.Upsert(t.Context(), tenantA, events.FamilyAIBOM,
		[]string{}, nil, true, "AIBOM disabled for this tenant"); err != nil {
		t.Fatalf("Upsert: %v", err)
	}

	got, ok, err := store.Get(t.Context(), tenantA, events.FamilyAIBOM)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if !ok {
		t.Fatal("expected a row (empty engine_ids is not an absent row)")
	}
	if len(got.EngineIDs) != 0 {
		t.Errorf("engine_ids = %v, want empty", got.EngineIDs)
	}
}

func TestGetIsTenantScoped(t *testing.T) {
	pool := newPoolOrSkip(t)
	store := policy.NewStore(pool)
	cleanupPolicy(t, pool, tenantA, events.FamilySBOM)

	if _, err := store.Upsert(t.Context(), tenantA, events.FamilySBOM,
		[]string{"syft"}, nil, true, ""); err != nil {
		t.Fatalf("Upsert: %v", err)
	}

	_, ok, err := store.Get(t.Context(), tenantB, events.FamilySBOM)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if ok {
		t.Error("tenantB saw tenantA's engine policy override")
	}
}

func TestGetReturnsNotOkWhenTenantHasNoOverride(t *testing.T) {
	pool := newPoolOrSkip(t)
	store := policy.NewStore(pool)

	_, ok, err := store.Get(t.Context(), tenantA, events.FamilyHBOM)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if ok {
		t.Error("expected no override for a tenant that has never customised HBOM")
	}
}

func TestDeleteRevertsToDefault(t *testing.T) {
	pool := newPoolOrSkip(t)
	store := policy.NewStore(pool)
	cleanupPolicy(t, pool, tenantA, events.FamilyQBOM)

	if _, err := store.Upsert(t.Context(), tenantA, events.FamilyQBOM,
		[]string{}, nil, false, "disabled by mistake"); err != nil {
		t.Fatalf("Upsert: %v", err)
	}
	if err := store.Delete(t.Context(), tenantA, events.FamilyQBOM); err != nil {
		t.Fatalf("Delete: %v", err)
	}

	_, ok, err := store.Get(t.Context(), tenantA, events.FamilyQBOM)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if ok {
		t.Error("expected no row after Delete")
	}
}

// TestOverridesForTenantDisabledMeansEmptySet asserts the one subtlety
// Registry.Resolve depends on: a DISABLED row must resolve to overrides[f] =
// [] (run nothing), not be omitted as if untouched — omitting it would fall
// back to the built-in default, silently re-enabling a family a tenant
// deliberately turned off.
func TestOverridesForTenantDisabledMeansEmptySet(t *testing.T) {
	pool := newPoolOrSkip(t)
	store := policy.NewStore(pool)
	cleanupPolicy(t, pool, tenantA, events.FamilyAIBOM)

	if _, err := store.Upsert(t.Context(), tenantA, events.FamilyAIBOM,
		[]string{"ai-bom"}, nil, false, "disabled"); err != nil {
		t.Fatalf("Upsert: %v", err)
	}

	overrides, err := store.OverridesForTenant(t.Context(), tenantA)
	if err != nil {
		t.Fatalf("OverridesForTenant: %v", err)
	}
	ids, present := overrides[events.FamilyAIBOM]
	if !present {
		t.Fatal("expected aibom to be present in overrides even though disabled")
	}
	if len(ids) != 0 {
		t.Errorf("disabled family's engine ids = %v, want empty (run nothing)", ids)
	}
}

func TestListForTenantOrdersByFamily(t *testing.T) {
	pool := newPoolOrSkip(t)
	store := policy.NewStore(pool)
	cleanupPolicy(t, pool, tenantA, events.FamilySBOM)
	cleanupPolicy(t, pool, tenantA, events.FamilyCBOM)

	if _, err := store.Upsert(t.Context(), tenantA, events.FamilyCBOM,
		[]string{"cbomkit-theia"}, nil, true, ""); err != nil {
		t.Fatalf("Upsert cbom: %v", err)
	}
	if _, err := store.Upsert(t.Context(), tenantA, events.FamilySBOM,
		[]string{"syft"}, nil, true, ""); err != nil {
		t.Fatalf("Upsert sbom: %v", err)
	}

	rows, err := store.ListForTenant(t.Context(), tenantA)
	if err != nil {
		t.Fatalf("ListForTenant: %v", err)
	}
	if len(rows) != 2 {
		t.Fatalf("got %d rows, want 2", len(rows))
	}
	if rows[0].Family != events.FamilyCBOM || rows[1].Family != events.FamilySBOM {
		t.Errorf("families = [%s, %s], want alphabetical [cbom, sbom]", rows[0].Family, rows[1].Family)
	}
}
