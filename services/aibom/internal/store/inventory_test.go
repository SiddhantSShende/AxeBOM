package store

import (
	"context"
	"fmt"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/axebom/axebom/libs/go-shared/platform/db"
)

// TestTheInventoryCostsTheSameWhateverTheCustomerFound.
//
// ⚠ THIS WAS 1 + 3N ROUND TRIPS, AND THE SHAPE OF THAT BUG IS THE POINT. Three
// models cost eleven queries and nobody notices. Two hundred model references —
// an ordinary number for a monorepo that uses an agent framework — cost six
// hundred, in a single HTTP request, holding a pooled connection inside a tenant
// transaction for every one of them. Nothing errors. The page simply gets slower
// in proportion to how much the customer found, so the customers who hit it are
// the ones with the most data and the least patience for it.
//
// The assertion is on the COUNT, not on a duration: a timing threshold passes on
// a fast machine with the N+1 still in place and fails on a slow one without it,
// which measures the hardware rather than the query.
func TestTheInventoryCostsTheSameWhateverTheCustomerFound(t *testing.T) {
	for _, modelCount := range []int{1, 3, 250} {
		t.Run(fmt.Sprintf("%d models", modelCount), func(t *testing.T) {
			models := make([]AIModel, modelCount)
			for i := range models {
				models[i].ID = fmt.Sprintf("m%03d", i)
			}
			tx := &countingTx{}
			if err := attachModelChildren(t.Context(), tx, models); err != nil {
				t.Fatalf("attach: %v", err)
			}
			// One per child table. Not "few", not "bounded" — exactly three,
			// because any number that grows with the input is the bug.
			if tx.queries != 3 {
				t.Errorf("issued %d queries for %d models; want 3 whatever the count",
					tx.queries, modelCount)
			}
		})
	}
}

// TestEachModelGetsItsOwnChildrenAndNobodyElses.
//
// Batching is only worth doing if the regrouping is right, and a regrouping bug
// is worse than the N+1 it replaced: attributing one model's datasets to another
// puts a false statement in a compliance document, where the slow version merely
// took longer to be correct.
func TestEachModelGetsItsOwnChildrenAndNobodyElses(t *testing.T) {
	models := []AIModel{{ID: "m1"}, {ID: "m2"}, {ID: "m3"}}
	tx := &countingTx{
		results: [][][]string{
			// datasets: (ai_model_id, name, version, format, limitations, license, source)
			{
				{"m1", "c4", "", "", "", "cc-by-4.0", ""},
				{"m3", "the-pile", "", "", "", "", ""},
			},
			// dependencies: (ai_model_id, component_key)
			{
				{"m1", "pkg:pypi/langchain"},
				{"m1", "pkg:pypi/transformers"},
				{"m2", "pkg:npm/openai"},
			},
			// provenance: (ai_model_id, engine_id)
			{
				{"m1", "ai-bom"},
				{"m1", "airom"},
				{"m2", "airom"},
			},
		},
	}

	if err := attachModelChildren(t.Context(), tx, models); err != nil {
		t.Fatalf("attach: %v", err)
	}

	if got := len(models[0].Datasets); got != 1 || models[0].Datasets[0].Name != "c4" {
		t.Errorf("m1 datasets = %v", models[0].Datasets)
	}
	if models[0].Datasets[0].License != "cc-by-4.0" {
		t.Errorf("a column landed in the wrong field: %+v", models[0].Datasets[0])
	}
	if got := len(models[1].Datasets); got != 0 {
		t.Errorf("m2 was given %d datasets it does not have", got)
	}
	if got := models[2].Datasets[0].Name; got != "the-pile" {
		t.Errorf("m3 datasets = %v", models[2].Datasets)
	}

	if got := len(models[0].Dependencies); got != 2 {
		t.Errorf("m1 dependencies = %v", models[0].Dependencies)
	}
	if got := models[1].Dependencies; len(got) != 1 || got[0] != "pkg:npm/openai" {
		t.Errorf("m2 dependencies = %v", got)
	}
	if got := len(models[2].Dependencies); got != 0 {
		t.Errorf("m3 was given %d dependencies it does not have", got)
	}

	if got := models[0].FoundBy; len(got) != 2 || got[0] != "ai-bom" || got[1] != "airom" {
		t.Errorf("m1 found_by = %v; the SQL ordering must survive the regrouping", got)
	}
}

// TestAModelNoEngineElaboratedStillSerializesAsAList.
//
// ⚠ `null` AND `[]` ARE NOT THE SAME THING TO A BROWSER. `datasets: null` makes
// every call site null-check, and the one that gets missed renders a blank
// screen — for the customer with the most models, since they are the ones with
// a model that has no datasets alongside ones that do.
func TestAModelNoEngineElaboratedStillSerializesAsAList(t *testing.T) {
	models := []AIModel{{ID: "m1"}}
	if err := attachModelChildren(t.Context(), &countingTx{}, models); err != nil {
		t.Fatalf("attach: %v", err)
	}
	if models[0].Datasets == nil || models[0].Dependencies == nil || models[0].FoundBy == nil {
		t.Errorf("a nil slice reached the DTO: %+v", models[0])
	}
}

func TestNoModelsIssuesNoQueries(t *testing.T) {
	// A project scanned for AIBOM that found nothing is ordinary. Three empty
	// `= ANY('{}')` queries would be three round trips to prove it.
	tx := &countingTx{}
	if err := attachModelChildren(t.Context(), tx, nil); err != nil {
		t.Fatalf("attach: %v", err)
	}
	if tx.queries != 0 {
		t.Errorf("issued %d queries for no models", tx.queries)
	}
}

// ---------------------------------------------------------------------------
// A Tx that counts, and replays canned rows
// ---------------------------------------------------------------------------

// countingTx records how many statements a function issues and answers each one
// from `results` in order.
//
// A fake rather than a real database on purpose: the property under test is
// "how many times does this talk to Postgres", which a real connection makes
// harder to observe, not easier. Correctness against real SQL is covered by the
// live inventory the endpoint serves.
type countingTx struct {
	queries int
	results [][][]string
}

func (t *countingTx) Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error) {
	_, _, _ = ctx, sql, args
	var rows [][]string
	if t.queries < len(t.results) {
		rows = t.results[t.queries]
	}
	t.queries++
	return &stringRows{rows: rows}, nil
}

func (t *countingTx) Exec(context.Context, string, ...any) (interface {
	RowsAffected() int64
	String() string
	Insert() bool
	Update() bool
	Delete() bool
	Select() bool
}, error) {
	panic("attachModelChildren must not write")
}

func (t *countingTx) QueryRow(context.Context, string, ...any) pgx.Row {
	panic("attachModelChildren issues no single-row queries")
}

func (t *countingTx) CopyFrom(context.Context, pgx.Identifier, []string, pgx.CopyFromSource) (int64, error) {
	panic("attachModelChildren must not write")
}

// countingTx satisfies the only handle domain code is given.
var _ db.Tx = (*countingTx)(nil)

// stringRows replays rows of text columns, which is every column these three
// queries select.
type stringRows struct {
	rows [][]string
	at   int
}

func (r *stringRows) Next() bool {
	r.at++
	return r.at <= len(r.rows)
}

func (r *stringRows) Scan(dest ...any) error {
	row := r.rows[r.at-1]
	if len(dest) != len(row) {
		// The arity bug this repository has already shipped once: a query
		// gaining a column while its Scan does not.
		return fmt.Errorf("number of field descriptions must equal number of destinations, got %d and %d",
			len(row), len(dest))
	}
	for i, d := range dest {
		p, ok := d.(*string)
		if !ok {
			return fmt.Errorf("destination %d is %T, not *string", i, d)
		}
		*p = row[i]
	}
	return nil
}

func (r *stringRows) Close()                                       {}
func (r *stringRows) Err() error                                   { return nil }
func (r *stringRows) CommandTag() pgconn.CommandTag                { return pgconn.CommandTag{} }
func (r *stringRows) FieldDescriptions() []pgconn.FieldDescription { return nil }
func (r *stringRows) Values() ([]any, error)                       { return nil, nil }
func (r *stringRows) RawValues() [][]byte                          { return nil }
func (r *stringRows) Conn() *pgx.Conn                              { return nil }
