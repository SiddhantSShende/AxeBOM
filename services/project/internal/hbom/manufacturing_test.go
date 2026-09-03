package hbom

import "testing"

// TestTheGoImportParsesTheManufacturingColumns.
//
// ⚠ THE INTERACTIVE IMPORT AND A SCAN OF THE SAME FILE MUST AGREE.
//
// They did not: workers/hbom gained the manufacturing columns for the scan
// path and this port did not, so /v1/hbom/import silently dropped designators,
// prices, SKUs and lifecycle that hbom-ecad kept from the identical CSV. A
// customer could see the difference and had no way to explain it.
func TestTheGoImportParsesTheManufacturingColumns(t *testing.T) {
	csv := "Level,Part Number,Qty,RefDes,Footprint,Supplier SKU,Distributor,Unit Price,Currency,DNP,Mounting,Part Status\n" +
		"0,ROOT,1,,,,,,,,,Active\n" +
		"1,RC0402,3,\"R1, R4, R17\",0402,311-10.0KLRCT-ND,Digi-Key,$0.0018,usd,no,SMD,In Production\n" +
		"1,TP-1,1,TP1,,,,,,DNP,Through-Hole,Not Recommended For New Designs\n" +
		"1,ODD,1,U9,,,,-5.00,US Dollars,maybe,levitation,teleporting\n"

	// ⚠ AN EXPLICIT MAPPING, BECAUSE THIS PORT DELIBERATELY HAS NO AUTOMATIC
	// ONE. This is the INTERACTIVE path: a human confirms which column is which
	// before anything is stored, which is exactly what HEADER_SUGGESTIONS'
	// docstring demands — silently deciding that a column called "Supplier" is
	// the component supplier rather than the product supplier would put data in
	// the wrong one of the two relationships Table 11 distinguishes. The scan
	// path infers and says so in a diagnostic; this one asks.
	mapping := map[string]string{
		"Level": "level", "Part Number": "part_number", "Qty": "quantity",
		"RefDes": "designator", "Footprint": "footprint",
		"Supplier SKU": "supplier_sku", "Distributor": "preferred_supplier",
		"Unit Price": "unit_cost", "Currency": "currency", "DNP": "dni",
		"Mounting": "assembly_type", "Part Status": "lifecycle",
	}

	result, err := Parse([]byte(csv), mapping)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(result.Roots) != 1 {
		t.Fatalf("roots = %d", len(result.Roots))
	}
	parts := result.Roots[0].Children
	if len(parts) != 3 {
		t.Fatalf("parts = %d", len(parts))
	}

	r := parts[0]
	if r.Quantity != 3 {
		t.Errorf("quantity = %d, want 3", r.Quantity)
	}
	if len(r.Designators) != 3 {
		t.Errorf("designators = %v, want three", r.Designators)
	}
	if r.PackageFootprint != "0402" || r.SupplierSKU != "311-10.0KLRCT-ND" ||
		r.PreferredSupplier != "Digi-Key" {
		t.Errorf("sourcing columns lost: %+v", r)
	}
	// ⚠ THE PRICE STAYS AN EXACT STRING. A float64 round-trip would give
	// 0.0018000000000000002 and the extended price over 4000 lines drifts.
	if r.UnitPrice != "0.0018" {
		t.Errorf("unit price = %q, want the exact string 0.0018", r.UnitPrice)
	}
	if r.Currency != "USD" {
		t.Errorf("currency = %q; a lower-case code is a case error, not a wrong "+
			"currency, and dropping the row over it would lose a real price", r.Currency)
	}
	if r.DoNotPopulate {
		t.Error("`no` was read as do-not-populate")
	}
	if r.AssemblyType != "smt" || r.LifecycleStatus != "active" {
		t.Errorf("assembly=%q lifecycle=%q; SMD and In Production are the names the "+
			"industry actually uses", r.AssemblyType, r.LifecycleStatus)
	}

	tp := parts[1]
	if !tp.DoNotPopulate || tp.AssemblyType != "tht" || tp.LifecycleStatus != "nrnd" {
		t.Errorf("test point = dnp:%v asm:%q life:%q", tp.DoNotPopulate,
			tp.AssemblyType, tp.LifecycleStatus)
	}

	// ⚠ UNRECOGNISED VALUES ARE DROPPED, NEVER COERCED. Mapping "levitation"
	// onto a plausible neighbour would invent a fact about somebody's hardware.
	odd := parts[2]
	if odd.AssemblyType != "" || odd.LifecycleStatus != "" {
		t.Errorf("an unrecognised enum was coerced: asm=%q life=%q",
			odd.AssemblyType, odd.LifecycleStatus)
	}
	if odd.UnitPrice != "" {
		t.Errorf("a negative price was accepted: %q", odd.UnitPrice)
	}
	if odd.Currency != "" {
		t.Errorf("%q is not an ISO 4217 code and must be dropped", odd.Currency)
	}
}
