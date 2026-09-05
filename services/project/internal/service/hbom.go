package service

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/axebom/axebom/libs/go-shared/model"
	"github.com/axebom/axebom/libs/go-shared/platform/errs"
	"github.com/axebom/axebom/services/project/internal/hbom"
	"github.com/axebom/axebom/services/project/internal/store"
)

// ---------------------------------------------------------------------------
// Hardware BOM
//
// ⚠ IMPORT PLUS STRUCTURED ENTRY. NOTHING HERE SCANS — every method here
// only ever reads a file the caller supplied or writes what a human typed.
// See services/project/internal/hbom's package doc for why this logic is a
// Go-native port of workers/hbom/*.py rather than a call into it.
// ---------------------------------------------------------------------------

// GetHardwareTree returns a project's hardware BOM.
func (s *Service) GetHardwareTree(ctx context.Context, tenantID, projectID string) ([]*hbom.Component, error) {
	tree, err := s.store.GetHardwareTree(ctx, tenantID, projectID)
	return tree, mapStoreError(err)
}

// SaveHardwareComponent validates and persists one hardware component, and
// recursively any descendants submitted with it (a fetched tree round-tripped
// through the edit form carries its existing children along).
func (s *Service) SaveHardwareComponent(ctx context.Context, tenantID, projectID string, c *hbom.Component) (*hbom.Component, error) {
	if err := validateHardwareComponent(c, "the component"); err != nil {
		return nil, err
	}

	// ⚠ ON CREATION ONLY. An empty ID is an insert (see store.SaveHardwareComponent);
	// an edit to an existing part must keep working even if the project's
	// classifications changed underneath it, or the customer can neither
	// correct nor remove hardware they already recorded.
	if c.ID == "" {
		if err := s.requireClassified(ctx, tenantID, projectID, model.BOMTypeHBOM); err != nil {
			return nil, err
		}
	}

	hbom.Normalize(c)

	saved, err := s.store.SaveHardwareComponent(ctx, tenantID, projectID, c)
	if err != nil {
		if errors.Is(err, store.ErrComponentNotFound) {
			return nil, errs.New(errs.NotFoundResource,
				"no such hardware component in this project")
		}
		return nil, mapStoreError(err)
	}
	return saved, nil
}

// validateHardwareComponent matches the assertions
// workers/hbom/form.py's from_payload() makes: a product name is required,
// and criticality — when given — must be one of the closed set. Everything
// else may be absent and is reported as not-provided rather than rejected.
func validateHardwareComponent(c *hbom.Component, path string) error {
	if c == nil {
		return errs.New(errs.ValidationBodyMalformed, "component payload is empty")
	}
	if strings.TrimSpace(c.ProductName) == "" {
		return errs.Newf(errs.ValidationFieldRequired,
			"%s: a product name is required. Every other field may be left blank and "+
				"reported as not-provided; a component with no name cannot be referred to at all.", path)
	}
	if crit := strings.ToLower(strings.TrimSpace(c.Criticality)); crit != "" && !hbom.CriticalityValues[crit] {
		// ⚠ THE SET WAS SPELLED OUT AS PROSE HERE — the fourth hand-written
		// copy of one closed list. A message naming values the validator no
		// longer accepts is worse than a vague one: the customer types exactly
		// what they were told and is refused again.
		return errs.Newf(errs.ValidationFieldInvalid,
			"%s: criticality %q is not one of %s", path, c.Criticality,
			strings.Join(hbom.Criticalities, ", "))
	}
	for i, child := range c.Children {
		if err := validateHardwareComponent(child, fmt.Sprintf("%s > child %d", path, i)); err != nil {
			return err
		}
	}
	return nil
}

// ReadImportHeaders returns just the column names of an uploaded parts list.
//
// ⚠ THE HEADER ROW USED TO BE PARSED IN THE BROWSER, by slicing the first 64 KiB
// and splitting on commas. That works for a CSV and for nothing else: a
// spreadsheet is a zip archive, so the mapping screen would have shown a row of
// binary garbage as the customer's column names.
//
// Reading it here is the same argument the level-sequence rule already makes in
// this file — one implementation, in the place that owns it. It also means the
// browser needs no spreadsheet library, and every format the importer learns
// next is supported by the mapping screen for free.
func (s *Service) ReadImportHeaders(data []byte, filename string) (headers []string, format string, sheets []string, err error) {
	f := hbom.DetectFormat(filename, data)
	head, _, rerr := hbom.ReadTable(data, f)
	if rerr != nil {
		return nil, "", nil, importErrToAPIError(rerr)
	}

	out := make([]string, 0, len(head))
	for _, h := range head {
		if trimmed := strings.TrimSpace(h); trimmed != "" {
			out = append(out, trimmed)
		}
	}
	return out, string(f), hbom.SheetNames(data, f), nil
}

// PreviewHBOMImport parses a parts list WITHOUT storing anything.
//
// ⚠ THE FORMAT IS DETECTED, NOT ASSUMED. This screen accepted `.csv` alone
// until now, which meant telling a customer to open their `.xlsx` and re-save
// it before AxeBOM would read it — by hand, using a library already in this
// binary. `filename` is the human's own statement about the file they just
// picked; DetectFormat checks the magic bytes anyway, because a workbook
// renamed to `.csv` is the case that actually happens.
func (s *Service) PreviewHBOMImport(data []byte, mapping map[string]string, filename string) (*hbom.ImportResult, error) {
	format := hbom.DetectFormat(filename, data)
	result, err := hbom.ParseFormat(data, mapping, format)
	if err != nil {
		return nil, importErrToAPIError(err)
	}
	result.Format = string(format)
	// ⚠ NAMED, NOT SILENTLY SKIPPED. A parts-list workbook routinely carries a
	// "Notes" or "Revisions" tab. Only the first sheet is read, and a reader
	// who cannot see which one was used has no way to notice the BOM was on
	// the second.
	result.Sheets = hbom.SheetNames(data, format)
	return result, nil
}

// ImportHBOM parses a CSV and stores it as a new hardware-BOM document
// version — never mutating a previous import's rows (CLAUDE.md invariant 10,
// applied to a full re-import rather than a scanner re-run; see
// store.ReplaceHardwareTree).
func (s *Service) ImportHBOM(ctx context.Context, tenantID, projectID string, data []byte, mapping map[string]string, filename string) (string, error) {
	if err := s.requireClassified(ctx, tenantID, projectID, model.BOMTypeHBOM); err != nil {
		return "", err
	}

	result, err := hbom.ParseFormat(data, mapping, hbom.DetectFormat(filename, data))
	if err != nil {
		return "", importErrToAPIError(err)
	}

	docID, err := s.store.ReplaceHardwareTree(ctx, tenantID, projectID, result.Roots)
	return docID, mapStoreError(err)
}

// importErrToAPIError turns a CSV parsing failure into the canonical
// taxonomy. Every case here is a malformed or ambiguous FILE, never a bug —
// hence VALIDATION_*, not an internal code.
func importErrToAPIError(err error) error {
	var ie *hbom.ImportError
	if errors.As(err, &ie) {
		return errs.New(errs.ValidationFieldInvalid, ie.Message)
	}
	return errs.Wrap(err, errs.ValidationBodyMalformed, "could not read this file as CSV")
}

// LookupParts enriches by manufacturer part number via whichever
// PartDataProvider is configured.
//
// ⚠ NEVER ERRORS ON A PROVIDER FAILURE. An unreachable commercial parts
// database is not this request's problem to report as a failure — see
// hbom.Provider.Lookup's doc comment. It returns which provider answered, so
// the caller can label the enrichment honestly rather than implying it came
// from nowhere.
func (s *Service) LookupParts(ctx context.Context, mpns []string) (provider string, enrichments map[string]hbom.Enrichment) {
	p := s.hbomProvider()
	return p.Name(), p.Lookup(ctx, mpns)
}

// PartProvider reports which PartDataProvider is configured.
//
// `configured` is false for `manual` — see hbom.ts's usePartProvider: the UI
// hides the lookup control entirely rather than showing one that always
// fails, and manual is not a failure, it is the correct default.
func (s *Service) PartProvider() (provider string, configured bool) {
	p := s.hbomProvider()
	return p.Name(), p.Name() != "manual"
}

func (s *Service) hbomProvider() hbom.Provider {
	return hbom.Resolve(hbom.NexarFromEnv(), hbom.MouserFromEnv())
}

// ---------------------------------------------------------------------------
// Devices
//
// ⚠ REGISTRATION, NOT DISCOVERY. Every field here is one a person typed or a
// file they supplied. Nothing in this service reaches a device.
// ---------------------------------------------------------------------------

// ListDevices returns a project's registered devices.
func (s *Service) ListDevices(ctx context.Context, tenantID, projectID string) ([]*hbom.Device, error) {
	devices, err := s.store.ListDevices(ctx, tenantID, projectID)
	if err != nil {
		return nil, mapStoreError(err)
	}
	if devices == nil {
		// [] not null, so a client can length-check without a nil guard.
		devices = []*hbom.Device{}
	}
	return devices, nil
}

// GetDevice reads one registered device.
func (s *Service) GetDevice(ctx context.Context, tenantID, projectID, deviceID string) (*hbom.Device, error) {
	d, err := s.store.GetDevice(ctx, tenantID, projectID, deviceID)
	return d, mapDeviceError(err)
}

// CreateDevice registers a device against a project.
func (s *Service) CreateDevice(ctx context.Context, tenantID, projectID, createdBy string,
	d *hbom.Device,
) (*hbom.Device, error) {
	// The defect this whole seam was named for: a device could be registered
	// against a project that produces only an SBOM. The row was written, the
	// device appeared on screen, and no report would ever contain it.
	if err := s.requireClassified(ctx, tenantID, projectID, model.BOMTypeHBOM); err != nil {
		return nil, err
	}
	if err := hbom.ValidateDevice(d); err != nil {
		return nil, errs.Newf(errs.ValidationFieldInvalid, "%v", err)
	}
	created, err := s.store.CreateDevice(ctx, tenantID, projectID, createdBy, d)
	return created, mapDeviceError(err)
}

// UpdateDevice edits a device's registration fields.
func (s *Service) UpdateDevice(ctx context.Context, tenantID, projectID, deviceID string,
	d *hbom.Device,
) (*hbom.Device, error) {
	if err := hbom.ValidateDevice(d); err != nil {
		return nil, errs.Newf(errs.ValidationFieldInvalid, "%v", err)
	}
	updated, err := s.store.UpdateDevice(ctx, tenantID, projectID, deviceID, d)
	return updated, mapDeviceError(err)
}

// DeleteDevice retires a device without destroying its BOM documents.
func (s *Service) DeleteDevice(ctx context.Context, tenantID, projectID, deviceID string) error {
	return mapDeviceError(s.store.DeleteDevice(ctx, tenantID, projectID, deviceID))
}

// mapDeviceError adds the two answers a device can give that a project cannot.
//
// ⚠ NOT-FOUND STAYS NOTFOUND_RESOURCE, NOT NOTFOUND_PROJECT. A caller who names
// a device id that belongs to another tenant must get the same answer as one
// who names an id that never existed — and mapStoreError's project wording
// would tell them their PROJECT was missing, which is a different and
// misleading fact.
func mapDeviceError(err error) error {
	switch {
	case err == nil:
		return nil
	case errors.Is(err, store.ErrSerialTaken):
		return errs.New(errs.ProjectDeviceIdentifierTaken,
			"a device with this serial number or asset tag is already registered "+
				"in your organisation. A serial identifies one physical unit, so "+
				"this usually means it has been registered already — search for it "+
				"rather than creating a second record.")
	case errors.Is(err, store.ErrNotFound):
		return errs.New(errs.NotFoundResource, "no such device")
	default:
		return err
	}
}
