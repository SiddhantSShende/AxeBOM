package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"
)

// `axebom collect hardware` — an inventory the operator's OWN machine reports.
//
// ⚠ THIS RUNS ON THE CUSTOMER'S MACHINE, BY THE CUSTOMER'S HAND. The AxeBOM
// service never reaches a device and this does not change that: it is a
// separate, offline binary somebody runs where the hardware is, producing a
// file they then choose to upload. Nothing here contacts AxeBOM, and nothing in
// AxeBOM invokes this.
//
// ⚠ WHY IT EXISTS WHEN hbom-host-report ALREADY READS lshw AND dmidecode:
// because those may not be installed, and asking somebody to install a package
// on a production appliance to document it is a real barrier. This needs
// nothing — it reads files the kernel already publishes.
//
// ⚠ WHAT IT CANNOT SEE, and the report says so too: the kernel publishes what
// it knows. A part with no driver and no SMBIOS entry appears nowhere in
// /sys, and its absence here is not evidence about the machine. Serial numbers
// in /sys/class/dmi/id are root-readable only — unprivileged output names each
// file it could not open rather than leaving a blank that reads as "no serial".
//
// ⚠ NO NETWORK, EVER. It opens no socket, resolves no name and reports to
// nobody. Auditing that claim is one `grep` over this file: there is no net
// import.

const collectSchema = "axebom-hbom-json-1"

func runCollect(_ context.Context, args []string) error {
	if len(args) == 0 {
		return usageCollect()
	}
	switch args[0] {
	case "hardware":
		return runCollectHardware(args[1:])
	case "-h", "--help", "help":
		return usageCollect()
	default:
		return fmt.Errorf("unknown subcommand %q (try: hardware)", args[0])
	}
}

func usageCollect() error {
	fmt.Fprintln(os.Stderr, "Usage: axebom collect hardware [-o FILE] [--quiet]")
	fmt.Fprintln(os.Stderr, "\nReads this machine's own hardware inventory from the files the")
	fmt.Fprintln(os.Stderr, "kernel publishes, and writes it as an AxeBOM hardware BOM you can")
	fmt.Fprintln(os.Stderr, "upload. It contacts nothing and sends nothing anywhere.")
	return exitError{code: 2}
}

func runCollectHardware(args []string) error {
	fs := flag.NewFlagSet("axebom collect hardware", flag.ExitOnError)
	out := fs.String("o", "hbom.json", "where to write the inventory (`-` for stdout)")
	quiet := fs.Bool("quiet", false, "do not print what is about to be read")
	if err := fs.Parse(args); err != nil {
		return err
	}

	if runtime.GOOS != "linux" {
		// ⚠ NAMED, NOT SILENTLY DEGRADED. A collector that produced an almost
		// empty file on macOS would look like the machine had no hardware.
		return fmt.Errorf(
			"this collector reads Linux's /sys and /proc and has no reader for %s.\n"+
				"On this platform, produce an inventory with a tool you already have and "+
				"upload that instead — AxeBOM reads lshw, dmidecode, fwupd, "+
				"Get-CimInstance and Redfish JSON", runtime.GOOS)
	}

	if !*quiet {
		// ⚠ SAY WHAT WILL BE READ BEFORE READING IT. This runs on somebody's
		// production machine at somebody else's suggestion; "trust me" is not
		// an acceptable interface for that.
		fmt.Fprintln(os.Stderr, "axebom collect hardware — reading, and nothing else:")
		for _, s := range collectSources {
			fmt.Fprintf(os.Stderr, "  %-28s %s\n", s.path, s.what)
		}
		fmt.Fprintln(os.Stderr, "\nNo network connection is opened. Nothing is sent anywhere.")
		fmt.Fprintln(os.Stderr, "Review the file before you upload it.")
		fmt.Fprintln(os.Stderr)
	}

	doc := collectHardware()

	body, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return fmt.Errorf("rendering the inventory: %w", err)
	}
	body = append(body, '\n')

	if *out == "-" {
		_, err = os.Stdout.Write(body)
		return err
	}
	// ⚠ 0600, NOT 0644, AND THAT IS A REAL DECISION RATHER THAN A LINTER FIX.
	// This file can contain serial numbers the operator needed root to read.
	// Writing it world-readable would take a value that required privilege and
	// hand it to every local account on a shared machine.
	if err := os.WriteFile(*out, body, 0o600); err != nil {
		return fmt.Errorf("writing %s: %w", *out, err)
	}

	if !*quiet {
		fmt.Fprintf(os.Stderr, "Wrote %s — %d component(s).\n", *out, countNodes(doc.Root))
		if len(doc.Unreadable) > 0 {
			fmt.Fprintf(os.Stderr,
				"\n%d file(s) could not be read; the inventory records which, and why.\n"+
					"Re-running with more privilege fills those in. It is recorded rather\n"+
					"than left blank because a missing serial and an unreadable one are\n"+
					"different facts.\n", len(doc.Unreadable))
		}
	}
	return nil
}

// ---------------------------------------------------------------------------
// The document
// ---------------------------------------------------------------------------

type collectDoc struct {
	Schema     string        `json:"axebom_hbom"`
	Collector  collectorInfo `json:"collector"`
	Root       *collectNode  `json:"root"`
	Unreadable []unreadable  `json:"unreadable,omitempty"`
}

type collectorInfo struct {
	Name        string `json:"name"`
	Version     string `json:"version"`
	OS          string `json:"os"`
	CollectedAt string `json:"collected_at"`
	Privileged  bool   `json:"privileged"`
	// Disclosure travels IN the document, because the document outlives the
	// terminal it was produced in and is the thing an auditor reads.
	Disclosure string `json:"disclosure"`
}

type unreadable struct {
	Path   string `json:"path"`
	Reason string `json:"reason"`
}

type collectNode struct {
	ProductName     string         `json:"product_name"`
	ProductVersion  string         `json:"product_version,omitempty"`
	Manufacturer    string         `json:"manufacturer_name,omitempty"`
	SerialNumber    string         `json:"serial_number,omitempty"`
	ModelNumber     string         `json:"model_number,omitempty"`
	FirmwareVersion string         `json:"firmware_version,omitempty"`
	Spec            string         `json:"technical_specification,omitempty"`
	Children        []*collectNode `json:"children,omitempty"`
}

func countNodes(n *collectNode) int {
	if n == nil {
		return 0
	}
	total := 1
	for _, c := range n.Children {
		total += countNodes(c)
	}
	return total
}

// collectSources is what the collector reads, published so it can be printed
// before anything is opened and cited in the document afterwards.
var collectSources = []struct{ path, what string }{
	{"/sys/class/dmi/id", "board, chassis and BIOS identity (SMBIOS)"},
	{"/proc/cpuinfo", "processor model"},
	{"/sys/block/*/device", "storage device model and vendor"},
	{"/sys/class/net/*/device", "network interface identity"},
}

// ---------------------------------------------------------------------------
// Collection
// ---------------------------------------------------------------------------

func collectHardware() collectDoc {
	var missing []unreadable
	read := func(path string) string {
		// #nosec G304 -- every path is a constant in this file, under
		// /sys/class/dmi/id. Nothing here is caller-supplied; the command takes
		// no path argument at all.
		body, err := os.ReadFile(path)
		if err != nil {
			if errors.Is(err, fs.ErrNotExist) {
				// Absent is ordinary — not every machine has every DMI field —
				// and recording it would drown the genuinely interesting case.
				return ""
			}
			missing = append(missing, unreadable{Path: path, Reason: reasonFor(err)})
			return ""
		}
		return cleanValue(string(body))
	}

	const dmi = "/sys/class/dmi/id/"
	root := &collectNode{
		ProductName:     firstNonBlank(read(dmi+"product_name"), "Reported host"),
		ProductVersion:  read(dmi + "product_version"),
		Manufacturer:    read(dmi + "sys_vendor"),
		SerialNumber:    read(dmi + "product_serial"),
		FirmwareVersion: read(dmi + "bios_version"),
		Spec:            "system",
	}

	if board := (&collectNode{
		ProductName:  firstNonBlank(read(dmi+"board_name"), ""),
		Manufacturer: read(dmi + "board_vendor"),
		SerialNumber: read(dmi + "board_serial"),
		Spec:         "baseboard",
	}); board.ProductName != "" {
		root.Children = append(root.Children, board)
	}

	if cpu := collectCPU(); cpu != nil {
		root.Children = append(root.Children, cpu)
	}
	root.Children = append(root.Children, collectBlockDevices(&missing)...)
	root.Children = append(root.Children, collectNetDevices(&missing)...)

	sort.Slice(missing, func(i, j int) bool { return missing[i].Path < missing[j].Path })

	return collectDoc{
		Schema: collectSchema,
		Collector: collectorInfo{
			Name:        "axebom collect hardware",
			Version:     Version,
			OS:          runtime.GOOS,
			CollectedAt: time.Now().UTC().Format(time.RFC3339),
			Privileged:  os.Geteuid() == 0,
			Disclosure: "Produced on this machine by its operator, from the files the " +
				"kernel publishes. AxeBOM did not examine any hardware and reached no " +
				"device. A part the kernel does not know about is absent from this list " +
				"rather than absent from the machine.",
		},
		Root:       root,
		Unreadable: missing,
	}
}

func collectCPU() *collectNode {
	body, err := os.ReadFile("/proc/cpuinfo")
	if err != nil {
		return nil
	}
	var model, vendor string
	for _, line := range strings.Split(string(body), "\n") {
		key, value, _ := strings.Cut(line, ":")
		switch strings.TrimSpace(key) {
		case "model name":
			if model == "" {
				model = strings.TrimSpace(value)
			}
		case "vendor_id":
			if vendor == "" {
				vendor = strings.TrimSpace(value)
			}
		}
	}
	if model == "" {
		return nil
	}
	// ⚠ ONE ROW, NOT ONE PER LOGICAL CPU. /proc/cpuinfo repeats the block for
	// every thread; emitting each would report a 64-thread server as 64
	// processors, which is a parts list nobody can order from.
	return &collectNode{ProductName: model, Manufacturer: vendor, Spec: "processor"}
}

func collectBlockDevices(missing *[]unreadable) []*collectNode {
	var out []*collectNode
	entries, err := os.ReadDir("/sys/block")
	if err != nil {
		return nil
	}
	for _, e := range entries {
		base := filepath.Join("/sys/block", e.Name(), "device")
		model := readTrimmed(base+"/model", missing)
		if model == "" {
			continue // loop devices, ram disks and device-mapper nodes
		}
		out = append(out, &collectNode{
			ProductName:  model,
			Manufacturer: readTrimmed(base+"/vendor", missing),
			SerialNumber: readTrimmed(base+"/serial", missing),
			Spec:         "storage (" + e.Name() + ")",
		})
	}
	return out
}

func collectNetDevices(missing *[]unreadable) []*collectNode {
	var out []*collectNode
	entries, err := os.ReadDir("/sys/class/net")
	if err != nil {
		return nil
	}
	for _, e := range entries {
		if e.Name() == "lo" {
			continue
		}
		base := filepath.Join("/sys/class/net", e.Name(), "device")
		vendor := readTrimmed(base+"/vendor", missing)
		device := readTrimmed(base+"/device", missing)
		if vendor == "" && device == "" {
			continue // virtual interfaces have no backing device
		}
		// ⚠ PCI IDS, NOT NAMES. Turning 0x8086 into "Intel" needs pci.ids,
		// which this binary does not ship and will not download — it opens no
		// network. The id is the fact; a lookup is somebody else's job.
		out = append(out, &collectNode{
			ProductName: "Network interface " + e.Name(),
			ModelNumber: strings.TrimSpace(vendor + " " + device),
			Spec:        "network",
		})
	}
	return out
}

func readTrimmed(path string, missing *[]unreadable) string {
	// #nosec G304 -- path is filepath.Join of a fixed sysfs root and a name the
	// KERNEL published through ReadDir, which never contains a separator and
	// never contains "." or "..". Nothing here is caller-supplied.
	body, err := os.ReadFile(path)
	if err != nil {
		if !errors.Is(err, fs.ErrNotExist) {
			*missing = append(*missing, unreadable{Path: path, Reason: reasonFor(err)})
		}
		return ""
	}
	return cleanValue(string(body))
}

func reasonFor(err error) string {
	if errors.Is(err, fs.ErrPermission) {
		return "permission denied — re-run with more privilege to include this"
	}
	return err.Error()
}

// cleanValue trims a sysfs value and rejects the placeholders firmware ships.
//
// ⚠ "Default string" AND "To Be Filled By O.E.M." ARE WHAT A MOTHERBOARD SAYS
// WHEN THE MANUFACTURER LEFT THE FIELD BLANK. Carrying one through records a
// serial number that is not one — and every board shipped with the same
// placeholder would then collide on the uniqueness that exists to catch a unit
// registered twice.
func cleanValue(raw string) string {
	value := strings.TrimSpace(raw)
	switch strings.ToLower(value) {
	case "", "none", "n/a", "unknown", "default string",
		"to be filled by o.e.m.", "to be filled by oem",
		"system serial number", "system manufacturer", "system product name",
		"not specified", "not available", "0", "00000000":
		return ""
	}
	return value
}

func firstNonBlank(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return ""
}
