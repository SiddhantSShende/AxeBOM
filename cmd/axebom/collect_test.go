package main

import (
	"go/parser"
	"go/token"
	"os"
	"strings"
	"testing"
)

// TestTheCollectorOpensNoNetwork.
//
// ⚠ THE ONE CLAIM THIS COMMAND MAKES THAT A USER CANNOT VERIFY BY LOOKING.
//
// `axebom collect hardware` runs on somebody's production machine, at somebody
// else's suggestion, and prints "No network connection is opened. Nothing is
// sent anywhere." That is either true or it is the worst kind of lie — and the
// only cheap, durable way to keep it true is to assert on the import set.
//
// A future `net/http` added here for "just a version check" fails this test
// with the sentence it broke.
func TestTheCollectorOpensNoNetwork(t *testing.T) {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "collect.go", nil, parser.ImportsOnly)
	if err != nil {
		t.Fatalf("parsing collect.go: %v", err)
	}

	forbidden := []string{"net", "net/http", "net/url", "os/exec"}
	for _, imp := range file.Imports {
		path := strings.Trim(imp.Path.Value, `"`)
		for _, bad := range forbidden {
			if path == bad {
				t.Errorf(
					"collect.go imports %q.\n"+
						"  This command tells the operator, on their own production "+
						"machine, that it opens no network connection and runs nothing. "+
						"Both have to stay true — and `os/exec` is on the list because "+
						"shelling out to lshw would also make this a GPL invocation "+
						"rather than a file read (CLAUDE.md invariant 9).", path)
			}
		}
	}
}

// TestFirmwarePlaceholdersAreNotRecordedAsValues.
//
// ⚠ "Default string" IS WHAT A MOTHERBOARD SAYS WHEN THE MANUFACTURER LEFT THE
// FIELD BLANK, and it is burned into millions of boards. Recorded as a serial
// it is not merely wrong — every one of those boards would then collide on the
// unique index that exists to catch one physical unit registered twice.
func TestFirmwarePlaceholdersAreNotRecordedAsValues(t *testing.T) {
	for _, placeholder := range []string{
		"Default string", "To Be Filled By O.E.M.", "System Serial Number",
		"Not Specified", "None", "n/a", "  ", "0",
	} {
		if got := cleanValue(placeholder); got != "" {
			t.Errorf("cleanValue(%q) = %q; a placeholder was recorded as a real value",
				placeholder, got)
		}
	}

	// And a real value survives, or the filter is useless in the other direction.
	if got := cleanValue("  PF0BBB\n"); got != "PF0BBB" {
		t.Errorf("cleanValue trimmed a real serial to %q", got)
	}
}

// TestTheCollectorSaysWhatItWillReadBeforeReadingIt.
//
// The source list is data rather than a printf, so the banner and the document
// cannot drift from each other — and so this test can assert the banner names
// the two paths that actually carry identity.
func TestTheCollectorSaysWhatItWillReadBeforeReadingIt(t *testing.T) {
	var paths []string
	for _, s := range collectSources {
		if s.what == "" {
			t.Errorf("%s is listed with no explanation of what is read from it", s.path)
		}
		paths = append(paths, s.path)
	}
	joined := strings.Join(paths, " ")
	for _, want := range []string{"/sys/class/dmi/id", "/proc/cpuinfo"} {
		if !strings.Contains(joined, want) {
			t.Errorf("the disclosed source list does not mention %s", want)
		}
	}
}

// TestAnUnreadableFieldIsRecordedRatherThanLeftBlank.
//
// ⚠ THE DIFFERENCE THE WHOLE COLLECTOR EXISTS TO PRESERVE. SMBIOS serials are
// root-readable only; lshw and dmidecode simply omit them when unprivileged, so
// a reader sees a blank and concludes the machine has no serial. "Nobody had
// permission to look" is fixed by re-running with sudo. "There is no serial" is
// not. They must not render the same.
func TestAnUnreadableFieldIsRecordedRatherThanLeftBlank(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("running as root, so nothing is unreadable to exercise")
	}
	doc := collectHardware()

	if doc.Collector.Disclosure == "" {
		t.Error("the document carries no disclosure; it outlives the terminal it was made in")
	}
	if doc.Collector.Privileged {
		t.Fatal("Geteuid is not 0 but the document claims a privileged run")
	}
	// On a Linux CI box /sys/class/dmi/id/product_serial exists and is 0400.
	// Where it does not exist at all, there is nothing to assert — absent is
	// ordinary and deliberately NOT recorded as unreadable.
	if _, err := os.Stat("/sys/class/dmi/id/product_serial"); err == nil {
		var found bool
		for _, u := range doc.Unreadable {
			if strings.HasSuffix(u.Path, "product_serial") {
				found = true
				if !strings.Contains(u.Reason, "permission") {
					t.Errorf("the reason does not name the cause: %q", u.Reason)
				}
			}
		}
		if !found {
			t.Error("a root-only field was skipped without being recorded")
		}
	}
}
