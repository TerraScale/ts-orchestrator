package naming

import (
	"errors"
	"testing"
)

func TestCellAndServerNames(t *testing.T) {
	gru := RegionCell("GRU")
	for _, tc := range []struct {
		got  func() (string, error)
		want string
	}{
		{gru.Name, "gru-1"},
		{func() (string, error) { return Cell{Region: "fra", Index: 2}.Name() }, "fra-2"},
		{func() (string, error) { return gru.Server(Controller, 3) }, "gru-1-ctl-3"},
		{func() (string, error) { return gru.Server(Member, 2) }, "gru-1-db-2"},
		{func() (string, error) { return gru.ControllerSlot("controller-a") }, "gru-1-ctl-1"},
		{func() (string, error) { return gru.ControllerSlot("controller-c") }, "gru-1-ctl-3"},
		{func() (string, error) { return gru.MemberSlot("member-b") }, "gru-1-db-2"},
		{gru.Image, "gru-1-arm64"},
		{func() (string, error) { return Data("sfo-1-db-1") }, "sfo-1-db-1-data"},
		{func() (string, error) { return gru.Server(Gateway, 1) }, "gru-1-gw-1"},
		{func() (string, error) { return gru.API("") }, "gru-1-api"},
		{func() (string, error) { return gru.API("subnet") }, "gru-1-api-subnet"},
	} {
		if got, err := tc.got(); err != nil || got != tc.want {
			t.Fatalf("got %q, %v; want %q", got, err, tc.want)
		}
	}
}

func TestGenerationRejectsOutOfSchemeInput(t *testing.T) {
	for _, call := range []func() (string, error){
		func() (string, error) { return RegionCell("LHR").Name() },
		func() (string, error) { return RegionCell("sa-saopaulo-1").Name() },
		func() (string, error) { return Cell{Region: "GRU"}.Name() },
		func() (string, error) { return RegionCell("GRU").Server("host", 1) },
		func() (string, error) { return RegionCell("GRU").Server(Member, 0) },
		func() (string, error) { return RegionCell("GRU").ControllerSlot("member-a") },
		func() (string, error) { return RegionCell("GRU").ControllerSlot("controller-ab") },
		func() (string, error) { return RegionCell("GRU").MemberSlot("controller-a") },
		func() (string, error) { return Data("gru-1") },
		func() (string, error) { return RegionCell("LHR").API("") },
		func() (string, error) { return RegionCell("GRU").API("Subnet-1") },
		func() (string, error) { return Data("gru-1-db-1-data") },
	} {
		if got, err := call(); !errors.Is(err, ErrName) || got != "" {
			t.Fatalf("got %q, %v; want ErrName", got, err)
		}
	}
}

func TestValidateRejectsReleaseDerivedAndLegacyNames(t *testing.T) {
	for _, name := range []string{"gru-1", "sfo-12", "fra-1-ctl-3", "gru-1-db-10", "gru-1-db-1-data", "gru-1-gw-1"} {
		if err := Validate(name); err != nil {
			t.Fatalf("rejected %q: %v", name, err)
		}
	}
	for _, name := range []string{
		"", "gru", "GRU-1", "gru-0", "gru-01", "lhr-1", "gru-1-ctl", "gru-1-ctl-0", "gru-1-host-1",
		"gru-1-ctl-1-data", "gru-1-gw-1-data", "gru-1-db-1-boot", " gru-1", "gru-1-ctl-1.", "gru-1-mem-1",
		// Names the cell carried before this scheme: slot, deployment and digest derived.
		"gru-controller-a", "controller-b", "gru-member-1",
		"ts-preview-gru-20260929-r4-controller-a", "ts-preview-gru-20260926-host-0123456789abcdef01234567",
		"ts-member-data-0123456789ab",
	} {
		if err := Validate(name); !errors.Is(err, ErrName) {
			t.Fatalf("accepted %q", name)
		}
	}
}

func TestNATSServerNamesControllerSlotsByTheScheme(t *testing.T) {
	for _, tc := range [][3]string{
		{"gru", "controller-a", "gru-1-ctl-1"},
		{"sfo", "controller-c", "sfo-1-ctl-3"},
		{"lab", "controller-a", "lab-controller-a"},
		{"gru", "placement-sizing", "gru-placement-sizing"},
	} {
		if got := NATSServer(tc[0], tc[1]); got != tc[2] {
			t.Fatalf("NATSServer(%q, %q) = %q, want %q", tc[0], tc[1], got, tc[2])
		}
	}
}
