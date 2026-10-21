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
		{func() (string, error) { return RegionCell("SJC").ControllerSlot("controller-a") }, "ts-sjc-1"},
		{func() (string, error) { return RegionCell("sjc").ControllerSlot("controller-c") }, "ts-sjc-3"},
		{gru.Image, "gru-1-arm64"},
		{func() (string, error) { return Data("sjc-1-db-1") }, "sjc-1-db-1-data"},
		{func() (string, error) { return gru.Server(Gateway, 1) }, "gru-1-gw-1"},
		{func() (string, error) { return gru.PoolServer("app", 3) }, "gru-1-pool-app-3"},
		{func() (string, error) { return gru.API("") }, "gru-1-api"},
		{func() (string, error) { return gru.API("subnet") }, "gru-1-api-subnet"},
		{func() (string, error) { return gru.Node(1) }, "ts-gru-1"},
		{func() (string, error) { return Cell{Region: "SJC", Index: 1}.Node(12) }, "ts-sjc-12"},
		{func() (string, error) { return Data("ts-gru-3") }, "ts-gru-3-data"},
	} {
		if got, err := tc.got(); err != nil || got != tc.want {
			t.Fatalf("got %q, %v; want %q", got, err, tc.want)
		}
	}
}

func TestGenerationRejectsOutOfSchemeInput(t *testing.T) {
	for _, call := range []func() (string, error){
		func() (string, error) { return RegionCell("XXX").Name() },
		func() (string, error) { return RegionCell("sa-saopaulo-1").Name() },
		func() (string, error) { return Cell{Region: "GRU"}.Name() },
		func() (string, error) { return RegionCell("GRU").Server("host", 1) },
		func() (string, error) { return RegionCell("GRU").Server(Member, 0) },
		func() (string, error) { return RegionCell("GRU").ControllerSlot("member-a") },
		func() (string, error) { return RegionCell("GRU").ControllerSlot("controller-ab") },
		func() (string, error) { return RegionCell("SJC").ControllerSlot("member-a") },
		func() (string, error) { return RegionCell("XXX").ControllerSlot("controller-a") },
		func() (string, error) { return RegionCell("GRU").MemberSlot("controller-a") },
		func() (string, error) { return Data("gru-1") },
		func() (string, error) { return RegionCell("XXX").API("") },
		func() (string, error) { return RegionCell("GRU").API("Subnet-1") },
		func() (string, error) { return Data("gru-1-db-1-data") },
		func() (string, error) { return RegionCell("GRU").PoolServer("a", 1) },
		func() (string, error) { return RegionCell("GRU").PoolServer("app-web", 1) },
		func() (string, error) { return RegionCell("GRU").PoolServer("app", 0) },
		func() (string, error) { return Data("gru-1-pool-app-1") },
		func() (string, error) { return RegionCell("GRU").Node(0) },
		func() (string, error) { return RegionCell("XXX").Node(1) },
		func() (string, error) { return RegionCell("GRU").Node(1000) },
		func() (string, error) { return Data("ts-gru-1-data") },
	} {
		if got, err := call(); !errors.Is(err, ErrName) || got != "" {
			t.Fatalf("got %q, %v; want ErrName", got, err)
		}
	}
}

func TestValidateRejectsReleaseDerivedAndLegacyNames(t *testing.T) {
	for _, name := range []string{"gru-1", "sjc-12", "fra-1-ctl-3", "gru-1-db-10", "gru-1-db-1-data", "gru-1-gw-1",
		"gru-1-pool-app-3", "gru-1-pool-general2-256", "ts-gru-1", "ts-sjc-2", "ts-gru-999", "ts-gru-1-data"} {
		if err := Validate(name); err != nil {
			t.Fatalf("rejected %q: %v", name, err)
		}
	}
	for _, name := range []string{
		"", "gru", "GRU-1", "gru-0", "gru-01", "xxx-1", "gru-1-ctl", "gru-1-ctl-0", "gru-1-host-1",
		"gru-1-ctl-1-data", "gru-1-gw-1-data", "gru-1-db-1-boot", " gru-1", "gru-1-ctl-1.", "gru-1-mem-1",
		"gru-1-pool-app", "gru-1-pool-app-0", "gru-1-pool-1app-1", "gru-1-pool-thirteenchars-1", "gru-1-pool-app-1-data",
		// Names the cell carried before this scheme: slot, deployment and digest derived.
		"gru-controller-a", "controller-b", "gru-member-1",
		"ts-preview-gru-20260929-r4-controller-a", "ts-preview-gru-20260926-host-0123456789abcdef01234567",
		"ts-member-data-0123456789ab",
		"ts-gru", "ts-gru-0", "ts-gru-01", "ts-xxx-1", "ts-gru-1000", "ts-gru-1-1", "ts-gru-1-ctl-1", "TS-gru-1", "ts-gru-1-data-data",
	} {
		if err := Validate(name); !errors.Is(err, ErrName) {
			t.Fatalf("accepted %q", name)
		}
	}
}

func TestNATSServerNamesControllerSlotsByTheScheme(t *testing.T) {
	for _, tc := range [][3]string{
		{"gru", "controller-a", "gru-1-ctl-1"},
		{"sjc", "controller-c", "ts-sjc-3"},
		{"lab", "controller-a", "lab-controller-a"},
		{"gru", "placement-sizing", "gru-placement-sizing"},
	} {
		if got := NATSServer(tc[0], tc[1]); got != tc[2] {
			t.Fatalf("NATSServer(%q, %q) = %q, want %q", tc[0], tc[1], got, tc[2])
		}
	}
}
