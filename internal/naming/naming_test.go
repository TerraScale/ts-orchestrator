package naming

import (
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
