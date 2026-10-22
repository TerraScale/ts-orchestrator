package regionhealth

import (
	"bytes"
	"context"
	"slices"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/observability"
	"github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nats.go"
)

const gibibyte = 1 << 30

func healthy() observability.SystemView {
	return observability.SystemView{
		MemTotalBytes: 24 * gibibyte, MemAvailBytes: 12 * gibibyte,
		Pressure:    map[string]observability.PSI{"memory": {SomeAvg10: 0.5}},
		Filesystems: []observability.FilesystemView{{Path: "/var/lib/containerd", SizeBytes: 100 * gibibyte, AvailBytes: 50 * gibibyte}},
	}
}

func TestClassify(t *testing.T) {
	cases := map[string]struct {
		edit    func(*Input)
		state   string
		reasons []string
	}{
		"ok":         {func(*Input) {}, StateOK, nil},
		"low memory": {func(in *Input) { in.System.MemAvailBytes = gibibyte * 11 / 10 }, StateDegraded, []string{"memory 1.1 GiB available, 4%"}},
		"stall":      {func(in *Input) { in.System.Pressure["memory"] = observability.PSI{SomeAvg10: 12.5} }, StateDegraded, []string{"memory pressure 12.5% stalled"}},
		// 4 GiB of 20 is 20% free but under the 5 GiB floor.
		"small disk": {func(in *Input) {
			in.System.Filesystems[0].SizeBytes, in.System.Filesystems[0].AvailBytes = 20*gibibyte, 4*gibibyte
		},
			StateDegraded, []string{"disk /var/lib/containerd 4.0 GiB free, 20%"}},
		"unreadable disk": {func(in *Input) { in.System.Filesystems[0].SizeBytes = 0 }, StateDegraded, []string{"disk /var/lib/containerd unreadable"}},
		"lagging":         {func(in *Input) { in.Lagging = []string{"api", "web"} }, StateDegraded, []string{"2 services below desired replicas: api, web"}},
		"node down": {func(in *Input) { in.Node, in.Lagging = "swarm node down", []string{"api"} },
			StateDown, []string{"swarm node down"}},
	}
	for name, tc := range cases {
		in := Input{System: healthy()}
		tc.edit(&in)
		state, reasons := Classify(in)
		if state != tc.state || !slices.Equal(reasons, tc.reasons) {
			t.Errorf("%s: got %s %q, want %s %q", name, state, reasons, tc.state, tc.reasons)
		}
	}
}

func TestWrite(t *testing.T) {
	var output bytes.Buffer
	err := write(&output, []string{"gru", "sjc", "iad"}, map[string]Report{
		"gru": {Region: "gru", State: StateDegraded, Reasons: []string{"memory 1.1 GiB available, 5%"}},
		"sjc": {Region: "sjc", State: StateOK},
	})
	want := "gru: degraded (memory 1.1 GiB available, 5%)\nsjc: ok\niad: unreachable\n"
	if output.String() != want || err == nil || err.Error() != "not ok: gru, iad" {
		t.Fatalf("got %q, %v", output.String(), err)
	}
	output.Reset()
	if err := write(&output, []string{"local"}, map[string]Report{"local": {State: StateOK}}); err != nil || output.String() != "local: ok\n" {
		t.Fatalf("got %q, %v", output.String(), err)
	}
}

// Two regions answer over NATS and a third never does.
func TestAskOverNATS(t *testing.T) {
	embedded, err := server.NewServer(&server.Options{Host: "127.0.0.1", Port: -1, NoSigs: true, NoLog: true})
	if err != nil {
		t.Fatal(err)
	}
	go embedded.Start()
	defer embedded.Shutdown()
	if !embedded.ReadyForConnections(5 * time.Second) {
		t.Fatal("NATS server did not start")
	}
	connect := func() *nats.Conn {
		conn, err := nats.Connect(embedded.ClientURL())
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(conn.Close)
		return conn
	}
	for region, report := range map[string]Report{
		"gru": {Server: "gru-1", State: StateDegraded, Reasons: []string{"memory 1.1 GiB available, 5%"}},
		"sjc": {Server: "sjc-1", State: StateOK},
	} {
		if err := serve(connect(), region, func() Report { return report }); err != nil {
			t.Fatal(err)
		}
	}
	reports, err := ask(context.Background(), connect(), 3, 300*time.Millisecond)
	if err != nil || len(reports) != 2 || reports["gru"].Server != "gru-1" || reports["sjc"].State != StateOK {
		t.Fatalf("got %+v, %v", reports, err)
	}
	var output bytes.Buffer
	_ = write(&output, []string{"gru", "sjc", "iad"}, reports)
	t.Log("\n" + output.String())
	if want := "gru: degraded (memory 1.1 GiB available, 5%)\nsjc: ok\niad: unreachable\n"; output.String() != want {
		t.Fatalf("got %q", output.String())
	}
}
