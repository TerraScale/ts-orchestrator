package regionhealth

import (
	"bytes"
	"context"
	"testing"
	"time"

	"github.com/nats-io/nats-server/v2/server"
)

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
