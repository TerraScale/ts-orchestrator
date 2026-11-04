package logs

import (
	"encoding/json/v2"
	"strings"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/protocol"
	"github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nats.go"
)

func startNATS(t *testing.T) *nats.Conn {
	t.Helper()
	srv, err := server.NewServer(&server.Options{Host: "127.0.0.1", Port: -1, JetStream: true,
		StoreDir: t.TempDir(), NoLog: true, NoSigs: true})
	if err != nil {
		t.Fatal(err)
	}
	go srv.Start()
	if !srv.ReadyForConnections(5 * time.Second) {
		t.Fatal("NATS did not start")
	}
	t.Cleanup(func() { srv.Shutdown(); srv.WaitForShutdown() })
	conn, err := nats.Connect(srv.ClientURL())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(conn.Close)
	return conn
}

func TestServeAnswersQueryAndRejectsInvalidRequests(t *testing.T) {
	p := newLogPipeline(t)
	p.publish(t, p.key, testWindow("node-a", "b1", 0, time.Now().UTC().Truncate(time.Minute), testClass("api", "WARN", "slow", 4)))
	p.sync(t)
	conn := p.conn
	if _, err := Serve(p.ctx, conn, "gru", p.view); err != nil {
		t.Fatal(err)
	}
	subject := protocol.Regional("gru", "query", "logs.v1")

	response, err := conn.Request(subject, []byte(`{"v":1,"window":"1h","min_level":"WARN","service":"","limit":500}`), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	var reply Reply
	if err := json.Unmarshal(response.Data, &reply); err != nil {
		t.Fatal(err)
	}
	if reply.Region != "gru" || len(reply.Classes) != 1 || reply.Classes[0].Count != 4 {
		t.Fatalf("reply = %s", response.Data)
	}

	invalid := []string{
		`{"v":2,"window":"1h","min_level":"DEBUG"}`,
		`{"v":1,"window":"1h","min_level":"DEBUG","limit":-1}`,
		`{"v":1,"window":"1h","min_level":"DEBUG","service":"` + strings.Repeat("s", maxServiceBytes+1) + `"}`,
		strings.Repeat(" ", maxRequestBytes) + `{}`,
		`{"v":1,"window":"2h","min_level":"DEBUG"}`,
		`{"v":1,"window":"1h","min_level":"LOUD"}`,
		`{"v":1,"window":"1h","min_level":"DEBUG","limit":501}`,
		`{"v":1,"window":"1h","min_level":"DEBUG","extra":true}`,
		`not json`,
	}
	for _, request := range invalid {
		response, err := conn.Request(subject, []byte(request), time.Second)
		if err != nil {
			t.Fatal(err)
		}
		if string(response.Data) != string(invalidRequest) {
			t.Errorf("%s: reply = %s, want invalid_request", request, response.Data)
		}
	}
}
