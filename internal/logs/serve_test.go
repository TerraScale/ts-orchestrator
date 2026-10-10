package logs

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nats.go"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/protocol"
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
	conn := startNATS(t)
	view := NewView("gru")
	now := time.Now().UTC()
	view.Add(testWindow("node-a", "b1", 0, now.Truncate(time.Minute), testClass("api", "WARN", "slow", 4)), now)
	if _, err := Serve(t.Context(), conn, "gru", view); err != nil {
		t.Fatal(err)
	}
	subject := protocol.Regional("gru", "query", "logs.v1")

	response, err := conn.Request(subject, []byte(`{"v":1,"window":"1h","min_level":"WARN","service":"","limit":5}`), time.Second)
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

func TestHandlerValidatesQueryParameters(t *testing.T) {
	view := NewView("gru")
	handler := Handler(view)

	bad := httptest.NewRecorder()
	handler.ServeHTTP(bad, httptest.NewRequest(http.MethodGet, "/v1/logs?window=2h", nil))
	if bad.Code != http.StatusBadRequest {
		t.Fatalf("window=2h: status %d, want 400", bad.Code)
	}

	good := httptest.NewRecorder()
	handler.ServeHTTP(good, httptest.NewRequest(http.MethodGet, "/v1/logs?min_level=WARN&limit=7", nil))
	var reply Reply
	if good.Code != http.StatusOK || json.Unmarshal(good.Body.Bytes(), &reply) != nil || reply.Region != "gru" {
		t.Fatalf("status %d body %s", good.Code, good.Body.String())
	}
}
