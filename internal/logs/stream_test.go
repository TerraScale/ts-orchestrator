package logs

import (
	"context"
	"encoding/json/v2"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/nats-io/nats.go/jetstream"
	"github.com/nats-io/nkeys"

	"github.com/TerraScale/ts-orchestrator/internal/protocol"
)

func publicUserKey(t *testing.T) string {
	t.Helper()
	pair, err := nkeys.CreateUser()
	if err != nil {
		t.Fatal(err)
	}
	public, err := pair.PublicKey()
	if err != nil {
		t.Fatal(err)
	}
	return public
}

func TestFollowCountsOnlyVerifiedWindows(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
	t.Cleanup(cancel)
	conn := startNATS(t)
	js, err := jetstream.New(conn)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := OpenStream(ctx, js, "gru", 1); err != nil {
		t.Fatal(err)
	}
	// Opening the existing stream again takes the update path.
	stream, err := OpenStream(ctx, js, "gru", 1)
	if err != nil {
		t.Fatal(err)
	}

	admitted, stranger := publicUserKey(t), publicUserKey(t)
	minute := time.Now().UTC().Truncate(time.Minute)
	publish := func(nkey string, window Window) {
		t.Helper()
		data, err := json.Marshal(window)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := js.Publish(ctx, protocol.AgentObservation("gru", nkey, "logs"), data); err != nil {
			t.Fatal(err)
		}
	}
	// Published before the follower starts, so the follower must replay them.
	publish(admitted, testWindow("node-a", "b1", 0, minute, testClass("api", "WARN", "slow", 2)))
	publish(stranger, testWindow("node-a", "b1", 0, minute, testClass("api", "WARN", "spoof", 9)))
	publish(admitted, testWindow("node-b", "b1", 0, minute, testClass("api", "WARN", "unregistered", 9)))
	invalidVersion := testWindow("node-a", "b1", 9, minute, testClass("api", "WARN", "bad version", 9))
	invalidVersion.Version = 2
	publish(admitted, invalidVersion)
	invalid, err := json.Marshal(testWindow("node-a", "b1", 10, minute, testClass("api", "WARN", "invalid payload", 9)))
	if err != nil {
		t.Fatal(err)
	}
	unknownField := strings.TrimSuffix(string(invalid), "}") + `,"extra":true}`
	oversized := string(invalid) + strings.Repeat(" ", maxWindowBytes-len(invalid)+1)
	for _, data := range []string{`not json`, unknownField, oversized} {
		if _, err := js.Publish(ctx, protocol.AgentObservation("gru", admitted, "logs"), []byte(data)); err != nil {
			t.Fatal(err)
		}
	}
	// The stream is ordered: once the last window is counted, the rejected ones before it were handled too.
	publish(admitted, testWindow("node-a", "b1", 1, minute, testClass("api", "INFO", "sentinel", 1)))

	view := NewView("gru")
	verify := func(_ context.Context, node, nkey string) bool { return node == "node-a" && nkey == admitted }
	followCtx, stop := context.WithCancel(ctx)
	done := make(chan struct{})
	go func() { defer close(done); stream.Follow(followCtx, view, verify) }()
	t.Cleanup(func() {
		stop()
		select {
		case <-done:
		case <-time.After(3 * time.Second):
			t.Error("log follower did not stop")
		}
	})
	endpoint := httptest.NewServer(Handler(view))
	endpoint.Client().Timeout = 2 * time.Second
	t.Cleanup(endpoint.Close)
	p := &logPipeline{ctx: ctx, http: endpoint}

	deadline := time.Now().Add(5 * time.Second)
	for {
		reply := p.get(t, "limit=500")
		if len(reply.Classes) == 2 {
			if reply.Classes[0].Message != "slow" || reply.Classes[0].Count != 2 || reply.Classes[1].Message != "sentinel" {
				t.Fatalf("classes = %+v, want only the verified windows", reply.Classes)
			}
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("follower counted %+v, want slow and sentinel", reply.Classes)
		}
		time.Sleep(10 * time.Millisecond)
	}
}
