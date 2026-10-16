package logs

import (
	"context"
	"encoding/json"
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
	conn := startNATS(t)
	js, err := jetstream.New(conn)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := OpenStream(t.Context(), js, "gru", 1); err != nil {
		t.Fatal(err)
	}
	// Opening the existing stream again takes the update path.
	stream, err := OpenStream(t.Context(), js, "gru", 1)
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
		if _, err := js.Publish(t.Context(), protocol.AgentObservation("gru", nkey, "logs"), data); err != nil {
			t.Fatal(err)
		}
	}
	// Published before the follower starts, so the follower must replay them.
	publish(admitted, testWindow("node-a", "b1", 0, minute, testClass("api", "WARN", "slow", 2)))
	publish(stranger, testWindow("node-a", "b1", 0, minute, testClass("api", "WARN", "spoof", 9)))
	publish(admitted, testWindow("node-b", "b1", 0, minute, testClass("api", "WARN", "unregistered", 9)))
	// The stream is ordered: once the last window is counted, the rejected ones before it were handled too.
	publish(admitted, testWindow("node-a", "b1", 1, minute, testClass("api", "INFO", "sentinel", 1)))

	view := NewView("gru")
	verify := func(_ context.Context, node, nkey string) bool { return node == "node-a" && nkey == admitted }
	ctx, cancel := context.WithCancel(t.Context())
	t.Cleanup(cancel)
	go stream.Follow(ctx, view, verify)

	deadline := time.Now().Add(5 * time.Second)
	for {
		reply := view.Summary(Request{Version: 1, Window: "1h", MinLevel: LevelDebug}, time.Now())
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
