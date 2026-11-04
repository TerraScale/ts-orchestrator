package mesh

import (
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/nats-io/nats.go"
)

const testTerraBaseToken = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

// TerraBase reaches the mesh's loopback listener with its token alone and may
// use only its own subjects and JetStream API (PIVOT D25); ts-orch's subjects
// stay refused and ts-orch's users still authenticate.
func TestTerraBaseTokenIsScopedToItsSubjects(t *testing.T) {
	ca, err := DeriveCA(make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	ports := freePorts(t, 2)
	node, err := start(config{region: "gru", server: "gru-1", dir: t.TempDir(), clusterHost: "127.0.0.1",
		clusterPort: ports[0], localPort: ports[1], ca: ca, terrabaseToken: testTerraBaseToken,
		applier: &fakeApplier{running: map[string]int64{}}, peersDir: t.TempDir(), peersEvery: time.Hour,
		address: func() (string, error) { return "10.200.0.1", nil }})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(node.Close)
	url := fmt.Sprintf("nats://127.0.0.1:%d", ports[1])

	if _, err := nats.Connect(url, nats.Token("wrong-token-0123456789abcdef")); err == nil {
		t.Fatal("a wrong token connected")
	}
	if _, err := nats.Connect(url); err == nil {
		t.Fatal("an anonymous client connected")
	}

	violations := make(chan error, 8)
	terrabase, err := nats.Connect(url, nats.Token(testTerraBaseToken),
		nats.ErrorHandler(func(_ *nats.Conn, _ *nats.Subscription, err error) { violations <- err }))
	if err != nil {
		t.Fatal(err)
	}
	defer terrabase.Close()
	peer, err := nats.Connect(url, nats.Token(testTerraBaseToken))
	if err != nil {
		t.Fatal(err)
	}
	defer peer.Close()

	notices, err := peer.SubscribeSync("terrabase.revision.>")
	if err != nil {
		t.Fatal(err)
	}
	if err := peer.Flush(); err != nil {
		t.Fatal(err)
	}
	if err := terrabase.Publish("terrabase.revision.gru.db1", []byte("{}")); err != nil {
		t.Fatal(err)
	}
	if message, err := notices.NextMsg(5 * time.Second); err != nil || message.Subject != "terrabase.revision.gru.db1" {
		t.Fatalf("revision notice: %v %v", message, err)
	}

	for _, subject := range []string{ApplySubject, PingSubject, "ts.anything", "$SYS.REQ.SERVER.PING"} {
		if err := terrabase.Publish(subject, nil); err != nil {
			t.Fatal(err)
		}
		if err := terrabase.Flush(); err != nil {
			t.Fatal(err)
		}
		select {
		case err := <-violations:
			if !errors.Is(err, nats.ErrPermissionViolation) || !strings.Contains(err.Error(), "Publish") {
				t.Fatalf("publish %s: %v", subject, err)
			}
		case <-time.After(5 * time.Second):
			t.Fatalf("publish to %s was not refused", subject)
		}
	}
	if _, err := terrabase.Subscribe(ApplySubject, func(*nats.Msg) {}); err != nil {
		t.Fatal(err)
	}
	_ = terrabase.Flush()
	select {
	case err := <-violations:
		if !errors.Is(err, nats.ErrPermissionViolation) || !strings.Contains(err.Error(), "Subscription") {
			t.Fatalf("subscribe %s: %v", ApplySubject, err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("subscribe to the apply subject was not refused")
	}

	// ts-orch's own users still connect by name and password.
	if err := node.conn.Flush(); err != nil {
		t.Fatal(err)
	}
	if _, err := nats.Connect(url, nats.UserInfo(orchUser, "wrong")); err == nil {
		t.Fatal("orch connected with a wrong password")
	}
}
