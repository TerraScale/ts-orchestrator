package host

import (
	"context"
	"strings"
	"testing"
	"time"

	network "github.com/TerraScale/ts-orchestrator/internal/netbird/rollout"
)

type networkSinkFake struct {
	node          string
	status        network.Status
	allowedDigest string
}

func (f *networkSinkFake) Exchange(_ context.Context, r Registration, status network.Status) ([]byte, error) {
	f.node = r.Node
	f.status = status
	return []byte("signed network command"), nil
}
func (f *networkSinkFake) BinaryAllowed(digest string) bool {
	return f.allowedDigest != "" && digest == f.allowedDigest
}

func TestNetBirdExchangeBindsHostIdentityAndRestrictsArtifacts(t *testing.T) {
	c, key, session, _ := reportedTestHost(t)
	status := network.Status{Version: "0.79.0", ObservedAt: time.Now().UTC()}
	if _, err := c.handleAuthorized(t.Context(), signedHostRequest(t, key, "netbird", session.SessionID, session.Epoch, status)); err == nil {
		t.Fatal("accepted without a network sink")
	}
	sink := &networkSinkFake{}
	c.SetNetBirdSink(sink)
	reply, err := c.handleAuthorized(t.Context(), signedHostRequest(t, key, "netbird", session.SessionID, session.Epoch, status))
	if err != nil {
		t.Fatal(err)
	}
	step, ok := reply.(NetBirdStep)
	if !ok || string(step.Step) != "signed network command" || sink.node != "node-a" || sink.status.Version != "0.79.0" {
		t.Fatalf("wrong authenticated exchange: %#v %+v", reply, sink)
	}
	if _, err := c.handleAuthorized(t.Context(), signedHostRequest(t, key, "netbird-binary", session.SessionID, session.Epoch, RolloutBinaryQuery{Digest: strings.Repeat("a", 64)})); err == nil {
		t.Fatal("served artifact not allowed by cell pin")
	}
	if _, err := c.handleAuthorized(t.Context(), signedHostRequest(t, key, "netbird", "wrong-session", session.Epoch, status)); err == nil {
		t.Fatal("accepted another session's status")
	}
}
