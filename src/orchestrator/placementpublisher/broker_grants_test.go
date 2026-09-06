package placementpublisher

import (
	"context"
	"strings"
	"testing"
	"time"

	natsserver "github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nkeys"
)

func TestBrokerGrantsEnforceExactHostOnRealNATS(t *testing.T) {
	cluster := newPlacementJournalCluster(t)
	key, err := nkeys.CreateUser()
	if err != nil {
		t.Fatal(err)
	}
	defer key.Wipe()
	public, err := key.PublicKey()
	if err != nil {
		t.Fatal(err)
	}
	target := newFakeTarget()
	grant := BrokerGrant{ServerIdentity: target.ServerIdentity(), PublicNKey: public, Account: "$G"}
	for i, server := range cluster.servers {
		options, err := ApplyBrokerGrants(cluster.options[i], []BrokerGrant{grant})
		if err != nil {
			t.Fatal(err)
		}
		if err := server.ReloadOptions(options); err != nil {
			t.Fatal(err)
		}
	}
	denied := make(chan error, 8)
	host, err := nats.Connect(cluster.servers[0].ClientURL(), nats.Secure(cluster.tls.Clone()), nats.Nkey(public, key.Sign), nats.NoReconnect(), nats.ReconnectBufSize(-1), nats.ErrorHandler(func(_ *nats.Conn, _ *nats.Subscription, err error) { denied <- err }))
	if err != nil {
		t.Fatal(err)
	}
	defer host.Close()
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	bridge, err := StartHostBridge(ctx, host, target)
	if err != nil {
		t.Fatal(err)
	}
	defer bridge.Close()
	controller := cluster.connect(t)
	remote, err := NewRemoteTarget(controller, target.ServerIdentity(), target.Principal(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	receipt, err := remote.Stage(ctx, "op-1", testRequest())
	if err != nil || receipt.Revision != 1 {
		t.Fatalf("admitted host could not stage: %v %v", receipt, err)
	}
	for _, subject := range []string{remote.subject, "$KV.ORCH_LEADERS.placement.proposal.state", "$KV.ORCH_LEADERS.authority.global"} {
		if err := host.Publish(subject, []byte("forbidden")); err != nil {
			t.Fatal(err)
		}
		if err := host.FlushWithContext(ctx); err != nil {
			t.Fatal(err)
		}
		select {
		case err := <-denied:
			if !strings.Contains(err.Error(), "Permissions Violation") {
				t.Fatal(err)
			}
		case <-ctx.Done():
			t.Fatal("host was granted authority publication")
		}
	}
}
func TestBrokerGrantRejectsAuthorityReuseAndUnboundedSubjects(t *testing.T) {
	key, err := nkeys.CreateUser()
	if err != nil {
		t.Fatal(err)
	}
	defer key.Wipe()
	public, _ := key.PublicKey()
	grant := BrokerGrant{ServerIdentity: newFakeTarget().ServerIdentity(), PublicNKey: public, Account: "$G"}
	raw, err := EncodeBrokerGrants([]BrokerGrant{grant})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ParseBrokerGrants(raw); err != nil {
		t.Fatal(err)
	}
	if _, err := ApplyBrokerGrants(&natsserver.Options{Nkeys: []*natsserver.NkeyUser{{Nkey: public}}}, []BrokerGrant{grant}); err == nil {
		t.Fatal("global authority key reused as host bridge")
	}
	if _, err := EncodeBrokerGrants([]BrokerGrant{grant, grant}); err == nil {
		t.Fatal("duplicate host/key accepted")
	}
	changed := grant
	changed.Account = "$SYS"
	if _, err := EncodeBrokerGrants([]BrokerGrant{changed}); err == nil {
		t.Fatal("system account admitted")
	}
	changed = grant
	changed.Account = "missing"
	if _, err := ApplyBrokerGrants(&natsserver.Options{}, []BrokerGrant{changed}); err == nil {
		t.Fatal("missing account silently created")
	}
	if _, err := ParseBrokerGrants([]byte(`{"version":1,"hosts":[],"publish":[">"]}`)); err == nil {
		t.Fatal("caller-defined grants accepted")
	}
}
