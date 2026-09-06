package databaseadmission

import (
	natsserver "github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nkeys"
	"strings"
	"testing"
	"time"
)

func databaseGrantFixture(t *testing.T) (BrokerGrant, nkeys.KeyPair, nkeys.KeyPair) {
	t.Helper()
	host, err := nkeys.CreateUser()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(host.Wipe)
	lifecycle, err := nkeys.CreateUser()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(lifecycle.Wipe)
	public, _ := host.PublicKey()
	lifePublic, _ := lifecycle.PublicKey()
	return BrokerGrant{ServerIdentity: "spiffe://terrascale.tech/production/terrabase-member/01ARZ3NDEKTSV4RRFFQ69G5FAV/01ARZ3NDEKTSV4RRFFQ69G5FAW", PublicNKey: public, LifecyclePublicNKey: lifePublic, Account: "$G"}, host, lifecycle
}
func TestDatabaseBrokerGrantsSeparateActualRoles(t *testing.T) {
	cluster := newAdmissionJournalCluster(t)
	grant, hostKey, lifecycleKey := databaseGrantFixture(t)
	for i, server := range cluster.servers {
		options, err := ApplyBrokerGrants(cluster.options[i], []BrokerGrant{grant})
		if err != nil {
			t.Fatal(err)
		}
		if err := server.ReloadOptions(options); err != nil {
			t.Fatal(err)
		}
	}
	for _, role := range []struct {
		name            string
		key             nkeys.KeyPair
		allowed, denied string
	}{{"host", hostKey, CreateSubject, LifecycleEventSubject}, {"lifecycle", lifecycleKey, LifecycleEventSubject, CreateSubject}} {
		t.Run(role.name, func(t *testing.T) {
			denied := make(chan error, 8)
			public, _ := role.key.PublicKey()
			connection, err := nats.Connect(cluster.servers[0].ClientURL(), nats.Secure(cluster.tls.Clone()), nats.Nkey(public, role.key.Sign), nats.NoReconnect(), nats.ReconnectBufSize(-1), nats.ErrorHandler(func(_ *nats.Conn, _ *nats.Subscription, err error) { denied <- err }))
			if err != nil {
				t.Fatal(err)
			}
			defer connection.Close()
			controller := cluster.connect(t)
			defer controller.Close()
			received := make(chan struct{}, 1)
			sub, err := controller.Subscribe(role.allowed, func(*nats.Msg) { received <- struct{}{} })
			if err != nil {
				t.Fatal(err)
			}
			defer sub.Unsubscribe()
			controller.Flush()
			if err := connection.Publish(role.allowed, []byte("admitted")); err != nil {
				t.Fatal(err)
			}
			connection.Flush()
			select {
			case <-received:
			case <-time.After(2 * time.Second):
				t.Fatal("exact role could not publish")
			}
			for _, subject := range []string{role.denied, "$KV.ORCH_LEADERS.authority.global"} {
				if err := connection.Publish(subject, []byte("denied")); err != nil {
					t.Fatal(err)
				}
				connection.Flush()
				select {
				case err := <-denied:
					if !strings.Contains(err.Error(), "Permissions Violation") {
						t.Fatal(err)
					}
				case <-time.After(2 * time.Second):
					t.Fatal("role granted foreign publication")
				}
			}
		})
	}
}
func TestDatabaseBrokerGrantsRejectReuse(t *testing.T) {
	grant, _, _ := databaseGrantFixture(t)
	raw, err := EncodeBrokerGrants([]BrokerGrant{grant})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ParseBrokerGrants(raw); err != nil {
		t.Fatal(err)
	}
	if _, err := ApplyBrokerGrants(&natsserver.Options{Nkeys: []*natsserver.NkeyUser{{Nkey: grant.PublicNKey}}}, []BrokerGrant{grant}); err == nil {
		t.Fatal("accepted broader authority key")
	}
	grant.LifecyclePublicNKey = grant.PublicNKey
	if _, err := EncodeBrokerGrants([]BrokerGrant{grant}); err == nil {
		t.Fatal("accepted shared lifecycle key")
	}
}
