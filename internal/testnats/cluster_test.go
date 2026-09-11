package testnats

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/nats-io/nats.go"
)

func TestPermissionedRolesEnforcePublishSubscribeAndKVBoundaries(t *testing.T) {
	cluster := NewPermissioned(t,
		RoleConfig{Name: "owner", Account: "APP", Publish: []string{">"}, Subscribe: []string{">"}},
		RoleConfig{Name: "publisher", Account: "APP", Publish: []string{"fixture.allowed"}},
		RoleConfig{Name: "subscriber", Account: "APP", Subscribe: []string{"fixture.allowed"}},
		RoleConfig{Name: "reader", Account: "APP", Publish: []string{"$JS.API.STREAM.INFO.KV_ALLOWED", "_INBOX.>"}, Subscribe: []string{"$JS.API.STREAM.INFO.KV_ALLOWED", "$KV.KV_ALLOWED.>", "_INBOX.>"}},
	)
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()

	subscriber := cluster.ConnectRole(t, "subscriber")
	received := make(chan struct{}, 1)
	subscription, err := subscriber.Subscribe("fixture.allowed", func(*nats.Msg) { received <- struct{}{} })
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = subscription.Unsubscribe() })
	if err := subscriber.Flush(); err != nil {
		t.Fatal(err)
	}
	publisher := cluster.ConnectRole(t, "publisher")
	if err := publisher.Publish("fixture.allowed", []byte("accepted")); err != nil {
		t.Fatal(err)
	}
	if err := publisher.Flush(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-received:
	case <-ctx.Done():
		t.Fatal("permitted role publication was not delivered")
	}

	denied := make(chan error, 4)
	publisher.SetErrorHandler(func(_ *nats.Conn, _ *nats.Subscription, err error) { denied <- err })
	if err := publisher.Publish("fixture.denied", []byte("rejected")); err != nil {
		t.Fatal(err)
	}
	if err := publisher.Flush(); err != nil {
		t.Fatal(err)
	}
	assertPermissionViolation(t, denied)

	subscriber.SetErrorHandler(func(_ *nats.Conn, _ *nats.Subscription, err error) { denied <- err })
	if _, err := subscriber.Subscribe("fixture.denied", func(*nats.Msg) {}); err != nil {
		t.Fatal(err)
	}
	if err := subscriber.Flush(); err != nil {
		t.Fatal(err)
	}
	assertPermissionViolation(t, denied)

	reader := cluster.ConnectRole(t, "reader")
	reader.SetErrorHandler(func(_ *nats.Conn, _ *nats.Subscription, err error) { denied <- err })
	if err := reader.Publish("$KV.KV_OTHER.secret", []byte("rejected")); err != nil {
		t.Fatal(err)
	}
	if err := reader.Flush(); err != nil {
		t.Fatal(err)
	}
	assertPermissionViolation(t, denied)
}

func TestPermissionedAccountsKeepJetStreamAcrossRestart(t *testing.T) {
	cluster := NewPermissioned(t, RoleConfig{Name: "owner", Account: "APP", Publish: []string{">"}, Subscribe: []string{">"}})
	// Creating a replicated JetStream bucket immediately after a three-node
	// restart requires route convergence. Allow that local integration setup
	// to finish on loaded qualification hosts while retaining a finite bound.
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()

	OpenLeaseStore(t, ctx, cluster.Connect(t), true)
	OpenLeaseStore(t, ctx, cluster.ConnectRole(t, "owner"), true)
	cluster.Restart(t)

	OpenLeaseStore(t, ctx, cluster.Connect(t), false)
	OpenLeaseStore(t, ctx, cluster.ConnectRole(t, "owner"), false)
}

func assertPermissionViolation(t *testing.T, denied <-chan error) {
	t.Helper()
	select {
	case err := <-denied:
		if !strings.Contains(err.Error(), "Permissions Violation") {
			t.Fatalf("unexpected NATS ACL error: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("unauthorized operation was not rejected")
	}
}
