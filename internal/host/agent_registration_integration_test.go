package host

import (
	"context"
	"crypto/ed25519"
	"testing"
)

func TestOwnRegistrationBindsActualSignedSessionAndKeys(t *testing.T) {
	controller, conn, _, _, responseKey := testController(t)
	hostKey := registerTestHost(t, controller)
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- controller.Run(ctx) }()
	<-controller.Ready()
	t.Cleanup(func() { cancel(); <-done })
	public := responseKey.Public().(ed25519.PublicKey)
	agent, err := NewAgent(AgentConfig{Cell: "gru", Node: "node-a", Environment: "production", Roles: []string{"terrabase"},
		Conn: conn, Identity: hostKey, NATSUserPublicKey: testNATSUserKey("node-a"), ControllerPublicKey: public,
		ClockCheck: func() error { return nil }, WorkloadIdentity: testAgentIdentity(),
		Runner: &memoryRunner{observed: make(map[string]Observation)}, InstallRoot: testAgentInstallRoot(t), StateRoot: testAgentStateRoot(t)})
	if err != nil {
		t.Fatal(err)
	}
	if err := agent.acquire(t.Context()); err != nil {
		t.Fatal(err)
	}
	statuses, err := controller.ListHosts(t.Context())
	if err != nil || len(statuses) != 1 {
		t.Fatal("actual ordered registration unavailable", err)
	}
	registration := statuses[0].Registration
	if err := agent.VerifyOwnRegistration(registration, public); err != nil {
		t.Fatal("actual signed session did not bind its own current registration", err)
	}
	for _, mutate := range []func(*Registration){
		func(r *Registration) { r.Node = "another-host" },
		func(r *Registration) { r.PublicKey = "another-key" },
		func(r *Registration) { r.NATSUserPublicKey = testNATSUserKey("another-host") },
		func(r *Registration) { r.Generation++ },
	} {
		changed := registration
		mutate(&changed)
		if err := agent.VerifyOwnRegistration(changed, public); err == nil {
			t.Fatal("actual session authorized another host, key or registration generation")
		}
	}
	wrong := append(ed25519.PublicKey(nil), public...)
	wrong[0] ^= 1
	if err := agent.VerifyOwnRegistration(registration, wrong); err == nil {
		t.Fatal("actual session accepted an unpinned controller signer")
	}
}
