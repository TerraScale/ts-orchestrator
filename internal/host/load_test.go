package host

import (
	"context"
	"crypto/ed25519"

	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/hostload"
)

func TestAgentPublishesLoadWithoutTelemetrySettings(t *testing.T) {
	if testing.Short() {
		t.Skip("agent load publication runs in the Slow suite")
	}
	controller, conn, _, _, responseKey := testController(t)
	hostKey := registerTestHost(t, controller)
	reported := make(chan hostload.Origin, 1)
	controller.SetLoadSink(func(origin hostload.Origin, report hostload.Report) error {
		if err := report.Validate(); err != nil {
			return err
		}
		select {
		case reported <- origin:
		default:
		}
		return nil
	})
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	t.Cleanup(cancel)
	controllerDone := make(chan error, 1)
	go func() { controllerDone <- controller.Run(ctx) }()
	t.Cleanup(func() { cancel(); <-controllerDone })
	select {
	case <-controller.Ready():
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	agent, err := NewAgent(AgentConfig{Cell: "gru", Node: "node-a", Environment: "production", Roles: []string{"terrabase"},
		Conn: conn, Identity: hostKey, NATSUserPublicKey: testNATSUserKey("node-a"),
		ControllerPublicKey: responseKey.Public().(ed25519.PublicKey),
		Runner:              &memoryRunner{observed: make(map[string]Observation)}, ClockCheck: func() error { return nil },
		WorkloadIdentity: testAgentIdentity(), InstallRoot: testAgentInstallRoot(t), StateRoot: testAgentStateRoot(t)})
	if err != nil {
		t.Fatal(err)
	}
	agentDone := make(chan error, 1)
	go func() { agentDone <- agent.Run(ctx) }()
	t.Cleanup(func() { cancel(); <-agentDone })
	select {
	case origin := <-reported:
		if origin != (hostload.Origin{Cell: "gru", Node: "node-a", Environment: "production"}) {
			t.Fatalf("load origin = %+v", origin)
		}
	case <-ctx.Done():
		t.Fatal("agent did not publish authenticated load with default settings")
	}
}
