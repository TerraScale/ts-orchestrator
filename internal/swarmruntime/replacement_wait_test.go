package swarmruntime

import (
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/handoff"
	"github.com/moby/swarmkit/v2/agent/exec"
	"github.com/moby/swarmkit/v2/api"
)

// sjc 2026-10-28: a dashboard release and its rollback started while
// TerraBase was being replaced and exited with TerraBaseUnavailableException.
func TestStartWaitsForAnotherServicesReplacement(t *testing.T) {
	const terrabase, dashboard = 38081, 38085
	task := func(port uint16) *controller {
		return &controller{task: &api.Task{Endpoint: &api.Endpoint{Spec: &api.EndpointSpec{Ports: []*api.PortConfig{
			{Protocol: api.ProtocolTCP, PublishMode: api.PublishModeHost, PublishedPort: uint32(port), TargetPort: uint32(port)}}}}}}
	}
	app := task(dashboard)
	now := time.Now()
	if err := app.awaitReplacements(now); err != nil {
		t.Fatalf("no replacement running: %v", err)
	}
	handoff.Hold(dashboard + 1) // an app's stop-first hold: nobody waits for it
	t.Cleanup(func() { handoff.Release(dashboard + 1) })
	if err := app.awaitReplacements(now); err != nil {
		t.Fatalf("waited for an app's replacement: %v", err)
	}
	handoff.Hold(terrabase)
	handoff.Await(terrabase)
	t.Cleanup(func() { handoff.Release(terrabase) })
	if err := app.awaitReplacements(now); !exec.IsTemporary(err) {
		t.Fatalf("started during TerraBase's replacement: %v", err)
	}
	// TerraBase's own replacement never waits, nor does one waiting on another.
	if err := task(terrabase).awaitReplacements(now); err != nil {
		t.Fatalf("TerraBase's replacement waited for itself: %v", err)
	}
	if err := task(dashboard + 2).awaitReplacements(now.Add(replacementWaitMax + time.Second)); err != nil {
		t.Fatalf("a hold that is never released blocked a later start: %v", err)
	}
	handoff.Release(terrabase)
	if err := app.awaitReplacements(now); err != nil || len(handoff.AwaitedPorts()) != 0 {
		t.Fatalf("released: %v, still awaited %v", err, handoff.AwaitedPorts())
	}
}
