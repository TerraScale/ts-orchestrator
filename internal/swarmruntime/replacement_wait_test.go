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
	handoff.Hold(terrabase)
	t.Cleanup(func() { handoff.Release(terrabase) })
	if err := app.awaitReplacements(now); !exec.IsTemporary(err) {
		t.Fatalf("started during TerraBase's replacement: %v", err)
	}
	// TerraBase's own replacement never waits, nor does one waiting on another.
	if err := task(terrabase).awaitReplacements(now); err != nil {
		t.Fatalf("TerraBase's replacement waited for itself: %v", err)
	}
	if err := app.awaitReplacements(now.Add(replacementWaitMax)); err != nil {
		t.Fatalf("a hold that is never released blocked the start: %v", err)
	}
	handoff.Release(terrabase)
	if err := app.awaitReplacements(now.Add(replacementWaitMax + time.Second)); err != nil || !app.replacementWait.IsZero() {
		t.Fatalf("released: %v, wait since %v", err, app.replacementWait)
	}
}
