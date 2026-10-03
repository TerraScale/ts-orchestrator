package natscell

import (
	"context"
	"strings"
	"testing"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/protocol"
	"github.com/nats-io/nats.go"
)

// assertObservabilityCrossesNarrowly: a region's summary and decision query
// services cross the leafnode as request/reply in both directions, while
// every other observability leaf (member snapshots, the raw journal) stays
// regional.
func assertObservabilityCrossesNarrowly(ctx context.Context, t *testing.T, hub, spoke *Runtime) {
	t.Helper()
	respond := func(runtime *Runtime, region, leaf string) {
		t.Helper()
		subject, err := protocol.ObservabilitySubject(region, leaf)
		if err != nil {
			t.Fatal(err)
		}
		subscription, err := runtime.Conn().Subscribe(subject, func(msg *nats.Msg) {
			_ = msg.Respond([]byte(region + "/" + leaf))
		})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = subscription.Unsubscribe() })
		if err := runtime.Conn().Flush(); err != nil {
			t.Fatal(err)
		}
	}
	for _, leaf := range []string{protocol.ObservabilityRegionLeaf, protocol.ObservabilityDecisionsLeaf, "snapshot", "journal"} {
		respond(spoke, "sfo", leaf)
		respond(hub, "gru", leaf)
	}
	for _, leaf := range protocol.InterRegionObservabilityLeaves() {
		for _, direction := range []struct {
			from   *Runtime
			region string
		}{{hub, "sfo"}, {spoke, "gru"}} {
			subject, _ := protocol.ObservabilitySubject(direction.region, leaf)
			reply := requestUntil(ctx, t, direction.from.Conn(), subject)
			if string(reply.Data) != direction.region+"/"+leaf {
				t.Fatalf("%s reply = %q", subject, reply.Data)
			}
		}
	}
	for _, leaf := range []string{"snapshot", "journal"} {
		for _, direction := range []struct {
			from   *Runtime
			region string
		}{{hub, "sfo"}, {spoke, "gru"}} {
			subject, _ := protocol.ObservabilitySubject(direction.region, leaf)
			requestCtx, cancel := context.WithTimeout(ctx, 500*time.Millisecond)
			msg, err := direction.from.Conn().RequestWithContext(requestCtx, subject, []byte("x"))
			cancel()
			if err == nil {
				t.Fatalf("regional observability leaf %s crossed the leafnode: %q", subject, msg.Data)
			}
		}
	}
}

func TestObservabilityContractIsExactRequestReply(t *testing.T) {
	t.Parallel()

	contract := InterRegionContract{Cell: "gru", Peers: []string{"sfo"}, GlobalHome: "gru",
		Subtrees: map[string][]string{"sfo": {"sfo"}}}
	for _, export := range contract.CellExports() {
		subject := string(export.Subject)
		if strings.Contains(subject, ".obs.") {
			if strings.ContainsAny(subject, "*>") || export.Type.String() != "service" {
				t.Errorf("observability export %q is not an exact service", subject)
			}
			if !strings.HasSuffix(subject, ".obs.region") && !strings.HasSuffix(subject, ".obs.decisions") {
				t.Errorf("unexpected observability export %q", subject)
			}
		}
	}
	permissions := contract.ChildLeafPermissions("sfo")
	gruRegion, _ := protocol.ObservabilitySubject("gru", protocol.ObservabilityRegionLeaf)
	sfoRegion, _ := protocol.ObservabilitySubject("sfo", protocol.ObservabilityRegionLeaf)
	gruSnapshot, _ := protocol.ObservabilitySubject("gru", "snapshot")
	if !permissions.Pub.Allow.Contains(gruRegion) || permissions.Sub.Allow.Contains(gruRegion) ||
		!permissions.Sub.Allow.Contains(sfoRegion) || permissions.Pub.Allow.Contains(gruSnapshot) {
		t.Fatalf("child observability permissions = %+v", permissions)
	}
}
