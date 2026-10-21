package app

import (
	"context"
	"crypto/ed25519"
	"errors"
	"io"
	"testing"

	"github.com/TerraScale/ts-orchestrator/internal/authority"
	"github.com/TerraScale/ts-orchestrator/internal/containermaterial"
	"github.com/TerraScale/ts-orchestrator/internal/delivery"
	"github.com/TerraScale/ts-orchestrator/internal/host"
	"github.com/TerraScale/ts-orchestrator/internal/oci"
	"github.com/TerraScale/ts-orchestrator/internal/placement"
	"github.com/TerraScale/ts-orchestrator/internal/release"
	"github.com/TerraScale/ts-orchestrator/internal/storage/execution"
	"github.com/TerraScale/ts-orchestrator/internal/storage/executionwire"
	"github.com/TerraScale/ts-orchestrator/internal/trust"
	"github.com/moby/swarmkit/v2/api"
)

type handoffUnusedControl struct{ api.ControlClient }
type handoffUnusedMembers struct{ placement.Store }

func TestStatefulHandoffRequiresHostAuthorityBeforeBecomingReady(t *testing.T) {
	ctx := t.Context()
	var slot statefulRuntimeSlot
	intent := delivery.Intent{Role: "terrabase", Container: &release.ContainerBundle{}}
	if err := slot.apply(ctx, intent); !errors.Is(err, containermaterial.ErrPending) {
		t.Fatalf("unready apply: %v", err)
	}
	for _, action := range []string{"acquire", "renew", "close"} {
		if _, err := slot.HandleRuntimeEffect(ctx, host.RuntimeEffectCaller{}, executionwire.RuntimeEffectQuery{Action: action}); !errors.Is(err, containermaterial.ErrPending) {
			t.Fatalf("unready %s: %v", action, err)
		}
	}
	denied := errors.New("current manager session is unavailable")
	unusedEvidence := func(context.Context, string, string) (io.ReadCloser, error) {
		return nil, errors.New("evidence must not be opened by constructor")
	}
	unusedAllocation := func(context.Context, string, release.ContainerBundle, trust.Keyring, release.ContainerTarget) (release.SequenceLocation, error) {
		return release.SequenceLocation{}, errors.New("allocation must not be opened by constructor")
	}
	config := statefulRuntimeConfig{Client: handoffUnusedControl{}, Authority: &authority.Runtime{}, Members: handoffUnusedMembers{}, Delivery: &delivery.Service{}, Volumes: &oci.VolumeMountObserver{},
		Roots: trust.Keyring{"fixture": make(ed25519.PublicKey, ed25519.PublicKeySize)}, HistoricalRoots: trust.Keyring{"fixture": make(ed25519.PublicKey, ed25519.PublicKeySize)},
		Evidence: unusedEvidence, RetainedEvidence: unusedEvidence, Allocations: unusedAllocation, RetainedAllocations: unusedAllocation,
		SessionGuard: func(context.Context) error { return denied }, Cell: "gru", Environment: "production"}
	if runtime, err := newStatefulRuntime(config); runtime != nil || !errors.Is(err, execution.ErrUnsafe) {
		t.Fatalf("stateful runtime accepted missing managed host authority: runtime=%v err=%v", runtime, err)
	}
	config.Hosts = &host.Controller{}
	runtime, err := newStatefulRuntime(config)
	if err != nil {
		t.Fatal(err)
	}
	slot.Store(runtime)
	if err := slot.apply(ctx, intent); !errors.Is(err, denied) {
		t.Fatalf("apply bypassed manager session: %v", err)
	}
	for _, action := range []string{"acquire", "renew", "close"} {
		if _, err := slot.HandleRuntimeEffect(ctx, host.RuntimeEffectCaller{}, executionwire.RuntimeEffectQuery{Action: action}); !errors.Is(err, denied) {
			t.Fatalf("%s bypassed manager session: %v", action, err)
		}
	}
	// This constructor/routing fixture grants no host, effect, stop, or volume
	// authority. Authenticated close still belongs to the existing DATA handler.
	slot.Store(nil)
	if _, err := slot.HandleRuntimeEffect(ctx, host.RuntimeEffectCaller{}, executionwire.RuntimeEffectQuery{Action: "close"}); !errors.Is(err, containermaterial.ErrPending) {
		t.Fatalf("removed runtime retained admission: %v", err)
	}
}
