package app

import (
	"context"
	"strings"
	"testing"

	"github.com/TerraScale/ts-orchestrator/internal/edge"
	"github.com/TerraScale/ts-orchestrator/internal/swarmruntime"
	"github.com/TerraScale/ts-orchestrator/internal/vaultsecret"
	"github.com/moby/swarmkit/v2/api"
)

func TestEdgeRequestProofReadsOnlyDeclaredTerraBaseCredential(t *testing.T) {
	t.Parallel()
	const key = "TERRABASE_PEER_SECRET_FILE"
	service := func(name, refs string) *api.Service {
		return &api.Service{Spec: api.ServiceSpec{Annotations: api.Annotations{Labels: map[string]string{
			swarmruntime.LabelServiceSpec: name, swarmruntime.LabelSecretRefs: refs,
		}}}}
	}
	services := []*api.Service{
		service("ts-dashboard", "invalid references must not be read"),
		service("terrabase", `{"TERRABASE_PEER_SECRET_FILE":{"vault":"approved-vault","name":"existing-peer-secret"},"OTHER_FILE":{"vault":"other","name":"must-not-read"}}`),
	}
	reads := 0
	read := func(_ context.Context, name string, refs map[string]vaultsecret.Ref) (map[string]string, error) {
		reads++
		if name != "terrabase" || len(refs) != 1 || refs[key].Vault != "approved-vault" || refs[key].Name != "existing-peer-secret" {
			t.Fatal("edge requested a credential outside the admitted TerraBase peer reference")
		}
		return map[string]string{key: strings.Repeat("aB", 32)}, nil
	}
	public := edge.New(t.TempDir())
	if err := refreshEdgeRequestProof(t.Context(), public, services, read); err != nil || reads != 1 {
		t.Fatalf("refresh error=%v, reads=%d", err, reads)
	}
	if err := refreshEdgeRequestProof(t.Context(), public, services[:1], read); err != nil || reads != 1 {
		t.Fatalf("missing service error=%v, reads=%d", err, reads)
	}
	if err := refreshEdgeRequestProof(t.Context(), public, []*api.Service{service("terrabase", "invalid")}, read); err == nil || reads != 1 {
		t.Fatal("invalid references reached the Vault reader")
	}
}
