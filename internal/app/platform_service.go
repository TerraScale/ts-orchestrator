package app

import (
	"errors"
	"maps"
	"slices"
	"strings"

	"github.com/TerraScale/ts-orchestrator/internal/delivery"
	"github.com/TerraScale/ts-orchestrator/internal/entityid"
	"github.com/TerraScale/ts-orchestrator/internal/ociregion/catalog"
	"github.com/TerraScale/ts-orchestrator/internal/protocol"
	"github.com/TerraScale/ts-orchestrator/internal/release"
	"github.com/TerraScale/ts-orchestrator/internal/swarmruntime"
	"github.com/TerraScale/ts-orchestrator/internal/trust"
	"github.com/moby/swarmkit/v2/api"
)

// The caller verifies current release authority before applying this exact
// profile to SwarmKit; decoding the envelope here grants no release authority.
func platformServiceIntent(intent delivery.Intent, profile WorkloadProfile, ociRegion, architecture string) (swarmruntime.ServiceIntent, error) {
	fail := func() (swarmruntime.ServiceIntent, error) {
		return swarmruntime.ServiceIntent{}, errors.New("platform container intent differs from its admitted profile or region")
	}
	region, ok := catalog.CellForOCIRegion(ociRegion)
	if intent.Validate() != nil || intent.Container == nil || !ok || region.Cell != strings.ToUpper(intent.Cell) ||
		intent.ConfigDigest != delivery.ConfigDigestOf(profile.Args, profile.Env, profile.Secrets) || intent.Role == "terrabase" ||
		profile.Resources.CPU < 1 || profile.Resources.CPU > 1000 || profile.Resources.MemoryBytes < 16<<20 {
		return fail()
	}
	envelope, err := trust.DecodeEnvelope(intent.Container.Claim)
	if err != nil {
		return fail()
	}
	var claim release.ContainerClaim
	if protocol.DecodeStrict(envelope.Payload, &claim, trust.MaxPayloadBytes) != nil || claim.Validate() != nil ||
		claim.Architecture != architecture || claim.Cell != region.Cell || claim.Role != intent.Role || claim.Environment != intent.Environment {
		return fail()
	}
	// Secret values may enter only through the encrypted own-host material
	// source. Keep releases held until that source is installed at startup.
	if len(profile.Secrets) != 0 {
		return swarmruntime.ServiceIntent{}, errors.New("platform container secret delivery is pending")
	}
	environment := make([]string, 0, len(profile.Env))
	for _, key := range slices.Sorted(maps.Keys(profile.Env)) {
		environment = append(environment, key+"="+profile.Env[key])
	}
	limits := &api.Resources{NanoCPUs: int64(profile.Resources.CPU) * 1_000_000_000, MemoryBytes: profile.Resources.MemoryBytes}
	service := swarmruntime.ServiceIntent{
		ID: entityid.Derive("platform-service", intent.Role, intent.Environment, ociRegion), OperationID: intent.OperationID,
		Role: intent.Role, Region: ociRegion, Environment: intent.Environment, Architecture: architecture,
		Replicas:  uint64(intent.DesiredReplicas),
		Container: &api.ContainerSpec{Image: claim.Image, User: "65532:65532", Args: slices.Clone(profile.Args), Env: environment},
		Resources: &api.ResourceRequirements{Limits: limits, Reservations: limits.Copy()},
	}
	if intent.Role == "ts-auth" {
		service.Ports = []*api.PortConfig{{Protocol: api.ProtocolTCP, TargetPort: 8080, PublishedPort: 8080, PublishMode: api.PublishModeHost}}
	}
	return service, nil
}
