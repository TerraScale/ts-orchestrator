package imagequalification

import (
	"crypto/ed25519"
	"encoding/json/v2"
	"errors"
	"slices"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/trust"
	"github.com/TerraScale/ts-orchestrator/tests/imagequalification/confinement"
	"github.com/TerraScale/ts-orchestrator/tests/imagequalification/principal"
)

// PrepareFromPrincipal refines the original signed finite preparation using only
// actual identities from the sealed SDK result. The existing qualifier signs the
// host approval; neither public receipt fields nor a journal confer authority.
func PrepareFromPrincipal(preparationWire, delegationWire []byte, roots trust.Keyring, result principal.Result, signer ed25519.PrivateKey, runID, diskPath, qualificationPath string, now time.Time) (Prepared, []byte, error) {
	var empty Prepared
	verified, err := principal.VerifyPreparation(preparationWire, delegationWire, roots, runID, now)
	if err != nil {
		return empty, nil, err
	}
	p := verified.Preparation()
	r := result.Receipt()
	original, err := trust.DecodeEnvelope(preparationWire)
	if err != nil {
		return empty, nil, err
	}
	if len(signer) != ed25519.PrivateKeySize {
		return empty, nil, errors.New("original qualifier signing key required")
	}
	signerID, err := trust.KeyID(signer.Public().(ed25519.PublicKey))
	if err != nil || signerID != original.KeyID {
		return empty, nil, errors.New("host approval must use the original preparation qualifier")
	}
	if err := result.ValidatePreparation(verified, now); err != nil {
		return empty, nil, err
	}

	scope := confinement.Scope{RunID: p.RunID, Group: r.Group, Compartment: p.Compartment, Bucket: p.Bucket, Object: p.Object, ExpiresAt: p.ExpiresAt, CleanupUntil: p.CleanupUntil}
	if !slices.Equal(r.PolicyStatements, confinement.RequiredStatements(scope)) {
		return empty, nil, errors.New("actual prepared policy differs from the exact approved operations")
	}
	a := Approval{Schema: ApprovalSchema, RunID: p.RunID, Candidate: p.Candidate, IAMRegion: p.IAMRegion, OCIRegion: p.OCIRegion, Tenancy: p.Tenancy, Principal: r.Principal, Compartment: p.Compartment, Subnet: p.Subnet, Namespace: p.Namespace, Bucket: p.Bucket, Group: r.Group, PolicyID: r.PolicyID, ProductionDynamicGroups: slices.Clone(p.ProductionDynamicGroups), ProfileIdentity: p.ProfileIdentity, ClientSHA256: p.ClientSHA256, KernelRelease: p.KernelRelease, PolicyStatements: slices.Clone(r.PolicyStatements), RunnerCIDR: p.RunnerCIDR, PeerCIDR: p.PeerCIDR, VCNCIDR: p.VCNCIDR, WorkloadImage: p.WorkloadImage, WorkloadArchiveSHA256: p.WorkloadArchiveSHA256, ImageBytes: p.ImageBytes, MaxSpendMicros: p.MaxSpendMicros, CleanupUntil: p.CleanupUntil, BinarySHA256: p.BinarySHA256, KernelSHA256: p.KernelSHA256, ContainerdSHA256: p.ContainerdSHA256, RuncSHA256: p.RuncSHA256, RunnerSHA256: p.RunnerSHA256}
	for _, host := range p.Hosts {
		a.Hosts = append(a.Hosts, HostSpec(host))
	}
	for _, material := range p.MaterialFixtures {
		a.MaterialFixtures = append(a.MaterialFixtures, MaterialApproval(material))
	}
	for _, artifact := range p.ContainerArtifacts {
		a.ContainerArtifacts = append(a.ContainerArtifacts, ContainerArtifactApproval(artifact))
	}
	if err := a.validate(); err != nil {
		return empty, nil, err
	}
	payload, err := json.Marshal(a, json.Deterministic(true))
	if err != nil {
		return empty, nil, err
	}
	envelope, err := trust.Sign(payload, ApprovalScope(runID, p.Candidate), now, p.ExpiresAt, signer)
	if err != nil {
		return empty, nil, err
	}
	wire, err := json.Marshal(envelope, json.Deterministic(true))
	if err != nil {
		return empty, nil, err
	}
	prepared, err := Prepare(wire, delegationWire, roots, p.Candidate, runID, diskPath, qualificationPath, now)
	if err != nil {
		return empty, nil, err
	}
	return prepared, wire, nil
}
