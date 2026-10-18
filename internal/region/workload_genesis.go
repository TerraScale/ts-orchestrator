package region

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json/v2"
	"errors"
	"strings"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/bootstrap"
	"github.com/TerraScale/ts-orchestrator/internal/oci"
	"github.com/TerraScale/ts-orchestrator/internal/protocol"
	"github.com/TerraScale/ts-orchestrator/internal/release"
	"github.com/TerraScale/ts-orchestrator/internal/trust"
)

// The full original proof travels separately from the 30KiB release bundle.
const MaxWorkloadGenesisEvidenceBytes = 512 << 10

// GenericWorkloadGeneses exposes original generic commitments before native
// startup. Historical migration grants have no prospective commitments.
func (r FoundationResolver) GenericWorkloadGeneses(ctx context.Context, cell, environment string) ([]release.VerifiedWorkloadGenesis, error) {
	reader, ok := r.Footprint.(*SignedFootprint)
	if !ok || reader == nil {
		return nil, errors.New("generic origin requires a signed foundation reader")
	}
	wire, err := reader.readGrant(ctx)
	if err != nil {
		return nil, err
	}
	grant, _, err := reader.verifyOriginalDocument(wire)
	if err != nil {
		return nil, err
	}
	if grant.SchemaVersion != 3 {
		return nil, nil
	}
	var origins []release.VerifiedWorkloadGenesis
	for _, role := range []string{"ts-auth", "function-worker"} {
		verified, _, err := r.WorkloadGenesis(ctx, cell, role, environment)
		if err != nil {
			return nil, err
		}
		origins = append(origins, verified)
	}
	return origins, nil
}

// VerifyOriginalWorkloadGenesisEvidence authenticates historical producer
// evidence only. Producers also read back its fixed permanent home object and
// independently verify their current delegation before allocating a sequence.
func VerifyOriginalWorkloadGenesisEvidence(wire []byte, independentGenesis trust.Keyring, target release.ContainerTarget) (release.VerifiedWorkloadGenesis, error) {
	var snapshot RetainedFoundation
	if err := protocol.DecodeStrict(wire, &snapshot, MaxWorkloadGenesisEvidenceBytes); err != nil {
		return release.VerifiedWorkloadGenesis{}, err
	}
	envelope, err := trust.DecodeEnvelope(snapshot.GrantWire)
	if err != nil {
		return release.VerifiedWorkloadGenesis{}, err
	}
	var grant FoundationGrant
	if err := json.Unmarshal(envelope.Payload, &grant, json.RejectUnknownMembers(true)); err != nil {
		return release.VerifiedWorkloadGenesis{}, err
	}
	for _, origin := range grant.WorkloadGenesis {
		if origin.Cell == target.Cell && origin.Role == target.Role && origin.Environment == target.Environment {
			verified, err := verifyWorkloadGenesisEvidence(wire, independentGenesis, origin)
			if err != nil {
				return release.VerifiedWorkloadGenesis{}, err
			}
			if !verified.Allows(target) {
				return release.VerifiedWorkloadGenesis{}, trust.ErrScopeMismatch
			}
			return verified, nil
		}
	}
	return release.VerifiedWorkloadGenesis{}, errors.New("original grant has no exact workload genesis target")
}

// WorkloadGenesis reads the permanent object selected by current root authority.
// Historical origin conveys neither current admission nor producer permission.
func (r FoundationResolver) WorkloadGenesis(ctx context.Context, cell, role, environment string) (release.VerifiedWorkloadGenesis, []byte, error) {
	reader, ok := r.Footprint.(*SignedFootprint)
	if !ok || reader == nil || reader.client == nil {
		return release.VerifiedWorkloadGenesis{}, nil, errors.New("workload genesis requires the authenticated home reader")
	}
	wire, err := reader.readGrant(ctx)
	if err != nil {
		return release.VerifiedWorkloadGenesis{}, nil, err
	}
	grant, _, err := reader.verifyOriginalDocument(wire)
	if err != nil {
		return release.VerifiedWorkloadGenesis{}, nil, err
	}
	var expected release.WorkloadGenesis
	for _, origin := range grant.WorkloadGenesis {
		if origin.Cell == cell && origin.Role == role && origin.Environment == environment {
			expected = origin
		}
	}
	if expected.Validate() != nil {
		return release.VerifiedWorkloadGenesis{}, nil, errors.New("current foundation has no exact original workload genesis")
	}
	name, err := release.WorkloadGenesisObject(expected.TenancyID, cell, environment, role)
	if err != nil {
		return release.VerifiedWorkloadGenesis{}, nil, err
	}
	original, err := readDiscoveryObject(ctx, reader.client, expected.Namespace, name, MaxWorkloadGenesisEvidenceBytes)
	if err != nil {
		return release.VerifiedWorkloadGenesis{}, nil, err
	}
	if len(reader.independentGenesis) == 0 {
		return release.VerifiedWorkloadGenesis{}, nil, errors.New("workload genesis requires its independent production root pin")
	}
	verified, err := verifyWorkloadGenesisEvidence(original, reader.independentGenesis, expected)
	if err != nil {
		return release.VerifiedWorkloadGenesis{}, nil, err
	}
	if err := ctx.Err(); err != nil {
		return release.VerifiedWorkloadGenesis{}, nil, err
	}
	return verified, original, nil
}

// VerifyWorkloadGenesisEvidence binds transported original proof to the current
// independently admitted installation. It never constructs runtime authority.
func VerifyWorkloadGenesisEvidence(wire []byte, independentGenesis trust.Keyring, current bootstrap.VerifiedBootstrapAnchor, cell, role, environment string) (release.VerifiedWorkloadGenesis, error) {
	if !current.IsVerified() || !time.Now().Before(current.ExpiresAt()) {
		return release.VerifiedWorkloadGenesis{}, errors.New("workload genesis requires a current admitted bootstrap anchor")
	}
	home, err := current.FoundationScope()
	if err != nil {
		return release.VerifiedWorkloadGenesis{}, err
	}
	local := current.Anchor()
	if !strings.EqualFold(string(local.Cell), cell) || local.Environment != environment {
		return release.VerifiedWorkloadGenesis{}, trust.ErrScopeMismatch
	}
	expected := release.WorkloadGenesis{Schema: release.WorkloadGenesisSchema, TenancyID: home.TenancyID, InstallationID: home.InstallationID,
		DeploymentID: local.DeploymentID, ClusterID: local.ClusterID, Cell: cell, Environment: environment, Role: role,
		Namespace: home.StorageDomain.Namespace, Bucket: home.StorageDomain.HeadBucket}
	return verifyWorkloadGenesisEvidence(wire, independentGenesis, expected)
}

func verifyWorkloadGenesisEvidence(wire []byte, independentGenesis trust.Keyring, expected release.WorkloadGenesis) (release.VerifiedWorkloadGenesis, error) {
	var snapshot RetainedFoundation
	if err := protocol.DecodeStrict(wire, &snapshot, MaxWorkloadGenesisEvidenceBytes); err != nil {
		return release.VerifiedWorkloadGenesis{}, err
	}
	if expected.Validate() != nil || snapshot.TenancyID != expected.TenancyID || snapshot.Namespace != expected.Namespace || len(snapshot.GrantWire) > foundationRecordLimit {
		return release.VerifiedWorkloadGenesis{}, errors.New("original workload genesis differs from admitted tenancy and home store")
	}
	envelope, err := trust.DecodeEnvelope(snapshot.AnchorWire)
	if err != nil {
		return release.VerifiedWorkloadGenesis{}, err
	}
	chain, err := trust.DecodeRootChain(snapshot.RootChainWire)
	if err != nil {
		return release.VerifiedWorkloadGenesis{}, err
	}
	roots, err := trust.VerifyRootChain(independentGenesis, foundationChainIdentity(envelope.Scope.DeploymentID), chain)
	if err != nil {
		return release.VerifiedWorkloadGenesis{}, err
	}
	grantEnvelope, err := trust.DecodeEnvelope(snapshot.GrantWire)
	if err != nil {
		return release.VerifiedWorkloadGenesis{}, err
	}
	anchor, err := bootstrap.VerifyHistoricalBootstrapAnchor(envelope, roots.Current, bootstrap.BootstrapAnchorExpectation{DeploymentID: envelope.Scope.DeploymentID, Cell: oci.RegionGRU, Environment: "production"}, grantEnvelope.IssuedAt, bootstrap.BootstrapAnchorTrustPolicy())
	if err != nil {
		return release.VerifiedWorkloadGenesis{}, err
	}
	home := anchor.Anchor().FoundationScope
	digest := sha256.Sum256(snapshot.GrantWire)
	if home == nil || home.Validate() != nil || home.InstallationID != expected.InstallationID || home.TenancyID != expected.TenancyID || home.OCIRegion != foundationHomeRegion || home.StorageDomain.Namespace != expected.Namespace || home.StorageDomain.HeadBucket != expected.Bucket || home.GrantSHA256 != hex.EncodeToString(digest[:]) || grantEnvelope.ExpiresAt.After(envelope.ExpiresAt) {
		return release.VerifiedWorkloadGenesis{}, errors.New("original workload grant differs from its exact root-pinned anchor")
	}
	var grant FoundationGrant
	if err := json.Unmarshal(grantEnvelope.Payload, &grant, json.RejectUnknownMembers(true)); err != nil {
		return release.VerifiedWorkloadGenesis{}, err
	}
	if grant.SchemaVersion != 3 || grant.Generation != home.GrantGeneration || validateFoundationWorkloadGenesis(grant, home.StorageDomain) != nil || validateFoundationAdmissionAttestors(grant, home.StorageDomain) != nil || validateOriginalSourceProducerPurposes(grant, home.StorageDomain) != nil || requireOriginalSourceProducerPurposes(grant) != nil {
		return release.VerifiedWorkloadGenesis{}, errors.New("original workload grant lacks its complete founding scope")
	}
	scope := trust.Scope{Domain: foundationGrantDomain, DeploymentID: home.DeploymentID, Cell: "GRU", Environment: expected.Environment, Role: "foundation", Slot: home.ClusterID}
	return release.VerifyWorkloadGenesis(snapshot.GrantWire, roots.Current, scope, expected)
}
