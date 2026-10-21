package region

import (
	"bytes"
	"context"
	"errors"
	"slices"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/ociclient"
	"github.com/TerraScale/ts-orchestrator/internal/trust"
)

func originalNetBirdComponentAuthority(state originalNetBirdState, role string) (VerifiedContainerReleaseAuthority, error) {
	if state.intent.intent.Components == nil || !time.Now().Before(state.intent.expires) {
		return VerifiedContainerReleaseAuthority{}, errNetBirdComponents
	}
	for i, expected := range netBirdComponentRoles() {
		if role != expected {
			continue
		}
		intent := state.intent.intent.Components[i].Release
		if intent.Role != role || intent.Environment != "production" || !slices.Equal(intent.Cells, []string{"GRU"}) || !slices.Equal(intent.Architectures, []string{"arm64"}) {
			return VerifiedContainerReleaseAuthority{}, errNetBirdComponents
		}
		delegation, err := trust.DecodeEnvelope(intent.DelegationWire)
		if err != nil {
			return VerifiedContainerReleaseAuthority{}, err
		}
		expires := state.intent.expires
		if delegation.ExpiresAt.Before(expires) {
			expires = delegation.ExpiresAt
		}
		if !time.Now().Before(expires) {
			return VerifiedContainerReleaseAuthority{}, errNetBirdComponents
		}
		intent.Cells = slices.Clone(intent.Cells)
		intent.Architectures = slices.Clone(intent.Architectures)
		intent.DelegationWire = bytes.Clone(intent.DelegationWire)
		intent.SequenceMigrationWire = bytes.Clone(intent.SequenceMigrationWire)
		return VerifiedContainerReleaseAuthority{intent: intent, expires: expires}, nil
	}
	return VerifiedContainerReleaseAuthority{}, errNetBirdComponents
}

func originalNetBirdOCIRIssuers(state originalNetBirdState) ([3]VerifiedOCIRIssuer, error) {
	var issuers [3]VerifiedOCIRIssuer
	if state.manager == nil || state.intent.intent.Material == nil || state.intent.intent.Components == nil || state.grant.SchemaVersion != 3 || state.grant.Generation != 1 {
		return issuers, errNetBirdComponents
	}
	for i, role := range netBirdComponentRoles() {
		authority, err := originalNetBirdComponentAuthority(state, role)
		if err != nil {
			return [3]VerifiedOCIRIssuer{}, err
		}
		intent := state.intent.intent.Components[i].Issuer
		issuer := VerifiedOCIRIssuer{intent: intent, tenancyID: state.grant.TenancyID, installationID: state.grant.InstallationID,
			generation: state.grant.Generation, grantDigest: state.intent.grantDigest, expires: authority.ExpiresAt()}
		if intent.OCIRegion != foundationHomeRegion || intent.VaultTarget != state.target() || intent.RepositoryCompartmentID != state.target().CompartmentID ||
			issuer.ImageRepository() != authority.ImageRepository() || validateOCIRIssuerIdentity(intent) != nil {
			return [3]VerifiedOCIRIssuer{}, errNetBirdComponents
		}
		issuers[i] = issuer
	}
	return issuers, nil
}

// ReadNetBirdOCIRIssuers exposes only the three original signed credential
// purposes after local manager admission; it grants no IAM write authority.
func ReadNetBirdOCIRIssuers(ctx context.Context, factory *ociclient.Factory, resolver FoundationResolver, manager VerifiedNetBirdManager) ([3]VerifiedOCIRIssuer, error) {
	reader, ok := resolver.Footprint.(*SignedFootprint)
	if ctx == nil || factory == nil || !ok || reader == nil || reader.factory != factory || factory.Region() != foundationHomeRegion {
		return [3]VerifiedOCIRIssuer{}, errNetBirdComponents
	}
	if err := manager.Check(ctx); err != nil {
		return [3]VerifiedOCIRIssuer{}, err
	}
	state, err := reader.originalNetBirdState(ctx, resolver)
	if err != nil {
		return [3]VerifiedOCIRIssuer{}, err
	}
	if manager.originalGrantSHA256 != state.intent.grantDigest || manager.CredentialTarget() != state.target() || manager.VaultTarget() != state.regionalTarget() ||
		manager.StoreGeneration() != state.intent.intent.Material.Context.StoreGeneration {
		return [3]VerifiedOCIRIssuer{}, errNetBirdComponents
	}
	issuers, err := originalNetBirdOCIRIssuers(state)
	if err != nil {
		return [3]VerifiedOCIRIssuer{}, err
	}
	if err := manager.Check(ctx); err != nil {
		return [3]VerifiedOCIRIssuer{}, err
	}
	return issuers, nil
}

func GuardNetBirdOCIRIssuer(ctx context.Context, factory *ociclient.Factory, resolver FoundationResolver, manager VerifiedNetBirdManager, expected VerifiedOCIRIssuer) error {
	if !expected.IsVerified() || !time.Now().Before(expected.ExpiresAt()) {
		return errNetBirdComponents
	}
	issuers, err := ReadNetBirdOCIRIssuers(ctx, factory, resolver, manager)
	if err != nil {
		return err
	}
	for _, current := range issuers {
		if current.intent == expected.intent && current.grantDigest == expected.grantDigest && current.generation == expected.generation &&
			current.tenancyID == expected.tenancyID && current.installationID == expected.installationID {
			return ctx.Err()
		}
	}
	return errNetBirdComponents
}

func (s *netBirdComponents) componentAuthority(ctx context.Context, role string) (VerifiedContainerReleaseAuthority, error) {
	if !s.original {
		return s.resolver.ContainerReleaseAuthority(ctx, "GRU", role, "production")
	}
	state, err := s.reader.originalNetBirdState(ctx, s.resolver)
	if err != nil || state.intent.grantDigest != s.intent.grantDigest {
		return VerifiedContainerReleaseAuthority{}, errors.Join(errNetBirdComponents, err)
	}
	return originalNetBirdComponentAuthority(state, role)
}

func (s *netBirdComponents) componentIssuer(ctx context.Context, role string, authority VerifiedContainerReleaseAuthority) (VerifiedOCIRIssuer, error) {
	if !s.original {
		return s.resolver.OCIRIssuer(ctx, authority.ImageRepository())
	}
	state, err := s.reader.originalNetBirdState(ctx, s.resolver)
	if err != nil || state.intent.grantDigest != s.intent.grantDigest {
		return VerifiedOCIRIssuer{}, errors.Join(errNetBirdComponents, err)
	}
	issuers, err := originalNetBirdOCIRIssuers(state)
	if err != nil {
		return VerifiedOCIRIssuer{}, err
	}
	for i, expected := range netBirdComponentRoles() {
		if role == expected && issuers[i].ImageRepository() == authority.ImageRepository() {
			return issuers[i], nil
		}
	}
	return VerifiedOCIRIssuer{}, errNetBirdComponents
}
