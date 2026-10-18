package region

import (
	"errors"
	"slices"
	"strings"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/bootstrap"
	"github.com/TerraScale/ts-orchestrator/internal/trust"
	"github.com/TerraScale/ts-orchestrator/internal/vaultsecret"
)

// NetBirdComponentAuthorityIntent binds one fixed component and its pull issuer
// to the original signed manager purpose, independently of workload genesis.
type NetBirdComponentAuthorityIntent struct {
	Release ContainerReleaseAuthorityIntent `json:"release"`
	Issuer  OCIRIssuerIntent                `json:"issuer"`
}

func validatePreparedNetBirdComponents(authorities [3]ContainerReleaseAuthorityIntent, home bootstrap.StorageDomain) error {
	seen := make(map[string]bool, 3)
	for index, role := range netBirdComponentRoles() {
		authority := authorities[index]
		if authority.Role != role || authority.Environment != "production" || !slices.Equal(authority.Cells, []string{"GRU"}) ||
			!slices.Equal(authority.Architectures, []string{"arm64"}) || len(authority.DelegationWire) == 0 || len(authority.SequenceMigrationWire) == 0 || seen[authority.ImageRepository] {
			return errors.New("original NetBird components require exactly the three distinct GRU production arm64 signed release authorities")
		}
		if err := validateContainerRepositories(authority, home.Namespace); err != nil {
			return err
		}
		region, namespace, _, err := parseOCIRRepository(authority.ImageRepository)
		if err != nil || region != foundationHomeRegion || namespace != home.Namespace {
			return errors.Join(errors.New("NetBird component repository differs from the original GRU home namespace"), err)
		}
		seen[authority.ImageRepository] = true
	}
	return nil
}

func prepareNetBirdComponentIntents(input FoundationPreparationInput, material NetBirdMaterialAuthority) (*[3]NetBirdComponentAuthorityIntent, error) {
	if err := validatePreparedNetBirdComponents(input.NetBirdComponents, input.HomeStorageDomain); err != nil {
		return nil, err
	}
	var components [3]NetBirdComponentAuthorityIntent
	for index, authority := range input.NetBirdComponents {
		authority.Cells = slices.Clone(authority.Cells)
		authority.Architectures = slices.Clone(authority.Architectures)
		authority.DelegationWire = slices.Clone(authority.DelegationWire)
		authority.SequenceMigrationWire = slices.Clone(authority.SequenceMigrationWire)
		principal, email, secret, err := OCIRServiceIdentity(material.Context.InstallationID, authority.ImageRepository)
		if err != nil {
			return nil, err
		}
		region, namespace, repository, err := parseOCIRRepository(authority.ImageRepository)
		if err != nil {
			return nil, err
		}
		host, _, _ := strings.Cut(authority.ImageRepository, "/")
		target := material.Context.Target
		components[index] = NetBirdComponentAuthorityIntent{Release: authority, Issuer: OCIRIssuerIntent{
			OCIRegion: region, RegistryHost: host, RepositoryCompartmentID: target.CompartmentOCID, RepositoryName: repository, RegistryNamespace: namespace,
			PrincipalName: principal, PrincipalEmail: email, SecretName: secret,
			VaultTarget: vaultsecret.Target{CompartmentID: target.CompartmentOCID, VaultID: target.VaultOCID, KeyID: target.KMSKeyOCID},
		}}
	}
	return &components, nil
}

func netBirdComponentIntent(grant FoundationGrant) (*NetBirdManagerIntent, error) {
	var manager *NetBirdManagerIntent
	for _, region := range grant.Regions {
		if region.NetBirdManager == nil {
			continue
		}
		if region.Plan["cell"] != "GRU" || manager != nil {
			return nil, errors.New("original NetBird component purpose repeats or leaves GRU")
		}
		manager = region.NetBirdManager
	}
	if manager == nil || manager.Components == nil {
		return nil, nil
	}
	if grant.SchemaVersion != 3 || grant.Generation != 1 || manager.Material == nil || manager.Material.validate() != nil ||
		manager.Material.Context.InstallationID != grant.InstallationID || manager.Material.Context.TenancyID != grant.TenancyID {
		return nil, errors.New("NetBird component purpose lacks the exact original signed material lineage")
	}
	return manager, nil
}

func validateNetBirdComponentIdentities(grant FoundationGrant, home bootstrap.StorageDomain) error {
	manager, err := netBirdComponentIntent(grant)
	if err != nil || manager == nil {
		return err
	}
	var releases [3]ContainerReleaseAuthorityIntent
	for index, component := range manager.Components {
		releases[index] = component.Release
	}
	if err := validatePreparedNetBirdComponents(releases, home); err != nil {
		return err
	}
	target := manager.Material.Context.Target
	for _, component := range manager.Components {
		issuer := component.Issuer
		if err := validateOCIRIssuerIdentity(issuer); err != nil {
			return err
		}
		principal, email, secret, err := OCIRServiceIdentity(grant.InstallationID, component.Release.ImageRepository)
		if err != nil || issuer.OCIRegion != foundationHomeRegion || issuer.RegistryHost+"/"+issuer.RegistryNamespace+"/"+issuer.RepositoryName != component.Release.ImageRepository ||
			issuer.RepositoryCompartmentID != target.CompartmentOCID || issuer.PrincipalName != principal || issuer.PrincipalEmail != email || issuer.SecretName != secret ||
			issuer.VaultTarget != (vaultsecret.Target{CompartmentID: target.CompartmentOCID, VaultID: target.VaultOCID, KeyID: target.KMSKeyOCID}) {
			return errors.Join(errors.New("NetBird pull issuer differs from its exact signed repository, principal or original credential escrow"), err)
		}
	}
	return nil
}

func validateNetBirdComponentIntents(grant FoundationGrant, roots trust.Keyring, home bootstrap.StorageDomain, now time.Time) error {
	if err := validateNetBirdComponentIdentities(grant, home); err != nil {
		return err
	}
	manager, err := netBirdComponentIntent(grant)
	if err != nil || manager == nil {
		return err
	}
	if len(roots) == 0 || now.IsZero() || home.Validate() != nil {
		return errors.New("NetBird component authority requires original roots, signed home storage and current time")
	}
	for _, component := range manager.Components {
		envelope, delegation, err := validateContainerReleaseDelegation(component.Release, roots, home, map[string]bool{"GRU": true}, now)
		if err != nil {
			return err
		}
		if err := validateContainerReleaseMigration(component.Release, envelope, delegation, roots, home); err != nil {
			return err
		}
	}
	return nil
}
