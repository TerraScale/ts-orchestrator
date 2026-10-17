package region

import (
	"bytes"
	"context"
	"encoding/json/v2"
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/distribution/reference"

	"github.com/TerraScale/ts-orchestrator/internal/bootstrap"
	"github.com/TerraScale/ts-orchestrator/internal/ociregion/catalog"
	"github.com/TerraScale/ts-orchestrator/internal/release"
	"github.com/TerraScale/ts-orchestrator/internal/trust"
)

// VerifiedContainerReleaseAuthority is constructed only from a current,
// independently verified foundation grant pinned by its bootstrap anchor.
type VerifiedContainerReleaseAuthority struct {
	intent  ContainerReleaseAuthorityIntent
	expires time.Time
}

func (v VerifiedContainerReleaseAuthority) IsVerified() bool        { return !v.expires.IsZero() }
func (v VerifiedContainerReleaseAuthority) ImageRepository() string { return v.intent.ImageRepository }
func (v VerifiedContainerReleaseAuthority) SourceRepository() string {
	return v.intent.SourceRepository
}
func (v VerifiedContainerReleaseAuthority) DelegationWire() []byte {
	return bytes.Clone(v.intent.DelegationWire)
}
func (v VerifiedContainerReleaseAuthority) SequenceMigrationWire() []byte {
	return bytes.Clone(v.intent.SequenceMigrationWire)
}
func (v VerifiedContainerReleaseAuthority) ExpiresAt() time.Time { return v.expires }
func (v VerifiedContainerReleaseAuthority) Architectures() []string {
	return slices.Clone(v.intent.Architectures)
}

func (r FoundationResolver) ContainerReleaseAuthority(ctx context.Context, cell, role, environment string) (VerifiedContainerReleaseAuthority, error) {
	reader, ok := r.Footprint.(interface {
		ContainerReleaseAuthority(context.Context, string, string, string) (VerifiedContainerReleaseAuthority, error)
	})
	if !ok {
		return VerifiedContainerReleaseAuthority{}, errors.New("foundation scope does not authorize container release discovery")
	}
	return reader.ContainerReleaseAuthority(ctx, cell, role, environment)
}

func (s *SignedFootprint) ContainerReleaseAuthority(ctx context.Context, cell, role, environment string) (VerifiedContainerReleaseAuthority, error) {
	wire, err := s.readGrant(ctx)
	if err != nil {
		return VerifiedContainerReleaseAuthority{}, err
	}
	_, expires, err := s.verifyGrant(wire)
	if err != nil {
		return VerifiedContainerReleaseAuthority{}, err
	}
	envelope, err := trust.DecodeEnvelope(wire)
	if err != nil {
		return VerifiedContainerReleaseAuthority{}, err
	}
	var grant FoundationGrant
	if err := json.Unmarshal(envelope.Payload, &grant, json.RejectUnknownMembers(true)); err != nil {
		return VerifiedContainerReleaseAuthority{}, err
	}
	if environment != s.scope.Environment {
		return VerifiedContainerReleaseAuthority{}, trust.ErrScopeMismatch
	}
	if err := ValidateContainerReleaseAuthorities(grant, s.roots, s.storage, time.Now()); err != nil {
		return VerifiedContainerReleaseAuthority{}, err
	}
	for _, intent := range grant.ReleaseAuthorities {
		if intent.Role != role || intent.Environment != environment || !slices.Contains(intent.Cells, cell) {
			continue
		}
		delegation, err := trust.DecodeEnvelope(intent.DelegationWire)
		if err != nil {
			return VerifiedContainerReleaseAuthority{}, err
		}
		if delegation.ExpiresAt.Before(expires) {
			expires = delegation.ExpiresAt
		}
		intent.Cells = slices.Clone(intent.Cells)
		intent.Architectures = slices.Clone(intent.Architectures)
		intent.DelegationWire = bytes.Clone(intent.DelegationWire)
		intent.SequenceMigrationWire = bytes.Clone(intent.SequenceMigrationWire)
		return VerifiedContainerReleaseAuthority{intent: intent, expires: expires}, nil
	}
	return VerifiedContainerReleaseAuthority{}, errors.New("signed foundation scope has no exact container release authority")
}

// ValidateContainerReleaseAuthorities checks producer inputs without granting
// runtime authority. The producer must sign the resulting foundation grant.
func ValidateContainerReleaseAuthorities(grant FoundationGrant, roots trust.Keyring, home bootstrap.StorageDomain, now time.Time) error {
	if err := validateFoundationWorkloadGenesis(grant, home); err != nil {
		return err
	}
	if len(grant.ReleaseAuthorities) == 0 {
		return nil
	}
	if len(grant.ReleaseAuthorities) > 64 || len(roots) == 0 || now.IsZero() || home.Validate() != nil {
		return errors.New("container release authority requires bounded entries, existing roots, time and signed home storage")
	}
	cells := make(map[string]bool, len(grant.Regions))
	for _, region := range grant.Regions {
		cell, ok := region.Plan["cell"].(string)
		if !ok || !catalog.IsCell(cell) || cells[cell] {
			return errors.New("container release authority requires an exact approved regional footprint")
		}
		cells[cell] = true
	}
	seen := make(map[string]bool, len(grant.ReleaseAuthorities))
	for _, intent := range grant.ReleaseAuthorities {
		key := intent.Role + "/" + intent.Environment
		if seen[key] || !release.ValidEnvironment(intent.Environment) || len(intent.Cells) == 0 || len(intent.Cells) > catalog.MaxRegions || len(intent.Architectures) == 0 || len(intent.Architectures) > 2 {
			return errors.New("container release authority has duplicate role/environment or invalid target scope")
		}
		seen[key] = true
		if err := validateContainerRepositories(intent, home.Namespace); err != nil {
			return err
		}
		expected := make(map[trust.Scope]bool, len(intent.Cells)*len(intent.Architectures))
		seenCells := make(map[string]bool, len(intent.Cells))
		for _, cell := range intent.Cells {
			if !cells[cell] || seenCells[cell] {
				return errors.New("container release authority cell is duplicate or outside the signed footprint")
			}
			seenCells[cell] = true
			for _, arch := range intent.Architectures {
				scope := release.ContainerScope(release.ContainerTarget{Cell: cell, Role: intent.Role, Environment: intent.Environment, Architecture: arch})
				if arch != "arm64" && arch != "amd64" || expected[scope] {
					return errors.New("container release authority architecture is invalid or duplicate")
				}
				expected[scope] = true
			}
		}
		delegationEnvelope, err := trust.DecodeEnvelope(intent.DelegationWire)
		if err != nil {
			return fmt.Errorf("container release delegation: %w", err)
		}
		delegation, err := trust.VerifyDelegationCurrent(delegationEnvelope, roots, now, trust.Policy{MaxLifetime: release.MaxUpdateReceiptLifetime})
		if err != nil {
			return err
		}
		if roots[delegation.SubjectKeyID()] != nil {
			return errors.New("container release signer must differ from existing offline roots")
		}
		for _, capability := range delegation.Capabilities() {
			for _, slot := range capability.Slots {
				scope := trust.Scope{Domain: capability.Domain, DeploymentID: capability.DeploymentID, Cell: capability.Cell, Environment: capability.Environment, Role: capability.Role, Slot: slot}
				if !expected[scope] {
					return errors.New("container release delegation grants extra or duplicate capabilities")
				}
				delete(expected, scope)
			}
		}
		if len(expected) != 0 {
			return errors.New("container release delegation omits approved capabilities")
		}
		if grant.SchemaVersion == 3 {
			continue
		}
		migrationEnvelope, err := trust.DecodeEnvelope(intent.SequenceMigrationWire)
		if err != nil {
			return fmt.Errorf("container release sequence migration: %w", err)
		}
		// Original durable migration bytes retain their floor after expiry;
		// the signer's first import still requires its existing current guard.
		migration, err := release.VerifySequenceMigrationHistorical(migrationEnvelope, roots, intent.Role, intent.Environment)
		if err != nil {
			return err
		}
		var public trust.Delegation
		if err := json.Unmarshal(delegationEnvelope.Payload, &public, json.RejectUnknownMembers(true)); err != nil {
			return err
		}
		if migration.SignerKeyID != delegation.SubjectKeyID() || migration.SignerPublicKey != public.SubjectPublicKey || migration.Namespace != home.Namespace || migration.Bucket != home.HeadBucket {
			return errors.New("container release sequence signer or store differs from signed authority")
		}
		for _, cell := range intent.Cells {
			if !slices.ContainsFunc(migration.Regions, func(floor release.SequenceFloor) bool { return floor.Cell == cell }) {
				return errors.New("container release sequence migration lacks an approved regional floor")
			}
		}
	}
	return nil
}

func foundationWorkloadGenesis(grant FoundationGrant, home bootstrap.StorageDomain) ([]release.WorkloadGenesis, error) {
	if grant.SchemaVersion != 3 || home.Validate() != nil || home.HeadBucket != foundationDiscoveryBucket || len(grant.Regions) != 3 || len(grant.ReleaseAuthorities) != 3 {
		return nil, errors.New("workload genesis requires the complete founding grant and fixed home store")
	}
	var origins []release.WorkloadGenesis
	seen := make(map[string]bool, 9)
	for _, authority := range grant.ReleaseAuthorities {
		if len(authority.SequenceMigrationWire) != 0 || authority.Environment != "production" || len(authority.Cells) != 3 {
			return nil, errors.New("workload genesis cannot import migration history or omit a founding cell")
		}
		for _, cell := range authority.Cells {
			var material *BootstrapMaterialIntent
			for _, regional := range grant.Regions {
				if regional.Plan["cell"] == cell {
					if material != nil {
						return nil, errors.New("workload genesis repeats a founding regional identity")
					}
					material = regional.BootstrapMaterial
				}
			}
			if material == nil || material.InstallationID != grant.InstallationID || material.Config.Cell != strings.ToLower(cell) || material.Config.Environment != authority.Environment {
				return nil, errors.New("workload genesis differs from its original signed regional material")
			}
			origin := release.WorkloadGenesis{Schema: release.WorkloadGenesisSchema, TenancyID: grant.TenancyID, InstallationID: grant.InstallationID,
				DeploymentID: material.Config.DeploymentID, ClusterID: material.Config.ClusterID, Cell: cell, Environment: authority.Environment, Role: authority.Role,
				Namespace: home.Namespace, Bucket: home.HeadBucket}
			name, err := release.WorkloadGenesisObject(origin.TenancyID, origin.Cell, origin.Environment, origin.Role)
			if err != nil || origin.Validate() != nil || seen[name] {
				return nil, errors.New("workload genesis has an invalid or repeated permanent founding scope")
			}
			seen[name] = true
			origins = append(origins, origin)
		}
	}
	return origins, nil
}

func validateFoundationWorkloadGenesis(grant FoundationGrant, home bootstrap.StorageDomain) error {
	if grant.SchemaVersion != 3 {
		if len(grant.WorkloadGenesis) != 0 {
			return errors.New("historical foundation grant cannot carry workload genesis")
		}
		return nil
	}
	expected, err := foundationWorkloadGenesis(grant, home)
	if err != nil {
		return err
	}
	if !slices.Equal(grant.WorkloadGenesis, expected) {
		return errors.New("workload genesis differs from the exact original founding scopes")
	}
	return nil
}

var githubRepositoryPath = regexp.MustCompile(`^/[A-Za-z0-9][A-Za-z0-9-]{0,38}/[A-Za-z0-9_][A-Za-z0-9_.-]{0,99}$`)

func validateContainerRepositories(intent ContainerReleaseAuthorityIntent, namespace string) error {
	ref, err := reference.ParseNormalizedNamed(intent.ImageRepository)
	if err != nil || ref.String() != intent.ImageRepository || !reference.IsNameOnly(ref) {
		return errors.New("container release repository must be canonical and contain no tag or digest")
	}
	host := reference.Domain(ref)
	known := slices.ContainsFunc(catalog.Entries(), func(entry catalog.Entry) bool {
		return host == strings.ToLower(entry.OCIRegionKey)+".ocir.io" || host == entry.OCIRegion+".ocir.io"
	})
	ns, repository, ok := strings.Cut(reference.Path(ref), "/")
	if !known || !ok || ns != namespace || repository == "" {
		return errors.New("container release repository differs from the signed home namespace or supported OCIR host")
	}
	source, err := url.Parse(intent.SourceRepository)
	if err != nil || source.Scheme != "https" || source.Host != "github.com" || source.User != nil || source.RawQuery != "" || source.ForceQuery || source.Fragment != "" || source.RawFragment != "" || source.RawPath != "" || source.Opaque != "" || !githubRepositoryPath.MatchString(source.Path) || strings.HasSuffix(source.Path, ".git") || source.String() != intent.SourceRepository {
		return errors.New("container release source must be an exact canonical HTTPS GitHub repository")
	}
	return nil
}
