package region

import (
	"context"
	"errors"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/vaultsecret"
)

// ErrNotOriginalNetBirdManager permits legacy recovery only for an admitted
// manager with no original lineage. Original proof failures never return it.
var ErrNotOriginalNetBirdManager = errors.New("NetBird manager has no original foundation lineage")

// VerifiedOriginalNetBirdBackupAuthority binds the current original manager to
// both retained bucket create histories. Its fields cannot confer host admission.
type VerifiedOriginalNetBirdBackupAuthority struct {
	installationID, storeGeneration, tenancyID, namespace, grantDigest string
	destinations                                                       [2]VerifiedBackupDestination
	expires                                                            time.Time
	check                                                              func(context.Context) error
}

func (v VerifiedOriginalNetBirdBackupAuthority) InstallationID() string  { return v.installationID }
func (v VerifiedOriginalNetBirdBackupAuthority) StoreGeneration() string { return v.storeGeneration }
func (v VerifiedOriginalNetBirdBackupAuthority) TenancyID() string       { return v.tenancyID }
func (v VerifiedOriginalNetBirdBackupAuthority) Namespace() string       { return v.namespace }
func (v VerifiedOriginalNetBirdBackupAuthority) Destinations() [2]VerifiedBackupDestination {
	return v.destinations
}
func (v VerifiedOriginalNetBirdBackupAuthority) Check(ctx context.Context) error {
	if v.check == nil || !time.Now().Before(v.expires) {
		return errors.New("original NetBird backup authority is absent or expired")
	}
	return v.check(ctx)
}

// OriginalNetBirdBackup reads original authority without widening the generic
// resolver or creating, adopting or repairing any recovery resource.
func (r FoundationResolver) OriginalNetBirdBackup(ctx context.Context, manager VerifiedNetBirdManager) (VerifiedOriginalNetBirdBackupAuthority, error) {
	var authority VerifiedOriginalNetBirdBackupAuthority
	if err := manager.Check(ctx); err != nil {
		return authority, originalBackupReadError(err)
	}
	if manager.originalGrantSHA256 == "" {
		return authority, ErrNotOriginalNetBirdManager
	}
	reader, ok := r.Footprint.(*SignedFootprint)
	if !ok || reader == nil {
		return authority, ErrOriginalSourceProducerHold
	}
	state, err := reader.originalNetBirdState(ctx, r)
	if err != nil {
		return authority, originalBackupReadError(err)
	}
	if state.intent.grantDigest != manager.originalGrantSHA256 || state.intent.intent.Material == nil ||
		state.intent.intent.Material.Context.StoreGeneration != manager.StoreGeneration() || state.regionalTarget() != manager.VaultTarget() ||
		state.target() != manager.CredentialTarget() || state.manager.Launch == nil || netBirdOriginalBinding(*state.manager.Launch) != manager.binding {
		return authority, ErrOriginalSourceProducerHold
	}
	if err := readOriginalNetBirdBackup(ctx, reader.factory, state.record); err != nil {
		return authority, originalBackupReadError(err)
	}
	journal := state.manager.Backup
	if journal == nil || !journal.Complete || journal.InstallationID != state.grant.InstallationID ||
		journal.StoreGeneration != manager.StoreGeneration() || journal.GrantSHA256 != state.intent.grantDigest || journal.Namespace != reader.storage.Namespace {
		return authority, ErrOriginalSourceProducerHold
	}
	authority = VerifiedOriginalNetBirdBackupAuthority{installationID: journal.InstallationID, storeGeneration: journal.StoreGeneration,
		tenancyID: state.record.TenancyID, namespace: journal.Namespace, grantDigest: state.intent.grantDigest, expires: state.intent.expires}
	for i, destination := range journal.Destinations {
		if destination.Cell != [2]string{"GRU", "SFO"}[i] || destination.OCIRegion != [2]string{"sa-saopaulo-1", "us-sanjose-1"}[i] || destination.Bucket.Provenance == nil {
			return VerifiedOriginalNetBirdBackupAuthority{}, ErrOriginalSourceProducerHold
		}
		target := vaultsecret.Target{CompartmentID: destination.CompartmentID, VaultID: destination.VaultID, KeyID: destination.KMSKeyID}
		if i == 0 && target != manager.VaultTarget() {
			return VerifiedOriginalNetBirdBackupAuthority{}, ErrOriginalSourceProducerHold
		}
		authority.destinations[i] = VerifiedBackupDestination{region: destination.OCIRegion, cell: destination.Cell, name: destination.BucketName,
			id: destination.Bucket.Provenance.ResourceID, target: target, generation: state.intent.generation, grantDigest: state.intent.grantDigest, expires: state.intent.expires}
	}
	authority.check = func(ctx context.Context) error {
		current, err := r.OriginalNetBirdBackup(ctx, manager)
		if err != nil {
			return err
		}
		if current.installationID != authority.installationID || current.storeGeneration != authority.storeGeneration ||
			current.tenancyID != authority.tenancyID || current.namespace != authority.namespace || current.grantDigest != authority.grantDigest {
			return ErrOriginalSourceProducerHold
		}
		for i, destination := range current.destinations {
			previous := authority.destinations[i]
			if destination.region != previous.region || destination.cell != previous.cell || destination.name != previous.name || destination.id != previous.id ||
				destination.target != previous.target || destination.generation != previous.generation || destination.grantDigest != previous.grantDigest {
				return ErrOriginalSourceProducerHold
			}
		}
		return ctx.Err()
	}
	for i := range authority.destinations {
		authority.destinations[i].check = authority.Check
	}
	return authority, ctx.Err()
}

// A failing reader cannot choose the legacy branch by returning its sentinel.
func originalBackupReadError(err error) error {
	if errors.Is(err, ErrNotOriginalNetBirdManager) {
		return ErrOriginalSourceProducerHold
	}
	return err
}
