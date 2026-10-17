// Package rootbackup owns the fixed OCI block-volume backup policy in root.
package rootbackup

import (
	"context"
	"errors"
	"os"
	"reflect"
	"slices"
	"strings"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/authority"
	"github.com/TerraScale/ts-orchestrator/internal/bootstrapstart"
	"github.com/TerraScale/ts-orchestrator/internal/hostenroll"
	"github.com/TerraScale/ts-orchestrator/internal/managedmaterial"
	"github.com/TerraScale/ts-orchestrator/internal/oci"
	"github.com/TerraScale/ts-orchestrator/internal/ociclient"
	"github.com/TerraScale/ts-orchestrator/internal/ociregion/capacityinventory"
	"github.com/TerraScale/ts-orchestrator/internal/placement"
	"github.com/TerraScale/ts-orchestrator/internal/region"
	"github.com/TerraScale/ts-orchestrator/internal/rootoci"
	"github.com/TerraScale/ts-orchestrator/internal/rootsecret"
	"github.com/TerraScale/ts-orchestrator/internal/storage/backup"
	"github.com/nats-io/nats.go/jetstream"
)

type Backend struct {
	factory  *ociclient.Factory
	reader   *bootstrapstart.CurrentFounderAuthorityReader
	accepted bootstrapstart.AcceptedIdentity
}

func New(factory *ociclient.Factory, reader *bootstrapstart.CurrentFounderAuthorityReader, accepted bootstrapstart.AcceptedIdentity) (*Backend, error) {
	if os.Geteuid() != 0 || factory == nil || reader == nil || accepted.Validate() != nil {
		return nil, rootoci.ErrUnauthorized
	}
	return &Backend{factory: factory, reader: reader, accepted: accepted.Clone()}, nil
}

func (b *Backend) ReconcileVolumeBackups(ctx context.Context, call rootoci.Call) (rootoci.VolumeBackupReport, error) {
	if os.Geteuid() != 0 || b == nil || b.factory == nil || b.reader == nil ||
		call.Operation() != "" && call.Operation() != rootoci.OperationReconcileVolumeBackups {
		return rootoci.VolumeBackupReport{}, rootoci.ErrUnauthorized
	}
	ctx, cancel := context.WithDeadline(ctx, call.Deadline())
	defer cancel()
	ctx = ociclient.WithRequestGuard(ctx, call.Guard)
	if err := call.Guard(ctx); err != nil {
		return rootoci.VolumeBackupReport{}, err
	}
	accepted, intent, config, err := bootstrapstart.LoadAcceptedOCIConfig()
	if err != nil || !reflect.DeepEqual(accepted, b.accepted) {
		return rootoci.VolumeBackupReport{}, errors.Join(rootoci.ErrUnauthorized, err)
	}
	ociRegion, err := config.Region.OCIRegion()
	if err != nil || ociRegion != b.factory.Region() || call.Expected().Cell != "" && !strings.EqualFold(call.Expected().Cell, accepted.Cell) {
		return rootoci.VolumeBackupReport{}, rootoci.ErrUnauthorized
	}
	runtime, err := b.reader.ReadRuntimeAuthority(ctx, accepted, time.Now().UTC())
	if err != nil {
		return rootoci.VolumeBackupReport{}, err
	}
	ctx, runtimeCancel := context.WithDeadline(ctx, runtime.ExpiresAt())
	defer runtimeCancel()
	spend, err := b.currentScope(ctx, config)
	if err != nil || call.Expected().GrantSHA256 != "" && call.Expected().GrantSHA256 != spend.GrantDigest() {
		return rootoci.VolumeBackupReport{}, errors.Join(rootoci.ErrUnauthorized, err)
	}
	ctx, spendCancel := context.WithDeadline(ctx, spend.ExpiresAt())
	defer spendCancel()
	connection, err := rootsecret.ConnectControllerReader(ctx)
	if err != nil {
		return rootoci.VolumeBackupReport{}, err
	}
	defer connection.Close()
	js, err := jetstream.New(connection)
	if err != nil {
		return rootoci.VolumeBackupReport{}, err
	}
	cell := strings.ToLower(accepted.Cell)
	lease, err := authority.Observe(ctx, js, cell)
	if err != nil || !matchesCaller(lease, accepted, call.RuntimeID()) ||
		call.Expected().Epoch != 0 && call.Expected().Epoch != lease.Epoch || call.Expected().OperationID != "" {
		return rootoci.VolumeBackupReport{}, errors.Join(rootoci.ErrUnauthorized, err)
	}
	ctx, leaseCancel := context.WithDeadline(ctx, lease.ExpiresAt)
	defer leaseCancel()
	reader, err := authority.OpenReader(ctx, js, cell)
	if err != nil {
		return rootoci.VolumeBackupReport{}, err
	}
	material, err := b.preparation(accepted, config, reader)
	if err != nil {
		return rootoci.VolumeBackupReport{}, err
	}
	intents, err := placement.NewAuthorityIntentReader(reader, cell, config.Region)
	if err != nil {
		return rootoci.VolumeBackupReport{}, err
	}
	placements, err := placement.OpenReadStore(ctx, js, cell, 3, verifiedIntents{AdmittedIntentReader: intents, material: material})
	if err != nil {
		return rootoci.VolumeBackupReport{}, err
	}
	journal, err := oci.OpenJournalReader(ctx, js, 3)
	if err != nil {
		return rootoci.VolumeBackupReport{}, err
	}
	listed, err := capture(ctx, placements, config.Region)
	if err != nil && !errors.Is(err, backup.ErrPartialVolumes) {
		return rootoci.VolumeBackupReport{}, err
	}
	listingErr := err
	guard := func(ctx context.Context) error {
		if err := call.Guard(ctx); err != nil {
			return err
		}
		current, _, currentConfig, err := bootstrapstart.LoadAcceptedOCIConfig()
		if err != nil || !reflect.DeepEqual(current, accepted) || !reflect.DeepEqual(currentConfig, config) {
			return errors.Join(rootoci.ErrUnauthorized, err)
		}
		if _, err := b.reader.ReadRuntimeAuthority(ctx, accepted, time.Now().UTC()); err != nil {
			return err
		}
		currentSpend, err := b.currentScope(ctx, config)
		if err != nil || currentSpend.GrantDigest() != spend.GrantDigest() || currentSpend.Generation() != spend.Generation() ||
			currentSpend.PhysicalScopeDigest() != spend.PhysicalScopeDigest() || currentSpend.BindingDigest() != spend.BindingDigest() {
			return errors.Join(rootoci.ErrUnauthorized, err)
		}
		currentListing, err := capture(ctx, placements, config.Region)
		if err != nil && !errors.Is(err, backup.ErrPartialVolumes) || !reflect.DeepEqual(currentListing, listed) {
			return errors.Join(rootoci.ErrUnauthorized, err)
		}
		currentLease, err := authority.Observe(ctx, js, cell)
		if err != nil || !sameLease(lease, currentLease) || !matchesCaller(currentLease, accepted, call.RuntimeID()) {
			return errors.Join(authority.ErrFenced, err)
		}
		if err := call.Guard(ctx); err != nil {
			return err
		}
		if deadline, ok := ctx.Deadline(); !ok || !time.Now().Before(deadline) {
			return context.DeadlineExceeded
		}
		return ctx.Err()
	}
	ctx = ociclient.WithAdmission(ctx, func(ctx context.Context) (func(), error) {
		if err := guard(ctx); err != nil {
			return nil, err
		}
		return func() {}, nil
	})
	provider, err := oci.NewRootVolumeBackupProvider(config, intent, b.factory, journal, guard)
	if err != nil {
		return rootoci.VolumeBackupReport{}, err
	}
	lease.Leader = true
	runner := backup.Runner{Scope: backup.Scope{Owner: config.Owner, Region: config.Region},
		Provider: provider, Fencer: policyFence{snapshot: lease, guard: guard},
		Volumes: func(context.Context) ([]string, error) { return slices.Clone(listed.volumes), listingErr }}
	result, err := runner.RunOnce(ctx)
	if finalErr := guard(ctx); finalErr != nil {
		return rootoci.VolumeBackupReport{}, errors.Join(err, finalErr)
	}
	expires, _ := ctx.Deadline()
	return rootoci.VolumeBackupReport{Created: result.Created, Deleted: result.Deleted, Skipped: result.Skipped,
		Epoch: lease.Epoch, ObservedAt: time.Now().UTC(), ExpiresAt: expires}, err
}

func (b *Backend) currentScope(ctx context.Context, config oci.RegionConfig) (region.VerifiedInfrastructureSpend, error) {
	resolver, err := region.DiscoverCurrentFoundation(ctx, b.factory)
	if err != nil {
		return region.VerifiedInfrastructureSpend{}, err
	}
	spend, err := resolver.InfrastructureSpend(ctx)
	if err != nil || !spend.ValidAt(time.Now()) || !slices.ContainsFunc(spend.Footprint().Regions, func(scopeRegion capacityinventory.RegionScope) bool {
		return scopeRegion.Cell == string(config.Region) && scopeRegion.OCIRegion == b.factory.Region() && slices.Contains(scopeRegion.CompartmentIDs, config.CompartmentID)
	}) {
		return region.VerifiedInfrastructureSpend{}, errors.Join(rootoci.ErrUnauthorized, err)
	}
	return spend, nil
}

func (b *Backend) preparation(accepted bootstrapstart.AcceptedIdentity, config oci.RegionConfig, receipts *authority.Reader) (*managedmaterial.PreparationReader, error) {
	domain := accepted.ManagedMaterial
	if domain == nil || domain.Validate() != nil || domain.MemberCompartmentOCID != config.CompartmentID || domain.MemberSubnetOCID != config.SubnetID {
		return nil, rootoci.ErrUnauthorized
	}
	launch, err := bootstrapstart.LoadAcceptedHostLaunchMaterial(accepted)
	if err != nil {
		return nil, err
	}
	bundle, err := hostenroll.ParsePublicBundle(launch.HostEnrollment)
	if err != nil {
		return nil, err
	}
	key, err := bundle.ResponsePublicKey()
	if err != nil {
		return nil, err
	}
	client, err := b.factory.ObjectStorage()
	if err != nil {
		return nil, err
	}
	return managedmaterial.NewPreparationReader(managedmaterial.RepositoryConfig{Region: config.Region, Cell: strings.ToLower(accepted.Cell),
		Namespace: domain.Namespace, Bucket: domain.Bucket, KMSKeyID: domain.KMSKeyOCID}, &client, receipts, key, domain.MemberSubnetCIDR)
}

type policyFence struct {
	snapshot authority.Snapshot
	guard    func(context.Context) error
}

func (f policyFence) Current() authority.Snapshot { return f.snapshot }
func (f policyFence) Guard(ctx context.Context, epoch uint64) error {
	if epoch != f.snapshot.Epoch {
		return authority.ErrFenced
	}
	return f.guard(ctx)
}

func matchesCaller(lease authority.Snapshot, accepted bootstrapstart.AcceptedIdentity, runtimeID string) bool {
	return runtimeID != "" && lease.Scope == strings.ToLower(accepted.Cell) && lease.DeploymentID == accepted.DeploymentID &&
		lease.CandidateID == runtimeID && lease.OwnerID != "" && lease.Ready && lease.Epoch > 0 && lease.Revision > 0 &&
		lease.Reason == "observed" && time.Now().Before(lease.ExpiresAt)
}

func sameLease(before, after authority.Snapshot) bool {
	return before.Scope == after.Scope && before.DeploymentID == after.DeploymentID && before.Epoch == after.Epoch &&
		before.CandidateID == after.CandidateID && before.OwnerID == after.OwnerID
}

var _ rootoci.VolumeBackups = (*Backend)(nil)
