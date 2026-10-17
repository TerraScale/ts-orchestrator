package region

import (
	"context"
	"errors"
	"maps"
	"slices"
	"strings"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/bootstrap"
	"github.com/TerraScale/ts-orchestrator/internal/ociclient"
	"github.com/oracle/oci-go-sdk/v65/core"
	"github.com/oracle/oci-go-sdk/v65/objectstorage"
)

// ReconcileNetBirdJournalUnderlay uses only the existing initial operator's
// authority, after both original native launches and before final discovery.
func (authority *HomeIAMAuthority) ReconcileNetBirdJournalUnderlay(ctx context.Context, resolver FoundationResolver, purpose VerifiedNetBirdJournalPurpose) error {
	if ctx == nil || authority == nil || authority.operator == nil || authority.factory == nil || resolver.Store == nil || purpose.GrantDigest() != authority.grantDigest ||
		purpose.Purpose().InstallationID != authority.installationID || purpose.Purpose().Storage != authority.domain {
		return errors.New("NetBird private underlay requires the genuine initial operator and signed exact journal purpose")
	}
	if err := validateNetBirdUnderlayStore(resolver, purpose); err != nil {
		return err
	}
	originalCtx := ctx
	ctx, cancel := context.WithDeadline(ctx, purpose.ExpiresAt())
	defer cancel()
	ctx, operatorCancel := context.WithDeadline(ctx, authority.operator.deadline)
	defer operatorCancel()
	// Select the retained original cap before HOME waits, SDK construction or reads.
	initial, _, err := resolver.Store.Load(ctx, "GRU")
	if err != nil {
		return err
	}
	if initial.NetBirdUnderlay != nil {
		var retainedCancel context.CancelFunc
		ctx, retainedCancel = context.WithDeadline(ctx, initial.NetBirdUnderlay.ExpiresAt)
		defer retainedCancel()
	}
	deadline, err := purpose.CurrentDeadline(ctx)
	if err != nil {
		return err
	}
	ctx, currentCancel := context.WithDeadline(ctx, deadline)
	defer currentCancel()
	ctx, release, err := authority.HomeWrite(ctx, 0)
	if err != nil {
		return err
	}
	defer release()
	factory, ctx, err := authority.GuardedFactory(ctx)
	if err != nil {
		return err
	}
	expected, err := netBirdUnderlayBirth(ctx, originalCtx, factory, resolver, purpose)
	if err != nil {
		return err
	}
	if authority.operator.deadline.Before(expected.ExpiresAt) {
		expected.ExpiresAt = authority.operator.deadline
	}
	expected.Origin = bootstrap.NetBirdJournalOriginReference{Namespace: authority.domain.Namespace,
		GrantObject: strings.TrimSuffix(authority.domain.Prefix, "/") + "/" + foundationGrantObject,
		GrantSHA256: purpose.GrantDigest(), RootChainSHA256: digestSource(authority.operator.bundle.RootChainWire)}
	ctx, capCancel := context.WithDeadline(ctx, expected.ExpiresAt)
	defer capCancel()
	firstCap := expected.ExpiresAt
	if deadline, ok := ctx.Deadline(); ok && deadline.Before(firstCap) {
		firstCap = deadline
	}
	currentCap := firstCap
	current, etag, err := resolver.Store.Load(ctx, "GRU")
	if err != nil {
		return err
	}
	startedAt := expected.StartedAt
	if current.NetBirdUnderlay != nil {
		startedAt = current.NetBirdUnderlay.StartedAt
	}
	origin, err := netBirdJournalOrigin(ctx, factory, authority.operator.genesis, expected.Origin, startedAt)
	if err != nil {
		return err
	}
	originDigest, err := origin.Purpose().Digest()
	if err != nil || originDigest != expected.PurposeSHA256 || origin.GrantDigest() != expected.GrantSHA256 {
		return errors.Join(errors.New("NetBird underlay archive differs from its exact original signed purpose"), err)
	}
	if current.NetBirdUnderlay == nil {
		current.NetBirdUnderlay = &expected
		current.UpdatedAt = time.Now().UTC()
		if err := authority.Guard(ctx, 0); err != nil {
			return err
		}
		if _, err := resolver.Store.CompareAndSwap(ctx, current, etag); err != nil {
			return err
		}
	} else if !sameNetBirdUnderlayBirth(*current.NetBirdUnderlay, expected) {
		return errors.New("NetBird underlay cannot replace its original purpose, launches or network")
	}
	if current.NetBirdUnderlay.ExpiresAt.Before(currentCap) {
		currentCap = current.NetBirdUnderlay.ExpiresAt
	}
	client, err := factory.Network()
	if err != nil {
		return err
	}
	for _, key := range netBirdUnderlaySteps {
		current, etag, err = resolver.Store.Load(ctx, "GRU")
		if err != nil {
			return err
		}
		if current.NetBirdUnderlay == nil || !sameNetBirdUnderlayBirth(*current.NetBirdUnderlay, expected) {
			return ErrFoundationFenced
		}
		if current.NetBirdUnderlay.ExpiresAt.Before(currentCap) {
			currentCap = current.NetBirdUnderlay.ExpiresAt
		}
		journal := *current.NetBirdUnderlay
		journal.Requests = maps.Clone(journal.Requests)
		q, exists := journal.Requests[key]
		if !exists {
			if err := authority.Guard(ctx, 0); err != nil {
				return err
			}
			actual, err := netBirdUnderlayBirth(ctx, originalCtx, factory, resolver, purpose)
			if err != nil || !sameNetBirdUnderlayBirth(journal, actual) {
				return errors.Join(ErrFoundationFenced, err)
			}
			if actual.ExpiresAt.Before(currentCap) {
				currentCap = actual.ExpiresAt
			}
			q, err = prepareNetBirdUnderlayRequest(ctx, client, journal, key)
			if err != nil {
				return err
			}
			wire, err := netBirdUnderlayRequestWire(q)
			if err != nil {
				return err
			}
			q.RequestDigest = digestSource(wire)
			q.RetryToken = digestSource([]byte(journal.PurposeSHA256 + "\x00" + key + "\x00" + q.RequestDigest))
			q.FirstAttemptAt = time.Now().UTC()
			journal.Requests[key] = q
			current.NetBirdUnderlay, current.UpdatedAt = &journal, q.FirstAttemptAt
			if err := authority.Guard(ctx, 0); err != nil {
				return err
			}
			if _, err := resolver.Store.CompareAndSwap(ctx, current, etag); err != nil {
				return err
			}
			// Re-read the exact accepted reservation before the one possible send.
			saved, _, err := resolver.Store.Load(ctx, "GRU")
			if err != nil || saved.NetBirdUnderlay == nil || !netBirdUnderlayEqual(saved.NetBirdUnderlay, &journal) {
				return errors.Join(ErrFoundationFenced, err)
			}
			if err := purpose.Revalidate(ctx); err != nil {
				return err
			}
			actual, err = netBirdUnderlayBirth(ctx, originalCtx, factory, resolver, purpose)
			if err != nil || !sameNetBirdUnderlayBirth(journal, actual) {
				return errors.Join(ErrFoundationFenced, err)
			}
			if actual.ExpiresAt.Before(currentCap) {
				currentCap = actual.ExpiresAt
			}
			if err := authority.Guard(ctx, 0); err != nil {
				return err
			}
			sendCap := currentCap
			// Run the retained local seal after every awaited SDK and source guard.
			dispatchCtx := ociclient.WithRequestGuard(ctx, func(requestCtx context.Context) error {
				if err := requestCtx.Err(); err != nil {
					return err
				}
				if err := originalCtx.Err(); err != nil {
					return err
				}
				if err := purpose.CheckOriginal(); err != nil {
					return err
				}
				now := time.Now()
				if !now.Before(firstCap) || !now.Before(sendCap) {
					return errors.New("NetBird underlay original or current birth expired before dispatch")
				}
				return originalCtx.Err()
			})
			responseID, err := dispatchNetBirdUnderlay(dispatchCtx, client, q)
			if err != nil {
				return errors.Join(ErrNetBirdUnderlayPending, err)
			}
			q.ResponseID, q.RespondedAt = responseID, time.Now().UTC()
			if err := checkpointNetBirdUnderlay(ctx, authority, resolver, journal, key, q); err != nil {
				return err
			}
			journal.Requests[key] = q
		} else if q.RespondedAt.IsZero() {
			return ErrNetBirdUnderlayPending
		}
		if err := observeNetBirdUnderlayRequest(ctx, client, journal, key); err != nil {
			return err
		}
		if q.VerifiedAt.IsZero() {
			q.VerifiedAt = time.Now().UTC()
			if err := checkpointNetBirdUnderlay(ctx, authority, resolver, journal, key, q); err != nil {
				return err
			}
		}
	}
	_, err = VerifyNetBirdJournalUnderlayForOperation(ctx, ctx, factory, resolver, purpose)
	return err
}

func checkpointNetBirdUnderlay(ctx context.Context, authority *HomeIAMAuthority, resolver FoundationResolver, expected NetBirdUnderlayRecord, key string, request NetBirdUnderlayRequest) error {
	current, etag, err := resolver.Store.Load(ctx, "GRU")
	if err != nil {
		return err
	}
	if current.NetBirdUnderlay == nil || !netBirdUnderlayEqual(current.NetBirdUnderlay, &expected) {
		return ErrFoundationFenced
	}
	updated := *current.NetBirdUnderlay
	updated.Requests = maps.Clone(updated.Requests)
	updated.Requests[key] = request
	current.NetBirdUnderlay, current.UpdatedAt = &updated, time.Now().UTC()
	if err := authority.Guard(ctx, 0); err != nil {
		return err
	}
	if _, err := resolver.Store.CompareAndSwap(ctx, current, etag); err != nil {
		return err
	}
	saved, _, err := resolver.Store.Load(ctx, "GRU")
	if err != nil || saved.NetBirdUnderlay == nil || !netBirdUnderlayEqual(saved.NetBirdUnderlay, &updated) {
		return errors.Join(ErrFoundationFenced, err)
	}
	return nil
}

func sameNetBirdUnderlayBirth(original, current NetBirdUnderlayRecord) bool {
	original.Requests, current.Requests = nil, nil
	original.StartedAt, current.StartedAt = time.Time{}, time.Time{}
	original.ExpiresAt, current.ExpiresAt = time.Time{}, time.Time{}
	return netBirdUnderlayEqual(original, current)
}

func netBirdUnderlayBirth(ctx, originalCtx context.Context, factory *ociclient.Factory, resolver FoundationResolver, purpose VerifiedNetBirdJournalPurpose) (NetBirdUnderlayRecord, error) {
	var zero NetBirdUnderlayRecord
	deadline, err := purpose.CurrentDeadline(ctx)
	if err != nil {
		return zero, err
	}
	ctx, cancel := context.WithDeadline(ctx, deadline)
	defer cancel()
	p := purpose.Purpose()
	reader, ok := resolver.Footprint.(*SignedFootprint)
	if !ok || reader == nil || factory == nil || factory.Region() != foundationHomeRegion || reader.storage != p.Storage || reader.tenancy == "" {
		return zero, errors.New("NetBird underlay native verification requires its actual signed GRU foundation")
	}
	if err := validateNetBirdUnderlayStore(resolver, purpose); err != nil {
		return zero, err
	}
	tenancy, err := factory.Provider().TenancyOCID()
	if err != nil || tenancy != reader.tenancy {
		return zero, errors.Join(errors.New("NetBird underlay native provider differs from its signed tenancy"), err)
	}
	record, err := resolver.Resolve(ctx, "GRU")
	if err != nil {
		return zero, err
	}
	managerIntent, err := reader.authorizedNetBirdManager(ctx)
	if err != nil {
		return zero, err
	}
	managerAllocation, err := resolver.BootstrapAllocation(ctx, p.Manager.SlotID)
	if err != nil {
		return zero, err
	}
	writerAllocation, err := resolver.BootstrapAllocation(ctx, p.Writer.SlotID)
	if err != nil {
		return zero, err
	}
	if err := validateNetBirdAllocation(managerAllocation, managerIntent, record.ResourceIDs["control_compartment"]); err != nil {
		return zero, err
	}
	for _, binding := range []struct {
		allocation VerifiedBootstrapAllocation
		logical    bootstrap.NetBirdJournalAllocation
	}{{managerAllocation, p.Manager}, {writerAllocation, p.Writer}} {
		slot := binding.allocation.SignedSlot()
		if !binding.allocation.IsVerified() || binding.allocation.GrantDigest() != purpose.GrantDigest() || binding.allocation.InstallationID() != p.InstallationID || binding.allocation.OperationID() != binding.logical.OperationID ||
			slot.SlotID != binding.logical.SlotID || slot.ProfileSHA256 != binding.logical.ProfileSHA256 || slot.RecipeSHA256 != binding.logical.RecipeSHA256 {
			return zero, errors.New("NetBird underlay differs from its actual original signed allocation")
		}
	}
	if _, err := netBirdRecipientCheckpoint(managerIntent, record, managerAllocation); err != nil {
		return zero, err
	}
	m := record.NetBirdManager
	if m.OriginGrantSHA256 != purpose.GrantDigest() || m.OriginBindingSHA256 != managerAllocation.BindingDigest() || m.OriginalScopeSHA256 != managerAllocation.ScopeDigest() || m.PhysicalScopeSHA256 != managerAllocation.PhysicalScopeDigest() {
		return zero, errors.New("NetBird underlay manager checkpoint differs from its original physical allocation")
	}
	material, err := reader.AuthorizedBootstrapMaterialForOperation(ctx, originalCtx, "GRU")
	if err != nil {
		return zero, err
	}
	writerImage, writerExpected, err := foundationWriterImage(ctx, resolver, material, "GRU")
	if err != nil {
		return zero, err
	}
	w := record.FoundationWriter
	if w == nil || w.validate() != nil || w.Cell != "GRU" || w.InstanceID == "" || w.GrantSHA256 != purpose.GrantDigest() || w.InstallationID != p.InstallationID || w.SlotID != p.Writer.SlotID ||
		w.OperationID != p.Writer.OperationID || w.ProfileSHA256 != p.Writer.ProfileSHA256 || w.RecipeSHA256 != p.Writer.RecipeSHA256 || w.BindingSHA256 != writerAllocation.BindingDigest() ||
		w.ScopeSHA256 != writerAllocation.ScopeDigest() || w.PhysicalScopeSHA256 != writerAllocation.PhysicalScopeDigest() || w.Generation != writerAllocation.Generation() ||
		w.Namespace != p.Storage.Namespace || w.Bucket != p.Storage.HeadBucket || w.KMSKeyID != p.Storage.HeadKMSKeyOCID || w.Policy == nil || w.Policy.PolicyID == "" || w.Policy.VerifiedAt.IsZero() {
		return zero, errors.New("NetBird underlay lacks the actual original writer launch and installed native policy")
	}
	if digest, err := netBirdRequestDigest(w.Request); err != nil || digest != w.RequestDigest {
		return zero, errors.Join(errors.New("NetBird underlay writer launch request changed"), err)
	}
	image, imageOK := w.Request.SourceDetails.(core.InstanceSourceViaImageDetails)
	if !imageOK || value(image.ImageId) != writerExpected.OCIImageOCID {
		return zero, errors.New("NetBird underlay writer image differs from its genuine current qualified source")
	}
	footprint, err := reader.AuthorizedRegions(ctx)
	if err != nil {
		return zero, err
	}
	foundRecipe := false
	for _, intent := range footprint.Regions {
		if intent.Plan["cell"] != "GRU" || intent.BootstrapMaterial == nil {
			continue
		}
		recipe, err := NetBirdJournalUnderlayRecipe(intent.Plan, managerIntent.intent.Profile, *intent.BootstrapMaterial)
		if err != nil || recipe != p.Underlay {
			return zero, errors.Join(errors.New("NetBird underlay recipe differs from the actual signed original GRU source"), err)
		}
		foundRecipe = true
	}
	if !foundRecipe {
		return zero, errors.New("NetBird underlay original GRU material is absent")
	}
	networkCompartment := record.ResourceIDs["network_compartment"]
	manager := NetBirdUnderlayEndpoint{InstanceID: record.NetBirdManager.InstanceID, CompartmentID: managerAllocation.Slot().CompartmentID, NetworkCompartmentID: networkCompartment,
		NetworkID: record.AuxiliaryIDs[p.Underlay.ManagerVCNKey], SubnetID: record.AuxiliaryIDs[p.Underlay.ManagerSubnetKey], RouteTableID: record.AuxiliaryIDs[p.Underlay.ManagerRouteTableKey], SecurityID: record.AuxiliaryIDs[p.Underlay.ManagerSecurityKey], NSGID: record.AuxiliaryIDs[p.Underlay.ManagerNSGKey]}
	writer := NetBirdUnderlayEndpoint{InstanceID: w.InstanceID, CompartmentID: writerAllocation.Slot().CompartmentID, NetworkCompartmentID: networkCompartment,
		NetworkID: record.ResourceIDs[p.Underlay.WriterVCNKey], SubnetID: record.ResourceIDs[p.Underlay.WriterSubnetKey], RouteTableID: record.ResourceIDs[p.Underlay.WriterRouteTableKey], SecurityID: record.ResourceIDs[p.Underlay.WriterSecurityKey], NSGID: record.ResourceIDs[p.Underlay.WriterNSGKey]}
	if w.Request.CreateVnicDetails == nil || value(w.Request.CreateVnicDetails.SubnetId) != writer.SubnetID || value(w.Request.CreateVnicDetails.PrivateIp) != p.Underlay.WriterPrivateIP ||
		!slices.Equal(w.Request.CreateVnicDetails.NsgIds, []string{writer.NSGID}) || w.Request.CreateVnicDetails.AssignPublicIp == nil || *w.Request.CreateVnicDetails.AssignPublicIp || value(w.Request.CompartmentId) != writer.CompartmentID {
		return zero, errors.New("NetBird underlay writer native request differs from the original signed endpoint")
	}
	bootID, err := observeNetBirdGeometry(ctx, factory, managerIntent.intent, *record.NetBirdManager, manager.CompartmentID)
	if err != nil || bootID != record.NetBirdManager.BootVolumeID {
		return zero, errors.Join(errors.New("NetBird underlay manager native image, allocation or boot attachment changed"), err)
	}
	if err := observeNetBirdUnderlayWriter(ctx, factory, *w); err != nil {
		return zero, err
	}
	manager.VNICID, err = observeNetBirdUnderlayEndpoint(ctx, factory, manager.InstanceID, manager.CompartmentID, manager.SubnetID, p.Underlay.ManagerPrivateIP, []string{manager.NSGID}, false)
	if err != nil {
		return zero, err
	}
	writer.VNICID, err = observeNetBirdUnderlayEndpoint(ctx, factory, writer.InstanceID, writer.CompartmentID, writer.SubnetID, p.Underlay.WriterPrivateIP, []string{writer.NSGID}, true)
	if err != nil {
		return zero, err
	}
	if err := observeNetBirdUnderlayNetworks(ctx, factory, p.Underlay, manager, writer); err != nil {
		return zero, err
	}
	if err := purpose.Revalidate(ctx); err != nil {
		return zero, err
	}
	if err := managerAllocation.Revalidate(ctx); err != nil {
		return zero, err
	}
	if err := writerAllocation.Revalidate(ctx); err != nil {
		return zero, err
	}
	expires := purpose.ExpiresAt()
	for _, cap := range []time.Time{deadline, managerIntent.expires, managerAllocation.ExpiresAt(), writerAllocation.ExpiresAt(), material.ExpiresAt(), writerImage.ExpiresAt()} {
		if cap.Before(expires) {
			expires = cap
		}
	}
	var origin bootstrap.NetBirdJournalOriginReference
	if record.NetBirdUnderlay != nil {
		origin = record.NetBirdUnderlay.Origin
		if origin.Validate() != nil || origin.Namespace != p.Storage.Namespace || origin.GrantSHA256 != purpose.GrantDigest() ||
			origin.GrantObject != strings.TrimSuffix(p.Storage.Prefix, "/")+"/"+foundationGrantObject {
			return zero, errors.New("NetBird underlay archive reference differs from its protected original signed source")
		}
	}
	return NetBirdUnderlayRecord{PurposeSHA256: purpose.Digest(), GrantSHA256: purpose.GrantDigest(), Origin: origin, OperationID: record.OperationID, IntentDigest: record.IntentDigest, Epoch: record.Epoch,
		Recipe: p.Underlay, Manager: manager, Writer: writer, StartedAt: time.Now().UTC(), ExpiresAt: expires, Requests: map[string]NetBirdUnderlayRequest{}}, nil
}

func observeNetBirdUnderlayNetworks(ctx context.Context, factory *ociclient.Factory, recipe bootstrap.NetBirdJournalUnderlayRecipe, manager, writer NetBirdUnderlayEndpoint) error {
	client, err := factory.Network()
	if err != nil {
		return err
	}
	for _, side := range []struct {
		e            NetBirdUnderlayEndpoint
		cidr, subnet string
		private      bool
	}{{manager, recipe.ManagerNetworkCIDR, recipe.ManagerNetworkCIDR, false}, {writer, recipe.WriterNetworkCIDR, recipe.WriterSubnetCIDR, true}} {
		vcn, err := client.GetVcn(ociclient.RequestContext(ctx), core.GetVcnRequest{VcnId: new(side.e.NetworkID)})
		if err != nil {
			return err
		}
		if value(vcn.Id) != side.e.NetworkID || value(vcn.CompartmentId) != side.e.NetworkCompartmentID || vcn.LifecycleState != core.VcnLifecycleStateAvailable ||
			len(vcn.CidrBlocks) != 1 || vcn.CidrBlocks[0] != side.cidr || len(vcn.Ipv6CidrBlocks) != 0 || len(vcn.Ipv6PrivateCidrBlocks) != 0 || len(vcn.Byoipv6CidrBlocks) != 0 {
			return errors.New("NetBird underlay VCN readback differs from its exact signed nonoverlap allocation")
		}
		subnet, err := client.GetSubnet(ociclient.RequestContext(ctx), core.GetSubnetRequest{SubnetId: new(side.e.SubnetID)})
		if err != nil {
			return err
		}
		if value(subnet.Id) != side.e.SubnetID || value(subnet.CompartmentId) != side.e.NetworkCompartmentID || value(subnet.VcnId) != side.e.NetworkID || value(subnet.CidrBlock) != side.subnet ||
			subnet.LifecycleState != core.SubnetLifecycleStateAvailable || value(subnet.RouteTableId) != side.e.RouteTableID || !slices.Equal(subnet.SecurityListIds, []string{side.e.SecurityID}) ||
			subnet.ProhibitPublicIpOnVnic == nil || *subnet.ProhibitPublicIpOnVnic != side.private || subnet.ProhibitInternetIngress == nil || *subnet.ProhibitInternetIngress != side.private ||
			value(subnet.Ipv6CidrBlock) != "" || len(subnet.Ipv6CidrBlocks) != 0 {
			return errors.New("NetBird underlay subnet readback differs from its signed endpoint attachments")
		}
	}
	return nil
}

func validateNetBirdUnderlayStore(resolver FoundationResolver, purpose VerifiedNetBirdJournalPurpose) error {
	store, ok := resolver.Store.(*ObjectFoundationStore)
	if !ok || store == nil || store.namespace != purpose.Purpose().Storage.Namespace || store.bucket != purpose.Purpose().Storage.HeadBucket {
		return errors.New("NetBird underlay requires the signed protected original foundation object store")
	}
	if client, ok := store.client.(*objectstorage.ObjectStorageClient); !ok || client == nil {
		return errors.New("NetBird underlay requires the real authenticated OCI Object Storage client")
	}
	return nil
}

func observeNetBirdUnderlayWriter(ctx context.Context, factory *ociclient.Factory, writer FoundationWriterRecord) error {
	client, err := factory.Compute()
	if err != nil {
		return err
	}
	response, err := client.GetInstance(ociclient.RequestContext(ctx), core.GetInstanceRequest{InstanceId: new(writer.InstanceID)})
	if err != nil {
		return err
	}
	i, expected := response.Instance, writer.Request
	actualImage, actualOK := i.SourceDetails.(core.InstanceSourceViaImageDetails)
	expectedImage, expectedOK := expected.SourceDetails.(core.InstanceSourceViaImageDetails)
	if !actualOK || !expectedOK || value(actualImage.ImageId) != value(expectedImage.ImageId) || value(i.Id) != writer.InstanceID || value(i.CompartmentId) != value(expected.CompartmentId) ||
		value(i.AvailabilityDomain) != value(expected.AvailabilityDomain) || value(i.FaultDomain) != value(expected.FaultDomain) || value(i.Shape) != value(expected.Shape) || i.ShapeConfig == nil || expected.ShapeConfig == nil ||
		value(i.ShapeConfig.Ocpus) != value(expected.ShapeConfig.Ocpus) || value(i.ShapeConfig.MemoryInGBs) != value(expected.ShapeConfig.MemoryInGBs) || i.LifecycleState != core.InstanceLifecycleStateRunning ||
		!netBirdUnderlayEqual(i.Metadata, expected.Metadata) || !netBirdUnderlayEqual(i.ExtendedMetadata, expected.ExtendedMetadata) {
		return errors.New("NetBird underlay original writer image, allocation or launch metadata changed")
	}
	return nil
}
