package rootfoundation

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/bootstrap"
	"github.com/TerraScale/ts-orchestrator/internal/bootstrapmaterial"
	"github.com/TerraScale/ts-orchestrator/internal/bootstrapstart"
	"github.com/TerraScale/ts-orchestrator/internal/bootstrapstart/materialsource"
	"github.com/TerraScale/ts-orchestrator/internal/oci"
	"github.com/TerraScale/ts-orchestrator/internal/ociclient"
	"github.com/TerraScale/ts-orchestrator/internal/ociregion/catalog"
	"github.com/TerraScale/ts-orchestrator/internal/region"
	"github.com/TerraScale/ts-orchestrator/internal/rootoci"
	"github.com/TerraScale/ts-orchestrator/internal/vaultsecret"
	"github.com/oracle/oci-go-sdk/v65/objectstorage"
	ocisecrets "github.com/oracle/oci-go-sdk/v65/secrets"
	ocivault "github.com/oracle/oci-go-sdk/v65/vault"
)

type sourceState struct {
	source   *materialsource.ColdStartMaterial
	material materialsource.VerifiedColdStartMaterial
	founder  bootstrapstart.VerifiedSourceFounder
	grant    region.VerifiedBootstrapMaterial
	resolver region.FoundationResolver
	factory  *ociclient.Factory
	objects  objectstorage.ObjectStorageClient
	ctx      context.Context
	guard    func(context.Context) error
}

func (b *Backend) source(ctx context.Context, call rootoci.Call) (sourceState, error) {
	if selected := call.Operation(); selected != "" && selected != rootoci.OperationEnsureSource {
		return sourceState{}, ErrScope
	}
	ctx = ociclient.WithRequestGuard(ctx, call.Guard)
	resolver, err := b.current(ctx, call)
	if err != nil {
		return sourceState{}, err
	}
	record, err := resolver.Resolve(ctx, b.cell)
	if err != nil {
		return sourceState{}, err
	}
	if err := checkCall(ctx, call, rootoci.OperationEnsureSource, rootoci.Expectations{
		Cell: b.cell, GrantSHA256: record.GrantSHA256, OperationID: record.OperationID, Epoch: record.Epoch,
	}); err != nil {
		return sourceState{}, err
	}
	founder, err := bootstrapstart.VerifySourceFounder(ctx, b.factory, b.template)
	if err != nil {
		return sourceState{}, err
	}
	protected := resolver
	guard := func(ctx context.Context) error {
		if err := b.guard(ctx, call); err != nil {
			return err
		}
		current, err := protected.Resolve(ctx, b.cell)
		if err != nil {
			return err
		}
		if current.Generation != record.Generation || current.GrantSHA256 != record.GrantSHA256 ||
			current.OperationID != record.OperationID || current.Epoch != record.Epoch ||
			current.LeaseID != "" && time.Now().Before(current.ExpiresAt) {
			return ErrScope
		}
		if err := founder.VerifyCurrent(ctx); err != nil {
			return err
		}
		if err := call.Guard(ctx); err != nil {
			return err
		}
		if !time.Now().Before(founder.ExpiresAt()) {
			return ErrScope
		}
		return ctx.Err()
	}
	resolver.Store = guardedStore{FoundationStore: resolver.Store, guard: guard}
	home, err := region.NewHomeIAMAuthority(ctx, founder, resolver)
	if err != nil {
		return sourceState{}, err
	}
	actor, err := region.NewSourceFounder(ctx, resolver, home)
	if err != nil {
		return sourceState{}, err
	}
	factory, guarded, err := founder.GuardedFactory(effectContext(ctx, guard))
	if err != nil {
		return sourceState{}, err
	}
	grant, err := resolver.BootstrapMaterial(guarded, b.cell)
	if err != nil {
		return sourceState{}, err
	}
	scope, err := b.anchor.FoundationScope()
	if err != nil {
		return sourceState{}, err
	}
	homeFactory, err := factory.ForRegion(scope.OCIRegion)
	if err != nil {
		return sourceState{}, err
	}
	objects, err := homeFactory.ObjectStorage()
	if err != nil {
		return sourceState{}, err
	}
	escrow, escrowBundles, err := vaultClients(homeFactory)
	if err != nil {
		return sourceState{}, err
	}
	if err := guard(guarded); err != nil {
		return sourceState{}, err
	}
	if err := os.MkdirAll(sourceDirectory, 0o700); err != nil {
		return sourceState{}, err
	}
	source, err := materialsource.ResolveColdStartMaterial(guarded, grant, actor, &objects, escrow, escrowBundles,
		filepath.Join(sourceDirectory, "regional"), time.Now().UTC())
	if err != nil {
		return sourceState{}, err
	}
	state := sourceState{source: source, founder: founder, grant: grant, resolver: resolver, factory: factory, objects: objects, ctx: guarded, guard: guard}
	target, err := b.target(guarded, resolver)
	if err != nil {
		return sourceState{}, err
	}
	management, bundles, err := vaultClients(factory)
	if err != nil {
		return sourceState{}, err
	}
	if _, err := source.Provision(guarded, target, management, bundles, time.Now().UTC()); err != nil {
		return sourceState{}, err
	}
	if err := guard(guarded); err != nil {
		return sourceState{}, err
	}
	state.material, err = source.InstallMaterial(guarded)
	if err != nil {
		return sourceState{}, err
	}
	return state, nil
}

func (b *Backend) EnsureSource(ctx context.Context, call rootoci.Call, request rootoci.SourceRequest) (rootoci.SourceReceipt, error) {
	if b == nil || request.Cell != b.cell || request.Kind != rootoci.SourceRegional && request.Kind != rootoci.SourceHomeLink && request.Kind != rootoci.SourceSpokeLink ||
		request.Kind != rootoci.SourceSpokeLink && request.RecipientCell != "" || request.Kind != rootoci.SourceRegional && b.cell != "GRU" {
		return rootoci.SourceReceipt{}, ErrScope
	}
	if request.Kind == rootoci.SourceSpokeLink {
		if _, ok := catalog.Lookup(request.RecipientCell); !ok || request.RecipientCell == "GRU" {
			return rootoci.SourceReceipt{}, ErrScope
		}
	}
	state, err := b.source(ctx, call)
	if err != nil {
		return rootoci.SourceReceipt{}, err
	}
	scope := sha256.Sum256([]byte(state.grant.InstallationID() + "\x00" + state.grant.Config().Cell))
	key := state.grant.StorageDomain().Prefix + "/bootstrap/v2/material-source/" + hex.EncodeToString(scope[:]) + ".json"
	if request.Kind != rootoci.SourceRegional {
		link, proof, err := b.homeLink(state)
		if err != nil {
			return rootoci.SourceReceipt{}, err
		}
		key = proof.Evidence().SourceObjectKey
		if request.Kind == rootoci.SourceSpokeLink {
			key, err = b.spokeLink(state, link, request.RecipientCell)
			if err != nil {
				return rootoci.SourceReceipt{}, err
			}
		}
	}
	if err := state.guard(state.ctx); err != nil {
		return rootoci.SourceReceipt{}, err
	}
	return rootoci.SourceReceipt{Cell: b.cell, Kind: request.Kind, RecipientCell: request.RecipientCell,
		GrantDigest: state.founder.GrantDigest(), Generation: state.founder.Generation(), ObjectKey: key}, nil
}

func (b *Backend) homeLink(state sourceState) (*materialsource.LinkSource, bootstrap.VerifiedStartupLink, error) {
	if b.cell != "GRU" {
		return nil, bootstrap.VerifiedStartupLink{}, ErrScope
	}
	home, err := state.factory.ForRegion("sa-saopaulo-1")
	if err != nil {
		return nil, bootstrap.VerifiedStartupLink{}, err
	}
	escrow, escrowBundles, err := vaultClients(home)
	if err != nil {
		return nil, bootstrap.VerifiedStartupLink{}, err
	}
	link, err := materialsource.ResolveLinkSource(state.ctx, state.source, state.source, nil, &state.objects, escrow, escrowBundles,
		filepath.Join(sourceDirectory, "link"), time.Now().UTC())
	if err != nil {
		return nil, bootstrap.VerifiedStartupLink{}, err
	}
	target, err := b.target(state.ctx, state.resolver)
	if err != nil {
		return nil, bootstrap.VerifiedStartupLink{}, err
	}
	management, bundles, err := vaultClients(state.factory)
	if err != nil {
		return nil, bootstrap.VerifiedStartupLink{}, err
	}
	if _, err := link.Provision(state.ctx, target, management, bundles, time.Now().UTC()); err != nil {
		return nil, bootstrap.VerifiedStartupLink{}, err
	}
	proof, err := link.StartupLink(state.ctx, b.template, time.Now().UTC())
	return link, proof, err
}

func (b *Backend) spokeLink(state sourceState, homeLink *materialsource.LinkSource, cell string) (string, error) {
	template, err := b.template.ForCell(state.ctx, oci.Region(cell), time.Now().UTC())
	if err != nil {
		return "", err
	}
	regional, err := bootstrap.LoadRegionalSource(state.ctx, template, &state.objects, time.Now().UTC())
	if err != nil {
		return "", err
	}
	home, err := state.founder.PublicSource(state.ctx)
	if err != nil {
		return "", err
	}
	recipient, err := bootstrap.VerifyLinkRecipient(state.ctx, regional, home, time.Now().UTC())
	if err != nil {
		return "", err
	}
	grant, err := state.resolver.BootstrapMaterial(state.ctx, cell)
	if err != nil {
		return "", err
	}
	homeFactory, err := state.factory.ForRegion("sa-saopaulo-1")
	if err != nil {
		return "", err
	}
	escrow, escrowBundles, err := vaultClients(homeFactory)
	if err != nil {
		return "", err
	}
	directory := filepath.Join(sourceDirectory, "regional-links", strings.ToLower(cell))
	if err := os.MkdirAll(filepath.Dir(directory), 0o700); err != nil {
		return "", err
	}
	link, err := materialsource.IssueRegionalLink(state.ctx, state.source, homeLink, recipient, grant, &state.objects, escrow, escrowBundles, directory, time.Now().UTC())
	if err != nil {
		return "", err
	}
	regionalFactory, err := state.factory.ForRegion(grant.Config().Region)
	if err != nil {
		return "", err
	}
	management, bundles, err := vaultClients(regionalFactory)
	if err != nil {
		return "", err
	}
	target := recipient.VaultTarget()
	if _, err := link.PublishRegionalLink(state.ctx, bootstrapmaterial.VaultTarget{CompartmentOCID: target.CompartmentOCID, VaultOCID: target.VaultOCID, KMSKeyOCID: target.KMSKeyOCID}, management, bundles, time.Now().UTC()); err != nil {
		return "", err
	}
	return recipient.LinkObjectKey(), nil
}

func (b *Backend) target(ctx context.Context, resolver region.FoundationResolver) (bootstrapmaterial.VaultTarget, error) {
	record, err := resolver.Resolve(ctx, b.cell)
	if err != nil {
		return bootstrapmaterial.VaultTarget{}, err
	}
	actual, err := record.VaultTarget()
	if err != nil {
		return bootstrapmaterial.VaultTarget{}, err
	}
	target := b.template.VaultTarget()
	if target.CompartmentOCID != actual.CompartmentID || target.VaultOCID != actual.VaultID || target.KMSKeyOCID != actual.KeyID {
		return bootstrapmaterial.VaultTarget{}, ErrScope
	}
	return bootstrapmaterial.VaultTarget{CompartmentOCID: actual.CompartmentID, VaultOCID: actual.VaultID, KMSKeyOCID: actual.KeyID}, nil
}

func vaultClients(factory *ociclient.Factory) (*ocivault.VaultsClient, *ocisecrets.SecretsClient, error) {
	management, err := ocivault.NewVaultsClientWithConfigurationProvider(factory.Provider())
	if err != nil {
		return nil, nil, err
	}
	management.SetRegion(factory.Region())
	factory.Configure(&management.BaseClient, ociclient.ServiceVault)
	bundles, err := vaultsecret.SecretsClient(factory)
	if err != nil {
		return nil, nil, err
	}
	return &management, &bundles, nil
}

// InitialMaterial stays inside the root bootstrap path; the IPC dispatcher has
// no operation returning this source handle or any signing material.
func (b *Backend) InitialMaterial(ctx context.Context, call rootoci.Call) (materialsource.VerifiedColdStartMaterial, bootstrap.VerifiedStartupLink, bootstrapstart.VerifiedSourceFounder, error) {
	state, err := b.source(ctx, call)
	if err != nil {
		return materialsource.VerifiedColdStartMaterial{}, bootstrap.VerifiedStartupLink{}, bootstrapstart.VerifiedSourceFounder{}, err
	}
	var proof bootstrap.VerifiedStartupLink
	if b.cell == "GRU" {
		_, proof, err = b.homeLink(state)
	} else {
		regional, loadErr := bootstrap.LoadRegionalSource(state.ctx, b.template, &state.objects, time.Now().UTC())
		if loadErr != nil {
			return materialsource.VerifiedColdStartMaterial{}, bootstrap.VerifiedStartupLink{}, bootstrapstart.VerifiedSourceFounder{}, loadErr
		}
		homeTemplate, loadErr := b.template.ForCell(state.ctx, oci.RegionGRU, time.Now().UTC())
		if loadErr != nil {
			return materialsource.VerifiedColdStartMaterial{}, bootstrap.VerifiedStartupLink{}, bootstrapstart.VerifiedSourceFounder{}, loadErr
		}
		home, loadErr := bootstrap.LoadRegionalSource(state.ctx, homeTemplate, &state.objects, time.Now().UTC())
		if loadErr != nil {
			return materialsource.VerifiedColdStartMaterial{}, bootstrap.VerifiedStartupLink{}, bootstrapstart.VerifiedSourceFounder{}, loadErr
		}
		recipient, loadErr := bootstrap.VerifyLinkRecipient(state.ctx, regional, home, time.Now().UTC())
		if loadErr != nil {
			return materialsource.VerifiedColdStartMaterial{}, bootstrap.VerifiedStartupLink{}, bootstrapstart.VerifiedSourceFounder{}, loadErr
		}
		_, bundles, loadErr := vaultClients(state.factory)
		if loadErr != nil {
			return materialsource.VerifiedColdStartMaterial{}, bootstrap.VerifiedStartupLink{}, bootstrapstart.VerifiedSourceFounder{}, loadErr
		}
		link, loadErr := materialsource.ResolveRegionalLink(state.ctx, state.material, recipient, &state.objects, bundles, filepath.Join(sourceDirectory, "link"), time.Now().UTC())
		if loadErr != nil {
			return materialsource.VerifiedColdStartMaterial{}, bootstrap.VerifiedStartupLink{}, bootstrapstart.VerifiedSourceFounder{}, loadErr
		}
		proof = link.Proof()
	}
	if err != nil {
		return materialsource.VerifiedColdStartMaterial{}, bootstrap.VerifiedStartupLink{}, bootstrapstart.VerifiedSourceFounder{}, err
	}
	if err := state.guard(state.ctx); err != nil {
		return materialsource.VerifiedColdStartMaterial{}, bootstrap.VerifiedStartupLink{}, bootstrapstart.VerifiedSourceFounder{}, err
	}
	return state.material, proof, state.founder, nil
}

func (b *Backend) PrepareSeedLedger(ctx context.Context, call rootoci.Call, authority bootstrap.DerivedStartupAuthority) error {
	state, err := b.source(ctx, call)
	if err != nil {
		return err
	}
	_, err = state.source.PrepareSeedLedger(state.ctx, b.baked.Roots, b.anchor, authority, state.founder)
	if err != nil {
		return err
	}
	if _, err := state.source.InstallMaterial(state.ctx); err != nil {
		return err
	}
	return state.guard(state.ctx)
}
