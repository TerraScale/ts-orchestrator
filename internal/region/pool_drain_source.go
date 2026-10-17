package region

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/cellspec"
	"github.com/TerraScale/ts-orchestrator/internal/drainwire"
	"github.com/TerraScale/ts-orchestrator/internal/trust"
)

// VerifyCurrentPoolDrainSource independently loads the signed SDK source and
// original writer. Captured NATS wire proves capture authority; the retained
// protected drain fence, rather than a claim of remote NATS currentness,
// prevents every later execution acquisition on this exact instance.
func (r FoundationResolver) VerifyCurrentPoolDrainSource(ctx context.Context, receipt drainwire.PoolReceipt) error {
	reader, ok := r.Footprint.(*SignedFootprint)
	if !ok || reader == nil || reader.factory == nil || ctx == nil || ctx.Err() != nil || receipt.Validate() != nil ||
		!time.Now().Before(receipt.ExpiresAt) {
		return errors.New("pool drain source requires genuine current signed SDK authority")
	}
	if _, err := r.ProtectedCapacityStore(reader.factory); err != nil {
		return err
	}
	current, err := r.Resolve(ctx, receipt.Child.Cell)
	if err != nil {
		return err
	}
	if current.Generation != receipt.Child.Generation || current.GrantSHA256 != receipt.Child.GrantSHA256 ||
		current.FoundationWriter == nil || current.FoundationWriter.InstanceID != receipt.Source.ManagerInstanceID {
		return errors.New("pool drain capture differs from current signed cell or original protected writer")
	}
	source, err := reader.workerSource(ctx, receipt.Child.Cell)
	if err != nil {
		return err
	}
	manifest := source.Manifest()
	if manifest.ControllerConfigSHA256 != receipt.Source.ControllerConfigSHA256 || manifest.DeploymentID != receipt.Source.DeploymentID ||
		!strings.EqualFold(string(manifest.Cell), receipt.Child.Cell) || !time.Now().Before(source.ExpiresAt()) {
		return errors.New("pool drain capture differs from independently loaded original regional source")
	}
	genesis, err := trust.DiscoveryGenesis()
	if err != nil {
		return err
	}
	chain, err := trust.DecodeRootChain(receipt.RootChainWire)
	if err != nil {
		return err
	}
	identity := trust.ChainIdentity{DeploymentID: manifest.DeploymentID, Cell: strings.ToLower(receipt.Child.Cell), Environment: manifest.Environment}
	roots, err := trust.VerifyRootChain(genesis, identity, chain)
	if err != nil {
		return err
	}
	spec, err := cellspec.VerifyCurrent(receipt.CellSpecWire, roots.Current, cellspec.Identity(identity), receipt.CapturedAt)
	if err != nil || !spec.RootSigned || spec.Generation != receipt.Source.CellSpecGeneration {
		return errors.Join(errors.New("pool drain lacks independently verified exact root-signed capture spec"), err)
	}
	return source.VerifyCurrent(ctx, time.Now().UTC())
}
