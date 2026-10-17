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

// PoolDrainSourcePin retains the identity independently verified from the
// original current signed SDK source when HOME consumes a stopped drain.
// It grants no new provider effect or extension of that source's lifetime.
type PoolDrainSourcePin struct {
	ReceiptSHA256 string              `json:"receiptSha256"`
	Identity      trust.ChainIdentity `json:"identity"`
	VerifiedAt    time.Time           `json:"verifiedAt"`
}

func (pin PoolDrainSourcePin) validateReceipt(receipt drainwire.PoolReceipt) error {
	digest, err := receipt.SHA256()
	if err != nil || receipt.Validate() != nil || receipt.Phase != drainwire.PoolStopped || pin.ReceiptSHA256 != digest ||
		pin.Identity.DeploymentID != receipt.Source.DeploymentID || pin.Identity.Cell != strings.ToLower(receipt.Child.Cell) ||
		pin.Identity.Environment == "" || pin.VerifiedAt.Before(receipt.StoppedAt) || !pin.VerifiedAt.Before(receipt.ExpiresAt) {
		return errors.Join(err, errors.New("historical drain source pin differs from its exact original stopped receipt"))
	}
	return nil
}

// PinPoolDrainSource uses actual signed SDK discovery, never caller identity.
func (r FoundationResolver) PinPoolDrainSource(ctx context.Context, receipt drainwire.PoolReceipt) (PoolDrainSourcePin, error) {
	if err := r.VerifyCurrentPoolDrainSource(ctx, receipt); err != nil {
		return PoolDrainSourcePin{}, err
	}
	reader := r.Footprint.(*SignedFootprint)
	source, err := reader.workerSource(ctx, receipt.Child.Cell)
	if err != nil {
		return PoolDrainSourcePin{}, err
	}
	manifest := source.Manifest()
	if manifest.ControllerConfigSHA256 != receipt.Source.ControllerConfigSHA256 || manifest.DeploymentID != receipt.Source.DeploymentID ||
		!strings.EqualFold(string(manifest.Cell), receipt.Child.Cell) {
		return PoolDrainSourcePin{}, errors.New("signed SDK source changed before retaining original drain identity")
	}
	if err := source.VerifyCurrent(ctx, time.Now().UTC()); err != nil {
		return PoolDrainSourcePin{}, err
	}
	digest, err := receipt.SHA256()
	if err != nil {
		return PoolDrainSourcePin{}, err
	}
	pin := PoolDrainSourcePin{ReceiptSHA256: digest, VerifiedAt: time.Now().UTC(),
		Identity: trust.ChainIdentity{DeploymentID: manifest.DeploymentID, Cell: strings.ToLower(receipt.Child.Cell), Environment: manifest.Environment}}
	if err := r.VerifyHistoricalPoolDrainSource(ctx, receipt, pin); err != nil {
		return PoolDrainSourcePin{}, err
	}
	return pin, nil
}

// VerifyHistoricalPoolDrainSource verifies replay evidence at the authentic
// stopped time. The caller separately loads current journal/lifecycle authority;
// this method never treats the old source or drain as current write permission.
func (r FoundationResolver) VerifyHistoricalPoolDrainSource(ctx context.Context, receipt drainwire.PoolReceipt, pin PoolDrainSourcePin) error {
	reader, ok := r.Footprint.(*SignedFootprint)
	if ctx == nil || ctx.Err() != nil || !ok || reader == nil || reader.factory == nil {
		return errors.New("historical drain replay requires actual signed SDK resolver and original context")
	}
	if _, err := r.ProtectedCapacityStore(reader.factory); err != nil {
		return err
	}
	if err := pin.validateReceipt(receipt); err != nil {
		return err
	}
	genesis, err := trust.DiscoveryGenesis()
	if err != nil {
		return err
	}
	chain, err := trust.DecodeRootChain(receipt.RootChainWire)
	if err != nil {
		return err
	}
	roots, err := trust.VerifyRootChain(genesis, pin.Identity, chain)
	if err != nil {
		return err
	}
	spec, err := cellspec.VerifyCurrent(receipt.CellSpecWire, roots.Current, cellspec.Identity(pin.Identity), receipt.StoppedAt)
	if err != nil || !spec.RootSigned || spec.Generation != receipt.Source.CellSpecGeneration {
		return errors.Join(err, errors.New("historical drain lost its exact original root-signed stopped-time spec"))
	}
	return ctx.Err()
}
