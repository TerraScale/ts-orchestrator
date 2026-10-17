package managedmaterial

import (
	"context"
	"crypto/ed25519"
	"errors"
	"net/netip"
	"slices"

	"github.com/TerraScale/ts-orchestrator/internal/authority"
	"github.com/TerraScale/ts-orchestrator/internal/placement"
)

// PreparationReader authenticates current R3 receipts and their exact immutable
// OCI versions with public verification material. It cannot prepare a bundle.
type PreparationReader struct {
	service       PreparationService
	controllerKey ed25519.PublicKey
}

func NewPreparationReader(config RepositoryConfig, client ObjectClient, receipts authority.MaterialReceiptStore, controllerKey ed25519.PublicKey, subnetCIDR string) (*PreparationReader, error) {
	if err := config.Validate(); err != nil {
		return nil, err
	}
	subnet, err := netip.ParsePrefix(subnetCIDR)
	if client == nil || receipts == nil || len(controllerKey) != ed25519.PublicKeySize || err != nil ||
		!subnet.Addr().Is4() || !subnet.Addr().IsPrivate() || subnet.Masked() != subnet {
		return nil, errors.New("managed material reader requires public trust, admitted receipts and accepted scope")
	}
	return &PreparationReader{service: PreparationService{Cell: config.Cell,
		Repository: &Repository{config: config, client: client}, Receipts: receipts, AllowedSubnetCIDR: subnetCIDR},
		controllerKey: slices.Clone(controllerKey)}, nil
}

func (reader *PreparationReader) Current(ctx context.Context, database, partition string) (PreparationReceipt, error) {
	if reader == nil {
		return PreparationReceipt{}, errors.New("managed material reader is unavailable")
	}
	receipt, _, err := reader.service.currentBundle(ctx, database, partition, reader.controllerKey)
	return receipt, err
}

func (reader *PreparationReader) Verify(ctx context.Context, intent placement.Intent) error {
	receipt, err := reader.Current(ctx, intent.DatabaseID, intent.PartitionID)
	if err != nil {
		return err
	}
	return VerifyIntentAgainstReceipt(intent, receipt)
}
