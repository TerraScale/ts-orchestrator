package managedmaterial

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"net/netip"
	"slices"

	"github.com/TerraScale/ts-orchestrator/internal/authority"
	"github.com/TerraScale/ts-orchestrator/internal/entityid"
	"github.com/TerraScale/ts-orchestrator/internal/placement"
	"github.com/TerraScale/ts-orchestrator/internal/protocol"
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
	if reader == nil || ctx == nil || ctx.Err() != nil || reader.service.Repository == nil || reader.service.Receipts == nil ||
		!entityid.Valid(database) || !entityid.Valid(partition) {
		return PreparationReceipt{}, errors.New("managed material reader is unavailable")
	}
	original, err := reader.service.Receipts.ReadMaterialReceipt(ctx, database, partition)
	if err != nil {
		return PreparationReceipt{}, err
	}
	receipt, bundle, err := reader.service.currentBundle(ctx, database, partition, reader.controllerKey)
	clearInitialBundle(&bundle)
	if err != nil {
		return PreparationReceipt{}, err
	}
	wire, err := protocol.EncodeJSON(receipt)
	if err != nil || !bytes.Equal(wire, original.Payload) {
		return PreparationReceipt{}, ErrMaterialConflict
	}
	current, err := reader.service.Receipts.ReadMaterialReceipt(ctx, database, partition)
	if err != nil || !sameCredentialFloorEntry(original, current) || ctx.Err() != nil {
		return PreparationReceipt{}, ErrMaterialConflict
	}
	return receipt, nil
}

func (reader *PreparationReader) Verify(ctx context.Context, intent placement.Intent) error {
	receipt, err := reader.Current(ctx, intent.DatabaseID, intent.PartitionID)
	if err != nil {
		return err
	}
	return VerifyIntentAgainstReceipt(intent, receipt)
}

func clearInitialBundle(bundle *InitialBundle) {
	clear(bundle.Retained.AuthoritySigner)
	clear(bundle.Retained.ReplicationCA)
	clear(bundle.Retained.HTTPSCA)
	for _, member := range bundle.Members {
		for _, file := range member.Files {
			clear(file.Contents)
		}
	}
	*bundle = InitialBundle{}
}
