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
	"github.com/TerraScale/ts-orchestrator/internal/ociclient"
	"github.com/TerraScale/ts-orchestrator/internal/protocol"
)

// CredentialFloorReader authenticates existing material without mutation keys.
type CredentialFloorReader struct {
	repository *Repository
	mutations  *authority.Reader
	controller ed25519.PublicKey
	subnet     netip.Prefix
}

// NewCredentialFloorReader requires independently signed repository, subnet and
// controller pins. Its private repository exposes no preparation or write API.
func NewCredentialFloorReader(config RepositoryConfig, client ObjectClient, mutations *authority.Reader,
	controller ed25519.PublicKey, subnetCIDR string,
) (*CredentialFloorReader, error) {
	if err := config.Validate(); err != nil {
		return nil, err
	}
	subnet, err := netip.ParsePrefix(subnetCIDR)
	if err != nil || !subnet.Addr().Is4() || !subnet.Addr().IsPrivate() || subnet.Masked() != subnet ||
		client == nil || mutations == nil || len(controller) != ed25519.PublicKeySize {
		return nil, ErrMaterialConflict
	}
	return &CredentialFloorReader{repository: &Repository{config: config, client: client}, mutations: mutations,
		controller: slices.Clone(controller), subnet: subnet}, nil
}

// Current returns only the verified generation of one actual placement scope.
// The caller must retain its original source/session deadline through SDK reads.
func (reader *CredentialFloorReader) Current(ctx context.Context, database, partition string) (uint64, error) {
	if reader == nil || reader.repository == nil || reader.mutations == nil || ctx == nil || ctx.Err() != nil ||
		!entityid.Valid(database) || !entityid.Valid(partition) {
		return 0, ErrMaterialConflict
	}
	if _, ok := ctx.Deadline(); !ok {
		return 0, ErrMaterialConflict
	}
	initialEntry, err := reader.mutations.ReadMaterialReceipt(ctx, database, partition)
	if err != nil {
		return 0, err
	}
	var initial PreparationReceipt
	if initialEntry.Kind != authority.MutationMaterialReceipt || initialEntry.Sequence == 0 ||
		initialEntry.SubjectKey != database+"."+partition || protocol.DecodeStrict(initialEntry.Payload, &initial, 1<<20) != nil ||
		initial.Spec.PlacementDatabaseID != database || initial.Spec.PartitionID != partition {
		return 0, ErrMaterialConflict
	}
	wire, err := protocol.EncodeJSON(initial)
	if err != nil || !bytes.Equal(wire, initialEntry.Payload) {
		return 0, ErrMaterialConflict
	}
	if verifyPreparationSignature(initial, reader.controller, reader.repository.config.Cell, partition) != nil {
		return 0, ErrMaterialConflict
	}
	region, err := reader.repository.config.Region.OCIRegion()
	if err != nil || initial.Spec.LiveS3.Region != region {
		return 0, ErrMaterialConflict
	}
	for _, member := range initial.Spec.Members {
		ip, err := netip.ParseAddr(member.ReplicationIP)
		if err != nil || !reader.subnet.Contains(ip) || member.ClientIP != member.ReplicationIP {
			return 0, ErrMaterialConflict
		}
	}
	overlay, overlayErr := reader.mutations.ReadClientCredentials(ctx, database, partition)
	if overlayErr != nil && !errors.Is(overlayErr, authority.ErrNotFound) {
		return 0, overlayErr
	}
	bundle, err := reader.repository.ReadPinned(ociclient.RequestContext(ctx), initial.Object, reader.controller)
	if err != nil {
		return 0, err
	}
	defer func() {
		clear(bundle.Retained.AuthoritySigner)
		clear(bundle.Retained.ReplicationCA)
		clear(bundle.Retained.HTTPSCA)
		for _, member := range bundle.Members {
			for _, file := range member.Files {
				clear(file.Contents)
			}
		}
	}()
	if VerifyPreparationReceipt(initial, reader.controller, reader.repository.config.Cell, partition, bundle) != nil {
		return 0, ErrMaterialConflict
	}
	generation := uint64(1)
	if overlayErr == nil {
		generation, err = reader.verifyOverlay(initial, bundle, overlay)
		if err != nil {
			return 0, err
		}
	}
	confirmed, err := reader.mutations.ReadMaterialReceipt(ctx, database, partition)
	if err != nil || !sameCredentialFloorEntry(initialEntry, confirmed) {
		return 0, ErrMaterialConflict
	}
	confirmedOverlay, err := reader.mutations.ReadClientCredentials(ctx, database, partition)
	if overlayErr == nil && (err != nil || !sameCredentialFloorEntry(overlay, confirmedOverlay)) ||
		errors.Is(overlayErr, authority.ErrNotFound) && !errors.Is(err, authority.ErrNotFound) || ctx.Err() != nil {
		return 0, ErrMaterialConflict
	}
	return generation, nil
}

func (reader *CredentialFloorReader) verifyOverlay(initial PreparationReceipt, bundle InitialBundle, entry authority.LogEntry) (uint64, error) {
	var receipt CredentialReceipt
	if entry.Kind != authority.MutationClientCredentials || entry.Sequence == 0 ||
		entry.SubjectKey != initial.Spec.PlacementDatabaseID+"."+initial.PartitionID ||
		protocol.DecodeStrict(entry.Payload, &receipt, 1<<20) != nil {
		return 0, ErrMaterialConflict
	}
	wire, err := protocol.EncodeJSON(receipt)
	if err != nil || !bytes.Equal(wire, entry.Payload) {
		return 0, ErrMaterialConflict
	}
	initialSHA, err := preparationReceiptDigest(initial)
	if err != nil || receipt.DatabaseID != initial.Spec.PlacementDatabaseID || receipt.PartitionID != initial.PartitionID ||
		receipt.Verify(reader.controller, initialSHA, bundle.Authority.TrustedKey) != nil ||
		validateCredentialRegistry(initial.Spec, receipt.State.Registry) != nil {
		return 0, ErrMaterialConflict
	}
	return receipt.State.Generation, nil
}

func sameCredentialFloorEntry(original, current authority.LogEntry) bool {
	return original.Kind == current.Kind && original.SubjectKey == current.SubjectKey && original.OperationID == current.OperationID &&
		original.Epoch == current.Epoch && original.Sequence == current.Sequence && original.CreatedAt.Equal(current.CreatedAt) && bytes.Equal(original.Payload, current.Payload)
}
