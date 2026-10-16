package managedmaterial

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json/v2"
	"errors"
	"fmt"
	"net/netip"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/entityid"

	"github.com/TerraScale/ts-orchestrator/internal/authority"
	"github.com/TerraScale/ts-orchestrator/internal/protocol"
)

// PreparationService owns the only transition from a create-only KMS object
// to an R3-committed, controller-signed initial material receipt. The caller
// must first authenticate an operator-signed preparation request, including
// the explicit member IPs in spec, against its regional operator grant.
type PreparationService struct {
	Cell                 string
	Repository           *Repository
	Receipts             authority.MaterialReceiptStore
	Fencer               authority.Fencer
	ControllerKey        ed25519.PrivateKey
	RecipientSigner      ed25519.PublicKey
	AllowedSubnetCIDR    string
	NativeValidator      NativeMaterialValidator
	NativeVerifierSHA256 string
}

// PrepareInitial is idempotent for one exact spec. A crash after OCI Put and
// before R3 CAS leaves an orphan object; a retry validates and reuses its exact
// bytes but that object has no authority until the CAS receipt is observed.
func (service PreparationService) PrepareInitial(ctx context.Context, epoch uint64,
	partition string, spec InitialSpec, now time.Time,
) (PreparationReceipt, error) {
	if ctx == nil || service.Repository == nil || service.Receipts == nil || service.Fencer == nil ||
		len(service.ControllerKey) != ed25519.PrivateKeySize || !entityid.Valid(partition) ||
		service.Cell != service.Repository.config.Cell || epoch == 0 || spec.PartitionID != partition {
		return PreparationReceipt{}, errors.New("managed material preparation service is incomplete")
	}
	if err := validateInitialSpec(spec, service.RecipientSigner, now); err != nil {
		return PreparationReceipt{}, err
	}
	if err := service.validateLiveS3Region(spec); err != nil {
		return PreparationReceipt{}, err
	}
	if err := service.validateSubnet(spec); err != nil {
		return PreparationReceipt{}, err
	}
	if err := service.Fencer.Guard(ctx, epoch); err != nil {
		return PreparationReceipt{}, err
	}
	if existing, err := service.current(ctx, partition, spec); err == nil {
		return existing, nil
	} else if !errors.Is(err, authority.ErrNotFound) {
		return PreparationReceipt{}, err
	}
	controllerPublic := service.ControllerKey.Public().(ed25519.PublicKey)
	bundle, object, err := service.Repository.LookupInitial(ctx, partition, spec, controllerPublic)
	if errors.Is(err, ErrMaterialNotFound) {
		bundle, err = GenerateInitial(spec, service.RecipientSigner, now)
		if err != nil {
			return PreparationReceipt{}, err
		}
		if err := service.validateNativeInitial(ctx, spec, bundle); err != nil {
			return PreparationReceipt{}, err
		}
		object, err = service.Repository.CreateInitial(ctx, epoch, partition, spec, bundle, service.ControllerKey)
	} else if err == nil {
		if err := service.validateNativeInitial(ctx, spec, bundle); err != nil {
			return PreparationReceipt{}, err
		}
	}
	if err != nil {
		return PreparationReceipt{}, err
	}
	if err := validateInitialSpec(spec, service.RecipientSigner, time.Now().UTC()); err != nil {
		return PreparationReceipt{}, err
	}
	receipt, err := SignPreparationReceipt(service.Cell, partition, spec, bundle, object, service.ControllerKey, now)
	if err != nil {
		return PreparationReceipt{}, err
	}
	payload, err := protocol.EncodeJSON(receipt)
	if err != nil {
		return PreparationReceipt{}, err
	}
	if err := service.Fencer.Guard(ctx, epoch); err != nil {
		return PreparationReceipt{}, err
	}
	operationID := entityid.Derive("material-preparation", object.SpecSHA256)
	_, commitErr := service.Receipts.CommitMaterialReceipt(ctx, epoch, spec.PlacementDatabaseID,
		partition, operationID, 0, payload)
	if commitErr != nil && !errors.Is(commitErr, authority.ErrConflict) &&
		!errors.Is(commitErr, authority.ErrOutcomeUnknown) {
		return PreparationReceipt{}, commitErr
	}
	confirmed, err := service.current(ctx, partition, spec)
	if err != nil {
		return PreparationReceipt{}, fmt.Errorf("%w: receipt commit: %v; read: %v", ErrMaterialUnknown, commitErr, err)
	}
	if commitErr == nil && confirmed.Signature != receipt.Signature {
		return PreparationReceipt{}, ErrMaterialConflict
	}
	return confirmed, nil
}

// Current returns the R3-committed receipt only after re-reading its exact OCI
// version and authenticating the controller signature and material pins.
func (service PreparationService) Current(ctx context.Context, database, partition string) (PreparationReceipt, error) {
	receipt, _, err := service.CurrentBundle(ctx, database, partition)
	return receipt, err
}

// CurrentBundle returns the authenticated exact OCI bytes with the receipt so
// confidential delivery can use one pinned object read per host request.
func (service PreparationService) CurrentBundle(ctx context.Context, database, partition string) (PreparationReceipt, InitialBundle, error) {
	if ctx == nil || service.Repository == nil || service.Receipts == nil ||
		len(service.ControllerKey) != ed25519.PrivateKeySize ||
		!entityid.Valid(database) || !entityid.Valid(partition) ||
		service.Cell != service.Repository.config.Cell {
		return PreparationReceipt{}, InitialBundle{}, errors.New("managed material receipt reader is incomplete")
	}
	entry, err := service.Receipts.ReadMaterialReceipt(ctx, database, partition)
	if err != nil {
		return PreparationReceipt{}, InitialBundle{}, err
	}
	var receipt PreparationReceipt
	if err := json.Unmarshal(entry.Payload, &receipt, json.RejectUnknownMembers(true)); err != nil ||
		receipt.Spec.PlacementDatabaseID != database || receipt.Spec.PartitionID != partition {
		return PreparationReceipt{}, InitialBundle{}, ErrMaterialConflict
	}
	return service.verifyCurrent(ctx, entry, partition, receipt.Spec)
}

func (service PreparationService) validateSubnet(spec InitialSpec) error {
	subnet, err := netip.ParsePrefix(service.AllowedSubnetCIDR)
	if err != nil || !subnet.Addr().Is4() || !subnet.Addr().IsPrivate() || subnet.Masked() != subnet {
		return errors.New("managed material allowed subnet is invalid")
	}
	for _, member := range spec.Members {
		ip, err := netip.ParseAddr(member.ReplicationIP)
		if err != nil || !subnet.Contains(ip) || member.ClientIP != member.ReplicationIP {
			return errors.New("managed member private IP is outside the accepted subnet")
		}
	}
	return nil
}

func (service PreparationService) validateLiveS3Region(spec InitialSpec) error {
	region, err := service.Repository.config.Region.OCIRegion()
	if err != nil || spec.LiveS3.Region != region {
		return errors.New("live S3 region differs from managed material cell")
	}
	return nil
}

func (service PreparationService) current(ctx context.Context, partition string, spec InitialSpec) (PreparationReceipt, error) {
	entry, err := service.Receipts.ReadMaterialReceipt(ctx, spec.PlacementDatabaseID, partition)
	if err != nil {
		return PreparationReceipt{}, err
	}
	receipt, _, err := service.verifyCurrent(ctx, entry, partition, spec)
	return receipt, err
}

func (service PreparationService) verifyCurrent(ctx context.Context, entry authority.LogEntry,
	partition string, spec InitialSpec,
) (PreparationReceipt, InitialBundle, error) {
	if err := service.validateLiveS3Region(spec); err != nil {
		return PreparationReceipt{}, InitialBundle{}, err
	}
	if err := service.validateSubnet(spec); err != nil {
		return PreparationReceipt{}, InitialBundle{}, err
	}
	if entry.Kind != authority.MutationMaterialReceipt || entry.Sequence == 0 || entry.SubjectKey != spec.PlacementDatabaseID+"."+partition {
		return PreparationReceipt{}, InitialBundle{}, ErrMaterialConflict
	}
	var receipt PreparationReceipt
	if err := json.Unmarshal(entry.Payload, &receipt, json.RejectUnknownMembers(true)); err != nil {
		return PreparationReceipt{}, InitialBundle{}, ErrMaterialConflict
	}
	wire, err := protocol.EncodeJSON(receipt)
	if err != nil || !bytes.Equal(wire, entry.Payload) {
		return PreparationReceipt{}, InitialBundle{}, ErrMaterialConflict
	}
	specSHA, err := specDigest(spec)
	if err != nil || receipt.SpecSHA256 != specSHA {
		return PreparationReceipt{}, InitialBundle{}, ErrMaterialConflict
	}
	bundle, err := service.Repository.ReadPinned(ctx, receipt.Object, service.ControllerKey.Public().(ed25519.PublicKey))
	if err != nil {
		return PreparationReceipt{}, InitialBundle{}, err
	}
	if err := VerifyPreparationReceipt(receipt, service.ControllerKey.Public().(ed25519.PublicKey),
		service.Cell, partition, bundle); err != nil {
		return PreparationReceipt{}, InitialBundle{}, err
	}
	return receipt, bundle, nil
}
