package managedmaterial

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json/v2"
	"encoding/pem"
	"errors"
	"fmt"
	"strconv"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/authority"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/protocol"
)

// CredentialService commits a full registry generation in the same fenced R3
// log as the immutable initial material. No bearer secret enters that log.
type CredentialService struct {
	Preparation PreparationService
	Store       authority.ClientCredentialStore
}

func (service CredentialService) Current(ctx context.Context, database, partition string) (
	CredentialState, *CredentialReceipt, error,
) {
	initial, bundle, err := service.Preparation.CurrentBundle(ctx, database, partition)
	if err != nil {
		return CredentialState{}, nil, err
	}
	return service.current(ctx, initial, bundle)
}

func (service CredentialService) current(ctx context.Context, initial PreparationReceipt,
	bundle InitialBundle,
) (CredentialState, *CredentialReceipt, error) {
	if service.Store == nil {
		return CredentialState{}, nil, errors.New("credential store is unavailable")
	}
	initialState, err := InitialCredentialState(initial, bundle)
	if err != nil {
		return CredentialState{}, nil, err
	}
	entry, err := service.Store.ReadClientCredentials(ctx, initial.Spec.PlacementDatabaseID, initial.PartitionID)
	if errors.Is(err, authority.ErrNotFound) {
		return initialState, nil, nil
	}
	if err != nil {
		return CredentialState{}, nil, err
	}
	var receipt CredentialReceipt
	if entry.Kind != authority.MutationClientCredentials || entry.Sequence == 0 ||
		entry.SubjectKey != initial.Spec.PlacementDatabaseID+"."+initial.PartitionID ||
		protocol.DecodeStrict(entry.Payload, &receipt, 1<<20) != nil {
		return CredentialState{}, nil, ErrMaterialConflict
	}
	wire, err := protocol.EncodeJSON(receipt)
	if err != nil || !bytes.Equal(wire, entry.Payload) {
		return CredentialState{}, nil, ErrMaterialConflict
	}
	initialSHA, err := preparationReceiptDigest(initial)
	if err != nil || receipt.DatabaseID != initial.Spec.PlacementDatabaseID ||
		receipt.PartitionID != initial.PartitionID ||
		receipt.Verify(service.Preparation.ControllerKey.Public().(ed25519.PublicKey),
			initialSHA, bundle.Authority.TrustedKey) != nil {
		return CredentialState{}, nil, ErrMaterialConflict
	}
	if err := validateCredentialRegistry(initial.Spec, receipt.State.Registry); err != nil {
		return CredentialState{}, nil, err
	}
	return receipt.State, &receipt, nil
}

// Apply returns a signed pending receipt. Application is successful only after
// both native members report the committed credential generation.
func (service CredentialService) Apply(ctx context.Context, epoch uint64, request CredentialRequest,
	now time.Time,
) (CredentialReceipt, error) {
	if ctx == nil || epoch == 0 || service.Store == nil || service.Preparation.Fencer == nil ||
		len(service.Preparation.ControllerKey) != ed25519.PrivateKeySize ||
		!repositoryToken.MatchString(request.DatabaseID) ||
		!repositoryToken.MatchString(request.PartitionID) ||
		!repositoryToken.MatchString(request.OperationID) ||
		!lowerHexDigest(request.InitialReceiptSHA) || request.ExpectedGeneration == 0 {
		return CredentialReceipt{}, ErrMaterialConflict
	}
	if err := service.Preparation.Fencer.Guard(ctx, epoch); err != nil {
		return CredentialReceipt{}, err
	}
	initial, bundle, err := service.Preparation.CurrentBundle(ctx, request.DatabaseID, request.PartitionID)
	if err != nil {
		return CredentialReceipt{}, err
	}
	initialSHA, err := preparationReceiptDigest(initial)
	if err != nil || initialSHA != request.InitialReceiptSHA {
		return CredentialReceipt{}, ErrMaterialConflict
	}
	requestWire, err := protocol.EncodeJSON(request)
	if err != nil {
		return CredentialReceipt{}, err
	}
	requestSum := sha256.Sum256(requestWire)
	requestSHA := hex.EncodeToString(requestSum[:])
	previous, existing, err := service.current(ctx, initial, bundle)
	if err != nil {
		return CredentialReceipt{}, err
	}
	if existing != nil && existing.State.Generation == request.ExpectedGeneration+1 &&
		existing.RequestSHA256 == requestSHA {
		return *existing, nil
	}
	// An exact committed retry may recover its encrypted token after the
	// recipient grant expires. Freshness still gates every new mutation.
	if err := validateCredentialRequest(request, initial.Spec, service.Preparation.RecipientSigner, now); err != nil {
		return CredentialReceipt{}, err
	}
	if previous.Generation != request.ExpectedGeneration || previous.Generation == ^uint64(0) {
		return CredentialReceipt{}, authority.ErrConflict
	}
	registry, customer, err := applyCredentialChange(previous.Registry, request, initial.Spec, bundle, now)
	if err != nil {
		return CredentialReceipt{}, err
	}
	state, err := SignCredentialState(previous.Generation+1, initialSHA, registry,
		bundle.Retained.AuthoritySigner)
	if err != nil {
		return CredentialReceipt{}, err
	}
	previousSHA, err := CredentialStateDigest(previous)
	if err != nil {
		return CredentialReceipt{}, err
	}
	receipt := CredentialReceipt{Version: 1, DatabaseID: request.DatabaseID,
		PartitionID: request.PartitionID, RequestSHA256: requestSHA,
		PreviousSHA256: previousSHA, State: state, Customer: customer}
	if err := receipt.sign(service.Preparation.ControllerKey); err != nil {
		return CredentialReceipt{}, err
	}
	payload, err := protocol.EncodeJSON(receipt)
	if err != nil || len(payload) > 1<<20 {
		return CredentialReceipt{}, ErrMaterialConflict
	}
	var expectedSequence uint64
	if existing != nil {
		entry, err := service.Store.ReadClientCredentials(ctx, request.DatabaseID, request.PartitionID)
		if err != nil {
			return CredentialReceipt{}, err
		}
		expectedSequence = entry.Sequence
	}
	if err := service.Preparation.Fencer.Guard(ctx, epoch); err != nil {
		return CredentialReceipt{}, err
	}
	_, commitErr := service.Store.CommitClientCredentials(ctx, epoch, request.DatabaseID,
		request.PartitionID, request.OperationID, expectedSequence, payload)
	confirmedState, confirmed, readErr := service.current(ctx, initial, bundle)
	if readErr != nil {
		return CredentialReceipt{}, fmt.Errorf("%w: commit: %v; read: %v", ErrMaterialUnknown, commitErr, readErr)
	}
	if confirmed != nil && confirmedState.Generation == receipt.State.Generation &&
		confirmed.RequestSHA256 == requestSHA && confirmed.Signature == receipt.Signature {
		return *confirmed, nil
	}
	if commitErr != nil {
		return CredentialReceipt{}, commitErr
	}
	return CredentialReceipt{}, ErrMaterialConflict
}

func validateCredentialRequest(request CredentialRequest, spec InitialSpec,
	recipientSigner ed25519.PublicKey, now time.Time,
) error {
	if request.DatabaseID != spec.PlacementDatabaseID || request.PartitionID != spec.PartitionID {
		return ErrMaterialConflict
	}
	switch request.Action {
	case CredentialRotate:
		if request.KeyID != "" {
			return ErrMaterialConflict
		}
		grantSpec := spec
		grantSpec.Recipient = request.Recipient
		return validateInitialSpec(grantSpec, recipientSigner, now)
	case CredentialRevoke:
		identifier, err := base64.RawURLEncoding.DecodeString(request.KeyID)
		if err != nil || len(identifier) != 16 ||
			base64.RawURLEncoding.EncodeToString(identifier) != request.KeyID ||
			len(request.Recipient.PublicKey) != 0 || len(request.Recipient.Signature) != 0 ||
			!request.Recipient.ExpiresAt.IsZero() {
			return ErrMaterialConflict
		}
		return nil
	default:
		return ErrMaterialConflict
	}
}

func applyCredentialChange(current []byte, request CredentialRequest, spec InitialSpec,
	bundle InitialBundle, now time.Time,
) ([]byte, *CustomerEnvelope, error) {
	var registry apiKeyRegistry
	if err := json.Unmarshal(current, &registry, json.RejectUnknownMembers(true)); err != nil ||
		registry.Version != 1 || len(registry.Keys) == 0 || len(registry.Keys) > 128 {
		return nil, nil, ErrMaterialConflict
	}
	switch request.Action {
	case CredentialRevoke:
		found := false
		for index := range registry.Keys {
			if registry.Keys[index].ID == request.KeyID && !registry.Keys[index].Revoked {
				registry.Keys[index].Revoked = true
				found = true
			}
		}
		if !found {
			return nil, nil, ErrMaterialConflict
		}
	case CredentialRotate:
		if len(registry.Keys) == 128 {
			return nil, nil, ErrMaterialConflict
		}
		var identifier [16]byte
		var secret [32]byte
		if _, err := rand.Read(identifier[:]); err != nil {
			return nil, nil, err
		}
		if _, err := rand.Read(secret[:]); err != nil {
			return nil, nil, err
		}
		defer clear(secret[:])
		id := base64.RawURLEncoding.EncodeToString(identifier[:])
		for _, key := range registry.Keys {
			if key.ID == id {
				return nil, nil, ErrMaterialConflict
			}
		}
		verifier := sha256.New()
		verifier.Write([]byte("TB-APIKEY-V1\x00"))
		verifier.Write(identifier[:])
		verifier.Write(secret[:])
		verifierSHA := hex.EncodeToString(verifier.Sum(nil))
		registry.Keys = append(registry.Keys, apiKeyEntry{ID: id, VerifierSHA256: verifierSHA,
			Tenant: spec.Scope.TenantID, Database: spec.Scope.DatabaseID,
			Shard:       strconv.FormatUint(spec.Scope.ShardID, 10),
			Collections: initialCollectionIDs(spec.Catalogs), TableIDs: initialSQLTableIDs(spec.SQLTables),
			Permissions: []string{"read", "write"}})
		grantSpec := spec
		grantSpec.Recipient = request.Recipient
		chain := bundle.Members[0].Files["client-chain.pem"].Contents
		_, caPEM := pem.Decode(chain)
		if len(caPEM) == 0 {
			return nil, nil, ErrMaterialConflict
		}
		// The recipient sees the raw key only inside the encrypted envelope.
		token := "tbk1." + id + "." + base64.RawURLEncoding.EncodeToString(secret[:])
		customer, err := encryptCustomerToken(grantSpec, token, verifierSHA, caPEM)
		if err != nil {
			return nil, nil, err
		}
		wire, err := protocol.EncodeJSON(registry)
		return wire, &customer, err
	default:
		return nil, nil, ErrMaterialConflict
	}
	wire, err := protocol.EncodeJSON(registry)
	if err != nil || len(wire) > maxCredentialRegistryBytes {
		return nil, nil, ErrMaterialConflict
	}
	return wire, nil, nil
}

func validateCredentialRegistry(spec InitialSpec, wire []byte) error {
	var registry apiKeyRegistry
	if err := json.Unmarshal(wire, &registry, json.RejectUnknownMembers(true)); err != nil ||
		registry.Version != 1 || len(registry.Keys) == 0 || len(registry.Keys) > 128 {
		return ErrMaterialConflict
	}
	seen := make(map[string]bool, len(registry.Keys))
	for _, key := range registry.Keys {
		identifier, err := base64.RawURLEncoding.DecodeString(key.ID)
		if err != nil || len(identifier) != 16 || seen[key.ID] || !lowerHexDigest(key.VerifierSHA256) ||
			key.Tenant != spec.Scope.TenantID || key.Database != spec.Scope.DatabaseID ||
			key.Shard != strconv.FormatUint(spec.Scope.ShardID, 10) ||
			len(key.Permissions) != 2 || key.Permissions[0] != "read" || key.Permissions[1] != "write" ||
			!slicesEqual(key.Collections, initialCollectionIDs(spec.Catalogs)) ||
			!slicesEqual(key.TableIDs, initialSQLTableIDs(spec.SQLTables)) {
			return ErrMaterialConflict
		}
		seen[key.ID] = true
	}
	return nil
}

func slicesEqual(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}
