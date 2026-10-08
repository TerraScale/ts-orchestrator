package managedmaterial

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json/v2"
	"errors"
	"strconv"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/entityid"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/protocol"
)

const credentialAuthorityDomain = "TS-CLIENT-CREDENTIALS-AUTHORITY-V1\x00"
const credentialReceiptDomain = "TS-CLIENT-CREDENTIALS-RECEIPT-V1\x00"
const maxCredentialRegistryBytes = 256 << 10

// CredentialState is the root-owned overlay consumed by TerraBase. The
// immutable initial registry and manifest remain the generation-one fallback.
// The signature uses a deliberately simple cross-language byte grammar.
type CredentialState struct {
	Version              uint64 `json:"version"`
	Generation           uint64 `json:"generation"`
	InitialReceiptSHA256 string `json:"initial_receipt_sha256"`
	RegistrySHA256       string `json:"registry_sha256"`
	Registry             []byte `json:"registry"`
	Signature            string `json:"signature"`
}

func (state CredentialState) signingMaterial() []byte {
	material := make([]byte, 0, len(credentialAuthorityDomain)+32+65+len(state.Registry))
	material = append(material, credentialAuthorityDomain...)
	material = strconv.AppendUint(material, state.Generation, 10)
	material = append(material, 0)
	material = append(material, state.InitialReceiptSHA256...)
	material = append(material, 0)
	return append(material, state.Registry...)
}

func SignCredentialState(generation uint64, initialReceiptSHA string, registry []byte,
	authorityKey ed25519.PrivateKey,
) (CredentialState, error) {
	if generation == 0 || !lowerHexDigest(initialReceiptSHA) || len(registry) == 0 ||
		len(registry) > maxCredentialRegistryBytes || len(authorityKey) != ed25519.PrivateKeySize {
		return CredentialState{}, ErrMaterialConflict
	}
	sum := sha256.Sum256(registry)
	state := CredentialState{Version: 1, Generation: generation, InitialReceiptSHA256: initialReceiptSHA,
		RegistrySHA256: hex.EncodeToString(sum[:]), Registry: bytes.Clone(registry)}
	state.Signature = base64.RawURLEncoding.EncodeToString(ed25519.Sign(authorityKey, state.signingMaterial()))
	return state, nil
}

func VerifyCredentialState(state CredentialState, initialReceiptSHA string, authorityKey ed25519.PublicKey) error {
	if state.Version != 1 || state.Generation == 0 || state.InitialReceiptSHA256 != initialReceiptSHA ||
		!lowerHexDigest(state.RegistrySHA256) || len(state.Registry) == 0 ||
		len(state.Registry) > maxCredentialRegistryBytes || len(authorityKey) != ed25519.PublicKeySize {
		return ErrMaterialConflict
	}
	sum := sha256.Sum256(state.Registry)
	signature, err := base64.RawURLEncoding.DecodeString(state.Signature)
	if err != nil || len(signature) != ed25519.SignatureSize ||
		hex.EncodeToString(sum[:]) != state.RegistrySHA256 ||
		!ed25519.Verify(authorityKey, state.signingMaterial(), signature) {
		return ErrMaterialConflict
	}
	var registry apiKeyRegistry
	if err := json.Unmarshal(state.Registry, &registry, json.RejectUnknownMembers(true)); err != nil ||
		registry.Version != 1 || len(registry.Keys) == 0 || len(registry.Keys) > 128 {
		return ErrMaterialConflict
	}
	for _, key := range registry.Keys {
		if !validSQLTableGrantIDs(key.TableIDs) {
			return ErrMaterialConflict
		}
	}
	canonical, err := protocol.EncodeJSON(registry)
	if err != nil || !bytes.Equal(canonical, state.Registry) || bytes.Contains(state.Registry, []byte("tbk1.")) {
		return ErrMaterialConflict
	}
	return nil
}

func validSQLTableGrantIDs(ids []string) bool {
	if len(ids) > sqlSchemaBundleMaxRows {
		return false
	}
	var previous []byte
	for _, id := range ids {
		decoded, err := entityid.Parse(id)
		if err != nil || len(decoded) != 16 || !entityid.Valid(id) ||
			previous != nil && bytes.Compare(previous, decoded[:]) >= 0 {
			return false
		}
		previous = decoded[:]
	}
	return true
}

func CredentialStateDigest(state CredentialState) (string, error) {
	wire, err := protocol.EncodeJSON(state)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(wire)
	return hex.EncodeToString(sum[:]), nil
}

func InitialCredentialState(receipt PreparationReceipt, bundle InitialBundle) (CredentialState, error) {
	initialSHA, err := preparationReceiptDigest(receipt)
	if err != nil {
		return CredentialState{}, err
	}
	left := bundle.Members[0].Files["client-api-keys.json"].Contents
	right := bundle.Members[1].Files["client-api-keys.json"].Contents
	if !bytes.Equal(left, right) || verifyStoredRegistry(receipt.Spec, bundle.Members[0], bundle.Customer) != nil {
		return CredentialState{}, ErrMaterialConflict
	}
	return SignCredentialState(1, initialSHA, left, bundle.Retained.AuthoritySigner)
}

func preparationReceiptDigest(receipt PreparationReceipt) (string, error) {
	wire, err := protocol.EncodeJSON(receipt)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(wire)
	return hex.EncodeToString(sum[:]), nil
}

type CredentialAction string

const (
	CredentialRotate CredentialAction = "rotate"
	CredentialRevoke CredentialAction = "revoke"
)

// CredentialRequest is the payload inside an operator-signed NATS envelope.
// ExpectedGeneration and operation ID make retries and contention explicit.
type CredentialRequest struct {
	DatabaseID         string           `json:"database_id"`
	PartitionID        string           `json:"partition_id"`
	InitialReceiptSHA  string           `json:"initial_receipt_sha256"`
	ExpectedGeneration uint64           `json:"expected_generation"`
	OperationID        string           `json:"operation_id"`
	Action             CredentialAction `json:"action"`
	KeyID              string           `json:"key_id,omitempty"`
	Recipient          RecipientGrant   `json:"recipient,omitzero"`
}

type CredentialReceipt struct {
	Version         uint64            `json:"version"`
	DatabaseID      string            `json:"database_id"`
	PartitionID     string            `json:"partition_id"`
	RequestSHA256   string            `json:"request_sha256"`
	PreviousSHA256  string            `json:"previous_sha256"`
	State           CredentialState   `json:"state"`
	Customer        *CustomerEnvelope `json:"customer,omitempty"`
	ControllerKeyID string            `json:"controller_key_id"`
	Signature       string            `json:"signature"`
}

// CredentialReply keeps a signed initial receipt and its authority key beside
// the new receipt so an offline operator can authenticate the customer token.
type CredentialReply struct {
	Initial      PreparationReceipt `json:"initial"`
	AuthorityKey []byte             `json:"authority_key"`
	Receipt      CredentialReceipt  `json:"receipt"`
}

func VerifyCredentialReply(reply CredentialReply, request CredentialRequest,
	controllerKey ed25519.PublicKey, cell string,
) error {
	if reply.Initial.Spec.PlacementDatabaseID != request.DatabaseID ||
		reply.Initial.PartitionID != request.PartitionID ||
		verifyPreparationSignature(reply.Initial, controllerKey, cell, request.PartitionID) != nil {
		return ErrMaterialConflict
	}
	initialSHA, err := preparationReceiptDigest(reply.Initial)
	if err != nil || initialSHA != request.InitialReceiptSHA ||
		len(reply.AuthorityKey) != ed25519.PublicKeySize {
		return ErrMaterialConflict
	}
	keySHA := sha256.Sum256(reply.AuthorityKey)
	if hex.EncodeToString(keySHA[:]) != reply.Initial.TrustedKeySHA256 ||
		reply.Receipt.DatabaseID != request.DatabaseID ||
		reply.Receipt.PartitionID != request.PartitionID ||
		reply.Receipt.State.Generation != request.ExpectedGeneration+1 ||
		reply.Receipt.Verify(controllerKey, initialSHA, reply.AuthorityKey) != nil {
		return ErrMaterialConflict
	}
	wire, err := protocol.EncodeJSON(request)
	if err != nil {
		return err
	}
	requestSHA := sha256.Sum256(wire)
	if hex.EncodeToString(requestSHA[:]) != reply.Receipt.RequestSHA256 ||
		request.Action == CredentialRotate && reply.Receipt.Customer == nil ||
		request.Action == CredentialRevoke && reply.Receipt.Customer != nil {
		return ErrMaterialConflict
	}
	return nil
}

func (receipt CredentialReceipt) signingMaterial() ([]byte, error) {
	receipt.Signature = ""
	wire, err := protocol.EncodeJSON(receipt)
	if err != nil {
		return nil, err
	}
	return append([]byte(credentialReceiptDomain), wire...), nil
}

func (receipt CredentialReceipt) Verify(controllerKey ed25519.PublicKey,
	initialSHA string, authorityKey ed25519.PublicKey,
) error {
	if receipt.Version != 1 || !entityid.Valid(receipt.DatabaseID) ||
		!entityid.Valid(receipt.PartitionID) || !lowerHexDigest(receipt.RequestSHA256) ||
		!lowerHexDigest(receipt.PreviousSHA256) || receipt.State.Generation < 2 ||
		len(controllerKey) != ed25519.PublicKeySize ||
		VerifyCredentialState(receipt.State, initialSHA, authorityKey) != nil {
		return ErrMaterialConflict
	}
	keyID, err := protocol.KeyID(controllerKey)
	if err != nil || keyID != receipt.ControllerKeyID {
		return ErrMaterialConflict
	}
	signature, err := base64.RawURLEncoding.DecodeString(receipt.Signature)
	material, materialErr := receipt.signingMaterial()
	if err != nil || materialErr != nil || len(signature) != ed25519.SignatureSize ||
		!ed25519.Verify(controllerKey, material, signature) {
		return ErrMaterialConflict
	}
	if receipt.Customer != nil {
		var registry apiKeyRegistry
		if err := json.Unmarshal(receipt.State.Registry, &registry, json.RejectUnknownMembers(true)); err != nil ||
			!validCredentialCustomer(*receipt.Customer, registry) {
			return ErrMaterialConflict
		}
	}
	return nil
}

func validCredentialCustomer(customer CustomerEnvelope, registry apiKeyRegistry) bool {
	if customer.Version != 2 || !lowerHexDigest(customer.VerifierSHA256) ||
		!lowerHexDigest(customer.HTTPSCASHA256) ||
		!entityid.Valid(customer.TokenID) ||
		!canonicalCredentialEncoding(customer.EphemeralPublicKey, 32) ||
		!canonicalCredentialEncoding(customer.Nonce, 12) ||
		!canonicalCredentialCiphertext(customer.Ciphertext) {
		return false
	}
	for _, key := range registry.Keys {
		if key.ID == customer.TokenID && key.VerifierSHA256 == customer.VerifierSHA256 && !key.Revoked {
			return true
		}
	}
	return false
}

func canonicalCredentialEncoding(value string, size int) bool {
	decoded, err := base64.RawURLEncoding.DecodeString(value)
	return err == nil && len(decoded) == size && base64.RawURLEncoding.EncodeToString(decoded) == value
}

func canonicalCredentialCiphertext(value string) bool {
	decoded, err := base64.RawURLEncoding.DecodeString(value)
	return err == nil && len(decoded) >= 16 && len(decoded) <= maxCustomerPlaintextBytes+16 &&
		base64.RawURLEncoding.EncodeToString(decoded) == value
}

func (receipt *CredentialReceipt) sign(controllerKey ed25519.PrivateKey) error {
	if receipt == nil || len(controllerKey) != ed25519.PrivateKeySize {
		return errors.New("credential receipt signer is invalid")
	}
	keyID, err := protocol.KeyID(controllerKey.Public().(ed25519.PublicKey))
	if err != nil {
		return err
	}
	receipt.ControllerKeyID = keyID
	material, err := receipt.signingMaterial()
	if err != nil {
		return err
	}
	receipt.Signature = base64.RawURLEncoding.EncodeToString(ed25519.Sign(controllerKey, material))
	return nil
}
