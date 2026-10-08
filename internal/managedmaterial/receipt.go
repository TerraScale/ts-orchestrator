package managedmaterial

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/entityid"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/protocol"
)

const preparationReceiptDomain = "TS-MANAGED-MATERIAL-PREPARATION-V2\x00"

// MemberPins are all files the host may install for one initial attempt.
// The signed receipt carries hashes only; the encrypted host channel carries
// the exact bytes after current desired and OCI identity are checked.
type MemberPins struct {
	MemberID      string            `json:"member_id"`
	TLSLeafSHA256 string            `json:"tls_leaf_sha256"`
	Files         map[string]string `json:"files"`
}

type PreparationReceipt struct {
	Version                  uint64          `json:"version"`
	Cell                     string          `json:"cell"`
	PartitionID              string          `json:"partition_id"`
	Generation               uint64          `json:"generation"`
	Spec                     InitialSpec     `json:"spec"`
	SpecSHA256               string          `json:"spec_sha256"`
	Object                   ObjectReference `json:"object"`
	AuthorityConfigurationID string          `json:"authority_configuration_id"`
	AuthoritySHA256          string          `json:"authority_sha256"`
	TrustedKeySHA256         string          `json:"trusted_key_sha256"`
	CustomerEnvelopeSHA256   string          `json:"customer_envelope_sha256"`
	Members                  [2]MemberPins   `json:"members"`
	IssuedAt                 time.Time       `json:"issued_at"`
	ControllerKeyID          string          `json:"controller_key_id"`
	Signature                string          `json:"signature"`
}

func (receipt PreparationReceipt) unsigned() PreparationReceipt {
	receipt.Signature = ""
	return receipt
}

// SignPreparationReceipt signs a producer-derived, version-pinned record. The
// same record must be committed with R3 CAS before an intent may use it.
func SignPreparationReceipt(cell, partition string, spec InitialSpec, bundle InitialBundle,
	object ObjectReference, controllerKey ed25519.PrivateKey, now time.Time,
) (PreparationReceipt, error) {
	if len(controllerKey) != ed25519.PrivateKeySize || now.IsZero() ||
		!repositoryToken.MatchString(cell) || !entityid.Valid(partition) ||
		spec.PartitionID != partition ||
		!lowerHexDigest(object.SHA256) || object.VersionID == "" || object.ETag == "" ||
		object.SpecSHA256 == "" {
		return PreparationReceipt{}, errors.New("managed material receipt signing inputs are invalid")
	}
	if err := validateBundleForSpec(spec, bundle); err != nil {
		return PreparationReceipt{}, err
	}
	specSHA, err := specDigest(spec)
	if err != nil || specSHA != object.SpecSHA256 {
		return PreparationReceipt{}, ErrMaterialConflict
	}
	wantName := fmt.Sprintf("material/v2/%s/%s/%s/g1-%s.json", cell, spec.PlacementDatabaseID, partition, specSHA)
	if object.Name != wantName {
		return PreparationReceipt{}, ErrMaterialConflict
	}
	keyID, err := protocol.KeyID(controllerKey.Public().(ed25519.PublicKey))
	if err != nil {
		return PreparationReceipt{}, err
	}
	certificate := sha256.Sum256(bundle.Authority.Certificate)
	trusted := sha256.Sum256(bundle.Authority.TrustedKey)
	customerSHA, err := customerEnvelopeDigest(bundle.Customer)
	if err != nil {
		return PreparationReceipt{}, err
	}
	receipt := PreparationReceipt{Version: 2, Cell: cell, PartitionID: partition,
		Generation: 1, Spec: spec, SpecSHA256: specSHA, Object: object,
		AuthorityConfigurationID: bundle.Authority.ConfigurationID,
		AuthoritySHA256:          hex.EncodeToString(certificate[:]), TrustedKeySHA256: hex.EncodeToString(trusted[:]),
		CustomerEnvelopeSHA256: customerSHA,
		IssuedAt:               now.UTC().Truncate(time.Second), ControllerKeyID: keyID}
	for index, member := range bundle.Members {
		pins := MemberPins{MemberID: member.MemberID, TLSLeafSHA256: member.TLSLeafSHA256,
			Files: make(map[string]string, len(member.Files))}
		for name, file := range member.Files {
			pins.Files[name] = file.SHA256
		}
		receipt.Members[index] = pins
	}
	material, err := receipt.signingMaterial()
	if err != nil {
		return PreparationReceipt{}, err
	}
	receipt.Signature = base64.RawURLEncoding.EncodeToString(ed25519.Sign(controllerKey, material))
	return receipt, nil
}

func (receipt PreparationReceipt) signingMaterial() ([]byte, error) {
	wire, err := protocol.EncodeJSON(receipt.unsigned())
	if err != nil {
		return nil, err
	}
	return append([]byte(preparationReceiptDomain), wire...), nil
}

func customerEnvelopeDigest(customer CustomerEnvelope) (string, error) {
	wire, err := protocol.EncodeJSON(customer)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(wire)
	return hex.EncodeToString(sum[:]), nil
}

// VerifyPreparationReply authenticates everything an operator may print from
// the controller response. The expected spec comes from the operator's signed
// request, and controllerKey is an independent local trust pin.
func VerifyPreparationReply(receipt PreparationReceipt, customer CustomerEnvelope,
	controllerKey ed25519.PublicKey, cell, partition string, expected InitialSpec,
) error {
	if err := verifyPreparationSignature(receipt, controllerKey, cell, partition); err != nil {
		return err
	}
	wantSpec, err := specDigest(expected)
	if err != nil || wantSpec != receipt.SpecSHA256 || expected.PlacementDatabaseID != receipt.Spec.PlacementDatabaseID {
		return ErrMaterialConflict
	}
	if customer.Version != 2 || !lowerHexDigest(customer.VerifierSHA256) ||
		!lowerHexDigest(customer.HTTPSCASHA256) {
		return ErrMaterialConflict
	}
	actual, err := customerEnvelopeDigest(customer)
	if err != nil || actual != receipt.CustomerEnvelopeSHA256 {
		return ErrMaterialConflict
	}
	return nil
}

func verifyPreparationSignature(receipt PreparationReceipt, controllerKey ed25519.PublicKey,
	cell, partition string,
) error {
	if len(controllerKey) != ed25519.PublicKeySize || receipt.Version != 2 ||
		receipt.Generation != 1 || receipt.Cell != cell || receipt.PartitionID != partition ||
		receipt.Spec.PartitionID != partition ||
		receipt.IssuedAt.IsZero() || !lowerHexDigest(receipt.SpecSHA256) ||
		receipt.SpecSHA256 != receipt.Object.SpecSHA256 || !lowerHexDigest(receipt.Object.SHA256) ||
		receipt.Object.VersionID == "" || receipt.Object.ETag == "" ||
		!lowerHexDigest(receipt.AuthoritySHA256) || !lowerHexDigest(receipt.TrustedKeySHA256) ||
		!lowerHexDigest(receipt.CustomerEnvelopeSHA256) ||
		!lowerHexDigest(receipt.AuthorityConfigurationID) {
		return errors.New("managed material preparation receipt is invalid")
	}
	keyID, err := protocol.KeyID(controllerKey)
	if err != nil || keyID != receipt.ControllerKeyID {
		return errors.New("managed material preparation signer differs from controller pin")
	}
	signature, err := base64.RawURLEncoding.DecodeString(receipt.Signature)
	if err != nil || len(signature) != ed25519.SignatureSize {
		return errors.New("managed material preparation signature is invalid")
	}
	material, err := receipt.signingMaterial()
	if err != nil || !ed25519.Verify(controllerKey, material, signature) {
		return errors.New("managed material preparation signature is invalid")
	}
	specSHA, err := specDigest(receipt.Spec)
	if err != nil || specSHA != receipt.SpecSHA256 ||
		receipt.Object.Name != fmt.Sprintf("material/v2/%s/%s/%s/g1-%s.json", cell,
			receipt.Spec.PlacementDatabaseID, partition, specSHA) {
		return ErrMaterialConflict
	}
	return nil
}

// VerifyPreparationReceipt checks the controller signature and all internal
// pins. Callers must also compare it byte-for-byte with the current R3 record,
// then compare its pins with the operator-signed placement intent.
func VerifyPreparationReceipt(receipt PreparationReceipt, controllerKey ed25519.PublicKey,
	cell, partition string, objectBundle InitialBundle,
) error {
	if err := VerifyPreparationReply(receipt, objectBundle.Customer, controllerKey,
		cell, partition, receipt.Spec); err != nil {
		return err
	}
	if err := validateBundleForSpec(receipt.Spec, objectBundle); err != nil {
		return err
	}
	certificate := sha256.Sum256(objectBundle.Authority.Certificate)
	trusted := sha256.Sum256(objectBundle.Authority.TrustedKey)
	if receipt.AuthoritySHA256 != hex.EncodeToString(certificate[:]) ||
		receipt.TrustedKeySHA256 != hex.EncodeToString(trusted[:]) ||
		receipt.AuthorityConfigurationID != objectBundle.Authority.ConfigurationID {
		return ErrMaterialConflict
	}
	for index, member := range objectBundle.Members {
		pins := receipt.Members[index]
		if pins.MemberID != member.MemberID || pins.TLSLeafSHA256 != member.TLSLeafSHA256 ||
			len(pins.Files) != len(member.Files) {
			return ErrMaterialConflict
		}
		for name, file := range member.Files {
			if pins.Files[name] != file.SHA256 {
				return ErrMaterialConflict
			}
		}
	}
	return nil
}

func (receipt PreparationReceipt) Digest() (string, error) {
	if receipt.Signature == "" {
		return "", errors.New("unsigned managed material receipt")
	}
	wire, err := protocol.EncodeJSON(receipt)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(wire)
	return hex.EncodeToString(sum[:]), nil
}
