package managedmaterial

import (
	"time"
)

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
