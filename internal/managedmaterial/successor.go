package managedmaterial

import (
	"crypto/ed25519"
	"crypto/sha256"
)

// SuccessorRequest identifies the two fresh certified origins in predecessor
// seat order. Their exact replication TLS leaves must already be staged with
// their private keys in the successor's confidential material.
type SuccessorRequest struct {
	Epoch   uint64
	Members [2]AuthorityMember
}

// SuccessorMaterial contains the exact public artifacts and pins for a D11
// Prepare. Attestation keys and SuccessorLeafPinsBySeat retain predecessor
// seat order even when the successor certificate sorts its member IDs in the
// opposite order. An absent SQL bundle is represented by SQLPresent=false and
// zero SQL digests. Its bytes must be durably pinned before Prepare dispatch.
type SuccessorMaterial struct {
	PredecessorScope           AuthorityScope
	SuccessorScope             AuthorityScope
	PredecessorConfigurationID string
	PredecessorAuthoritySHA256 [sha256.Size]byte
	SuccessorAuthority         SignedAuthority
	SuccessorAuthoritySHA256   [sha256.Size]byte
	TrustedKeySHA256           [sha256.Size]byte
	PredecessorSQLBundleSHA256 [sha256.Size]byte
	SuccessorSQLBundle         []byte
	SuccessorSQLBundleSHA256   [sha256.Size]byte
	SQLPresent                 bool
	DocumentCatalogSetSHA256   [sha256.Size]byte
	PredecessorAttestationKeys [2]ed25519.PublicKey
	SuccessorAttestationKeys   [2]ed25519.PublicKey
	SuccessorLeafPinsBySeat    [2]string
}
