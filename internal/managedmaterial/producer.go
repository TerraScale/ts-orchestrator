package managedmaterial

import (
	"crypto/ed25519"
	"time"
)

// InitialMember fixes the two initial seats before certificate and file hashes
// are admitted. MaterialDirectory is the deterministic directory for attempt 1.
type InitialMember struct {
	SeatID            string `json:"seat_id"`
	MemberID          string `json:"member_id"`
	Incarnation       string `json:"incarnation"`
	ServerName        string `json:"server_name"`
	FailureDomain     string `json:"failure_domain"`
	MaterialDirectory string `json:"material_directory"`
	ReplicationIP     string `json:"replication_ip"`
	ReplicationPort   uint16 `json:"replication_port"`
	ClientIP          string `json:"client_ip"`
	ClientPort        uint16 `json:"client_port"`
	SQLListenPort     uint16 `json:"sql_listen_port,omitzero"`
}

// RecipientGrant is signed by the customer recipient signer pinned by the
// controller's regional configuration. It authorizes one X25519 key and one
// shard scope until ExpiresAt. The raw token is never returned by the producer.
type RecipientGrant struct {
	PublicKey []byte    `json:"public_key"`
	ExpiresAt time.Time `json:"expires_at"`
	Signature []byte    `json:"signature"`
}

type InitialSpec struct {
	PlacementDatabaseID string                `json:"placement_database_id"`
	PartitionID         string                `json:"partition_id"`
	Scope               AuthorityScope        `json:"scope"`
	LiveS3              LiveS3Target          `json:"live_s3"`
	Backup              *InitialBackupSpec    `json:"backup,omitempty"`
	Catalogs            []InitialCatalogInput `json:"catalogs"`
	SQLTables           []InitialSQLTable     `json:"sql_tables,omitempty"`
	Members             [2]InitialMember      `json:"members"`
	Recipient           RecipientGrant        `json:"recipient"`
}

// File is one exact host file and its placement digest. Contents are sensitive
// even though the digest is public; callers must only send them encrypted.
type File struct {
	Contents []byte
	SHA256   string
}

type MemberBundle struct {
	MemberID      string
	TLSLeafSHA256 string
	Files         map[string]File
}

// RetainedSecrets are controller-only rotation continuity keys. They are never
// added to MemberBundle.Files or the customer ciphertext.
type RetainedSecrets struct {
	AuthoritySigner ed25519.PrivateKey
	ReplicationCA   []byte
	HTTPSCA         []byte
}

type CustomerEnvelope struct {
	Version            uint64 `json:"version"`
	TokenID            string `json:"token_id"`
	VerifierSHA256     string `json:"verifier_sha256"`
	HTTPSCASHA256      string `json:"https_ca_sha256"`
	EphemeralPublicKey string `json:"ephemeral_public_key"`
	Nonce              string `json:"nonce"`
	Ciphertext         string `json:"ciphertext"`
}

type InitialBundle struct {
	Authority SignedAuthority
	Members   [2]MemberBundle
	Customer  CustomerEnvelope
	Retained  RetainedSecrets
}

const (
	leafKeyEd25519 leafKey = iota
	leafKeyP256
)

type leafKey int
