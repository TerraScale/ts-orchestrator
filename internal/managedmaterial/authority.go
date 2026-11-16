package managedmaterial

import (
	"crypto/ed25519"
)

// AuthorityScope is the immutable shard identity in one initial two-member
// TerraBase authority. Rotation requires a separate coordinated transition.
type AuthorityScope struct {
	ClusterID  string `json:"cluster_id"`
	TenantID   string `json:"tenant_id"`
	DatabaseID string `json:"database_id"`
	ShardID    uint64 `json:"shard_id"`
	Epoch      uint64 `json:"epoch"`
}

type AuthorityMember struct {
	MemberID      string
	Incarnation   string
	ServerName    string
	FailureDomain string
	LeafDER       []byte
}

type AuthorityCatalog struct {
	CollectionID     string
	SchemaGeneration uint64
	SchemaDigest     string
	Bytes            []byte
}

// InitialCatalogInput is one exact canonical TBCAT001 catalog in the signed
// operator request. Catalogs are sorted by collection ULID bytes.
type InitialCatalogInput struct {
	CollectionID     string `json:"collection_id"`
	CanonicalCatalog []byte `json:"canonical_catalog"`
}

type SignedAuthority struct {
	Certificate     []byte
	ConfigurationID string
	TrustedKey      ed25519.PublicKey
	MemberLeafPins  [2]string
}

// TerraBase TBSCH001 field type and flag codes (tb-format document schema).
