package managedmaterial

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"hash/crc32"
	"slices"
	"strings"

	"github.com/TerraScale/ts-orchestrator/internal/entityid"
	"github.com/oklog/ulid/v2"
)

const (
	maxAuthorityPayload = 4 << 20
	maxCatalogBytes     = 1_048_576
)

var authorityCRC = crc32.MakeTable(crc32.Castagnoli)

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

// CatalogUTF8Field is one optional, non-nullable top-level UTF-8 document
// field in a generation-one TBSCH001 schema.
type CatalogUTF8Field struct {
	ID   uint32 `json:"id"`
	Name string `json:"name"`
}

// TerraBase TBSCH001 field type and flag codes (tb-format document schema).
const (
	schemaFieldTypeUTF8 = 4
	maxCatalogFields    = 256
)

// InitialCatalog produces a generation-one TBCAT001 envelope around a
// TBSCH001 schema with the given optional UTF-8 fields and no relationships.
func InitialCatalog(collectionID string, fields []CatalogUTF8Field) (AuthorityCatalog, error) {
	collection, err := canonicalID(collectionID)
	if err != nil {
		return AuthorityCatalog{}, err
	}
	if len(fields) > maxCatalogFields {
		return AuthorityCatalog{}, errors.New("initial catalog has too many fields")
	}
	schema := make([]byte, 0, 64)
	schema = append(schema, "TBSCH001"...)
	schema = binary.LittleEndian.AppendUint32(schema, 0)
	schema = binary.LittleEndian.AppendUint16(schema, uint16(len(fields)))
	seen := make(map[uint32]struct{}, len(fields))
	names := make(map[string]struct{}, len(fields))
	for _, field := range fields {
		_, repeatedID := seen[field.ID]
		_, repeatedName := names[field.Name]
		if field.ID == 0 || repeatedID || repeatedName || !validCatalogFieldName(field.Name) {
			return AuthorityCatalog{}, errors.New("initial catalog field is invalid or repeated")
		}
		seen[field.ID], names[field.Name] = struct{}{}, struct{}{}
		schema = binary.LittleEndian.AppendUint32(schema, field.ID)
		schema = binary.LittleEndian.AppendUint32(schema, 0)
		schema = append(schema, schemaFieldTypeUTF8, 0, 0)
		schema = binary.LittleEndian.AppendUint16(schema, uint16(len(field.Name)))
		schema = append(schema, field.Name...)
	}
	binary.LittleEndian.PutUint32(schema[8:12], uint32(len(schema)+4))
	schema = binary.LittleEndian.AppendUint32(schema, crc32.Checksum(schema, authorityCRC))
	digest := sha256.Sum256(schema)
	size := 84 + len(schema)
	catalog := make([]byte, 0, size)
	catalog = append(catalog, "TBCAT001"...)
	catalog = binary.LittleEndian.AppendUint32(catalog, uint32(size))
	catalog = append(catalog, collection[:]...)
	catalog = binary.LittleEndian.AppendUint64(catalog, 1)
	catalog = binary.LittleEndian.AppendUint64(catalog, 0)
	catalog = append(catalog, digest[:]...)
	catalog = binary.LittleEndian.AppendUint32(catalog, uint32(len(schema)))
	catalog = append(catalog, schema...)
	catalog = binary.LittleEndian.AppendUint32(catalog, crc32.Checksum(catalog, authorityCRC))
	return AuthorityCatalog{CollectionID: collectionID, SchemaGeneration: 1,
		SchemaDigest: hex.EncodeToString(digest[:]), Bytes: catalog}, nil
}

func validCatalogFieldName(name string) bool {
	if len(name) == 0 || len(name) > 64 || name[0] < 'a' || name[0] > 'z' {
		return false
	}
	for index := range len(name) {
		if !lowerAlphaNumeric(name[index]) && name[index] != '_' {
			return false
		}
	}
	return true
}

// SignInitialAuthorityV2 encodes the fixed TBCAU002 grammar consumed by the
// TerraBase signed-v2 authority verifier. The Ed25519 signer must already be
// durably retained and pinned by the controller before this call.
func SignInitialAuthorityV2(scope AuthorityScope, members [2]AuthorityMember, catalogs []AuthorityCatalog,
	signer ed25519.PrivateKey,
) (SignedAuthority, error) {
	if len(signer) != ed25519.PrivateKeySize || scope.ShardID == 0 || scope.Epoch == 0 {
		return SignedAuthority{}, errors.New("initial authority signer or scope is invalid")
	}
	cluster, err := hex.DecodeString(scope.ClusterID)
	if err != nil || !lowerHexIdentity(scope.ClusterID) || len(cluster) != 16 || allZero(cluster[:]) {
		return SignedAuthority{}, errors.New("initial authority cluster ID is invalid")
	}
	tenant, err := canonicalID(scope.TenantID)
	if err != nil {
		return SignedAuthority{}, err
	}
	database, err := canonicalID(scope.DatabaseID)
	if err != nil {
		return SignedAuthority{}, err
	}
	if len(catalogs) < 1 || len(catalogs) > 1024 {
		return SignedAuthority{}, errors.New("initial authority catalog count is invalid")
	}
	var previousCollection []byte
	for _, catalog := range catalogs {
		collection, err := canonicalID(catalog.CollectionID)
		if err != nil || catalog.SchemaGeneration != 1 || !validInitialCatalog(catalog, collection) ||
			previousCollection != nil && bytes.Compare(previousCollection, collection[:]) >= 0 {
			return SignedAuthority{}, errors.New("initial authority catalog is invalid or out of order")
		}
		previousCollection = collection[:]
	}
	var memberIDs [2]ulid.ULID
	var leafPins [2]string
	for index, member := range members {
		memberIDs[index], err = canonicalID(member.MemberID)
		incarnation, decodeErr := hex.DecodeString(member.Incarnation)
		if err != nil || decodeErr != nil || !lowerHexIdentity(member.Incarnation) || len(incarnation) != 16 || allZero(incarnation[:]) ||
			!validServerName(member.ServerName) || !validFailureDomain(member.FailureDomain) ||
			len(member.LeafDER) == 0 || len(member.LeafDER) > maxCatalogBytes {
			return SignedAuthority{}, errors.New("initial authority member is invalid")
		}
		leaf := sha256.Sum256(member.LeafDER)
		leafPins[index] = hex.EncodeToString(leaf[:])
	}
	if bytes.Compare(memberIDs[0][:], memberIDs[1][:]) >= 0 || members[0].ServerName == members[1].ServerName ||
		leafPins[0] == leafPins[1] {
		return SignedAuthority{}, errors.New("initial authority members are not distinct and ordered")
	}
	payload := make([]byte, 0, 156+len(members[0].ServerName)+len(members[1].ServerName)+
		len(members[0].FailureDomain)+len(members[1].FailureDomain))
	payload = append(payload, "TBCAU002"...)
	payload = binary.LittleEndian.AppendUint32(payload, 0)
	payload = binary.LittleEndian.AppendUint16(payload, 2)
	payload = binary.LittleEndian.AppendUint16(payload, 1)
	payload = append(payload, cluster[:]...)
	payload = append(payload, tenant[:]...)
	payload = append(payload, database[:]...)
	payload = binary.LittleEndian.AppendUint64(payload, scope.ShardID)
	payload = binary.LittleEndian.AppendUint64(payload, scope.Epoch)
	payload = binary.LittleEndian.AppendUint16(payload, 2)
	payload = binary.LittleEndian.AppendUint16(payload, uint16(len(catalogs)))
	payload = binary.LittleEndian.AppendUint16(payload, uint16(len(catalogs)))
	for index, member := range members {
		incarnation, _ := hex.DecodeString(member.Incarnation)
		fingerprint, _ := hex.DecodeString(leafPins[index])
		payload = append(payload, memberIDs[index][:]...)
		payload = append(payload, incarnation[:]...)
		payload = append(payload, fingerprint...)
		payload = append(payload, byte(len(member.ServerName)))
		payload = append(payload, member.ServerName...)
		payload = append(payload, byte(len(member.FailureDomain)))
		payload = append(payload, member.FailureDomain...)
	}
	for _, catalog := range catalogs {
		collection, _ := canonicalID(catalog.CollectionID)
		schemaDigest, _ := hex.DecodeString(catalog.SchemaDigest)
		payload = append(payload, collection[:]...)
		payload = binary.LittleEndian.AppendUint64(payload, catalog.SchemaGeneration)
		payload = append(payload, schemaDigest...)
		payload = binary.LittleEndian.AppendUint32(payload, uint32(len(catalog.Bytes)))
		payload = append(payload, catalog.Bytes...)
	}
	for _, catalog := range catalogs {
		collection, _ := canonicalID(catalog.CollectionID)
		schemaDigest, _ := hex.DecodeString(catalog.SchemaDigest)
		payload = append(payload, collection[:]...)
		payload = binary.LittleEndian.AppendUint64(payload, catalog.SchemaGeneration)
		payload = append(payload, schemaDigest...)
	}
	if len(payload) > maxAuthorityPayload {
		return SignedAuthority{}, errors.New("initial authority exceeds TerraBase payload limit")
	}
	binary.LittleEndian.PutUint32(payload[8:12], uint32(len(payload)))
	configuration := sha256.Sum256(append([]byte("TB-CONFIG-FIXED-V2\x00"), payload...))
	signature := ed25519.Sign(signer, append([]byte("TB-AUTHORITY-FIXED-V2\x00"), payload...))
	certificate := append(payload, signature...)
	return SignedAuthority{Certificate: certificate, ConfigurationID: hex.EncodeToString(configuration[:]),
		TrustedKey: slices.Clone(signer.Public().(ed25519.PublicKey)), MemberLeafPins: leafPins}, nil
}

func validInitialCatalog(catalog AuthorityCatalog, collection ulid.ULID) bool {
	data := catalog.Bytes
	if len(data) < 102 || len(data) > maxCatalogBytes || !bytes.Equal(data[:8], []byte("TBCAT001")) ||
		binary.LittleEndian.Uint32(data[8:12]) != uint32(len(data)) ||
		!bytes.Equal(data[12:28], collection[:]) ||
		binary.LittleEndian.Uint64(data[28:36]) != 1 || binary.LittleEndian.Uint64(data[36:44]) != 0 ||
		binary.LittleEndian.Uint32(data[76:80]) != uint32(len(data)-84) ||
		crc32.Checksum(data[:len(data)-4], authorityCRC) != binary.LittleEndian.Uint32(data[len(data)-4:]) {
		return false
	}
	schema := data[80 : len(data)-4]
	if len(schema) < 18 || !bytes.Equal(schema[:8], []byte("TBSCH001")) ||
		binary.LittleEndian.Uint32(schema[8:12]) != uint32(len(schema)) ||
		crc32.Checksum(schema[:len(schema)-4], authorityCRC) != binary.LittleEndian.Uint32(schema[len(schema)-4:]) {
		return false
	}
	digest := sha256.Sum256(schema)
	return bytes.Equal(data[44:76], digest[:]) && catalog.SchemaDigest == hex.EncodeToString(digest[:])
}

func initialCatalogs(inputs []InitialCatalogInput) ([]AuthorityCatalog, error) {
	if len(inputs) < 1 || len(inputs) > 1024 {
		return nil, errors.New("initial catalog count is invalid")
	}
	catalogs := make([]AuthorityCatalog, 0, len(inputs))
	var previousCollection []byte
	for _, input := range inputs {
		collection, err := canonicalID(input.CollectionID)
		if err != nil || previousCollection != nil && bytes.Compare(previousCollection, collection[:]) >= 0 ||
			len(input.CanonicalCatalog) < 102 || len(input.CanonicalCatalog) > maxCatalogBytes {
			return nil, errors.New("initial catalogs are invalid or out of order")
		}
		previousCollection = collection[:]
		schema := input.CanonicalCatalog[80 : len(input.CanonicalCatalog)-4]
		digest := sha256.Sum256(schema)
		catalog := AuthorityCatalog{CollectionID: input.CollectionID, SchemaGeneration: 1,
			SchemaDigest: hex.EncodeToString(digest[:]), Bytes: input.CanonicalCatalog}
		if !validInitialCatalog(catalog, collection) {
			return nil, errors.New("initial catalog envelope is invalid")
		}
		catalogs = append(catalogs, catalog)
	}
	return catalogs, nil
}

func canonicalID(value string) (ulid.ULID, error) { return entityid.Parse(value) }

func allZero(value []byte) bool {
	return !slices.ContainsFunc(value, func(b byte) bool { return b != 0 })
}

func validServerName(value string) bool {
	if len(value) < 1 || len(value) > 253 {
		return false
	}
	for label := range strings.SplitSeq(value, ".") {
		if len(label) < 1 || len(label) > 63 || !lowerAlphaNumeric(label[0]) || !lowerAlphaNumeric(label[len(label)-1]) {
			return false
		}
		for index := range len(label) {
			if !lowerAlphaNumeric(label[index]) && label[index] != '-' {
				return false
			}
		}
	}
	return true
}

func lowerAlphaNumeric(value byte) bool {
	return value >= 'a' && value <= 'z' || value >= '0' && value <= '9'
}

func validFailureDomain(value string) bool {
	if len(value) < 1 || len(value) > 64 {
		return false
	}
	for index := range len(value) {
		character := value[index]
		if character >= 'a' && character <= 'z' || character >= 'A' && character <= 'Z' ||
			character >= '0' && character <= '9' || character == '.' || character == '_' || character == '-' {
			continue
		}
		return false
	}
	return true
}
