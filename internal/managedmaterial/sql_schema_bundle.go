package managedmaterial

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"net"
	"strconv"
	"strings"

	"github.com/oklog/ulid/v2"
)

const (
	sqlSchemaBundleFileName = "sql-schema-bundle.tbsqb"
	sqlSchemaBundleMagic    = "TBSQB001"
	sqlSchemaBundleVersion  = uint16(1)
	sqlSchemaBundleMaxBytes = 4 << 10
	sqlSchemaBundleMaxRows  = 16
	sqlSchemaHeaderBytes    = 112
	sqlSchemaSignatureBytes = ed25519.SignatureSize
	sqlSchemaSignDomain     = "TB-SQL-SCHEMA-BUNDLE-V1\x00"
	sqlTableDigestDomain    = "TB-SQL-TABLE-V1\x00"
	sqlTableSetDigestDomain = "TB-CUSTOMER-SQL-TABLE-SET-V2\x00"
)

// InitialSQLTable is one generation-one SQL table with an i64 primary key and
// a text payload. IDs are assigned by the caller before the InitialSpec is
// signed and remain unchanged across retries and credential rotations.
type InitialSQLTable struct {
	TableID       string `json:"table_id"`
	Name          string `json:"name"`
	KeyColumn     string `json:"key_column"`
	PayloadColumn string `json:"payload_column"`
}

// ValidateSQLConfiguration checks the immutable table definitions and their
// host listener bindings before an operator signs an SQL-enabled InitialSpec.
func (spec InitialSpec) ValidateSQLConfiguration() error {
	if err := validateSQLTables(spec.SQLTables, spec.Catalogs); err != nil {
		return err
	}
	for _, member := range spec.Members {
		if len(spec.SQLTables) == 0 {
			if member.SQLListenPort != 0 {
				return errors.New("SQL listener port requires an initial SQL table set")
			}
			continue
		}
		if !validPrivateIP(member.ClientIP) || member.ClientIP != member.ReplicationIP ||
			member.SQLListenPort == 0 || member.SQLListenPort == member.ClientPort ||
			member.SQLListenPort == member.ReplicationPort {
			return errors.New("initial SQL listener must use a private port distinct from HTTPS and replication")
		}
	}
	return nil
}

func validateSQLTables(tables []InitialSQLTable, catalogs []InitialCatalogInput) error {
	if len(tables) == 0 {
		return nil
	}
	if len(tables) > sqlSchemaBundleMaxRows {
		return errors.New("initial SQL table count is invalid")
	}

	names := make(map[string]struct{}, len(tables))
	collectionIDs := make(map[ulid.ULID]struct{}, len(catalogs))
	for _, catalog := range catalogs {
		id, err := canonicalID(catalog.CollectionID)
		if err != nil {
			return errors.New("initial SQL table set conflicts with catalog identities")
		}
		collectionIDs[id] = struct{}{}
	}
	var previousID ulid.ULID
	for index, table := range tables {
		id, err := canonicalID(table.TableID)
		if err != nil {
			return errors.New("initial SQL table ID must be a canonical ULID")
		}
		if _, exists := collectionIDs[id]; exists {
			return errors.New("initial SQL table ID duplicates a catalog collection ID")
		}
		if index > 0 && bytes.Compare(previousID[:], id[:]) >= 0 {
			return errors.New("initial SQL tables must be strictly sorted by ULID bytes")
		}
		previousID = id
		if _, exists := names[table.Name]; exists {
			return errors.New("initial SQL table names are duplicated")
		}
		names[table.Name] = struct{}{}
		if _, err := sqlTableRow(table); err != nil {
			return err
		}
	}
	return nil
}

func sqlTableRow(table InitialSQLTable) ([]byte, error) {
	for _, name := range []string{table.Name, table.KeyColumn, table.PayloadColumn} {
		if !validSQLIdentifier(name) {
			return nil, errors.New("initial SQL table or column identifier is invalid")
		}
	}
	if table.KeyColumn == table.PayloadColumn {
		return nil, errors.New("initial SQL key and payload columns must differ")
	}
	id, err := canonicalID(table.TableID)
	if err != nil {
		return nil, errors.New("initial SQL table ID must be a canonical ULID")
	}
	row := make([]byte, 0, 28+3+len(table.Name)+len(table.KeyColumn)+len(table.PayloadColumn))
	row = append(row, id[:]...)
	row = binary.LittleEndian.AppendUint64(row, 1)
	row = binary.LittleEndian.AppendUint16(row, 1)
	row = binary.LittleEndian.AppendUint16(row, 2)
	for _, name := range []string{table.Name, table.KeyColumn, table.PayloadColumn} {
		row = append(row, byte(len(name)))
		row = append(row, name...)
	}
	return row, nil
}

func validSQLIdentifier(value string) bool {
	if len(value) == 0 || len(value) > 63 || value[0] < 'a' || value[0] > 'z' ||
		strings.HasPrefix(value, "tb_") || strings.HasPrefix(value, "sqlite_") ||
		strings.HasPrefix(value, "pg_") || strings.HasPrefix(value, "turso_") ||
		strings.HasPrefix(value, "information_schema") {
		return false
	}
	for index := 1; index < len(value); index++ {
		character := value[index]
		if !((character >= 'a' && character <= 'z') ||
			(character >= '0' && character <= '9') || character == '_') {
			return false
		}
	}
	return true
}

func encodeSQLSchemaBundle(scope AuthorityScope, configurationID string, tables []InitialSQLTable,
	signer ed25519.PrivateKey,
) ([]byte, error) {
	if len(signer) != ed25519.PrivateKeySize || len(tables) == 0 || len(tables) > sqlSchemaBundleMaxRows {
		return nil, errors.New("SQL schema bundle signer or table count is invalid")
	}
	if err := validateSQLTables(tables, nil); err != nil {
		return nil, err
	}
	configuration, configurationErr := hex.DecodeString(configurationID)
	cluster, clusterErr := hex.DecodeString(scope.ClusterID)
	tenant, tenantErr := canonicalID(scope.TenantID)
	database, databaseErr := canonicalID(scope.DatabaseID)
	if configurationErr != nil || len(configuration) != sha256.Size ||
		clusterErr != nil || !lowerHexIdentity(scope.ClusterID) || allZero(cluster[:]) || tenantErr != nil || databaseErr != nil ||
		scope.ShardID == 0 || scope.Epoch == 0 {
		return nil, errors.New("SQL schema bundle authority scope is invalid")
	}

	payload := make([]byte, 0, sqlSchemaBundleMaxBytes-sqlSchemaSignatureBytes)
	payload = append(payload, sqlSchemaBundleMagic...)
	payload = binary.LittleEndian.AppendUint32(payload, 0)
	payload = binary.LittleEndian.AppendUint16(payload, sqlSchemaBundleVersion)
	payload = binary.LittleEndian.AppendUint16(payload, uint16(len(tables)))
	payload = append(payload, configuration...)
	payload = append(payload, cluster[:]...)
	payload = append(payload, tenant[:]...)
	payload = append(payload, database[:]...)
	payload = binary.LittleEndian.AppendUint64(payload, scope.ShardID)
	payload = binary.LittleEndian.AppendUint64(payload, scope.Epoch)
	for _, table := range tables {
		row, err := sqlTableRow(table)
		if err != nil {
			return nil, err
		}
		payload = append(payload, row...)
	}
	if len(payload)+sqlSchemaSignatureBytes > sqlSchemaBundleMaxBytes {
		return nil, errors.New("SQL schema bundle exceeds its byte limit")
	}
	binary.LittleEndian.PutUint32(payload[8:12], uint32(len(payload)))
	signingInput := make([]byte, 0, len(sqlSchemaSignDomain)+len(payload))
	signingInput = append(signingInput, sqlSchemaSignDomain...)
	signingInput = append(signingInput, payload...)
	bundle := make([]byte, 0, len(payload)+sqlSchemaSignatureBytes)
	bundle = append(bundle, payload...)
	bundle = append(bundle, ed25519.Sign(signer, signingInput)...)
	return bundle, nil
}

func sqlTableSetDigest(tables []InitialSQLTable) (string, error) {
	if err := validateSQLTables(tables, nil); err != nil {
		return "", err
	}
	material := make([]byte, 0, len(sqlTableSetDigestDomain)+2+len(tables)*128)
	material = append(material, sqlTableSetDigestDomain...)
	material = binary.LittleEndian.AppendUint16(material, uint16(len(tables)))
	for _, table := range tables {
		row, err := sqlTableRow(table)
		if err != nil {
			return "", err
		}
		material = binary.LittleEndian.AppendUint16(material, uint16(len(row)))
		material = append(material, row...)
	}
	sum := sha256.Sum256(material)
	return hex.EncodeToString(sum[:]), nil
}

func initialSQLTableIDs(tables []InitialSQLTable) []string {
	ids := make([]string, 0, len(tables))
	for _, table := range tables {
		id, err := canonicalID(table.TableID)
		if err != nil {
			return nil
		}
		ids = append(ids, id.String())
	}
	return ids
}

func sqlListenAddress(member InitialMember) string {
	if member.SQLListenPort == 0 {
		return ""
	}
	return net.JoinHostPort(member.ClientIP, strconv.Itoa(int(member.SQLListenPort)))
}
