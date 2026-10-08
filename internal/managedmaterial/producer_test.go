package managedmaterial

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json/v2"
	"hash/crc32"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/entityid"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/oci"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/testutil/tier"
)

func initialFixture(t *testing.T) (InitialSpec, ed25519.PublicKey, *ecdh.PrivateKey) {
	t.Helper()
	recipient, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	public, signer, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	firstCatalog, err := InitialCatalog("1G000000000000000000000001", nil)
	if err != nil {
		t.Fatal(err)
	}
	secondCatalog, err := InitialCatalog("1G000000000000000000000002", nil)
	if err != nil {
		t.Fatal(err)
	}
	spec := InitialSpec{
		PlacementDatabaseID: "0000000000JJVVW9EMWY1PE1VX",
		PartitionID:         "0000000000Z3WK359G2W66CVT8",
		Scope: AuthorityScope{ClusterID: "01081G81860W40J2GB1G6GW3RG",
			TenantID: "0G000000000000000000000001", DatabaseID: "10000000000000000000000001",
			ShardID: 7, Epoch: 1},
		LiveS3: LiveS3Target{Bucket: "alpha-live", Region: "sa-saopaulo-1",
			Endpoint:   "https://alpha.compat.objectstorage.sa-saopaulo-1.oci.customer-oci.com",
			Credential: oci.SecretVersionReference{SecretOCID: "ocid1.vaultsecret.oc1.sa-saopaulo-1.alpha", VersionNumber: 3}},
		Catalogs: []InitialCatalogInput{
			{CollectionID: firstCatalog.CollectionID, CanonicalCatalog: firstCatalog.Bytes},
			{CollectionID: secondCatalog.CollectionID, CanonicalCatalog: secondCatalog.Bytes},
		},
		Members: [2]InitialMember{
			{SeatID: "00000000000E5NVMSGX0D07DPA", MemberID: "20000000000000000000000001", Incarnation: "01040G2081040G2081040G2081",
				ServerName: "a.replication.example", FailureDomain: "FAULT-DOMAIN-1",
				MaterialDirectory: "/var/lib/terrabase/attempt-a/material", ReplicationIP: "10.0.0.11", ReplicationPort: 9443,
				ClientIP: "10.0.0.11", ClientPort: 9465},
			{SeatID: "00000000008SEAHD1YMMYV3ARR", MemberID: "20000000000000000000000002", Incarnation: "02081040G2081040G2081040G2",
				ServerName: "b.replication.example", FailureDomain: "FAULT-DOMAIN-2",
				MaterialDirectory: "/var/lib/terrabase/attempt-b/material", ReplicationIP: "10.0.0.12", ReplicationPort: 9443,
				ClientIP: "10.0.0.12", ClientPort: 9465},
		},
		Recipient: RecipientGrant{PublicKey: recipient.PublicKey().Bytes(), ExpiresAt: time.Now().UTC().Add(time.Hour).Truncate(time.Second)},
	}
	spec.Recipient.Signature = ed25519.Sign(signer, RecipientGrantMessage(spec))
	return spec, public, recipient
}

func initialSQLFixture(t *testing.T) (InitialSpec, ed25519.PublicKey, *ecdh.PrivateKey) {
	t.Helper()
	spec, _, recipient := initialFixture(t)
	public, signer, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	spec.SQLTables = []InitialSQLTable{{
		TableID: "248H248H24EH288H248H248H24", Name: "items",
		KeyColumn: "id", PayloadColumn: "body",
	}}
	for index := range spec.Members {
		spec.Members[index].SQLListenPort = 5432
	}
	spec.Recipient.Signature = ed25519.Sign(signer, RecipientGrantMessage(spec))
	return spec, public, recipient
}

func TestInitialMultiCatalogAuthorityBindsCanonicalCatalogsAndActiveRows(t *testing.T) {
	spec, signer, _ := initialFixture(t)
	catalogs, err := initialCatalogs(spec.Catalogs)
	if err != nil || len(catalogs) != 2 || !bytes.Equal(catalogs[0].Bytes[80:88], []byte("TBSCH001")) ||
		len(catalogs[0].Bytes) != 102 || len(catalogs[0].Bytes[80:len(catalogs[0].Bytes)-4]) != 18 {
		t.Fatalf("two canonical initial catalogs were not accepted: %v", err)
	}
	bundle, err := GenerateInitial(spec, signer, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	certificate := bundle.Authority.Certificate
	if binary.LittleEndian.Uint16(certificate[82:84]) != 2 ||
		binary.LittleEndian.Uint16(certificate[84:86]) != 2 ||
		!bytes.Contains(certificate, catalogs[0].Bytes) || !bytes.Contains(certificate, catalogs[1].Bytes) {
		t.Fatal("signed authority omitted a catalog or active binding")
	}
	active := certificate[len(certificate)-ed25519.SignatureSize-2*56 : len(certificate)-ed25519.SignatureSize]
	for index, catalog := range catalogs {
		collection, err := canonicalID(catalog.CollectionID)
		if err != nil {
			t.Fatal(err)
		}
		digest, err := hex.DecodeString(catalog.SchemaDigest)
		if err != nil {
			t.Fatal(err)
		}
		row := active[index*56 : (index+1)*56]
		if !bytes.Equal(row[:16], collection[:]) || binary.LittleEndian.Uint64(row[16:24]) != 1 ||
			!bytes.Equal(row[24:], digest) {
			t.Fatalf("active binding %d differs from its signed catalog", index)
		}
	}
	if err := validateBundleForSpec(spec, bundle); err != nil {
		t.Fatalf("stored multi-catalog authority did not revalidate: %v", err)
	}
	reversed := []InitialCatalogInput{spec.Catalogs[1], spec.Catalogs[0]}
	if _, err := initialCatalogs(reversed); err == nil {
		t.Fatal("out-of-order catalogs were accepted")
	}
	duplicate := []InitialCatalogInput{spec.Catalogs[0], spec.Catalogs[0]}
	if _, err := initialCatalogs(duplicate); err == nil {
		t.Fatal("duplicate catalogs were accepted")
	}
	corrupt := []InitialCatalogInput{spec.Catalogs[0], spec.Catalogs[1]}
	corrupt[0].CanonicalCatalog = bytes.Clone(corrupt[0].CanonicalCatalog)
	corrupt[0].CanonicalCatalog[len(corrupt[0].CanonicalCatalog)-1] ^= 1
	if _, err := initialCatalogs(corrupt); err == nil {
		t.Fatal("corrupted canonical catalog was accepted")
	}
	oldVersion := []InitialCatalogInput{spec.Catalogs[0], spec.Catalogs[1]}
	oldVersion[1].CanonicalCatalog = bytes.Clone(oldVersion[1].CanonicalCatalog)
	oldCatalog := oldVersion[1].CanonicalCatalog
	copy(oldCatalog[80:88], "TBSCH002")
	oldSchema := oldCatalog[80 : len(oldCatalog)-4]
	binary.LittleEndian.PutUint32(oldSchema[len(oldSchema)-4:], crc32.Checksum(oldSchema[:len(oldSchema)-4], authorityCRC))
	oldDigest := sha256.Sum256(oldSchema)
	copy(oldCatalog[44:76], oldDigest[:])
	binary.LittleEndian.PutUint32(oldCatalog[len(oldCatalog)-4:], crc32.Checksum(oldCatalog[:len(oldCatalog)-4], authorityCRC))
	if _, err := initialCatalogs(oldVersion); err == nil {
		t.Fatal("unsupported schema version was accepted")
	}
	if bytes.Equal(RecipientGrantMessage(spec), RecipientGrantMessage(InitialSpec{PlacementDatabaseID: spec.PlacementDatabaseID,
		PartitionID: spec.PartitionID, Scope: spec.Scope, Catalogs: corrupt, Recipient: spec.Recipient})) {
		t.Fatal("recipient grant did not bind exact catalog bytes")
	}
}

func TestGenerateInitialBindsAuthorityTLSRegistryAndCustomerCiphertext(t *testing.T) {
	spec, signer, recipient := initialFixture(t)
	bundle, err := GenerateInitial(spec, signer, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	if bundle.Authority.ConfigurationID == "" || len(bundle.Authority.Certificate) < ed25519.SignatureSize ||
		len(bundle.Retained.AuthoritySigner) != ed25519.PrivateKeySize ||
		len(bundle.Retained.ReplicationCA) != ed25519.PrivateKeySize || len(bundle.Retained.HTTPSCA) != ed25519.PrivateKeySize {
		t.Fatal("initial authority or retained continuity keys are missing")
	}
	certificate := bundle.Authority.Certificate
	signed := append([]byte("TB-AUTHORITY-FIXED-V2\x00"), certificate[:len(certificate)-ed25519.SignatureSize]...)
	if !ed25519.Verify(bundle.Authority.TrustedKey, signed, certificate[len(certificate)-ed25519.SignatureSize:]) {
		t.Fatal("TerraBase authority signature does not verify")
	}
	configuration := sha256.Sum256(append([]byte("TB-CONFIG-FIXED-V2\x00"), certificate[:len(certificate)-ed25519.SignatureSize]...))
	if bundle.Authority.ConfigurationID != hex.EncodeToString(configuration[:]) {
		t.Fatal("TerraBase authority configuration ID is wrong")
	}
	liveConfig, err := spec.LiveS3.ConfigJSON()
	if err != nil {
		t.Fatal(err)
	}
	liveConfigDigest := sha256.Sum256(liveConfig)
	for index, member := range bundle.Members {
		if member.MemberID != spec.Members[index].MemberID || len(member.Files) != len(initialHostFiles) {
			t.Fatalf("member %d file graph is incomplete", index)
		}
		liveFile, present := member.Files["signed-v2-s3-config.json"]
		if !present || !bytes.Equal(liveFile.Contents, liveConfig) ||
			liveFile.SHA256 != hex.EncodeToString(liveConfigDigest[:]) {
			t.Fatalf("member %d lacks the exact signed ObjectDurable target", index)
		}
		for name, file := range member.Files {
			digest := sha256.Sum256(file.Contents)
			if file.SHA256 != hex.EncodeToString(digest[:]) || len(file.Contents) == 0 {
				t.Fatalf("member %d file %s has wrong digest", index, name)
			}
		}
		if !bytes.Equal(member.Files["authority.tbca"].Contents, certificate) ||
			!bytes.Equal(member.Files["trusted-public-key"].Contents, bundle.Authority.TrustedKey) {
			t.Fatal("member has different authority material")
		}
		verifyMemberTLS(t, spec.Members[index], member)
		if bytes.Contains(member.Files["client-api-keys.json"].Contents, []byte("tbk1.")) {
			t.Fatal("host registry contains a bearer token")
		}
		for _, file := range member.Files {
			if bytes.Contains(file.Contents, bundle.Retained.AuthoritySigner) ||
				bytes.Contains(file.Contents, bundle.Retained.ReplicationCA) ||
				bytes.Contains(file.Contents, bundle.Retained.HTTPSCA) {
				t.Fatal("host file contains a retained signing key")
			}
		}
	}
	customer, err := OpenCustomerEnvelope(spec, bundle.Customer, recipient)
	if err != nil {
		t.Fatal(err)
	}
	if customer.Version != 1 || !strings.HasPrefix(customer.Token, "tbk1.") || customer.HTTPSCAPEM == "" {
		t.Fatal("customer ciphertext does not contain the expected token and HTTPS CA")
	}
	parts := strings.Split(customer.Token, ".")
	if len(parts) != 3 {
		t.Fatal("customer token grammar is invalid")
	}
	id, err := entityid.Parse(parts[1])
	if err != nil {
		t.Fatal("customer token ID is invalid")
	}
	secret, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil || len(secret) != 32 {
		t.Fatal("customer token secret is invalid")
	}
	material := append([]byte("TB-APIKEY-V1\x00"), id[:]...)
	material = append(material, secret...)
	verifier := sha256.Sum256(material)
	caDigest := sha256.Sum256([]byte(customer.HTTPSCAPEM))
	if bundle.Customer.TokenID != parts[1] || bundle.Customer.VerifierSHA256 != hex.EncodeToString(verifier[:]) ||
		bundle.Customer.HTTPSCASHA256 != hex.EncodeToString(caDigest[:]) {
		t.Fatal("customer plaintext differs from public producer commitment")
	}
	var registry apiKeyRegistry
	if err := json.Unmarshal(bundle.Members[0].Files["client-api-keys.json"].Contents, &registry, json.RejectUnknownMembers(true)); err != nil {
		t.Fatal(err)
	}
	if len(registry.Keys) != 1 || registry.Keys[0].VerifierSHA256 != hex.EncodeToString(verifier[:]) ||
		registry.Keys[0].Tenant != spec.Scope.TenantID || registry.Keys[0].Database != spec.Scope.DatabaseID ||
		registry.Keys[0].Shard != "7" || !slices.Equal(registry.Keys[0].Collections, initialCollectionIDs(spec.Catalogs)) {
		t.Fatal("host verifier or scope differs from encrypted customer token")
	}
	if !bytes.Equal(bundle.Members[0].Files["client-api-keys.json"].Contents,
		bundle.Members[1].Files["client-api-keys.json"].Contents) {
		t.Fatal("two members have different initial API grants")
	}
}

func verifyMemberTLS(t *testing.T, spec InitialMember, member MemberBundle) {
	t.Helper()
	server := member.Files["server.crt"].Contents
	serverKey := member.Files["server.key"].Contents
	pair, err := tls.X509KeyPair(server, serverKey)
	if err != nil || len(pair.Certificate) == 0 {
		t.Fatalf("replication key pair: %v", err)
	}
	leaf, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	leafDigest := sha256.Sum256(pair.Certificate[0])
	if hex.EncodeToString(leafDigest[:]) != member.TLSLeafSHA256 {
		t.Fatal("replication leaf differs from signed authority")
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(member.Files["server-ca.pem"].Contents) ||
		!bytes.Equal(member.Files["server-ca.pem"].Contents, member.Files["client-ca.pem"].Contents) {
		t.Fatal("replication CA roots differ")
	}
	for _, usage := range []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth} {
		if _, err := leaf.Verify(x509.VerifyOptions{Roots: pool, DNSName: spec.ServerName,
			KeyUsages: []x509.ExtKeyUsage{usage}}); err != nil {
			t.Fatalf("replication certificate cannot serve both TLS roles: %v", err)
		}
	}
	https, err := tls.X509KeyPair(member.Files["client-chain.pem"].Contents,
		member.Files["client-private-key.pem"].Contents)
	if err != nil || len(https.Certificate) == 0 {
		t.Fatalf("HTTPS key pair: %v", err)
	}
	httpsLeaf, err := x509.ParseCertificate(https.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	httpsRoots := x509.NewCertPool()
	if !httpsRoots.AppendCertsFromPEM(member.Files["client-chain.pem"].Contents) {
		t.Fatal("HTTPS CA chain is invalid")
	}
	if _, err := httpsLeaf.Verify(x509.VerifyOptions{Roots: httpsRoots, DNSName: spec.ClientIP,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}); err != nil {
		t.Fatalf("HTTPS leaf is not bound to its private IP: %v", err)
	}
}

func TestGenerateInitialIssuesECDSAClientHTTPSLeaves(t *testing.T) {
	spec, signer, _ := initialFixture(t)
	bundle, err := GenerateInitial(spec, signer, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	for _, member := range bundle.Members {
		pair, err := tls.X509KeyPair(member.Files["client-chain.pem"].Contents, member.Files["client-private-key.pem"].Contents)
		if err != nil {
			t.Fatal(err)
		}
		leaf, err := x509.ParseCertificate(pair.Certificate[0])
		if err != nil {
			t.Fatal(err)
		}
		public, ok := leaf.PublicKey.(*ecdsa.PublicKey)
		if !ok || public.Curve != elliptic.P256() {
			t.Fatalf("member %s client HTTPS leaf key is %T, want ECDSA P-256", member.MemberID, leaf.PublicKey)
		}
		replication, err := tls.X509KeyPair(member.Files["server.crt"].Contents, member.Files["server.key"].Contents)
		if err != nil {
			t.Fatal(err)
		}
		if _, ok := replication.PrivateKey.(ed25519.PrivateKey); !ok {
			t.Fatalf("member %s replication key is %T, want Ed25519", member.MemberID, replication.PrivateKey)
		}
	}
}

func TestGenerateInitialRejectsRecipientAndMemberSubstitution(t *testing.T) {
	spec, signer, _ := initialFixture(t)
	spec.Recipient.ExpiresAt = spec.Recipient.ExpiresAt.Add(500 * time.Millisecond)
	if _, err := GenerateInitial(spec, signer, time.Now().UTC()); err == nil {
		t.Fatal("subsecond recipient expiry extended a second-precision grant")
	}
	spec, signer, _ = initialFixture(t)
	spec.Members[0].ClientIP = "10.0.0.99"
	if _, err := GenerateInitial(spec, signer, time.Now().UTC()); err == nil {
		t.Fatal("mismatched HTTPS and replication IP was accepted")
	}
	spec.Members[0].ReplicationIP = spec.Members[0].ClientIP
	spec.Recipient.PublicKey[0] ^= 1
	if _, err := GenerateInitial(spec, signer, time.Now().UTC()); err == nil {
		t.Fatal("substituted customer recipient was accepted")
	}
	spec, signer, _ = initialFixture(t)
	spec.Members[0].ReplicationIP = "127.0.0.1"
	if _, err := GenerateInitial(spec, signer, time.Now().UTC()); err == nil {
		t.Fatal("loopback replication IP was accepted")
	}
	spec, signer, _ = initialFixture(t)
	spec.Members[0], spec.Members[1] = spec.Members[1], spec.Members[0]
	if _, err := GenerateInitial(spec, signer, time.Now().UTC()); err == nil {
		t.Fatal("out-of-order authority members were accepted")
	}
}

func TestSQLSchemaBundleMatchesFrozenRustRowVector(t *testing.T) {
	table := InitialSQLTable{
		TableID: "248H248H24EH288H248H248H24", Name: "items",
		KeyColumn: "id", PayloadColumn: "body",
	}
	row, err := sqlTableRow(table)
	if err != nil {
		t.Fatal(err)
	}
	wantRow, err := hex.DecodeString("44444444444474448444444444444444010000000000000001000200056974656d7302696404626f6479")
	if err != nil || !bytes.Equal(row, wantRow) || len(row) != 42 {
		t.Fatalf("canonical SQL row = %x (%d bytes), want frozen Rust vector", row, len(row))
	}
	digestInput := append([]byte(sqlTableDigestDomain), row...)
	digest := sha256.Sum256(digestInput)
	if got := hex.EncodeToString(digest[:]); got != "7d9ad68383d500d959e80918e2db23e34ffa72e26d8a07a7bd06f7a58ce0e6bc" {
		t.Fatalf("SQL table digest = %s, want frozen Rust vector", got)
	}

	seed := bytes.Repeat([]byte{0x42}, ed25519.SeedSize)
	signer := ed25519.NewKeyFromSeed(seed)
	bundle, err := encodeSQLSchemaBundle(AuthorityScope{
		ClusterID: "01081G81860W40J2GB1G6GW3RG",
		TenantID:  "0G000000000000000000000001", DatabaseID: "10000000000000000000000001",
		ShardID: 7, Epoch: 1,
	}, strings.Repeat("a", 64), []InitialSQLTable{table}, signer)
	if err != nil {
		t.Fatal(err)
	}
	if len(bundle) != 218 || binary.LittleEndian.Uint32(bundle[8:12]) != 154 ||
		binary.LittleEndian.Uint16(bundle[12:14]) != sqlSchemaBundleVersion ||
		binary.LittleEndian.Uint16(bundle[14:16]) != 1 || !bytes.Equal(bundle[sqlSchemaHeaderBytes:len(bundle)-sqlSchemaSignatureBytes], wantRow) {
		t.Fatalf("SQL bundle header or payload differs from frozen ABI: len=%d", len(bundle))
	}
	signingInput := append([]byte(sqlSchemaSignDomain), bundle[:len(bundle)-sqlSchemaSignatureBytes]...)
	if !ed25519.Verify(signer.Public().(ed25519.PublicKey), signingInput, bundle[len(bundle)-sqlSchemaSignatureBytes:]) {
		t.Fatal("SQL bundle signature does not verify over the Rust domain and payload")
	}
	tableSetDigest, err := sqlTableSetDigest([]InitialSQLTable{table})
	if err != nil || tableSetDigest != "b47712d2f954fbb5321dd225d5d4787b5b81af89c03087ddeb363a63b3ce9178" {
		t.Fatalf("SQL table-set digest = %s, want frozen grant digest: %v", tableSetDigest, err)
	}
}

func TestNoSQLInitialMaterialPreservesGenerationOneContract(t *testing.T) {
	spec, signer, _ := initialFixture(t)
	wantGrant := []byte(recipientDomain + spec.PlacementDatabaseID + "/" + spec.PartitionID + "/" + spec.Scope.ClusterID + "/" +
		spec.Scope.TenantID + "/" + spec.Scope.DatabaseID + "/" +
		strconv.FormatUint(spec.Scope.ShardID, 10) + "/" + catalogSetDigest(spec.Catalogs) + "/" +
		hex.EncodeToString(spec.Recipient.PublicKey) + "/" + strconv.FormatInt(spec.Recipient.ExpiresAt.UTC().Unix(), 10))
	if got := RecipientGrantMessage(spec); !bytes.Equal(got, wantGrant) || !ed25519.Verify(signer, got, spec.Recipient.Signature) {
		t.Fatal("no-SQL recipient grant no longer uses its exact generation-one message")
	}

	bundle, err := GenerateInitial(spec, signer, time.Now().UTC())
	if err != nil {
		t.Fatalf("produce generation-one no-SQL material: %v", err)
	}
	if err := validateBundleForSpec(spec, bundle); err != nil {
		t.Fatalf("validate generation-one no-SQL material: %v", err)
	}
	for index, member := range bundle.Members {
		if len(member.Files) != len(initialHostFiles) {
			t.Fatalf("member %d generation-one file count = %d, want %d", index, len(member.Files), len(initialHostFiles))
		}
		if _, exists := member.Files[sqlSchemaBundleFileName]; exists {
			t.Fatalf("member %d has an SQL bundle without an SQL table set", index)
		}
		for filename, field := range map[string]string{
			"client-config.json":   "sql_listen_addr",
			"client-api-keys.json": "table_ids",
		} {
			if bytes.Contains(member.Files[filename].Contents, []byte(`"`+field+`"`)) {
				t.Fatalf("member %d %s unexpectedly contains %s", index, filename, field)
			}
		}
	}
}

func TestGenerateInitialBindsSQLBundleAndTableGrants(t *testing.T) {
	spec, signer, _ := initialSQLFixture(t)
	bundle, err := GenerateInitial(spec, signer, time.Now().UTC())
	if err != nil {
		t.Fatalf("produce SQL material: %v", err)
	}
	if err := validateBundleForSpec(spec, bundle); err != nil {
		t.Fatalf("validate SQL material: %v", err)
	}
	left, leftOK := bundle.Members[0].Files[sqlSchemaBundleFileName]
	right, rightOK := bundle.Members[1].Files[sqlSchemaBundleFileName]
	if !leftOK || !rightOK || len(left.Contents) > sqlSchemaBundleMaxBytes ||
		!bytes.Equal(left.Contents, right.Contents) || left.SHA256 != right.SHA256 {
		t.Fatal("members do not hold the same bounded immutable SQL schema bundle")
	}
	for index, member := range bundle.Members {
		var config struct {
			SQLListenAddress string `json:"sql_listen_addr"`
		}
		if err := json.Unmarshal(member.Files["client-config.json"].Contents, &config); err != nil ||
			config.SQLListenAddress != sqlListenAddress(spec.Members[index]) {
			t.Fatalf("member %d SQL listener is not bound into client config: %v", index, err)
		}
		var registry apiKeyRegistry
		if err := json.Unmarshal(member.Files["client-api-keys.json"].Contents, &registry); err != nil ||
			len(registry.Keys) != 1 || !slices.Equal(registry.Keys[0].TableIDs, []string{"248H248H24EH288H248H248H24"}) ||
			!slices.Equal(registry.Keys[0].Collections, initialCollectionIDs(spec.Catalogs)) {
			t.Fatalf("member %d registry does not bind SQL table and catalog grants: %v", index, err)
		}
		if len(member.Files) != len(initialHostFiles)+1 {
			t.Fatalf("member %d file count = %d, want conditional 13-file SQL set", index, len(member.Files))
		}
	}

	changed := spec
	changed.SQLTables = slices.Clone(spec.SQLTables)
	changed.SQLTables[0].PayloadColumn = "value"
	if _, err := GenerateInitial(changed, signer, time.Now().UTC()); err == nil {
		t.Fatal("recipient grant authorized changed SQL definitions")
	}
	message := RecipientGrantMessage(spec)
	digest, err := sqlTableSetDigest(spec.SQLTables)
	if err != nil || !bytes.HasPrefix(message, []byte(sqlRecipientDomain)) || !bytes.Contains(message, []byte(digest)) {
		t.Fatalf("SQL recipient grant does not identify its versioned table-set digest: %v", err)
	}
	if bytes.Equal(message, RecipientGrantMessage(changed)) {
		t.Fatal("SQL recipient grant message did not change with the table-set scope")
	}
	changedScope := spec
	changedScope.Scope.ShardID++
	if bytes.Equal(message, RecipientGrantMessage(changedScope)) {
		t.Fatal("SQL recipient grant message did not bind its shard scope")
	}
	changedBundle := bundle
	changedMember := bundle.Members[0]
	changedFiles := make(map[string]File, len(changedMember.Files))
	for name, file := range changedMember.Files {
		changedFiles[name] = file
	}
	corrupted := bytes.Clone(left.Contents)
	corrupted[len(corrupted)-1] ^= 0x01
	changedFiles[sqlSchemaBundleFileName] = makeFile(corrupted)
	changedMember.Files = changedFiles
	changedBundle.Members[0] = changedMember
	if err := validateBundleForSpec(spec, changedBundle); err == nil {
		t.Fatal("re-signed SQL bundle substitution escaped exact spec validation")
	}
}

type sqlProcessPacketFile struct {
	Name   string `json:"name"`
	SHA256 string `json:"sha256"`
}

type sqlProcessPacketMember struct {
	SeatID                   string                 `json:"seat_id"`
	FilesDirectory           string                 `json:"files_directory"`
	MemberID                 string                 `json:"member_id"`
	Incarnation              string                 `json:"incarnation"`
	ServerName               string                 `json:"server_name"`
	FailureDomain            string                 `json:"failure_domain"`
	TLSLeafSHA256            string                 `json:"tls_leaf_sha256"`
	ClientListenAddress      string                 `json:"client_listen_address"`
	SQLListenAddress         string                 `json:"sql_listen_address"`
	ReplicationListenAddress string                 `json:"replication_listen_address"`
	ReplicationPeerMemberID  string                 `json:"replication_peer_member_id"`
	ReplicationPeerAddress   string                 `json:"replication_peer_address"`
	Files                    []sqlProcessPacketFile `json:"files"`
}

type sqlProcessPacketManifest struct {
	Version                     uint64                   `json:"version"`
	Scope                       AuthorityScope           `json:"scope"`
	AuthorityConfigurationID    string                   `json:"authority_configuration_id"`
	AuthoritySHA256             string                   `json:"authority_sha256"`
	TrustedPublicKeySHA256      string                   `json:"trusted_public_key_sha256"`
	SQLSchemaBundleSHA256       string                   `json:"sql_schema_bundle_sha256"`
	SQLSchemaBundlePath         string                   `json:"sql_schema_bundle_path"`
	TableSetDigest              string                   `json:"table_set_digest"`
	Tables                      []InitialSQLTable        `json:"tables"`
	Collections                 []string                 `json:"collections"`
	RecipientGrantMessageSHA256 string                   `json:"recipient_grant_message_sha256"`
	ClientTLSRootPath           string                   `json:"client_tls_root_path"`
	PGPassFile                  string                   `json:"pgpass_file"`
	SQLUsername                 string                   `json:"sql_username"`
	Members                     []sqlProcessPacketMember `json:"members"`
}

// Run with TB_SQL_PROCESS_PACKET_DIR set to a private, nonexistent absolute
// directory. The token appears only in the exported mode-0600 pgpass file.
func TestExportSQLProcessPacket(t *testing.T) {
	// TB_SQL_PROCESS_PACKET_DIR feeds the cross-language SQL process oracle.
	packetDirectory := tier.Qualification(t, "TB_SQL_PROCESS_PACKET_DIR")[0]
	if !filepath.IsAbs(packetDirectory) || filepath.Clean(packetDirectory) != packetDirectory || packetDirectory == "/" {
		t.Fatal("SQL process packet directory must be a clean absolute path")
	}
	if _, err := os.Lstat(packetDirectory); err == nil || !os.IsNotExist(err) {
		t.Fatal("SQL process packet directory must not already exist")
	}
	parent := filepath.Dir(packetDirectory)
	parentInfo, err := os.Stat(parent)
	if err != nil || !parentInfo.IsDir() {
		t.Fatal("SQL process packet parent must already exist")
	}
	staging, err := os.MkdirTemp(parent, ".terrabase-sql-process-packet-")
	if err != nil {
		t.Fatal("create private SQL process packet staging directory")
	}
	defer os.RemoveAll(staging)

	spec, _, recipient := initialFixture(t)
	activeCatalog, err := InitialCatalog("1144GJ289144GJ289144GJ2891", nil)
	if err != nil {
		t.Fatal(err)
	}
	inactiveCatalog, err := InitialCatalog("1248H248H248H248H248H248H2", nil)
	if err != nil {
		t.Fatal(err)
	}
	spec.Scope = AuthorityScope{
		ClusterID: "1H64RK2C9H64RK2C9H64RK2C9H",
		TenantID:  "21850M2GA1850M2GA1850M2GA1", DatabaseID: "2HA58N2MAHA58N2MAHA58N2MAH",
		ShardID: 7, Epoch: 1,
	}
	spec.Catalogs = []InitialCatalogInput{
		{CollectionID: activeCatalog.CollectionID, CanonicalCatalog: activeCatalog.Bytes},
		{CollectionID: inactiveCatalog.CollectionID, CanonicalCatalog: inactiveCatalog.Bytes},
	}
	spec.SQLTables = []InitialSQLTable{{
		TableID: "248H248H24EH288H248H248H24", Name: "items",
		KeyColumn: "id", PayloadColumn: "body",
	}}
	memberIDs := [2]string{
		"31C5GP2RB1C5GP2RB1C5GP2RB1",
		"3HE5RQ2WBHE5RQ2WBHE5RQ2WBH",
	}
	incarnations := [2]string{strings.Repeat("62", 16), strings.Repeat("72", 16)}
	clientIPs := [2]string{"10.0.0.11", "10.0.0.12"}
	for index := range spec.Members {
		suffix := string(rune('a' + index))
		spec.Members[index] = InitialMember{
			SeatID: "0000000000SNQ2922YA2BV9HY5" + suffix, MemberID: memberIDs[index], Incarnation: incarnations[index],
			ServerName: suffix + ".replication.example", FailureDomain: "FAULT-DOMAIN-" + strconv.Itoa(index+1),
			MaterialDirectory: filepath.Join(packetDirectory, "0000000000SNQ2922YA2BV9HY5"+suffix),
			ReplicationIP:     clientIPs[index], ReplicationPort: 9443,
			ClientIP: clientIPs[index], ClientPort: 9465, SQLListenPort: 5432,
		}
	}
	if err := os.Mkdir(filepath.Join(staging, "0000000000WM3QQGQPMW5X58P9"), 0o700); err != nil {
		t.Fatal("create member-a packet directory")
	}
	if err := os.Mkdir(filepath.Join(staging, "0000000000N9X5GQEQJ9NA9A7V"), 0o700); err != nil {
		t.Fatal("create member-b packet directory")
	}
	for index := range spec.Members {
		if len(spec.Members[index].MaterialDirectory) > 100 {
			t.Fatal("SQL process packet path exceeds the managed material path limit")
		}
	}
	_, recipientSigner, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	spec.Recipient.ExpiresAt = time.Now().UTC().Add(2 * time.Hour).Truncate(time.Second)
	spec.Recipient.Signature = ed25519.Sign(recipientSigner, RecipientGrantMessage(spec))
	bundle, err := GenerateInitial(spec, recipientSigner.Public().(ed25519.PublicKey), time.Now().UTC())
	if err != nil {
		t.Fatal("produce SQL process packet material")
	}
	customer, err := OpenCustomerEnvelope(spec, bundle.Customer, recipient)
	if err != nil {
		t.Fatal("open SQL process packet customer envelope")
	}

	writePacketFile := func(name string, contents []byte) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(staging, name), contents, 0o600); err != nil {
			t.Fatal("write SQL process packet file")
		}
	}
	packetMembers := make([]sqlProcessPacketMember, 0, len(spec.Members))
	for index, member := range spec.Members {
		memberDirectoryName := "0000000000SNQ2922YA2BV9HY5" + string(rune('a'+index))
		memberDirectory := filepath.Join(staging, memberDirectoryName)
		files := bundle.Members[index].Files
		fileNames := make([]string, 0, len(files))
		for name := range files {
			fileNames = append(fileNames, name)
		}
		slices.Sort(fileNames)
		fileHashes := make([]sqlProcessPacketFile, 0, len(fileNames))
		for _, name := range fileNames {
			file := files[name]
			digest := sha256.Sum256(file.Contents)
			if file.SHA256 != hex.EncodeToString(digest[:]) {
				t.Fatalf("producer returned an invalid %s digest", name)
			}
			if err := os.WriteFile(filepath.Join(memberDirectory, name), file.Contents, 0o600); err != nil {
				t.Fatal("write SQL process packet member file")
			}
			fileHashes = append(fileHashes, sqlProcessPacketFile{Name: name, SHA256: file.SHA256})
		}
		peer := spec.Members[0]
		if peer.MemberID == member.MemberID {
			peer = spec.Members[1]
		}
		packetMembers = append(packetMembers, sqlProcessPacketMember{
			SeatID: member.SeatID, FilesDirectory: memberDirectoryName,
			MemberID: member.MemberID, Incarnation: member.Incarnation,
			ServerName: member.ServerName, FailureDomain: member.FailureDomain,
			TLSLeafSHA256:            bundle.Members[index].TLSLeafSHA256,
			ClientListenAddress:      net.JoinHostPort(member.ClientIP, strconv.Itoa(int(member.ClientPort))),
			SQLListenAddress:         sqlListenAddress(member),
			ReplicationListenAddress: net.JoinHostPort(member.ReplicationIP, strconv.Itoa(int(member.ReplicationPort))),
			ReplicationPeerMemberID:  peer.MemberID,
			ReplicationPeerAddress:   net.JoinHostPort(peer.ReplicationIP, strconv.Itoa(int(peer.ReplicationPort))),
			Files:                    fileHashes,
		})
	}
	firstFiles := bundle.Members[0].Files
	writePacketFile("authority.tbca", bundle.Authority.Certificate)
	writePacketFile("authority.pub", bundle.Authority.TrustedKey)
	writePacketFile("sql-schema.tbsqb", firstFiles[sqlSchemaBundleFileName].Contents)
	writePacketFile("https-ca.pem", []byte(customer.HTTPSCAPEM))
	keyID := strings.Split(customer.Token, ".")[1]
	var passfile strings.Builder
	for _, member := range spec.Members {
		passfile.WriteString(strings.Join([]string{
			member.ClientIP, strconv.Itoa(int(member.SQLListenPort)), spec.Scope.DatabaseID, keyID, customer.Token,
		}, ":"))
		passfile.WriteByte('\n')
	}
	writePacketFile("pgpass", []byte(passfile.String()))
	tableSetDigest, err := sqlTableSetDigest(spec.SQLTables)
	if err != nil {
		t.Fatal("digest SQL process packet table set")
	}
	grantMessageDigest := sha256.Sum256(RecipientGrantMessage(spec))
	bundleDigest := firstFiles[sqlSchemaBundleFileName].SHA256
	manifest := sqlProcessPacketManifest{
		Version: 1, Scope: spec.Scope, AuthorityConfigurationID: bundle.Authority.ConfigurationID,
		AuthoritySHA256:        sha256Hex(bundle.Authority.Certificate),
		TrustedPublicKeySHA256: sha256Hex(bundle.Authority.TrustedKey),
		SQLSchemaBundleSHA256:  bundleDigest, SQLSchemaBundlePath: "sql-schema.tbsqb",
		TableSetDigest: tableSetDigest, Tables: spec.SQLTables,
		Collections:                 initialCollectionIDs(spec.Catalogs),
		RecipientGrantMessageSHA256: hex.EncodeToString(grantMessageDigest[:]),
		ClientTLSRootPath:           "https-ca.pem", PGPassFile: "pgpass", SQLUsername: keyID, Members: packetMembers,
	}
	manifestBytes, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal("encode SQL process packet manifest")
	}
	writePacketFile("manifest.json", manifestBytes)
	if err := os.Rename(staging, packetDirectory); err != nil {
		t.Fatal("atomically publish SQL process packet")
	}
	staging = ""
	t.Logf("exported SQL process packet path=%s schema_bundle_sha256=%s", packetDirectory, bundleDigest)
}

func TestInitialSQLSpecRejectsInvalidIdentityNamesGrantsAndPorts(t *testing.T) {
	tests := []struct {
		name   string
		change func(*InitialSpec)
	}{
		{"invalid version", func(spec *InitialSpec) { spec.SQLTables[0].TableID = "248H248H24CH288H248H248H24" }},
		{"invalid variant", func(spec *InitialSpec) { spec.SQLTables[0].TableID = "248H248H24EH278H248H248H24" }},
		{"reserved table name", func(spec *InitialSpec) { spec.SQLTables[0].Name = "tb_items" }},
		{"invalid column name", func(spec *InitialSpec) { spec.SQLTables[0].PayloadColumn = "Payload" }},
		{"duplicate columns", func(spec *InitialSpec) { spec.SQLTables[0].PayloadColumn = spec.SQLTables[0].KeyColumn }},
		{"missing SQL port", func(spec *InitialSpec) { spec.Members[0].SQLListenPort = 0 }},
		{"HTTPS port reuse", func(spec *InitialSpec) { spec.Members[0].SQLListenPort = spec.Members[0].ClientPort }},
		{"replication port reuse", func(spec *InitialSpec) { spec.Members[0].SQLListenPort = spec.Members[0].ReplicationPort }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			spec, signer, _ := initialSQLFixture(t)
			test.change(&spec)
			if _, err := GenerateInitial(spec, signer, time.Now().UTC()); err == nil {
				t.Fatal("invalid SQL-enabled initial spec was accepted")
			}
		})
	}

	t.Run("duplicate names", func(t *testing.T) {
		spec, signer, _ := initialSQLFixture(t)
		spec.SQLTables = append(spec.SQLTables, InitialSQLTable{
			TableID: "248H248H24EH288H248H248H25", Name: "items", KeyColumn: "id", PayloadColumn: "body",
		})
		if _, err := GenerateInitial(spec, signer, time.Now().UTC()); err == nil {
			t.Fatal("duplicate SQL table names were accepted")
		}
	})
	t.Run("table ID reuses catalog identity", func(t *testing.T) {
		spec, signer, _ := initialSQLFixture(t)
		catalog, err := InitialCatalog(spec.SQLTables[0].TableID, nil)
		if err != nil {
			t.Fatal(err)
		}
		spec.Catalogs[1] = InitialCatalogInput{CollectionID: catalog.CollectionID, CanonicalCatalog: catalog.Bytes}
		if _, err := GenerateInitial(spec, signer, time.Now().UTC()); err == nil {
			t.Fatal("SQL table ID equal to a catalog collection ID was accepted")
		}
	})
}

// Run with TB_MANAGED_AUTHORITY_EXPORT_DIR set to a private disposable absolute
// directory, then pass manifest.json to the TerraBase process oracle.
func TestExportManagedAuthorityPacket(t *testing.T) {
	// TB_MANAGED_AUTHORITY_EXPORT_DIR feeds the cross-language decoder oracle.
	directory := tier.Qualification(t, "TB_MANAGED_AUTHORITY_EXPORT_DIR")[0]
	if !filepath.IsAbs(directory) {
		t.Fatal("export directory must be absolute")
	}
	spec, _, recipient := initialFixture(t)
	_, recipientSigner, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	for index, name := range []string{"a", "b"} {
		spec.Members[index].MaterialDirectory = filepath.Join(directory, name)
	}
	spec.Recipient.Signature = ed25519.Sign(recipientSigner, RecipientGrantMessage(spec))
	catalogs, err := initialCatalogs(spec.Catalogs)
	if err != nil {
		t.Fatal(err)
	}
	bundle, err := GenerateInitial(spec, recipientSigner.Public().(ed25519.PublicKey), time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	manifest := map[string]any{"profile": "managed-member-serving-v1", "members": map[string]any{}}
	members := manifest["members"].(map[string]any)
	for index, name := range []string{"a", "b"} {
		member := bundle.Members[index]
		if err := os.MkdirAll(spec.Members[index].MaterialDirectory, 0o700); err != nil {
			t.Fatal(err)
		}
		inputs := map[string]any{}
		for key, fileName := range map[string]string{
			"authority_tbca": "authority.tbca", "trusted_public_key": "trusted-public-key",
			"server_crt": "server.crt", "server_key": "server.key", "server_ca_pem": "server-ca.pem",
			"client_ca_pem": "client-ca.pem", "client_chain_pem": "client-chain.pem",
			"client_private_key_pem": "client-private-key.pem", "client_api_keys_json": "client-api-keys.json",
			"client_config_json": "client-config.json", "client_managed_manifest_json": "client-managed-manifest.json",
		} {
			file := member.Files[fileName]
			path := filepath.Join(spec.Members[index].MaterialDirectory, fileName)
			writer, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := writer.Write(file.Contents); err != nil {
				writer.Close()
				t.Fatal(err)
			}
			if err := writer.Close(); err != nil {
				t.Fatal(err)
			}
			inputs[key] = map[string]any{"path": path, "sha256": file.SHA256}
		}
		seat := spec.Members[index]
		members[name] = map[string]any{"inputs": inputs, "guest_config": map[string]any{
			"member": map[string]any{"scope": map[string]any{
				"cluster_id": spec.Scope.ClusterID, "tenant_id": spec.Scope.TenantID,
				"database_id": spec.Scope.DatabaseID, "shard_id": spec.Scope.ShardID,
				"member_id": seat.MemberID, "incarnation": seat.Incarnation,
			}},
			"authority": map[string]any{"epoch": spec.Scope.Epoch,
				"configuration_id": bundle.Authority.ConfigurationID, "tls_leaf_sha256": member.TLSLeafSHA256},
			"failure_domain": seat.FailureDomain, "collection_id": catalogs[0].CollectionID,
			"schema_generation": uint64(1), "schema_digest": catalogs[0].SchemaDigest,
		}}
	}
	customer, err := OpenCustomerEnvelope(spec, bundle.Customer, recipient)
	if err != nil {
		t.Fatal(err)
	}
	customerMaterial, err := json.Marshal(customer)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(customerMaterial)
	customerPath := filepath.Join(directory, "customer-material.json")
	if err := os.WriteFile(customerPath, customerMaterial, 0o600); err != nil {
		t.Fatal(err)
	}
	customerSHA := sha256.Sum256(customerMaterial)
	manifest["customer_material"] = map[string]any{"path": customerPath, "sha256": hex.EncodeToString(customerSHA[:])}
	wire, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(directory, "manifest.json")
	if err := os.WriteFile(path, wire, 0o600); err != nil {
		t.Fatal(err)
	}
	t.Logf("TerraBase decoder manifest: %s", path)
}
