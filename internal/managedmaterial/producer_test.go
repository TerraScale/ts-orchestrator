package managedmaterial

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json/v2"
	"hash/crc32"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/oci"
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
	firstCatalog, err := EmptyInitialCatalog("30000000-0000-0000-0000-000000000001")
	if err != nil {
		t.Fatal(err)
	}
	secondCatalog, err := EmptyInitialCatalog("30000000-0000-0000-0000-000000000002")
	if err != nil {
		t.Fatal(err)
	}
	spec := InitialSpec{
		PlacementDatabaseID: "db-main",
		PartitionID:         "partition-a",
		Scope: AuthorityScope{ClusterID: "0102030405060708090a0b0c0d0e0f10",
			TenantID: "10000000-0000-0000-0000-000000000001", DatabaseID: "20000000-0000-0000-0000-000000000001",
			ShardID: 7, Epoch: 1},
		LiveS3: LiveS3Target{Bucket: "alpha-live", Region: "sa-saopaulo-1",
			Endpoint:   "https://alpha.compat.objectstorage.sa-saopaulo-1.oci.customer-oci.com",
			Credential: oci.SecretVersionReference{SecretOCID: "ocid1.vaultsecret.oc1.sa-saopaulo-1.alpha", VersionNumber: 3}},
		Catalogs: []InitialCatalogInput{
			{CollectionID: firstCatalog.CollectionID, CanonicalCatalog: firstCatalog.Bytes},
			{CollectionID: secondCatalog.CollectionID, CanonicalCatalog: secondCatalog.Bytes},
		},
		Members: [2]InitialMember{
			{SeatID: "permanent-a", MemberID: "40000000-0000-0000-0000-000000000001", Incarnation: "01010101010101010101010101010101",
				ServerName: "a.replication.example", FailureDomain: "FAULT-DOMAIN-1",
				MaterialDirectory: "/var/lib/terrabase/attempt-a/material", ReplicationIP: "10.0.0.11", ReplicationPort: 9443,
				ClientIP: "10.0.0.11", ClientPort: 9465},
			{SeatID: "elastic-gru", MemberID: "40000000-0000-0000-0000-000000000002", Incarnation: "02020202020202020202020202020202",
				ServerName: "b.replication.example", FailureDomain: "FAULT-DOMAIN-2",
				MaterialDirectory: "/var/lib/terrabase/attempt-b/material", ReplicationIP: "10.0.0.12", ReplicationPort: 9443,
				ClientIP: "10.0.0.12", ClientPort: 9465},
		},
		Recipient: RecipientGrant{PublicKey: recipient.PublicKey().Bytes(), ExpiresAt: time.Now().UTC().Add(time.Hour).Truncate(time.Second)},
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
		collection, err := canonicalUUID(catalog.CollectionID)
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
	id, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil || len(id) != 16 {
		t.Fatal("customer token ID is invalid")
	}
	secret, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil || len(secret) != 32 {
		t.Fatal("customer token secret is invalid")
	}
	material := append([]byte("TB-APIKEY-V1\x00"), id...)
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

// Run with TB_MANAGED_AUTHORITY_EXPORT_DIR set to a private disposable absolute
// directory, then pass manifest.json to the TerraBase process oracle.
func TestExportManagedAuthorityPacket(t *testing.T) {
	directory := os.Getenv("TB_MANAGED_AUTHORITY_EXPORT_DIR")
	if directory == "" {
		t.Skip("set TB_MANAGED_AUTHORITY_EXPORT_DIR for the cross-language decoder oracle")
	}
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
