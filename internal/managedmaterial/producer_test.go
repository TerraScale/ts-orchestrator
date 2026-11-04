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
	"encoding/hex"
	"encoding/json/v2"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/entityid"
	"github.com/TerraScale/ts-orchestrator/internal/oci"
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
		Scope: AuthorityScope{ClusterID: "0102030405060708090a0b0c0d0e0f10",
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
			{SeatID: "000000000082AXF7GZQT1D126Y", MemberID: "20000000000000000000000001", Incarnation: "01010101010101010101010101010101",
				ServerName: "a.replication.example", FailureDomain: "FAULT-DOMAIN-1",
				MaterialDirectory: "/var/lib/terrabase/attempt-a/material", ReplicationIP: "10.0.0.11", ReplicationPort: 9443,
				ClientIP: "10.0.0.11", ClientPort: 9465},
			{SeatID: "0000000000XG8SBD7XGE97V28G", MemberID: "20000000000000000000000002", Incarnation: "02020202020202020202020202020202",
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
