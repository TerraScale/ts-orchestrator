package managedmaterial

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/binary"
	"encoding/hex"
	"encoding/pem"
	"testing"
	"time"
)

func successorFixture(t *testing.T, service PreparationService, spec InitialSpec, now time.Time) SuccessorRequest {
	t.Helper()
	_, current, err := service.CurrentBundle(t.Context(), spec.PlacementDatabaseID, spec.PartitionID)
	if err != nil {
		t.Fatal(err)
	}
	block, rest := pem.Decode(current.Members[0].Files["server-ca.pem"].Contents)
	if block == nil || len(rest) != 0 {
		t.Fatal("current replication CA PEM is invalid")
	}
	certificate, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	ca := certificateAuthority{Certificate: certificate, RawPEM: current.Members[0].Files["server-ca.pem"].Contents}
	request := SuccessorRequest{Epoch: spec.Scope.Epoch + 1}
	for index := range request.Members {
		name := []string{"c.replication.example", "d.replication.example"}[index]
		leaf, _, _, err := generateLeaf(ca, current.Retained.ReplicationCA, leafKeyEd25519, name, nil, now,
			[]x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth})
		if err != nil {
			t.Fatal(err)
		}
		request.Members[index] = AuthorityMember{
			MemberID:      []string{"2G000000000000000000000001", "2G000000000000000000000002"}[index],
			Incarnation:   []string{"03030303030303030303030303030303", "04040404040404040404040404040404"}[index],
			ServerName:    name,
			FailureDomain: []string{"FAULT-DOMAIN-1", "FAULT-DOMAIN-2"}[index],
			LeafDER:       leaf,
		}
	}
	return request
}

func TestProduceSuccessorBindsCurrentReceiptAndExactSQLArtifacts(t *testing.T) {
	service, _, _, _ := preparationFixture(t)
	spec, recipientSigner, _ := initialSQLFixture(t)
	service.RecipientSigner = recipientSigner
	now := time.Now().UTC().Truncate(time.Second)
	if _, err := service.PrepareInitial(t.Context(), 9, spec.PartitionID, spec, now); err != nil {
		t.Fatal(err)
	}
	request := successorFixture(t, service, spec, now)
	material, err := service.ProduceSuccessor(t.Context(), spec.PlacementDatabaseID, spec.PartitionID, request, now)
	if err != nil {
		t.Fatal(err)
	}
	repeat, err := service.ProduceSuccessor(t.Context(), spec.PlacementDatabaseID, spec.PartitionID, request, now)
	if err != nil || !bytes.Equal(repeat.SuccessorAuthority.Certificate, material.SuccessorAuthority.Certificate) ||
		!bytes.Equal(repeat.SuccessorSQLBundle, material.SuccessorSQLBundle) {
		t.Fatalf("same staged leaves did not reproduce exact signed bytes: %v", err)
	}
	_, current, err := service.CurrentBundle(t.Context(), spec.PlacementDatabaseID, spec.PartitionID)
	if err != nil {
		t.Fatal(err)
	}
	oldSQL := current.Members[0].Files[sqlSchemaBundleFileName].Contents
	if material.PredecessorScope != spec.Scope || material.SuccessorScope.Epoch != spec.Scope.Epoch+1 ||
		material.SuccessorScope.ClusterID != spec.Scope.ClusterID ||
		material.SuccessorScope.TenantID != spec.Scope.TenantID ||
		material.SuccessorScope.DatabaseID != spec.Scope.DatabaseID ||
		material.SuccessorScope.ShardID != spec.Scope.ShardID ||
		material.PredecessorConfigurationID != current.Authority.ConfigurationID ||
		material.SuccessorAuthority.ConfigurationID == current.Authority.ConfigurationID ||
		!bytes.Equal(material.SuccessorAuthority.TrustedKey, current.Authority.TrustedKey) ||
		material.PredecessorAuthoritySHA256 != sha256.Sum256(current.Authority.Certificate) ||
		material.SuccessorAuthoritySHA256 != sha256.Sum256(material.SuccessorAuthority.Certificate) ||
		material.TrustedKeySHA256 != sha256.Sum256(current.Authority.TrustedKey) ||
		!material.SQLPresent || material.PredecessorSQLBundleSHA256 != sha256.Sum256(oldSQL) ||
		material.SuccessorSQLBundleSHA256 != sha256.Sum256(material.SuccessorSQLBundle) ||
		material.SuccessorSQLBundleSHA256 == material.PredecessorSQLBundleSHA256 {
		t.Fatal("successor material did not bind exact authenticated predecessor and successor bytes")
	}
	if !bytes.Equal(oldSQL[sqlSchemaHeaderBytes:len(oldSQL)-ed25519.SignatureSize],
		material.SuccessorSQLBundle[sqlSchemaHeaderBytes:len(material.SuccessorSQLBundle)-ed25519.SignatureSize]) {
		t.Fatal("logical SQL table rows changed across the successor epoch")
	}
	if binary.LittleEndian.Uint64(material.SuccessorSQLBundle[104:112]) != request.Epoch {
		t.Fatal("successor SQL bundle did not bind the new epoch")
	}
	newPayload := material.SuccessorSQLBundle[:len(material.SuccessorSQLBundle)-ed25519.SignatureSize]
	if !ed25519.Verify(current.Authority.TrustedKey, append([]byte(sqlSchemaSignDomain), newPayload...),
		material.SuccessorSQLBundle[len(newPayload):]) {
		t.Fatal("successor SQL bundle is not signed by the retained authority key")
	}
	certificate := material.SuccessorAuthority.Certificate
	if !ed25519.Verify(current.Authority.TrustedKey,
		append([]byte("TB-AUTHORITY-FIXED-V2\x00"), certificate[:len(certificate)-ed25519.SignatureSize]...),
		certificate[len(certificate)-ed25519.SignatureSize:]) {
		t.Fatal("successor certificate is not signed by the retained authority key")
	}
	for index := range request.Members {
		leaf, err := x509.ParseCertificate(request.Members[index].LeafDER)
		if err != nil {
			t.Fatal(err)
		}
		wantKey := leaf.PublicKey.(ed25519.PublicKey)
		leafSHA := sha256.Sum256(leaf.Raw)
		if !bytes.Equal(material.SuccessorAttestationKeys[index], wantKey) ||
			!bytes.Equal(material.PredecessorAttestationKeys[index],
				mustCurrentLeafKey(t, current.Members[index])) ||
			material.SuccessorLeafPinsBySeat[index] != hex.EncodeToString(leafSHA[:]) ||
			material.SuccessorAuthority.MemberLeafPins[index] != hex.EncodeToString(leafSHA[:]) {
			t.Fatalf("seat %d attestation key or leaf pin differs", index)
		}
	}
	catalogs, err := initialCatalogs(spec.Catalogs)
	if err != nil {
		t.Fatal(err)
	}
	wantCatalogDigest, err := successorCatalogSetDigest(catalogs)
	if err != nil || material.DocumentCatalogSetSHA256 != wantCatalogDigest {
		t.Fatal("document catalog set digest differs from exact certified catalogs")
	}
}

func mustCurrentLeafKey(t *testing.T, member MemberBundle) ed25519.PublicKey {
	t.Helper()
	block, _ := pem.Decode(member.Files["server.crt"].Contents)
	if block == nil {
		t.Fatal("current leaf is missing")
	}
	leaf, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	return leaf.PublicKey.(ed25519.PublicKey)
}
