package managedmaterial

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/binary"
	"encoding/hex"
	"encoding/json/v2"
	"encoding/pem"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/testutil/tier"
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

func TestProduceSuccessorKeepsCrossedMappingInPredecessorSeatOrder(t *testing.T) {
	service, spec, _, _ := preparationFixture(t)
	now := time.Now().UTC().Truncate(time.Second)
	if _, err := service.PrepareInitial(t.Context(), 9, spec.PartitionID, spec, now); err != nil {
		t.Fatal(err)
	}
	request := successorFixture(t, service, spec, now)
	request.Members[0].MemberID, request.Members[1].MemberID =
		request.Members[1].MemberID, request.Members[0].MemberID
	material, err := service.ProduceSuccessor(t.Context(), spec.PlacementDatabaseID, spec.PartitionID, request, now)
	if err != nil {
		t.Fatalf("crossed predecessor-to-successor seat mapping was rejected: %v", err)
	}
	firstID, err := canonicalID(request.Members[1].MemberID)
	if err != nil {
		t.Fatal(err)
	}
	certificate := material.SuccessorAuthority.Certificate
	if !bytes.Equal(certificate[86:102], firstID[:]) {
		t.Fatal("successor certificate did not sort member IDs independently")
	}
	for index := range request.Members {
		leaf, err := x509.ParseCertificate(request.Members[index].LeafDER)
		if err != nil {
			t.Fatal(err)
		}
		leafSHA := sha256.Sum256(leaf.Raw)
		if !bytes.Equal(material.SuccessorAttestationKeys[index], leaf.PublicKey.(ed25519.PublicKey)) ||
			material.SuccessorLeafPinsBySeat[index] != hex.EncodeToString(leafSHA[:]) ||
			material.SuccessorAuthority.MemberLeafPins[1-index] != hex.EncodeToString(leafSHA[:]) {
			t.Fatalf("crossed successor seat %d lost its predecessor mapping", index)
		}
	}
}

func TestProduceSuccessorAllowsMemberIDReuseWithFreshOrigins(t *testing.T) {
	service, _, _, _ := preparationFixture(t)
	spec, recipientSigner, _ := initialSQLFixture(t)
	service.RecipientSigner = recipientSigner
	now := time.Now().UTC().Truncate(time.Second)
	if _, err := service.PrepareInitial(t.Context(), 9, spec.PartitionID, spec, now); err != nil {
		t.Fatal(err)
	}
	request := successorFixture(t, service, spec, now)
	for index := range request.Members {
		request.Members[index].MemberID = spec.Members[index].MemberID
	}
	material, err := service.ProduceSuccessor(t.Context(), spec.PlacementDatabaseID, spec.PartitionID, request, now)
	if err != nil {
		t.Fatalf("reused logical member IDs with fresh incarnations were rejected: %v", err)
	}
	if material.SuccessorAuthoritySHA256 == material.PredecessorAuthoritySHA256 ||
		material.SuccessorAuthority.ConfigurationID == material.PredecessorConfigurationID ||
		material.SuccessorSQLBundleSHA256 == material.PredecessorSQLBundleSHA256 {
		t.Fatal("fresh origins did not change signed successor artifact identities")
	}
	for index := range request.Members {
		leaf, err := x509.ParseCertificate(request.Members[index].LeafDER)
		if err != nil {
			t.Fatal(err)
		}
		leafSHA := sha256.Sum256(leaf.Raw)
		if bytes.Equal(material.PredecessorAttestationKeys[index], material.SuccessorAttestationKeys[index]) ||
			!bytes.Equal(material.SuccessorAttestationKeys[index], leaf.PublicKey.(ed25519.PublicKey)) ||
			material.SuccessorLeafPinsBySeat[index] != hex.EncodeToString(leafSHA[:]) {
			t.Fatalf("reused member ID at seat %d did not carry a fresh certified leaf", index)
		}
	}
}

func TestProduceSuccessorRejectsCaseVariantOfOldIncarnation(t *testing.T) {
	service, spec, _, _ := preparationFixture(t)
	spec.Members[0].Incarnation = "a1b2c3d4e5f60718293a4b5c6d7e8f90"
	now := time.Now().UTC().Truncate(time.Second)
	if _, err := service.PrepareInitial(t.Context(), 9, spec.PartitionID, spec, now); err != nil {
		t.Fatal(err)
	}
	request := successorFixture(t, service, spec, now)
	request.Members[0].MemberID = spec.Members[0].MemberID
	request.Members[0].Incarnation = strings.ToUpper(spec.Members[0].Incarnation)
	if request.Members[0].Incarnation == spec.Members[0].Incarnation {
		t.Fatal("fixture did not change hex spelling")
	}
	if _, err := service.ProduceSuccessor(t.Context(), spec.PlacementDatabaseID,
		spec.PartitionID, request, now); err == nil {
		t.Fatal("same old origin bytes with uppercase hex were signed")
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

func TestProduceSuccessorRejectsStaleOrMismatchedMaterial(t *testing.T) {
	service, spec, _, receipts := preparationFixture(t)
	now := time.Now().UTC().Truncate(time.Second)
	if _, err := service.PrepareInitial(t.Context(), 9, spec.PartitionID, spec, now); err != nil {
		t.Fatal(err)
	}
	valid := successorFixture(t, service, spec, now)
	for name, change := range map[string]func(*SuccessorRequest){
		"stale epoch":     func(r *SuccessorRequest) { r.Epoch = spec.Scope.Epoch },
		"old incarnation": func(r *SuccessorRequest) { r.Members[0].Incarnation = spec.Members[0].Incarnation },
		"old origin pair": func(r *SuccessorRequest) {
			r.Members[0].MemberID = spec.Members[0].MemberID
			r.Members[0].Incarnation = spec.Members[0].Incarnation
		},
		"same incarnation": func(r *SuccessorRequest) { r.Members[1].Incarnation = r.Members[0].Incarnation },
		"case-variant successor incarnation": func(r *SuccessorRequest) {
			r.Members[0].Incarnation = "abcdef0123456789abcdef0123456789"
			r.Members[1].Incarnation = strings.ToUpper(r.Members[0].Incarnation)
		},
		"wrong server name": func(r *SuccessorRequest) { r.Members[0].ServerName = "wrong.replication.example" },
		"wrong leaf": func(r *SuccessorRequest) {
			r.Members[0].LeafDER = bytes.Clone(r.Members[0].LeafDER)
			r.Members[0].LeafDER[len(r.Members[0].LeafDER)-1] ^= 1
		},
	} {
		t.Run(name, func(t *testing.T) {
			request := valid
			change(&request)
			if _, err := service.ProduceSuccessor(t.Context(), spec.PlacementDatabaseID,
				spec.PartitionID, request, now); err == nil {
				t.Fatal("invalid successor material was signed")
			}
		})
	}
	receipts.entry.Payload = bytes.Clone(receipts.entry.Payload)
	receipts.entry.Payload[len(receipts.entry.Payload)-1] ^= 1
	if _, err := service.ProduceSuccessor(t.Context(), spec.PlacementDatabaseID,
		spec.PartitionID, valid, now); err == nil {
		t.Fatal("tampered current R3 receipt supplied a successor signer")
	}
}

func TestProduceSuccessorPreservesSQLAbsence(t *testing.T) {
	service, spec, _, _ := preparationFixture(t)
	now := time.Now().UTC().Truncate(time.Second)
	if _, err := service.PrepareInitial(t.Context(), 9, spec.PartitionID, spec, now); err != nil {
		t.Fatal(err)
	}
	request := successorFixture(t, service, spec, now)
	material, err := service.ProduceSuccessor(t.Context(), spec.PlacementDatabaseID, spec.PartitionID, request, now)
	if err != nil {
		t.Fatal(err)
	}
	if material.SQLPresent || len(material.SuccessorSQLBundle) != 0 ||
		material.PredecessorSQLBundleSHA256 != ([sha256.Size]byte{}) ||
		material.SuccessorSQLBundleSHA256 != ([sha256.Size]byte{}) ||
		material.SuccessorAuthoritySHA256 == material.PredecessorAuthoritySHA256 {
		t.Fatal("SQL absence or authority transition was encoded incorrectly")
	}
}

// Set TS_D11_RUST_SERVER to a pinned tb-server binary to exercise its real V2
// certificate verifier, and TS_D11_PUBLIC_ARTIFACT_DIR to export only public
// bytes for the Rust SQL bundle verifier.
func TestProduceSuccessorRustInterop(t *testing.T) {
	binary := os.Getenv("TS_D11_RUST_SERVER")
	artifactDir := os.Getenv("TS_D11_PUBLIC_ARTIFACT_DIR")
	if binary == "" && artifactDir == "" {
		tier.Unavailable(t, "D11 public artifact interop was not requested: set TS_D11_RUST_SERVER or TS_D11_PUBLIC_ARTIFACT_DIR")
	}
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
	_, current, err := service.CurrentBundle(t.Context(), spec.PlacementDatabaseID, spec.PartitionID)
	if err != nil {
		t.Fatal(err)
	}
	if binary != "" {
		targetDigest, err := spec.LiveS3.Digest()
		if err != nil {
			t.Fatal(err)
		}
		input := NativeMaterialInput{
			Certificate:             material.SuccessorAuthority.Certificate,
			TrustedKey:              material.SuccessorAuthority.TrustedKey,
			SignedV2S3Config:        current.Members[0].Files["signed-v2-s3-config.json"].Contents,
			Scope:                   material.SuccessorScope,
			MemberIDs:               []string{request.Members[0].MemberID, request.Members[1].MemberID},
			ExpectedConfigurationID: material.SuccessorAuthority.ConfigurationID,
			ExpectedS3TargetDigest:  targetDigest,
		}
		wire, err := encodeNativeValidationRequest(input)
		if err != nil {
			t.Fatal(err)
		}
		command := exec.CommandContext(t.Context(), binary, "validate-managed-material-v1")
		command.Stdin = bytes.NewReader(wire)
		output, err := command.CombinedOutput()
		if err != nil {
			t.Fatalf("Rust V2 verifier rejected Go successor certificate: %v: %s", err, output)
		}
		wrongEpoch := input
		wrongEpoch.Scope.Epoch = spec.Scope.Epoch
		wire, err = encodeNativeValidationRequest(wrongEpoch)
		if err != nil {
			t.Fatal(err)
		}
		command = exec.CommandContext(t.Context(), binary, "validate-managed-material-v1")
		command.Stdin = bytes.NewReader(wire)
		if output, err := command.CombinedOutput(); err == nil {
			t.Fatalf("Rust V2 verifier accepted successor certificate at predecessor epoch: %s", output)
		}
	}
	if artifactDir == "" {
		return
	}
	if err := os.MkdirAll(artifactDir, 0o700); err != nil {
		t.Fatal(err)
	}
	for name, contents := range map[string][]byte{
		"predecessor.tbca":   current.Authority.Certificate,
		"successor.tbca":     material.SuccessorAuthority.Certificate,
		"predecessor.tbsqb":  current.Members[0].Files[sqlSchemaBundleFileName].Contents,
		"successor.tbsqb":    material.SuccessorSQLBundle,
		"trusted-public-key": material.SuccessorAuthority.TrustedKey,
	} {
		if err := os.WriteFile(filepath.Join(artifactDir, name), contents, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	manifest, err := json.Marshal(struct {
		PredecessorScope           AuthorityScope `json:"predecessor_scope"`
		SuccessorScope             AuthorityScope `json:"successor_scope"`
		PredecessorMemberIDs       [2]string      `json:"predecessor_member_ids"`
		SuccessorMemberIDsBySeat   [2]string      `json:"successor_member_ids_by_predecessor_seat"`
		SuccessorLeafPinsBySeat    [2]string      `json:"successor_leaf_pins_by_predecessor_seat"`
		PredecessorConfigurationID string         `json:"predecessor_configuration_id"`
		SuccessorConfigurationID   string         `json:"successor_configuration_id"`
		PredecessorCertificateSHA  string         `json:"predecessor_certificate_sha256"`
		SuccessorCertificateSHA    string         `json:"successor_certificate_sha256"`
		PredecessorSQLBundleSHA    string         `json:"predecessor_sql_bundle_sha256"`
		SuccessorSQLBundleSHA      string         `json:"successor_sql_bundle_sha256"`
		CatalogSetSHA              string         `json:"document_catalog_set_sha256"`
	}{material.PredecessorScope, material.SuccessorScope,
		[2]string{spec.Members[0].MemberID, spec.Members[1].MemberID},
		[2]string{request.Members[0].MemberID, request.Members[1].MemberID}, material.SuccessorLeafPinsBySeat,
		material.PredecessorConfigurationID, material.SuccessorAuthority.ConfigurationID,
		hex.EncodeToString(material.PredecessorAuthoritySHA256[:]),
		hex.EncodeToString(material.SuccessorAuthoritySHA256[:]),
		hex.EncodeToString(material.PredecessorSQLBundleSHA256[:]),
		hex.EncodeToString(material.SuccessorSQLBundleSHA256[:]),
		hex.EncodeToString(material.DocumentCatalogSetSHA256[:])})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(artifactDir, "manifest.json"), manifest, 0o600); err != nil {
		t.Fatal(err)
	}
	t.Logf("exported public D11 predecessor/successor artifacts to %s", artifactDir)
}
