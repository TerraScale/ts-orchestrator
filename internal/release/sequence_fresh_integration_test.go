package release

import (
	"crypto/ed25519"
	"crypto/rand"
	"strings"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/trust"
)

func TestFreshRoleSequenceAuthoritySDK(t *testing.T) {
	_, newLocation := sequenceSDKFixture(t)
	fixture := freshRoleSequenceFixture(t)
	envelope, err := SignSequenceMigration(fixture.migration, fixture.now, fixture.root)
	if err != nil {
		t.Fatal(err)
	}
	if envelope.Scope.Slot != SequenceFreshRolePurpose {
		t.Fatal("fresh baseline reused the legacy migration purpose")
	}
	fingerprint, err := trust.Fingerprint(envelope)
	if err != nil {
		t.Fatal(err)
	}
	for _, cell := range []string{"GRU", "SFO", "FRA"} {
		proof, err := VerifyFreshRoleBaselineCurrent(envelope, fixture.roots, "function-worker", "production", cell, fixture.now)
		if err != nil {
			t.Fatal(err)
		}
		if proof.ExpiresAt() != envelope.ExpiresAt || proof.ValidFor("function-worker", "production", cell, fingerprint, fixture.now) != nil {
			t.Fatal("fresh baseline lost its exact scope or original deadline")
		}
	}
	identity := SequenceIdentity{Role: "function-worker", Environment: "production", SourceRevision: strings.Repeat("b", 40), ManifestSHA256: strings.Repeat("c", 64)}
	location := newLocation()
	if _, err := location.Allocate(t.Context(), identity, fixture.roots, fixture.signer); err == nil {
		t.Fatal("missing original migration was treated as historical authority")
	}
	expired, err := SignSequenceMigration(fixture.migration, fixture.now.Add(-2*MaxSequenceMigrationLifetime), fixture.root)
	if err != nil {
		t.Fatal(err)
	}
	if err := location.ImportMigration(t.Context(), expired, fixture.roots, identity.Role, identity.Environment, fixture.now); err == nil {
		t.Fatal("expired migration initialized a fresh allocator")
	}
	if err := location.ImportMigration(t.Context(), envelope, fixture.roots, identity.Role, identity.Environment, fixture.now); err != nil {
		t.Fatal(err)
	}
	if sequence, err := location.Allocate(t.Context(), identity, fixture.roots, fixture.signer); err != nil || sequence != 101 {
		t.Fatalf("initial sequence %d: %v", sequence, err)
	}
	if sequence, err := newLocation().Allocate(t.Context(), identity, fixture.roots, fixture.signer); err != nil || sequence != 101 {
		t.Fatalf("fresh SDK client lost retained reservation %d: %v", sequence, err)
	}
	identity.ManifestSHA256 = strings.Repeat("d", 64)
	if sequence, err := newLocation().Allocate(t.Context(), identity, fixture.roots, fixture.signer); err != nil || sequence != 102 {
		t.Fatalf("successor sequence %d: %v", sequence, err)
	}
	if err := newLocation().ImportMigration(t.Context(), envelope, fixture.roots, identity.Role, identity.Environment, envelope.ExpiresAt); err != nil {
		t.Fatalf("same durable migration lost historical import: %v", err)
	}
	changed := fixture.migration
	changed.SequenceFloor = 1
	other, err := SignSequenceMigration(changed, fixture.now, fixture.root)
	if err != nil {
		t.Fatal(err)
	}
	if err := newLocation().ImportMigration(t.Context(), other, fixture.roots, identity.Role, identity.Environment, fixture.now); err == nil {
		t.Fatal("fresh baseline reset a previously imported migration")
	}
	if sequence, err := newLocation().Allocate(t.Context(), identity, fixture.roots, fixture.signer); err != nil || sequence != 102 {
		t.Fatalf("rejected import changed durable floor %d: %v", sequence, err)
	}
	verified, err := VerifySequenceMigrationHistorical(envelope, fixture.roots, identity.Role, identity.Environment)
	if err != nil {
		t.Fatal(err)
	}
	if verified.AdmitsLegacyFloor("GRU", 0, time.Time{}) || verified.AdmitsLegacyFloor("GRU", 100, fixture.now) {
		t.Fatal("fresh authority fabricated retained legacy history")
	}
}

func TestFreshRoleSequenceRejectsMixedAuthority(t *testing.T) {
	fixture := freshRoleSequenceFixture(t)
	legacy := fixture.migration
	legacy.Schema, legacy.Purpose, legacy.FreshCells = SequenceMigrationSchema, "", nil
	for _, cell := range []string{"GRU", "SFO", "FRA"} {
		legacy.Regions = append(legacy.Regions, SequenceFloor{Cell: cell, RunNumber: 100, EvidenceSHA256: strings.Repeat("a", 64)})
	}
	cases := []struct {
		name   string
		change func(*SequenceMigration, *trust.Scope)
	}{
		{"legacy_schema", func(m *SequenceMigration, s *trust.Scope) {
			*m = legacy
			s.Slot = "migration"
		}},
		{"legacy_schema_mixed_purpose", func(m *SequenceMigration, _ *trust.Scope) { m.Schema = SequenceMigrationSchema }},
		{"legacy_schema_fresh_cells", func(m *SequenceMigration, s *trust.Scope) {
			*m = legacy
			m.FreshCells = fixture.migration.FreshCells
			s.Slot = "migration"
		}},
		{"legacy_schema_fresh_purpose", func(m *SequenceMigration, s *trust.Scope) {
			*m = legacy
			m.Purpose = SequenceFreshRolePurpose
			s.Slot = "migration"
		}},
		{"legacy_schema_fresh_slot", func(m *SequenceMigration, _ *trust.Scope) { *m = legacy }},
		{"missing_purpose", func(m *SequenceMigration, _ *trust.Scope) { m.Purpose = "" }},
		{"wrong_purpose", func(m *SequenceMigration, _ *trust.Scope) { m.Purpose = "legacy-migration" }},
		{"mixed_legacy_history", func(m *SequenceMigration, _ *trust.Scope) {
			m.Regions = []SequenceFloor{{Cell: "GRU", RunNumber: 100, EvidenceSHA256: strings.Repeat("a", 64)}}
		}},
		{"missing_cells", func(m *SequenceMigration, _ *trust.Scope) { m.FreshCells = nil }},
		{"incomplete_cells", func(m *SequenceMigration, _ *trust.Scope) { m.FreshCells = []string{"GRU", "SFO"} }},
		{"duplicate_cells", func(m *SequenceMigration, _ *trust.Scope) { m.FreshCells = []string{"GRU", "GRU", "FRA"} }},
		{"unknown_cell", func(m *SequenceMigration, _ *trust.Scope) { m.FreshCells = []string{"GRU", "SFO", "UNKNOWN"} }},
		{"lowercase_cell", func(m *SequenceMigration, _ *trust.Scope) { m.FreshCells = []string{"gru", "SFO", "FRA"} }},
		{"zero_floor", func(m *SequenceMigration, _ *trust.Scope) { m.SequenceFloor = 0 }},
		{"missing_namespace", func(m *SequenceMigration, _ *trust.Scope) { m.Namespace = "" }},
		{"wrong_bucket", func(m *SequenceMigration, _ *trust.Scope) { m.Bucket = "other" }},
		{"wrong_allocator_region", func(m *SequenceMigration, _ *trust.Scope) { m.Region = "SFO" }},
		{"wrong_role", func(m *SequenceMigration, _ *trust.Scope) { m.Role = "ts-auth" }},
		{"wrong_environment", func(m *SequenceMigration, _ *trust.Scope) { m.Environment = "staging" }},
		{"signer_is_root", func(m *SequenceMigration, _ *trust.Scope) {
			public := fixture.root.Public().(ed25519.PublicKey)
			m.SignerKeyID, _ = trust.KeyID(public)
			m.SignerPublicKey, _ = trust.EncodeDelegatedPublicKey(public)
		}},
		{"signer_key_mismatch", func(m *SequenceMigration, _ *trust.Scope) { m.SignerKeyID = strings.Repeat("a", 64) }},
		{"legacy_signature_slot", func(_ *SequenceMigration, s *trust.Scope) { s.Slot = "migration" }},
		{"wrong_signature_role", func(_ *SequenceMigration, s *trust.Scope) { s.Role = "ts-auth" }},
		{"wrong_signature_environment", func(_ *SequenceMigration, s *trust.Scope) { s.Environment = "staging" }},
		{"wrong_signature_cell", func(_ *SequenceMigration, s *trust.Scope) { s.Cell = "GRU" }},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			migration := fixture.migration
			scope := migration.signingScope()
			test.change(&migration, &scope)
			payload, err := trust.EncodePayload(migration)
			if err != nil {
				t.Fatal(err)
			}
			envelope, err := trust.Sign(payload, scope, fixture.now, fixture.now.Add(MaxSequenceMigrationLifetime), fixture.root)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := VerifyFreshRoleBaselineCurrent(envelope, fixture.roots, "function-worker", "production", "GRU", fixture.now); err == nil {
				t.Fatal("mixed or legacy authority authorized a fresh baseline")
			}
			_, err = VerifySequenceMigrationCurrent(envelope, fixture.roots, "function-worker", "production", fixture.now)
			if test.name == "legacy_schema" {
				if err != nil {
					t.Fatalf("legacy authority lost its original use: %v", err)
				}
			} else if err == nil {
				t.Fatal("general verifier admitted mixed migration authority")
			}
		})
	}
	for _, test := range []struct {
		name      string
		issuedAt  time.Time
		expiresAt time.Time
	}{
		{"expired", fixture.now.Add(-MaxSequenceMigrationLifetime), fixture.now},
		{"future", fixture.now.Add(time.Second), fixture.now.Add(time.Hour)},
		{"overlong", fixture.now, fixture.now.Add(MaxSequenceMigrationLifetime + time.Second)},
	} {
		t.Run(test.name, func(t *testing.T) {
			payload, err := trust.EncodePayload(fixture.migration)
			if err != nil {
				t.Fatal(err)
			}
			envelope, err := trust.Sign(payload, fixture.migration.signingScope(), test.issuedAt, test.expiresAt, fixture.root)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := VerifyFreshRoleBaselineCurrent(envelope, fixture.roots, "function-worker", "production", "GRU", fixture.now); err == nil {
				t.Fatal("fresh authority exceeded its original interval")
			}
		})
	}
}

func TestFreshRoleSequenceProofRetainsOriginalScope(t *testing.T) {
	fixture := freshRoleSequenceFixture(t)
	envelope, err := SignSequenceMigration(fixture.migration, fixture.now, fixture.root)
	if err != nil {
		t.Fatal(err)
	}
	fingerprint, err := trust.Fingerprint(envelope)
	if err != nil {
		t.Fatal(err)
	}
	verifiedAt := fixture.now.Add(time.Second)
	proof, err := VerifyFreshRoleBaselineCurrent(envelope, fixture.roots, "function-worker", "production", "GRU", verifiedAt)
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name, role, environment, cell, migration string
		now                                      time.Time
	}{
		{"other_role", "ts-auth", "production", "GRU", fingerprint, verifiedAt},
		{"other_environment", "function-worker", "staging", "GRU", fingerprint, verifiedAt},
		{"other_cell", "function-worker", "production", "SFO", fingerprint, verifiedAt},
		{"other_migration", "function-worker", "production", "GRU", strings.Repeat("f", 64), verifiedAt},
		{"backdated", "function-worker", "production", "GRU", fingerprint, verifiedAt.Add(-time.Nanosecond)},
		{"expired", "function-worker", "production", "GRU", fingerprint, envelope.ExpiresAt},
	} {
		t.Run(test.name, func(t *testing.T) {
			if err := proof.ValidFor(test.role, test.environment, test.cell, test.migration, test.now); err == nil {
				t.Fatal("opaque baseline was reused outside its original authorization")
			}
		})
	}
	if err := (VerifiedFreshRoleBaseline{}).ValidFor("function-worker", "production", "GRU", fingerprint, fixture.now); err == nil {
		t.Fatal("zero opaque baseline authorized a fresh role")
	}
	if _, err := VerifyFreshRoleBaselineCurrent(envelope, fixture.roots, "function-worker", "production", "UNKNOWN", fixture.now); err == nil {
		t.Fatal("baseline admitted an unlisted cell")
	}
	if _, err := VerifyFreshRoleBaselineCurrent(envelope, fixture.roots, "function-worker", "production", "GRU", time.Time{}); err == nil {
		t.Fatal("baseline admitted a zero verification time")
	}
	if _, err := VerifyFreshRoleBaselineCurrent(envelope, nil, "function-worker", "production", "GRU", fixture.now); err == nil {
		t.Fatal("baseline admitted an unknown root")
	}
}

type freshRoleSequenceData struct {
	migration    SequenceMigration
	root, signer ed25519.PrivateKey
	roots        trust.Keyring
	now          time.Time
}

func freshRoleSequenceFixture(t *testing.T) freshRoleSequenceData {
	t.Helper()
	public, root, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signerPublic, signer, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	id, err := trust.KeyID(signerPublic)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := trust.EncodeDelegatedPublicKey(signerPublic)
	if err != nil {
		t.Fatal(err)
	}
	roots, err := trust.ParseKeyring(public)
	if err != nil {
		t.Fatal(err)
	}
	return freshRoleSequenceData{migration: SequenceMigration{Schema: SequenceFreshRoleSchema, Purpose: SequenceFreshRolePurpose,
		Namespace: "ns", Bucket: "gru-1-head", Region: "GRU", Role: "function-worker", Environment: "production", SequenceFloor: 100,
		SignerKeyID: id, SignerPublicKey: encoded, FreshCells: []string{"GRU", "SFO", "FRA"}},
		root: root, signer: signer, roots: roots, now: time.Now().UTC().Truncate(time.Second)}
}
