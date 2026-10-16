package release

import (
	"crypto/ed25519"
	"encoding/base64"
	"fmt"
	"regexp"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/entityid"
	"github.com/TerraScale/ts-orchestrator/internal/trust"
)

const (
	SequenceMigrationSchema      = "terrascale.release.sequence-migration.v1"
	SequenceMigrationDomain      = "terrascale.release.sequence-migration"
	MaxSequenceMigrationLifetime = 24 * time.Hour
)

var sequenceRole = regexp.MustCompile(`^[a-z][a-z0-9-]{0,63}$`)

// SequenceFloor records an authenticated regional admission floor. EvidenceSHA256
// identifies the signed receipt or claim from which the root reviewed the floor.
type SequenceFloor struct {
	Cell           string    `json:"cell"`
	RunNumber      int64     `json:"run_number,omitzero"`
	IssuedAt       time.Time `json:"issued_at,omitzero"`
	EvidenceSHA256 string    `json:"evidence_sha256"`
}

// SequenceMigration explicitly admits one shared ordering namespace without
// changing the provenance or signatures of historical releases.
type SequenceMigration struct {
	Namespace       string          `json:"namespace"`
	Bucket          string          `json:"bucket"`
	Region          string          `json:"region"`
	Schema          string          `json:"schema"`
	SignerKeyID     string          `json:"signer_key_id"`
	SignerPublicKey string          `json:"signer_public_key"`
	Role            string          `json:"role"`
	Environment     string          `json:"environment"`
	SequenceFloor   uint64          `json:"sequence_floor"`
	Regions         []SequenceFloor `json:"regions"`
}

func (migration SequenceMigration) Validate() error {
	if migration.Schema != SequenceMigrationSchema || migration.Namespace == "" || len(migration.Namespace) > 128 || migration.Bucket != "gru-1-head" || migration.Region != "GRU" || !sequenceRole.MatchString(migration.Role) || validateEnvironment(migration.Environment) != nil || migration.SequenceFloor == 0 || len(migration.Regions) != 3 {
		return fmt.Errorf("%w: sequence migration scope or regional floors", ErrInvalidReceipt)
	}
	public, err := base64.RawURLEncoding.Strict().DecodeString(migration.SignerPublicKey)
	if err != nil || len(public) != ed25519.PublicKeySize {
		return fmt.Errorf("%w: sequence signer", ErrInvalidReceipt)
	}
	keyID, err := trust.KeyID(ed25519.PublicKey(public))
	if err != nil || keyID != migration.SignerKeyID {
		return trust.ErrKeyMismatch
	}
	seen := make(map[string]bool, 3)
	for _, floor := range migration.Regions {
		if !ValidRegion(floor.Cell) || seen[floor.Cell] || floor.RunNumber < 0 || uint64(floor.RunNumber) > migration.SequenceFloor || !digestPattern.MatchString(floor.EvidenceSHA256) || (floor.RunNumber == 0 && floor.IssuedAt.IsZero()) || (!floor.IssuedAt.IsZero() && floor.IssuedAt.Location() != time.UTC) {
			return fmt.Errorf("%w: sequence migration regional floor", ErrInvalidReceipt)
		}
		seen[floor.Cell] = true
	}
	return nil
}

func SequenceMigrationScope(role, environment string) trust.Scope {
	return trust.Scope{Domain: SequenceMigrationDomain, DeploymentID: entityid.Derive("release-sequence", role, environment), Cell: "global", Environment: environment, Role: role, Slot: "migration"}
}

func SignSequenceMigration(migration SequenceMigration, now time.Time, root ed25519.PrivateKey) (trust.Envelope, error) {
	if err := migration.Validate(); err != nil {
		return trust.Envelope{}, err
	}
	payload, err := trust.EncodePayload(migration)
	if err != nil {
		return trust.Envelope{}, err
	}
	return trust.Sign(payload, SequenceMigrationScope(migration.Role, migration.Environment), now, now.Add(MaxSequenceMigrationLifetime), root)
}

// VerifySequenceMigrationHistorical checks a durable authorization already
// imported by the signer; importing a new migration requires current validity.
func VerifySequenceMigrationHistorical(envelope trust.Envelope, roots trust.Keyring, role, environment string) (SequenceMigration, error) {
	return verifySequenceMigration(envelope, roots, role, environment, time.Time{})
}

func VerifySequenceMigrationCurrent(envelope trust.Envelope, roots trust.Keyring, role, environment string, now time.Time) (SequenceMigration, error) {
	if now.IsZero() {
		return SequenceMigration{}, fmt.Errorf("%w: migration verification time", ErrInvalidReceipt)
	}
	return verifySequenceMigration(envelope, roots, role, environment, now)
}

func verifySequenceMigration(envelope trust.Envelope, roots trust.Keyring, role, environment string, now time.Time) (SequenceMigration, error) {
	scope := SequenceMigrationScope(role, environment)
	policy := trust.Policy{MaxLifetime: MaxSequenceMigrationLifetime}
	var payload []byte
	var err error
	if now.IsZero() {
		payload, err = trust.VerifyHistorical(envelope, scope, roots, policy)
	} else {
		payload, err = trust.VerifyCurrent(envelope, scope, roots, now, policy)
	}
	if err != nil {
		return SequenceMigration{}, err
	}
	migration, err := decodeCanonicalPayload[SequenceMigration](payload)
	if err != nil {
		return SequenceMigration{}, err
	}
	if err := migration.Validate(); err != nil {
		return SequenceMigration{}, err
	}
	if migration.Role != role || migration.Environment != environment {
		return SequenceMigration{}, trust.ErrScopeMismatch
	}
	return migration, nil
}

// AdmitsLegacyFloor ensures a migration cannot erase the consumer's retained
// ordering floor, even if its current channel object has been replaced.
func (migration SequenceMigration) AdmitsLegacyFloor(cell string, run int64, issued time.Time) bool {
	for _, floor := range migration.Regions {
		if floor.Cell == cell {
			return run <= floor.RunNumber && (issued.IsZero() || !floor.IssuedAt.IsZero() && !issued.After(floor.IssuedAt))
		}
	}
	return false
}
