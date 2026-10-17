package release

import (
	"context"
	"crypto/sha256"
	"encoding/json/jsontext"
	"errors"
	"fmt"
	"io"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/entityid"
	"github.com/TerraScale/ts-orchestrator/internal/protocol"
	"github.com/TerraScale/ts-orchestrator/internal/trust"
	"github.com/distribution/reference"
)

const ContainerClaimSchema = "terrascale.release.container.v1"
const ContainerClaimDomain = "terrascale.release.container"

// ContainerTarget is the consumer's admitted target, never read from the proof.
type ContainerTarget struct{ Cell, Environment, Role, Architecture string }

// ContainerClaim identifies an OCI child manifest, distinct from native binary
// and tarball artifacts. Its independent qualifier binds this exact candidate.
type ContainerClaim struct {
	Schema                  string `json:"schema"`
	Image                   string `json:"image"`
	SourceRepository        string `json:"source_repository"`
	SourceRevision          string `json:"source_revision"`
	SourceTreeSHA256        string `json:"source_tree_sha256"`
	Cell                    string `json:"cell"`
	Environment             string `json:"environment"`
	Role                    string `json:"role"`
	Architecture            string `json:"architecture"`
	ReleaseSequence         uint64 `json:"release_sequence"`
	SequenceMigrationSHA256 string `json:"sequence_migration_sha256"`
	// QualificationSHA256 pins retained OCI root/index bytes (or a directly pinned manifest).
	QualificationSHA256 string          `json:"qualification_sha256"`
	Production          ProductionProof `json:"production"`
}

type ContainerBundle struct {
	Claim      jsontext.Value `json:"claim"`
	Index      []byte         `json:"index,omitempty"`
	Sequence   []byte         `json:"sequence,omitempty"`
	Delegation jsontext.Value `json:"delegation,omitempty"`
	Migration  jsontext.Value `json:"sequence_migration"`
}

// VerifiedContainer can only be populated by the signature/qualification verifier.
type VerifiedContainer struct {
	claim             ContainerClaim
	familyEvidence    []byte
	migration         SequenceMigration
	migrationEnvelope trust.Envelope
	bundleSHA256      string
	fingerprint       string
	identity          string
	issuedAt          time.Time
	expiresAt         time.Time
}

func (c VerifiedContainer) Claim() ContainerClaim {
	claim := c.claim
	claim.Production.Qualification = slices.Clone(claim.Production.Qualification)
	claim.Production.Delegation = slices.Clone(claim.Production.Delegation)
	return claim
}
func (c VerifiedContainer) BundleSHA256() string    { return c.bundleSHA256 }
func (c VerifiedContainer) Fingerprint() string     { return c.fingerprint }
func (c VerifiedContainer) ReleaseIdentity() string { return c.identity }
func (c VerifiedContainer) ExpiresAt() time.Time    { return c.expiresAt }
func (c VerifiedContainer) Valid(now time.Time) bool {
	return !now.IsZero() && c.fingerprint != "" && !now.Before(c.issuedAt) && now.Before(c.expiresAt)
}

// ContentManifestDigest remains stable when independent qualification is renewed.
func (claim ContainerClaim) ContentManifestDigest() (string, error) {
	claim.ReleaseSequence = 0
	claim.SequenceMigrationSHA256 = ""
	claim.Production = ProductionProof{}
	wire, err := trust.EncodePayload(claim)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%x", sha256.Sum256(wire)), nil
}
func (c VerifiedContainer) Migration() SequenceMigration {
	m := c.migration
	m.Regions = slices.Clone(m.Regions)
	return m
}
func (c VerifiedContainer) MigrationEnvelope() trust.Envelope {
	e := c.migrationEnvelope
	e.Payload = slices.Clone(e.Payload)
	return e
}

func ContainerScope(target ContainerTarget) trust.Scope {
	return trust.Scope{Domain: ContainerClaimDomain, DeploymentID: entityid.Derive("container-release", target.Role, target.Environment), Cell: target.Cell, Environment: target.Environment, Role: target.Role, Slot: "linux-" + target.Architecture}
}

func (claim ContainerClaim) Validate() error {
	repository, err := url.Parse(claim.SourceRepository)
	if err != nil || repository.Scheme != "https" || repository.Host == "" || repository.User != nil || repository.RawQuery != "" || repository.Fragment != "" || len(claim.SourceRepository) > 512 || !digestPattern.MatchString(claim.SourceTreeSHA256) {
		return errors.New("container release source requires HTTPS repository and exact SHA-256 tree")
	}

	if claim.Schema != ContainerClaimSchema || !ValidSourceRevision(claim.SourceRevision) || !ValidRegion(claim.Cell) || !ValidEnvironment(claim.Environment) || !serviceRolePattern.MatchString(claim.Role) || claim.Architecture != "arm64" && claim.Architecture != "amd64" || claim.ReleaseSequence == 0 || !digestPattern.MatchString(claim.SequenceMigrationSHA256) || !digestPattern.MatchString(claim.QualificationSHA256) {
		return errors.New("invalid OCI container release claim")
	}
	ref, err := reference.ParseNormalizedNamed(claim.Image)
	if err != nil {
		return fmt.Errorf("invalid container image: %w", err)
	}
	digest, ok := ref.(reference.Canonical)
	if !ok || ref.String() != claim.Image || digest.Digest().Algorithm().String() != "sha256" || digest.Digest().Validate() != nil {
		return errors.New("container release requires canonical sha256 child image reference")
	}
	if _, tagged := ref.(reference.Tagged); tagged {
		return errors.New("container release image must not carry a mutable tag")
	}
	return nil
}

// VerifyContainerCurrent independently verifies release authority, shared signer
// ordering, exact candidate qualification and retained evidence bytes. Both the
// present instant and operation deadline must remain authorized. The immutable
// winning allocation must be read from the root-authorized signer store.
func VerifyContainerCurrent(ctx context.Context, bundle ContainerBundle, roots trust.Keyring, expected ContainerTarget, now, validUntil time.Time, evidence func(context.Context, string) (io.ReadCloser, error), allocations SequenceLocation) (VerifiedContainer, error) {
	if now.IsZero() || validUntil.Before(now) || !ValidRegion(expected.Cell) || !ValidEnvironment(expected.Environment) || !serviceRolePattern.MatchString(expected.Role) || expected.Architecture != "arm64" && expected.Architecture != "amd64" || evidence == nil {
		return VerifiedContainer{}, errors.New("container verification requires admitted target, current time, deadline and evidence store")
	}
	envelope, err := trust.DecodeEnvelope(bundle.Claim)
	if err != nil {
		return VerifiedContainer{}, err
	}
	policy := trust.Policy{MaxLifetime: MaxUpdateReceiptLifetime}
	verify := func(at time.Time) ([]byte, error) {
		if len(bundle.Delegation) == 0 {
			return trust.VerifyCurrent(envelope, ContainerScope(expected), roots, at, policy)
		}
		grant, err := trust.DecodeEnvelope(bundle.Delegation)
		if err != nil {
			return nil, err
		}
		delegation, err := trust.VerifyDelegationCurrent(grant, roots, at, policy)
		if err != nil {
			return nil, err
		}
		return trust.VerifyDelegatedCurrent(envelope, ContainerScope(expected), delegation, at, policy)
	}
	payload, err := verify(now)
	if err != nil {
		return VerifiedContainer{}, err
	}
	if _, err := verify(validUntil); err != nil {
		return VerifiedContainer{}, err
	}
	verified, err := verifyContainerIdentity(bundle, roots, expected, envelope, payload)
	if err != nil {
		return VerifiedContainer{}, err
	}
	verified.familyEvidence, err = allocations.readWorkerFamily(ctx, roots, verified)
	if err != nil {
		return VerifiedContainer{}, err
	}
	claim := verified.claim
	_, imageDigest, _ := strings.Cut(claim.Image, "@sha256:")
	candidate := ProductionExpectation{SourceRevision: claim.SourceRevision, ArtifactSHA256: imageDigest, QualificationSHA256: claim.QualificationSHA256, Cell: expected.Cell, Environment: expected.Environment, Runtime: ProductionRuntime, Architecture: expected.Architecture, Role: expected.Role}
	proof, err := VerifyProductionCurrent(claim.Production.Qualification, claim.Production.Delegation, roots, candidate, now)
	if err != nil {
		return VerifiedContainer{}, err
	}
	if _, err := VerifyProductionCurrent(claim.Production.Qualification, claim.Production.Delegation, roots, candidate, validUntil); err != nil {
		return VerifiedContainer{}, err
	}
	for _, retained := range proof.Evidence {
		reader, err := evidence(ctx, retained.SHA256)
		if err != nil {
			return VerifiedContainer{}, fmt.Errorf("read qualification evidence: %w", err)
		}
		if reader == nil {
			return VerifiedContainer{}, errors.New("qualification evidence store returned no reader")
		}
		hash := sha256.New()
		n, readErr := io.Copy(hash, io.LimitReader(reader, retained.Bytes+1))
		closeErr := reader.Close()
		if err := errors.Join(readErr, closeErr); err != nil {
			return VerifiedContainer{}, err
		}
		if n != retained.Bytes || fmt.Sprintf("%x", hash.Sum(nil)) != retained.SHA256 {
			return VerifiedContainer{}, errors.New("container qualification evidence bytes differ from signed proof")
		}
	}
	qualificationEnvelope, err := trust.DecodeEnvelope(claim.Production.Qualification)
	if err != nil {
		return VerifiedContainer{}, err
	}
	verified.issuedAt = envelope.IssuedAt
	if qualificationEnvelope.IssuedAt.After(verified.issuedAt) {
		verified.issuedAt = qualificationEnvelope.IssuedAt
	}
	verified.expiresAt = validUntil
	for _, expires := range []time.Time{envelope.ExpiresAt, qualificationEnvelope.ExpiresAt} {
		if expires.Before(verified.expiresAt) {
			verified.expiresAt = expires
		}
	}
	return verified, nil
}

// HistoricalContainer authenticates retained ordering evidence without granting runtime authority.
type HistoricalContainer struct{ value VerifiedContainer }

func (c HistoricalContainer) Claim() ContainerClaim   { return c.value.Claim() }
func (c HistoricalContainer) Fingerprint() string     { return c.value.Fingerprint() }
func (c HistoricalContainer) BundleSHA256() string    { return c.value.BundleSHA256() }
func (c HistoricalContainer) ReleaseIdentity() string { return c.value.ReleaseIdentity() }

// VerifyContainerHistorical authenticates an immutable channel floor, including expired
// release/delegation intervals. Runtime consumers must use VerifyContainerCurrent.
func VerifyContainerHistorical(bundle ContainerBundle, roots trust.Keyring, expected ContainerTarget) (HistoricalContainer, error) {
	envelope, err := trust.DecodeEnvelope(bundle.Claim)
	if err != nil {
		return HistoricalContainer{}, err
	}
	policy := trust.Policy{MaxLifetime: MaxUpdateReceiptLifetime}
	var payload []byte
	if len(bundle.Delegation) == 0 {
		payload, err = trust.VerifyHistorical(envelope, ContainerScope(expected), roots, policy)
	} else {
		grant, decodeErr := trust.DecodeEnvelope(bundle.Delegation)
		if decodeErr != nil {
			return HistoricalContainer{}, decodeErr
		}
		delegation, verifyErr := trust.VerifyDelegationHistorical(grant, roots, policy)
		if verifyErr != nil {
			return HistoricalContainer{}, verifyErr
		}
		payload, err = trust.VerifyDelegatedHistorical(envelope, ContainerScope(expected), delegation, policy)
	}
	if err != nil {
		return HistoricalContainer{}, err
	}
	verified, err := verifyContainerIdentity(bundle, roots, expected, envelope, payload)
	if err != nil {
		return HistoricalContainer{}, err
	}
	return HistoricalContainer{value: verified}, nil
}

func verifyContainerIdentity(bundle ContainerBundle, roots trust.Keyring, expected ContainerTarget, envelope trust.Envelope, payload []byte) (VerifiedContainer, error) {
	if !ValidRegion(expected.Cell) || !ValidEnvironment(expected.Environment) || !serviceRolePattern.MatchString(expected.Role) || expected.Architecture != "arm64" && expected.Architecture != "amd64" {
		return VerifiedContainer{}, errors.New("container verification requires admitted target")
	}
	var claim ContainerClaim
	if err := protocol.DecodeStrict(payload, &claim, trust.MaxPayloadBytes); err != nil {
		return VerifiedContainer{}, err
	}
	if err := claim.Validate(); err != nil {
		return VerifiedContainer{}, err
	}
	if err := verifyContainerIndex(bundle.Index, claim); err != nil {
		return VerifiedContainer{}, err
	}
	if claim.Cell != expected.Cell || claim.Environment != expected.Environment || claim.Role != expected.Role || claim.Architecture != expected.Architecture {
		return VerifiedContainer{}, trust.ErrScopeMismatch
	}
	migrationEnvelope, err := trust.DecodeEnvelope(bundle.Migration)
	if err != nil {
		return VerifiedContainer{}, err
	}
	migration, err := VerifySequenceMigrationHistorical(migrationEnvelope, roots, expected.Role, expected.Environment)
	if err != nil {
		return VerifiedContainer{}, err
	}
	migrationDigest, err := trust.Fingerprint(migrationEnvelope)
	if err != nil {
		return VerifiedContainer{}, err
	}
	if claim.ReleaseSequence <= migration.SequenceFloor || claim.SequenceMigrationSHA256 != migrationDigest || envelope.KeyID != migration.SignerKeyID {
		return VerifiedContainer{}, errors.New("container release differs from root-authorized sequence signer or migration")
	}
	if err := verifyWorkerFamilyEvidence(bundle.Sequence, roots, claim); err != nil {
		return VerifiedContainer{}, err
	}
	fingerprint, err := trust.Fingerprint(envelope)
	if err != nil {
		return VerifiedContainer{}, err
	}
	content, err := claim.ContentManifestDigest()
	if err != nil {
		return VerifiedContainer{}, err
	}
	bundleDigest, err := ContainerBundleSHA256(bundle)
	if err != nil {
		return VerifiedContainer{}, err
	}
	identity := fmt.Sprintf("%x", sha256.Sum256([]byte(content+"/"+claim.SequenceMigrationSHA256)))
	return VerifiedContainer{claim: claim, bundleSHA256: bundleDigest, familyEvidence: slices.Clone(bundle.Sequence), migration: migration, migrationEnvelope: migrationEnvelope, fingerprint: fingerprint, identity: identity}, nil
}

// ContainerBundleSHA256 identifies the complete retained bundle, including
// delegation renewals whose signed claim fingerprint remains unchanged.
func ContainerBundleSHA256(bundle ContainerBundle) (string, error) {
	wire, err := protocol.EncodeJSON(bundle)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%x", sha256.Sum256(wire)), nil
}
