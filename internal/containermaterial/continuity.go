package containermaterial

import (
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/release"
	"github.com/TerraScale/ts-orchestrator/internal/trust"
)

// VerifyRuntimePolicy compares independently authenticated original and current
// runtime policy. Releasers and host grants confer no archival authority.
func VerifyRuntimePolicy(original, current Profile) error {
	if original.fingerprint == "" || current.fingerprint == "" || original.specSHA256 == "" || current.specSHA256 == "" ||
		original.runtimePolicy == "" || original.runtimePolicy != current.runtimePolicy ||
		original.identity != current.identity || original.role != current.role ||
		original.intent.Validate() != nil || current.intent.Validate() != nil || original.intent.Container == nil || current.intent.Container == nil ||
		original.intent.SchemaVersion != current.intent.SchemaVersion || original.intent.Source != current.intent.Source ||
		original.intent.Cell != current.intent.Cell || original.intent.Environment != current.intent.Environment || original.intent.Role != current.intent.Role ||
		original.intent.Generation != current.intent.Generation || original.intent.DesiredReplicas != current.intent.DesiredReplicas ||
		original.intent.ConfigDigest != current.intent.ConfigDigest {
		return ErrPending
	}
	return nil
}

// VerifyHistoricalContinuity compares signed renewal policy without granting
// current release, actor, lease or task admission.
func VerifyHistoricalContinuity(original Profile, historical release.HistoricalContainer, candidate Profile, renewed release.HistoricalContainer) error {
	return verifyContinuity(original, historical, candidate, renewed)
}

// VerifyContinuity compares an archived original release with independently
// current authority. It grants no actor, lease or task admission.
func VerifyContinuity(original Profile, historical release.HistoricalContainer, current Profile, verified release.VerifiedContainer, now time.Time) error {
	if !verified.Valid(now) {
		return ErrPending
	}
	return verifyContinuity(original, historical, current, verified)
}

type continuityRelease interface {
	Claim() release.ContainerClaim
	Fingerprint() string
	BundleSHA256() string
	ReleaseIdentity() string
}

func verifyContinuity(original Profile, historical release.HistoricalContainer, current Profile, verified continuityRelease) error {
	if VerifyRuntimePolicy(original, current) != nil || original.continuation != nil || current.continuation != nil ||
		original.runtimeOperationID != original.intent.OperationID || current.runtimeOperationID != current.intent.OperationID ||
		historical.ReleaseIdentity() == "" || historical.ReleaseIdentity() != verified.ReleaseIdentity() {
		return ErrPending
	}
	for _, pair := range []struct {
		profile      Profile
		fingerprint  string
		bundleSHA256 string
	}{{original, historical.Fingerprint(), historical.BundleSHA256()}, {current, verified.Fingerprint(), verified.BundleSHA256()}} {
		envelope, err := trust.DecodeEnvelope(pair.profile.intent.Container.Claim)
		if err != nil {
			return ErrPending
		}
		fingerprint, err := trust.Fingerprint(envelope)
		if err != nil || fingerprint != pair.fingerprint {
			return ErrPending
		}
		bundleSHA256, err := release.ContainerBundleSHA256(*pair.profile.intent.Container)
		if err != nil || bundleSHA256 != pair.bundleSHA256 {
			return ErrPending
		}
	}
	before, after := historical.Claim(), verified.Claim()
	if before.SourceRepository != after.SourceRepository || before.SourceRevision != after.SourceRevision || before.SourceTreeSHA256 != after.SourceTreeSHA256 ||
		before.Cell != after.Cell || before.Environment != after.Environment || before.Role != after.Role || before.Architecture != after.Architecture ||
		before.Image != after.Image || before.QualificationSHA256 != after.QualificationSHA256 || before.ReleaseSequence != after.ReleaseSequence ||
		before.SequenceMigrationSHA256 != after.SequenceMigrationSHA256 {
		return ErrPending
	}
	return nil
}

// ContinueProfile creates a fresh current-authority proof retaining the exact
// original runtime operation. Existing admissions keep their original sources.
func ContinueProfile(original Profile, historical release.HistoricalContainer, current Profile, verified release.VerifiedContainer, now time.Time) (Profile, error) {
	if err := VerifyContinuity(original, historical, current, verified, now); err != nil {
		return Profile{}, err
	}
	current.runtimeOperationID = original.intent.OperationID
	current.continuation = new(original)
	return current, nil
}
