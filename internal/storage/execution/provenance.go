package execution

import (
	"context"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/protocol"
	"github.com/TerraScale/ts-orchestrator/internal/release"
	"github.com/TerraScale/ts-orchestrator/internal/trust"
)

// VerifyRetainedProvenance reads the prior possible writer's immutable signed
// result. Historical verification grants no permission to execute that release.
// The manager retains this bundle before starting a writer, including uncertain
// starts, and compares all independently recorded volume/source pins here.
func VerifyRetainedProvenance(ctx context.Context, bundle release.ContainerBundle, roots trust.Keyring,
	target release.ContainerTarget, expected RetainedData, evidence func(context.Context, string) (io.ReadCloser, error), allocations release.SequenceLocation,
) (RetainedData, error) {
	if ctx == nil || ctx.Err() != nil || target.Role != "terrabase" || evidence == nil {
		return RetainedData{}, ErrUnsafe
	}
	if allocations.Genesis.IsVerified() {
		target.Genesis = allocations.Genesis
	}
	previous, err := release.VerifyContainerHistorical(bundle, roots, target)
	if err != nil {
		return RetainedData{}, err
	}
	claim := previous.Claim()
	_, imageDigest, _ := strings.Cut(claim.Image, "@sha256:")
	if claim.SourceTreeSHA256 != expected.SourceTreeSHA256 || imageDigest != expected.SourceArtifactSHA256 || claim.Architecture != expected.SourceArchitecture {
		return RetainedData{}, fmt.Errorf("%w: retained writer differs from recorded source", ErrUnsafe)
	}
	envelope, err := trust.DecodeEnvelope(bundle.Claim)
	if err != nil {
		return RetainedData{}, err
	}
	candidate := release.ProductionExpectation{SourceRevision: claim.SourceRevision, ArtifactSHA256: imageDigest, QualificationSHA256: claim.QualificationSHA256, Cell: target.Cell, Environment: target.Environment, Runtime: release.ProductionRuntime, Architecture: target.Architecture, Role: target.Role}
	// Verify at the authenticated release issue instant solely to recover prior
	// provenance after expiry; the current execution path verifies wall-clock time.
	qualification, err := release.VerifyProductionCurrent(claim.Production.Qualification, claim.Production.Delegation, roots, candidate, envelope.IssuedAt)
	if err != nil {
		return RetainedData{}, err
	}
	wire, err := readStatefulEvidence(ctx, evidence, qualification.Evidence[1], trust.MaxPayloadBytes)
	if err != nil {
		return RetainedData{}, err
	}
	var proof StatefulQualification
	if err := protocol.DecodeStrict(wire, &proof, trust.MaxPayloadBytes); err != nil {
		return RetainedData{}, err
	}
	verified, err := VerifyStatefulCurrent(ctx, bundle, roots, target, proof.Data, proof.TargetCPU, envelope.IssuedAt, envelope.IssuedAt.Add(time.Nanosecond), evidence, allocations)
	if err != nil {
		return RetainedData{}, err
	}
	result := verified.ResultData()
	comparison := result
	if expected.DiskFormatSHA256 == "" {
		comparison.DiskFormatSHA256 = ""
	}
	if comparison != expected {
		return RetainedData{}, fmt.Errorf("%w: retained signed result differs from current volume", ErrUnsafe)
	}
	return result, nil
}

// VerifyNativeRetainedProvenance bridges the initial native writer. The current
// signed desired pins the exact native artifact/source and existing volume. The
// independent qualifier supplies the disk format; retained artifact bytes prove
// its architecture through the ELF header. No native binary is executed.
func VerifyNativeRetainedProvenance(ctx context.Context, bundle release.ContainerBundle, roots trust.Keyring, target release.ContainerTarget, expected RetainedData, now, until time.Time, evidence func(context.Context, string) (io.ReadCloser, error), allocations release.SequenceLocation) (RetainedData, error) {
	if allocations.Genesis.IsVerified() {
		target.Genesis = allocations.Genesis
	}
	verified, err := VerifyStatefulDeclared(ctx, bundle, roots, target, now, until, evidence, allocations)
	if err != nil {
		return RetainedData{}, err
	}
	if !verified.nativeSource {
		return RetainedData{}, fmt.Errorf("%w: exact native source artifact evidence missing", ErrUnsafe)
	}
	data := verified.Data()
	comparison := data
	if expected.DiskFormatSHA256 == "" {
		comparison.DiskFormatSHA256 = ""
	}
	if expected.SourceArchitecture == "" {
		comparison.SourceArchitecture = ""
	}
	if comparison != expected {
		return RetainedData{}, fmt.Errorf("%w: native source or volume differs", ErrUnsafe)
	}
	return data, nil
}
