package execution

import (
	"bytes"
	"context"
	"crypto/sha256"
	"debug/elf"
	"encoding/hex"
	"encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"maps"
	"slices"
	"strings"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/entityid"
	"github.com/TerraScale/ts-orchestrator/internal/protocol"
	"github.com/TerraScale/ts-orchestrator/internal/release"
	"github.com/TerraScale/ts-orchestrator/internal/storage/executionwire"
	"github.com/TerraScale/ts-orchestrator/internal/storage/hostvolume"
	"github.com/TerraScale/ts-orchestrator/internal/trust"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
)

const StatefulQualificationSchema = "terrascale.release.stateful-workload-safety.v1"

// RetainedData identifies the existing data and the source that last owned its format.
// Its values come from current authority/member/OCI records, never the release proof.
type RetainedData = executionwire.RetainedData

// CPUProfile binds qualification to the actual feature intersection of the host CPUs.
type CPUProfile struct {
	Architecture   string `json:"architecture"`
	FeaturesSHA256 string `json:"features_sha256"`
}

// StatefulQualification is the retained workload-safety payload authenticated by
// the existing independent ProductionQualification. The monorepo produces it.
type StatefulQualification struct {
	Schema                    string                           `json:"schema"`
	CandidateSourceTreeSHA256 string                           `json:"candidate_source_tree_sha256"`
	Data                      RetainedData                     `json:"data"`
	ResultData                RetainedData                     `json:"result_data"`
	SourceCPU                 CPUProfile                       `json:"source_cpu"`
	TargetCPU                 CPUProfile                       `json:"target_cpu"`
	DiskFormatSHA256          string                           `json:"disk_format_sha256"`
	SourceArtifact            *release.ProductionGateEvidence  `json:"source_artifact,omitempty"`
	ImageManifest             release.ProductionGateEvidence   `json:"image_manifest"`
	ImageConfig               release.ProductionGateEvidence   `json:"image_config"`
	Scenarios                 []release.ProductionGateEvidence `json:"passed_scenarios"`
}

// VerifiedStateful has no public constructor or writable authorization fields.
type VerifiedStateful struct {
	container    release.VerifiedContainer
	data         RetainedData
	result       RetainedData
	cpu          CPUProfile
	digest       string
	until        time.Time
	imageConfig  ocispec.Image
	nativeSource bool
}

func (v VerifiedStateful) Container() release.VerifiedContainer { return v.container }
func (v VerifiedStateful) Data() RetainedData                   { return v.data }
func (v VerifiedStateful) ResultData() RetainedData             { return v.result }
func (v VerifiedStateful) CPU() CPUProfile                      { return v.cpu }
func (v VerifiedStateful) SHA256() string                       { return v.digest }
func (v VerifiedStateful) ValidUntil() time.Time                { return v.until }
func (v VerifiedStateful) ImageConfig() ocispec.ImageConfig {
	config := v.imageConfig.Config
	config.Env = slices.Clone(config.Env)
	config.Entrypoint = slices.Clone(config.Entrypoint)
	config.Cmd = slices.Clone(config.Cmd)
	config.ExposedPorts = maps.Clone(config.ExposedPorts)
	config.Volumes = maps.Clone(config.Volumes)
	config.Labels = maps.Clone(config.Labels)
	return config
}

func digestValid(value string) bool {
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == sha256.Size && hex.EncodeToString(decoded) == value
}

func retainedDataValid(data RetainedData) bool {
	return entityid.Valid(data.DatabaseID) && entityid.Valid(data.PartitionID) &&
		strings.HasPrefix(data.VolumeID, "ocid1.volume.") && hostvolume.ValidUUID(data.FileSystemUUID) &&
		(data.FileSystemType == "ext4" || data.FileSystemType == "xfs") &&
		digestValid(data.DiskFormatSHA256) && digestValid(data.SourceArtifactSHA256) && digestValid(data.SourceTreeSHA256) &&
		(data.SourceArchitecture == "amd64" || data.SourceArchitecture == "arm64")
}

func (cpu CPUProfile) valid() bool {
	return (cpu.Architecture == "amd64" || cpu.Architecture == "arm64") && digestValid(cpu.FeaturesSHA256)
}

// VerifyStatefulCurrent consumes the existing signed OCI release and independent
// qualifier. Generic workload evidence cannot authorize a database migration.
func VerifyStatefulCurrent(ctx context.Context, bundle release.ContainerBundle, roots trust.Keyring,
	target release.ContainerTarget, data RetainedData, cpu CPUProfile, now, until time.Time,
	evidence func(context.Context, string) (io.ReadCloser, error),
) (VerifiedStateful, error) {
	if ctx == nil || ctx.Err() != nil || target.Role != "terrabase" || !retainedDataValid(data) || !cpu.valid() ||
		cpu.Architecture != target.Architecture || now.IsZero() || !until.After(now) || evidence == nil {
		return VerifiedStateful{}, fmt.Errorf("%w: stateful qualification scope", release.ErrProductionQualification)
	}
	container, err := release.VerifyContainerCurrent(ctx, bundle, roots, target, now, until, evidence)
	if err != nil {
		return VerifiedStateful{}, err
	}
	claim := container.Claim()
	_, imageDigest, _ := strings.Cut(claim.Image, "@sha256:")
	expected := release.ProductionExpectation{SourceRevision: claim.SourceRevision, ArtifactSHA256: imageDigest,
		QualificationSHA256: claim.QualificationSHA256, Cell: claim.Cell, Environment: claim.Environment,
		Runtime: release.ProductionRuntime, Architecture: claim.Architecture, Role: claim.Role}
	qualification, err := release.VerifyProductionCurrent(claim.Production.Qualification, claim.Production.Delegation, roots, expected, now)
	if err != nil {
		return VerifiedStateful{}, err
	}
	retained := qualification.Evidence[1]
	// The signed outer verifier fixes this index to workload-safety.
	wire, err := readStatefulEvidence(ctx, evidence, retained, trust.MaxPayloadBytes)
	if err != nil {
		return VerifiedStateful{}, err
	}
	var proof StatefulQualification
	if err := protocol.DecodeStrict(wire, &proof, trust.MaxPayloadBytes); err != nil {
		return VerifiedStateful{}, fmt.Errorf("%w: typed workload-safety evidence", release.ErrProductionQualification)
	}
	if proof.Schema != StatefulQualificationSchema || proof.CandidateSourceTreeSHA256 != claim.SourceTreeSHA256 ||
		proof.Data != data || proof.TargetCPU != cpu || !proof.SourceCPU.valid() ||
		proof.SourceCPU.Architecture != data.SourceArchitecture || proof.DiskFormatSHA256 != data.DiskFormatSHA256 {
		return VerifiedStateful{}, fmt.Errorf("%w: retained data, source, CPU or disk format differs", release.ErrProductionQualification)
	}
	expectedResult := proof.ResultData
	expectedResult.DiskFormatSHA256 = data.DiskFormatSHA256
	expectedResult.SourceArtifactSHA256 = data.SourceArtifactSHA256
	expectedResult.SourceTreeSHA256 = data.SourceTreeSHA256
	expectedResult.SourceArchitecture = data.SourceArchitecture
	if !retainedDataValid(proof.ResultData) || expectedResult != data || proof.ResultData.SourceArtifactSHA256 != imageDigest ||
		proof.ResultData.SourceTreeSHA256 != claim.SourceTreeSHA256 || proof.ResultData.SourceArchitecture != claim.Architecture {
		return VerifiedStateful{}, fmt.Errorf("%w: resulting retained data provenance differs", release.ErrProductionQualification)
	}
	if proof.ImageManifest.Gate != "image-manifest" || proof.ImageManifest.SHA256 != imageDigest ||
		proof.ImageConfig.Gate != "image-config" || proof.ImageManifest.CompletedAt.IsZero() || proof.ImageConfig.CompletedAt.IsZero() ||
		proof.ImageManifest.CompletedAt.After(retained.CompletedAt) || proof.ImageConfig.CompletedAt.After(retained.CompletedAt) {
		return VerifiedStateful{}, fmt.Errorf("%w: image config provenance", release.ErrProductionQualification)
	}
	manifestWire, err := readStatefulEvidence(ctx, evidence, proof.ImageManifest, trust.MaxPayloadBytes)
	if err != nil {
		return VerifiedStateful{}, err
	}
	configWire, err := readStatefulEvidence(ctx, evidence, proof.ImageConfig, trust.MaxPayloadBytes)
	if err != nil {
		return VerifiedStateful{}, err
	}
	var manifest ocispec.Manifest
	var imageConfig ocispec.Image
	if err := json.Unmarshal(manifestWire, &manifest); err != nil {
		return VerifiedStateful{}, err
	}
	if err := json.Unmarshal(configWire, &imageConfig); err != nil {
		return VerifiedStateful{}, err
	}
	if manifest.SchemaVersion != 2 || manifest.Config.Digest.String() != "sha256:"+proof.ImageConfig.SHA256 || manifest.Config.Size != proof.ImageConfig.Bytes ||
		imageConfig.Architecture != claim.Architecture || imageConfig.OS != "linux" || len(imageConfig.Config.Entrypoint) == 0 || len(imageConfig.Config.Cmd) != 0 {
		return VerifiedStateful{}, fmt.Errorf("%w: exact child image configuration", release.ErrProductionQualification)
	}
	gates := [...]string{"retained-restart", "restore", "replication-catchup", "durable-drain", "sigterm", "cpu-format-transition"}
	if len(proof.Scenarios) != len(gates) {
		return VerifiedStateful{}, fmt.Errorf("%w: required stateful scenarios", release.ErrProductionQualification)
	}
	total := retained.Bytes + proof.ImageManifest.Bytes + proof.ImageConfig.Bytes
	nativeSource := false
	if proof.SourceArtifact != nil {
		source := *proof.SourceArtifact
		if source.Gate != "native-source-artifact" || source.SHA256 != data.SourceArtifactSHA256 || source.CompletedAt.IsZero() || source.CompletedAt.After(retained.CompletedAt) || source.Bytes > release.MaxProductionEvidenceBytes-total {
			return VerifiedStateful{}, release.ErrProductionQualification
		}
		sourceWire, err := readStatefulEvidence(ctx, evidence, source, release.MaxProductionEvidenceBytes-total)
		if err != nil {
			return VerifiedStateful{}, err
		}
		binary, err := elf.NewFile(bytes.NewReader(sourceWire))
		if err != nil {
			return VerifiedStateful{}, fmt.Errorf("%w: native source ELF", release.ErrProductionQualification)
		}
		arch := ""
		switch binary.Machine {
		case elf.EM_X86_64:
			arch = "amd64"
		case elf.EM_AARCH64:
			arch = "arm64"
		}
		if arch == "" || arch != data.SourceArchitecture || binary.Class != elf.ELFCLASS64 || binary.Data != elf.ELFDATA2LSB {
			return VerifiedStateful{}, release.ErrProductionQualification
		}
		total += source.Bytes
		nativeSource = true
	}
	for index, gate := range gates {
		scenario := proof.Scenarios[index]
		if scenario.Gate != gate || scenario.CompletedAt.IsZero() || scenario.CompletedAt.After(retained.CompletedAt) ||
			scenario.Bytes <= 0 || scenario.Bytes > release.MaxProductionEvidenceBytes-total {
			return VerifiedStateful{}, fmt.Errorf("%w: %s scenario", release.ErrProductionQualification, gate)
		}
		total += scenario.Bytes
		if _, err := readStatefulEvidence(ctx, evidence, scenario, release.MaxProductionEvidenceBytes); err != nil {
			return VerifiedStateful{}, err
		}
	}
	return VerifiedStateful{container: container, data: data, result: proof.ResultData, cpu: cpu, digest: retained.SHA256, until: until, imageConfig: imageConfig, nativeSource: nativeSource}, nil
}

func readStatefulEvidence(ctx context.Context, open func(context.Context, string) (io.ReadCloser, error),
	evidence release.ProductionGateEvidence, maximum int64,
) ([]byte, error) {
	if !digestValid(evidence.SHA256) || evidence.Bytes <= 0 || evidence.Bytes > maximum {
		return nil, release.ErrProductionQualification
	}
	reader, err := open(ctx, evidence.SHA256)
	if err != nil {
		return nil, err
	}
	if reader == nil {
		return nil, release.ErrProductionQualification
	}
	wire, readErr := io.ReadAll(io.LimitReader(reader, evidence.Bytes+1))
	if err := errors.Join(readErr, reader.Close()); err != nil {
		return nil, err
	}
	if int64(len(wire)) != evidence.Bytes || fmt.Sprintf("%x", sha256.Sum256(wire)) != evidence.SHA256 {
		return nil, fmt.Errorf("%w: retained stateful evidence bytes differ", release.ErrProductionQualification)
	}
	return wire, nil
}

func statefulDigest(value any) (string, error) {
	wire, err := json.Marshal(value, json.Deterministic(true))
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%x", sha256.Sum256(wire)), nil
}

// VerifyStatefulDeclared authenticates the release's declared qualification for
// manager service construction. It does not observe a worker CPU or volume and
// cannot replace Source's independent runtime admission.
func VerifyStatefulDeclared(ctx context.Context, bundle release.ContainerBundle, roots trust.Keyring, target release.ContainerTarget, now, until time.Time, evidence func(context.Context, string) (io.ReadCloser, error)) (VerifiedStateful, error) {
	container, err := release.VerifyContainerCurrent(ctx, bundle, roots, target, now, until, evidence)
	if err != nil {
		return VerifiedStateful{}, err
	}
	claim := container.Claim()
	_, imageDigest, _ := strings.Cut(claim.Image, "@sha256:")
	expected := release.ProductionExpectation{SourceRevision: claim.SourceRevision, ArtifactSHA256: imageDigest, QualificationSHA256: claim.QualificationSHA256, Cell: claim.Cell, Environment: claim.Environment, Runtime: release.ProductionRuntime, Architecture: claim.Architecture, Role: claim.Role}
	qualified, err := release.VerifyProductionCurrent(claim.Production.Qualification, claim.Production.Delegation, roots, expected, now)
	if err != nil {
		return VerifiedStateful{}, err
	}
	wire, err := readStatefulEvidence(ctx, evidence, qualified.Evidence[1], trust.MaxPayloadBytes)
	if err != nil {
		return VerifiedStateful{}, err
	}
	var declared StatefulQualification
	if err := protocol.DecodeStrict(wire, &declared, trust.MaxPayloadBytes); err != nil {
		return VerifiedStateful{}, err
	}
	return VerifyStatefulCurrent(ctx, bundle, roots, target, declared.Data, declared.TargetCPU, now, until, evidence)
}
