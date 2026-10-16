package release

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/TerraScale/ts-orchestrator/internal/protocol"
)

const (
	QualificationSchema     = "terrascale.release.qualification.v1"
	QualificationRepository = "TerraScale/ts-orchestrator"
	QualificationWorkflow   = "ci.yml"
	QualificationJob        = "verify/go + artifact/linux-amd64-arm64"
	MaxQualificationBytes   = 64 << 10
)

var ErrInvalidQualification = errors.New("release qualification is invalid")

// Qualification identifies a successful source check and the exact binary
// assets retained by that check. The caller must independently verify the
// GitHub run result before treating this manifest as promotion authority.
type Qualification struct {
	Schema         string              `json:"schema"`
	Repository     string              `json:"repository"`
	SourceRevision string              `json:"source_revision"`
	SourceTree     string              `json:"source_tree"`
	GoVersion      string              `json:"go_version"`
	GoModSHA256    string              `json:"go_mod_sha256"`
	GoSumSHA256    string              `json:"go_sum_sha256"`
	Verification   QualificationCheck  `json:"verification"`
	Artifacts      []QualifiedArtifact `json:"artifacts"`
}

type QualificationCheck struct {
	Workflow   string `json:"workflow"`
	Job        string `json:"job"`
	RunID      int64  `json:"run_id"`
	RunNumber  int64  `json:"run_number"`
	Conclusion string `json:"conclusion"`
}

type QualifiedArtifact struct {
	Architecture string `json:"architecture"`
	Name         string `json:"name"`
	Bytes        int64  `json:"bytes"`
	SHA256       string `json:"sha256"`
}

// DecodeQualification rejects ambiguous JSON and returns the digest of the
// exact retained manifest bytes. Its success field is only a claim until the
// caller checks the GitHub result independently.
func DecodeQualification(wire []byte) (Qualification, string, error) {
	var qualification Qualification
	if err := protocol.DecodeStrict(wire, &qualification, MaxQualificationBytes); err != nil {
		return Qualification{}, "", fmt.Errorf("decode qualification: %w", err)
	}
	if err := qualification.Validate(); err != nil {
		return Qualification{}, "", err
	}
	digest := sha256.Sum256(wire)
	return qualification, hex.EncodeToString(digest[:]), nil
}

func (qualification Qualification) Validate() error {
	if qualification.Schema != QualificationSchema || qualification.Repository != QualificationRepository ||
		!revisionPattern.MatchString(qualification.SourceRevision) || !revisionPattern.MatchString(qualification.SourceTree) ||
		qualification.GoVersion != DefaultGoVersion || !digestPattern.MatchString(qualification.GoModSHA256) ||
		!digestPattern.MatchString(qualification.GoSumSHA256) ||
		qualification.Verification.Workflow != QualificationWorkflow || qualification.Verification.Job != QualificationJob ||
		qualification.Verification.RunID <= 0 || qualification.Verification.RunNumber <= 0 ||
		qualification.Verification.Conclusion != "success" {
		return fmt.Errorf("%w: source or required successful check", ErrInvalidQualification)
	}
	if len(qualification.Artifacts) != 2 {
		return fmt.Errorf("%w: both Linux architectures are required", ErrInvalidQualification)
	}
	for index, architecture := range [...]string{"amd64", "arm64"} {
		asset := qualification.Artifacts[index]
		if asset.Architecture != architecture || asset.Name != "terrascale-orchestrator-linux-"+architecture ||
			asset.Bytes <= 0 || asset.Bytes > MaxArtifactBytes || !digestPattern.MatchString(asset.SHA256) {
			return fmt.Errorf("%w: invalid or unordered %s artifact", ErrInvalidQualification, architecture)
		}
	}
	return nil
}

// MatchBinary binds a v2 signed receipt to the exact qualification manifest
// and the retained artifact metadata for its architecture.
func (qualification Qualification) MatchBinary(receipt BinaryReceipt, qualificationSHA256 string) error {
	if err := qualification.Validate(); err != nil {
		return err
	}
	if err := receipt.Validate(); err != nil {
		return err
	}
	if receipt.SourceRevision != qualification.SourceRevision || receipt.GoVersion != qualification.GoVersion ||
		receipt.QualificationSHA256 != qualificationSHA256 {
		return fmt.Errorf("%w: binary source or manifest digest mismatch", ErrInvalidQualification)
	}
	for _, asset := range qualification.Artifacts {
		if asset.Architecture == receipt.GOARCH {
			if asset.Bytes != receipt.Bytes || asset.SHA256 != receipt.SHA256 {
				return fmt.Errorf("%w: binary differs from retained artifact", ErrInvalidQualification)
			}
			return nil
		}
	}
	return fmt.Errorf("%w: binary architecture is missing", ErrInvalidQualification)
}
