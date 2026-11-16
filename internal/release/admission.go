package release

import (
	"errors"
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
