package imagequalification

import (
	"encoding/json/v2"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/app"
	"github.com/TerraScale/ts-orchestrator/internal/protocol"
	"github.com/TerraScale/ts-orchestrator/internal/qualification"
	"github.com/TerraScale/ts-orchestrator/internal/release"
	"github.com/TerraScale/ts-orchestrator/tests/imagequalification/host"
)

// retainRootCredentialEvidence retains only this gate, never a production proof.
// The final writer v2 proof additionally requires both actual runtime gates on
// this exact retained imported image under their separately signed purpose.
func retainRootCredentialEvidence(p Prepared, report host.Report, evidence release.RootCredentialBoundaryEvidence, j journal, cloudHosts []hostObservation, proofs map[string][]byte, directory string, now time.Time) (release.ProductionGateEvidence, error) {
	var empty release.ProductionGateEvidence
	a := p.approval
	expected := a.Candidate
	expected.ImageOCID = j.ImageID
	if a.Purpose != qualification.RootCredentialBoundaryPurpose || a.Candidate.Role != release.FoundationWriterRole ||
		a.Candidate.ImageOCID != "" && a.Candidate.ImageOCID != j.ImageID || j.ImageID == "" || j.ImageDeleted ||
		hashBytes(p.approvalWire) != p.approvalSHA256 || len(p.principalWire) == 0 ||
		j.RunID != a.RunID || j.ApprovalSHA256 != p.approvalSHA256 || report.RunID != a.RunID || report.Candidate != expected || report.ImageOCID != j.ImageID ||
		report.StartedAt.Before(p.issuedAt) || report.CompletedAt.Before(report.StartedAt) || report.CompletedAt.After(p.expires) ||
		!evidence.CompletedAt.Equal(report.CompletedAt) || now.Before(report.CompletedAt) || now.After(a.CleanupUntil) ||
		len(report.Hosts) != 4 || len(cloudHosts) != 4 || len(a.Hosts) != 4 || len(proofs) != 4 || len(report.Scenarios) != 1 {
		return empty, errors.New("root credential evidence lacks exact retained candidate, purpose or finite authority")
	}
	if err := evidence.Validate(expected); err != nil {
		return empty, err
	}
	scenario := report.Scenarios[0]
	if scenario.Gate != release.RootCredentialBoundaryGate || scenario.Name != release.RootCredentialBoundaryGate ||
		scenario.StartedAt.Before(report.StartedAt) || scenario.CompletedAt.Before(scenario.StartedAt) || scenario.CompletedAt.After(report.CompletedAt) ||
		len(scenario.HostIDs) != 4 || len(scenario.Transcript) == 0 || hashBytes(scenario.Transcript) != scenario.TranscriptSHA256 {
		return empty, errors.New("root credential native scenario is absent or changed")
	}
	for i, spec := range a.Hosts {
		h, c, e := report.Hosts[i], cloudHosts[i], evidence.Hosts[i]
		role := spec.Role
		if role == "worker" {
			role = "container"
		}
		if e.InstanceID != j.Hosts[spec.Name] || h.OCID != e.InstanceID || h.Role != role || e.Role != role || c.Name != spec.Name || c.InstanceID != h.OCID ||
			c.ImageID != j.ImageID || h.Address != c.PrivateIP || e.NamespaceSHA256 != hashBytes([]byte(a.Namespace)) || !slices.Contains(scenario.HostIDs, h.OCID) ||
			h.Observed.InstanceID != h.OCID || h.Observed.ImageOCID != j.ImageID || h.Observed.Architecture != a.Candidate.Architecture || h.Observed.BinarySHA256 != a.BinarySHA256 ||
			h.Observed.KernelRelease != a.KernelRelease || h.Observed.KernelSHA256 != a.KernelSHA256 || h.Observed.ContainerdSHA256 != a.ContainerdSHA256 || h.Observed.RuncSHA256 != a.RuncSHA256 ||
			h.WorkerSHA256 != a.RunnerSHA256 || h.WorkerSourceRevision != a.Candidate.SourceRevision || len(proofs[h.OCID]) == 0 {
			return empty, errors.New("root credential evidence differs from approved native SDK host observations")
		}
		var result app.RootOCIQualificationResult
		if protocol.DecodeStrict(e.Transcript, &result, 64<<10) != nil || result.SourceSHA256 != hashBytes(proofs[h.OCID]) ||
			result.InstanceID != h.OCID || result.ImageID != j.ImageID || result.BinarySHA256 != a.BinarySHA256 || result.NamespaceSHA256 != e.NamespaceSHA256 ||
			result.RootUID != 0 || result.PeerUID != e.OrdinaryUID || !result.Negative.SameUIDProcessDenied || !result.Negative.ProtectedWriteDenied || !result.Negative.RawSignDenied || !result.Negative.IMDSDenied {
			return empty, errors.New("root credential typed transcript differs from exact signed host admission")
		}
		local := result.Readers.LocalInstance
		if len(local.Response) == 0 || local.Bytes != int64(len(local.Response)) || local.SHA256 != hashBytes(local.Response) {
			return empty, errors.New("root credential local-instance response is absent or changed")
		}
	}
	wire, err := json.Marshal(evidence, json.Deterministic(true))
	if err != nil {
		return empty, err
	}
	wire = append(wire, '\n')
	if len(wire) > release.MaxProductionEvidenceBytes {
		return empty, errors.New("root credential evidence exceeds retained object limit")
	}
	if err := os.MkdirAll(filepath.Join(directory, "objects"), 0700); err != nil {
		return empty, err
	}
	digest := hashBytes(wire)
	if err := retainBytes(filepath.Join(directory, "objects", digest), wire); err != nil {
		return empty, err
	}
	return release.ProductionGateEvidence{Gate: release.RootCredentialBoundaryGate, SHA256: digest, Bytes: int64(len(wire)), CompletedAt: evidence.CompletedAt}, nil
}
