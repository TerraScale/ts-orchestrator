package imagequalification

import (
	"encoding/json/jsontext"
	"encoding/json/v2"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/release"
	"github.com/TerraScale/ts-orchestrator/tests/imagequalification/host"
)

// HostObservation comes from authenticated Compute/VNIC observations before SSH.
// Guest IMDS observations are checked against it, not treated as attestation.
type hostObservation struct {
	Name             string `json:"name"`
	InstanceID       string `json:"instance_id"`
	ImageID          string `json:"image_id"`
	PrivateIP        string `json:"private_ip"`
	HostKeySHA256    string `json:"host_key_sha256"`
	ConsoleHistoryID string `json:"console_history_id"`
	ConsoleSHA256    string `json:"console_sha256"`
}

type gateRecord struct {
	Schema             string            `json:"schema"`
	ApprovalEnvelope   []byte            `json:"approval_envelope"`
	ApprovalDelegation []byte            `json:"approval_delegation,omitempty"`
	ApprovalSHA256     string            `json:"approval_sha256"`
	ConfinementSHA256  string            `json:"confinement_sha256"`
	Confinement        []byte            `json:"confinement"`
	Approval           Approval          `json:"approval"`
	ImageID            string            `json:"image_id"`
	Hosts              []host.HostReport `json:"hosts"`
	CloudHosts         []hostObservation `json:"cloud_hosts"`
	Scenarios          []host.Scenario   `json:"scenarios"`
	Resources          journal           `json:"resources"`
	CompletedAt        time.Time         `json:"completed_at"`
}

// retainProof writes an unsigned payload for an independent existing qualifier.
// No report, file or SDK observation grants production signing authority.
func retainProof(p Prepared, report host.Report, resources journal, hosts []hostObservation, confinement []byte, directory string, now time.Time) (release.ProductionQualification, error) {
	var result release.ProductionQualification
	if hashBytes(p.approvalWire) != p.approvalSHA256 || !jsontext.Value(p.approvalWire).IsValid() {
		return result, errors.New("sealed signed approval bytes are absent or changed")
	}
	if err := validateReport(p, report, resources, hosts, now); err != nil {
		return result, err
	}
	if !jsontext.Value(confinement).IsValid() {
		return result, errors.New("retained confinement observations are absent or invalid")
	}
	result = release.ProductionQualification{Schema: release.ProductionQualificationSchema, Candidate: p.approval.Candidate}
	if err := os.MkdirAll(filepath.Join(directory, "objects"), 0700); err != nil {
		return result, err
	}
	for _, gate := range []string{"runtime-ha", "workload-safety"} {
		record := gateRecord{Schema: "terrascale.test.image-qualification.evidence.v1", ApprovalEnvelope: p.approvalWire, ApprovalDelegation: p.delegationWire, ApprovalSHA256: p.approvalSHA256, ConfinementSHA256: hashBytes(confinement), Confinement: confinement, Approval: p.Approval(), ImageID: report.ImageOCID, Hosts: report.Hosts, CloudHosts: hosts, Resources: resources, CompletedAt: now}
		for _, scenario := range report.Scenarios {
			if scenario.Gate == gate {
				record.Scenarios = append(record.Scenarios, scenario)
			}
		}
		wire, err := json.Marshal(record, json.Deterministic(true))
		if err != nil {
			return result, err
		}
		wire = append(wire, '\n')
		if len(wire) > release.MaxProductionEvidenceBytes {
			return result, errors.New("native gate evidence exceeds retained object limit")
		}
		digest := hashBytes(wire)
		if err := retainBytes(filepath.Join(directory, "objects", digest), wire); err != nil {
			return result, err
		}
		result.Evidence = append(result.Evidence, release.ProductionGateEvidence{Gate: gate, SHA256: digest, Bytes: int64(len(wire)), CompletedAt: now})
	}
	wire, err := json.Marshal(result, json.Deterministic(true))
	if err != nil {
		return result, err
	}
	return result, retainBytes(filepath.Join(directory, "production.unsigned.json"), append(wire, '\n'))
}

func retainBytes(path string, wire []byte) error {
	if existing, err := os.ReadFile(path); err == nil {
		if string(existing) != string(wire) {
			return errors.New("retained qualification output already contains different bytes")
		}
		return nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	_, err = file.Write(wire)
	if err == nil {
		err = file.Sync()
	}
	return errors.Join(err, file.Close())
}

func validateReport(p Prepared, r host.Report, j journal, cloudHosts []hostObservation, now time.Time) error {
	a := p.approval
	if a.Candidate.Role != "orchestrator" || a.Candidate.Runtime != release.ProductionRuntime || r.RunID != a.RunID || r.Candidate != a.Candidate || r.ImageOCID == "" || r.ImageOCID != j.ImageID || r.WorkloadImage != a.WorkloadImage || r.WorkloadArchiveSHA256 != a.WorkloadArchiveSHA256 {
		return errors.New("native report candidate or immutable artifacts differ")
	}
	if r.StartedAt.IsZero() || r.CompletedAt.Before(r.StartedAt) || r.CompletedAt.After(p.expires) || now.Before(r.CompletedAt) || now.After(a.CleanupUntil) {
		return errors.New("native run or cleanup is outside finite authority")
	}
	if j.RunID != a.RunID || j.ApprovalSHA256 != p.approvalSHA256 || !j.ImageDeleted || !j.ObjectDeleted || len(j.Hosts) != len(a.Hosts) || len(j.Terminated) != len(a.Hosts) || len(r.Hosts) != len(a.Hosts) || len(cloudHosts) != len(a.Hosts) {
		return errors.New("native qualification requires complete exact-resource cleanup")
	}
	peer, _ := netip.ParsePrefix(a.PeerCIDR)
	ids, addresses, keys, nodes := map[string]bool{}, map[string]bool{}, map[string]bool{}, map[string]bool{}
	for index, spec := range a.Hosts {
		h, c := r.Hosts[index], cloudHosts[index]
		role := spec.Role
		if role == "worker" {
			role = "container"
		}
		ip, err := netip.ParseAddr(h.Address)
		if err != nil || !peer.Contains(ip) || ids[h.OCID] || addresses[h.Address] || h.Role != role || h.OCID != j.Hosts[spec.Name] || !j.Terminated[spec.Name] || c.Name != spec.Name || c.InstanceID != h.OCID || c.ImageID != r.ImageOCID || c.PrivateIP != h.Address || !validHash(c.HostKeySHA256) || !validHash(c.ConsoleSHA256) || keys[c.HostKeySHA256] || c.HostKeySHA256 != hashBytes([]byte(j.HostKeys[spec.Name])) || c.ConsoleSHA256 != j.ConsoleDigests[spec.Name] || c.ConsoleHistoryID == "" || c.ConsoleHistoryID != j.HostConsoleHistory[spec.Name] {
			return errors.New("native host differs from authenticated exact-image host observations")
		}
		i := h.Observed
		if i.InstanceID != h.OCID || i.ImageOCID != r.ImageOCID || i.Architecture != a.Candidate.Architecture || i.KernelRelease != a.KernelRelease || i.KernelSHA256 != a.KernelSHA256 || i.BinarySHA256 != a.BinarySHA256 || i.ContainerdSHA256 != a.ContainerdSHA256 || i.RuncSHA256 != a.RuncSHA256 || h.WorkerSHA256 != a.RunnerSHA256 || h.WorkerSourceRevision != a.Candidate.SourceRevision || h.NodeID == "" || nodes[h.NodeID] {
			return errors.New("observed native runtime or worker source differs")
		}
		ids[h.OCID], addresses[h.Address], keys[c.HostKeySHA256], nodes[h.NodeID] = true, true, true, true
	}
	required := map[string]string{"native-three-manager-formation": "runtime-ha", "manager-loss": "runtime-ha", "manager-partition": "runtime-ha", "agent-restart": "runtime-ha", "unavailable-agent-replacement": "runtime-ha", "cleanup": "runtime-ha", "container-isolation": "workload-safety", "readiness-rejection": "workload-safety", "rollback": "workload-safety"}
	if len(r.Scenarios) != len(required) {
		return errors.New("native report lacks exact required scenarios")
	}
	seen := map[string]bool{}
	for _, scenario := range r.Scenarios {
		if seen[scenario.Name] || required[scenario.Name] == "" || required[scenario.Name] != scenario.Gate || scenario.StartedAt.Before(r.StartedAt) || scenario.CompletedAt.Before(scenario.StartedAt) || scenario.CompletedAt.After(r.CompletedAt) || len(scenario.Transcript) == 0 || hashBytes(scenario.Transcript) != scenario.TranscriptSHA256 || len(scenario.HostIDs) != len(a.Hosts) {
			return fmt.Errorf("native scenario %q identity, transcript or bounds differ", scenario.Name)
		}
		for _, h := range r.Hosts {
			if !slices.Contains(scenario.HostIDs, h.OCID) {
				return errors.New("native scenario omits an exact host")
			}
		}
		seen[scenario.Name] = true
	}
	for operation := range j.ConsoleHistories {
		if !j.ConsoleDeleted[operation] {
			return errors.New("console-history cleanup is incomplete")
		}
	}
	for operation := range j.Intents {
		if !j.resolved(operation) {
			return errors.New("unresolved create intent cannot produce qualification")
		}
	}
	return nil
}
