package imagequalification

import (
	"context"
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
	"github.com/TerraScale/ts-orchestrator/tests/imagequalification/confinement"
	"github.com/TerraScale/ts-orchestrator/tests/imagequalification/host"
	"github.com/TerraScale/ts-orchestrator/tests/imagequalification/netbird"
	"github.com/TerraScale/ts-orchestrator/tests/imagequalification/netbird/protocol"
)

type netBirdObservationRecord struct {
	gateRecord
	StartedAt      time.Time `json:"started_at"`
	RunCompletedAt time.Time `json:"run_completed_at"`
}

type netBirdEvent struct {
	Host        string               `json:"host"`
	Operation   string               `json:"operation"`
	Observation protocol.Observation `json:"observation"`
}

// retainNetBirdProof retains public observations even when a scenario failed.
// The existing ProductionQualification carrier remains empty until every real
// dedicated-role gate exists; the signed-SDK fixture supplies no recovery gate.
func retainNetBirdProof(ctx context.Context, p Prepared, verified confinement.Verified, r host.Report, j journal, hosts []hostObservation, directory string, now time.Time) (release.ProductionQualification, string, error) {
	var proof release.ProductionQualification
	a := p.approval
	if err := a.validate(); err != nil {
		return proof, "", err
	}
	if a.Candidate.Role != "netbird-manager" || hashBytes(p.approvalWire) != p.approvalSHA256 || p.approvalSHA256 == "" || !jsontext.Value(p.approvalWire).IsValid() || r.RunID != a.RunID || r.Candidate != a.Candidate || r.ImageOCID == "" || r.ImageOCID != j.ImageID || r.WorkloadImage != "" || r.WorkloadArchiveSHA256 != "" {
		return proof, "", errors.New("dedicated NetBird observations differ from sealed candidate")
	}
	wire, err := validatedConfinement(ctx, p, j, verified)
	if err != nil {
		return proof, "", err
	}
	if err := netBirdPublicScenarios(r, j); err != nil {
		return proof, "", err
	}
	record := netBirdObservationRecord{gateRecord: gateRecord{Schema: "terrascale.test.netbird-image-observations.v1", ApprovalEnvelope: p.approvalWire, ApprovalDelegation: p.delegationWire, ApprovalSHA256: p.approvalSHA256, ConfinementSHA256: hashBytes(wire), Confinement: wire, Approval: p.Approval(), ImageID: r.ImageOCID, Hosts: r.Hosts, CloudHosts: hosts, Scenarios: r.Scenarios, Resources: j, CompletedAt: now}, StartedAt: r.StartedAt, RunCompletedAt: r.CompletedAt}
	wire, err = json.Marshal(record, json.Deterministic(true))
	if err != nil {
		return proof, "", err
	}
	wire = append(wire, '\n')
	if len(wire) > release.MaxProductionEvidenceBytes {
		return proof, "", errors.New("dedicated NetBird observations exceed retained object bound")
	}
	path := filepath.Join(directory, "objects", hashBytes(wire))
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return proof, "", err
	}
	if err := retainBytes(path, wire); err != nil {
		return proof, "", err
	}
	if err := validateNetBirdReport(p, r, j, hosts, now); err != nil {
		return proof, path, err
	}
	// The current worker reports internal fixture TLS and signed-SDK fixture
	// storage. Neither can establish all required production recovery guarantees.
	return proof, path, errors.New("dedicated NetBird observations retained; required netbird-recovery gate is absent")
}

func netBirdPublicScenarios(r host.Report, j journal) error {
	seen := map[string]bool{}
	for _, scenario := range r.Scenarios {
		if seen[scenario.Name] || !slices.Contains([]string{"netbird-foundation", "netbird-recovery", "cleanup"}, scenario.Name) || len(scenario.Transcript) == 0 || len(scenario.Transcript) > release.MaxProductionEvidenceBytes || hashBytes(scenario.Transcript) != scenario.TranscriptSHA256 {
			return errors.New("dedicated NetBird scenario identity or transcript differs")
		}
		seen[scenario.Name] = true
		var events []jsontext.Value
		if err := json.Unmarshal(scenario.Transcript, &events); err != nil || len(events) > 32 {
			return errors.New("dedicated NetBird transcript is not a bounded event array")
		}
		for _, wire := range events {
			var event netBirdEvent
			if err := json.Unmarshal(wire, &event, json.RejectUnknownMembers(true)); err == nil {
				if !slices.Contains([]string{"identity", "backup-store", "foundation", "restart", "rotate", "backup", "retire", "restore", "cleanup"}, event.Operation) || !netBirdJournalHost(j, event.Host) {
					return errors.New("dedicated NetBird transcript event is outside exact hosts or operations")
				}
				continue
			}
			var removed netbird.Removal
			if err := json.Unmarshal(wire, &removed, json.RejectUnknownMembers(true)); err != nil || removed.State != "TERMINATED" || removed.ObservedAt.IsZero() || !netBirdJournalHost(j, removed.InstanceID) {
				return errors.New("dedicated NetBird transcript contains nonpublic or invalid fields")
			}
		}
	}
	return nil
}

func netBirdJournalHost(j journal, id string) bool {
	for _, owned := range j.Hosts {
		if id != "" && owned == id {
			return true
		}
	}
	return false
}

func validateNetBirdReport(p Prepared, r host.Report, j journal, cloudHosts []hostObservation, now time.Time) error {
	a := p.approval
	if r.StartedAt.IsZero() || r.StartedAt.Before(p.issuedAt) || r.CompletedAt.Before(r.StartedAt) || r.CompletedAt.After(p.expires) || now.Before(r.CompletedAt) || now.After(a.CleanupUntil) {
		return errors.New("dedicated NetBird run or cleanup is outside finite authority")
	}
	if j.RunID != a.RunID || j.ApprovalSHA256 != p.approvalSHA256 || j.CapabilityID == "" || j.CapabilityVersion == "" || !j.CapabilityDeleted || !j.ImageDeleted || !j.ObjectDeleted || len(j.Hosts) != 2 || len(j.Terminated) != 2 || len(r.Hosts) != 2 || len(cloudHosts) != 2 {
		return errors.New("dedicated NetBird report requires complete exact-resource cleanup")
	}
	peer, _ := netip.ParsePrefix(a.PeerCIDR)
	ids, addresses, keys := map[string]bool{}, map[string]bool{}, map[string]bool{}
	for index, spec := range a.Hosts {
		h, c := r.Hosts[index], cloudHosts[index]
		ip, err := netip.ParseAddr(h.Address)
		if err != nil || !peer.Contains(ip) || ids[h.OCID] || addresses[h.Address] || h.Role != spec.Role || h.OCID != j.Hosts[spec.Name] || !j.Terminated[spec.Name] || c.Name != spec.Name || c.InstanceID != h.OCID || c.ImageID != r.ImageOCID || c.PrivateIP != h.Address || !validHash(c.HostKeySHA256) || keys[c.HostKeySHA256] || c.HostKeySHA256 != hashBytes([]byte(j.HostKeys[spec.Name])) || !validHash(c.ConsoleSHA256) || c.ConsoleSHA256 != j.ConsoleDigests[spec.Name] || c.ConsoleHistoryID == "" || c.ConsoleHistoryID != j.HostConsoleHistory[spec.Name] {
			return errors.New("dedicated NetBird host differs from authenticated console and Compute observations")
		}
		i := h.Observed
		// File hashes bind the candidate's bytes, not running daemon/process identity.
		if i.InstanceID != h.OCID || i.ImageOCID != r.ImageOCID || i.Architecture != a.Candidate.Architecture || i.KernelRelease != a.KernelRelease || i.KernelSHA256 != a.KernelSHA256 || i.BinarySHA256 != a.BinarySHA256 || i.ContainerdSHA256 != a.ContainerdSHA256 || i.RuncSHA256 != a.RuncSHA256 || h.WorkerSHA256 != a.RunnerSHA256 || h.WorkerSourceRevision != a.Candidate.SourceRevision || h.NodeID != "" {
			return errors.New("dedicated NetBird runtime bytes or worker source differ")
		}
		ids[h.OCID], addresses[h.Address], keys[c.HostKeySHA256] = true, true, true
	}
	required := map[string]string{"netbird-foundation": "netbird-foundation", "netbird-recovery": "", "cleanup": ""}
	if len(r.Scenarios) != len(required) {
		return errors.New("dedicated NetBird report lacks exact role scenarios")
	}
	for _, scenario := range r.Scenarios {
		gate, exists := required[scenario.Name]
		if !exists || scenario.Gate != gate || scenario.StartedAt.Before(r.StartedAt) || scenario.CompletedAt.Before(scenario.StartedAt) || scenario.CompletedAt.After(r.CompletedAt) || len(scenario.HostIDs) != 2 || scenario.HostIDs[0] == scenario.HostIDs[1] {
			return fmt.Errorf("dedicated NetBird scenario %q gate, hosts or bounds differ", scenario.Name)
		}
		for _, h := range r.Hosts {
			if !slices.Contains(scenario.HostIDs, h.OCID) {
				return errors.New("dedicated NetBird scenario omits an exact native host")
			}
		}
	}
	for operation := range j.ConsoleHistories {
		if !j.ConsoleDeleted[operation] {
			return errors.New("dedicated NetBird console cleanup is incomplete")
		}
	}
	for operation := range j.Intents {
		if !j.resolved(operation) {
			return errors.New("dedicated NetBird unresolved create intent cannot qualify")
		}
	}
	return nil
}
