package imagequalification

import (
	"encoding/json/v2"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/release"
	"github.com/TerraScale/ts-orchestrator/internal/trust"
	"github.com/TerraScale/ts-orchestrator/tests/imagequalification/host"
)

// This exercises the evidence consumer using constructed reports. It does not
// establish that native scenarios ran or that any production image qualifies.
func reportFixture(t *testing.T, f qualificationFixture) (host.Report, journal, []hostObservation) {
	a := f.prepared.Approval()
	start := f.now.Add(time.Minute)
	r := host.Report{RunID: a.RunID, Candidate: a.Candidate, ImageOCID: "ocid1.image.oc1..fixture", WorkloadImage: a.WorkloadImage, WorkloadArchiveSHA256: a.WorkloadArchiveSHA256, StartedAt: start, CompletedAt: start.Add(time.Minute)}
	j := journal{RunID: a.RunID, ApprovalSHA256: f.prepared.approvalSHA256, ImageID: r.ImageOCID, Hosts: map[string]string{}, Terminated: map[string]bool{}, ImageDeleted: true, ObjectDeleted: true, Intents: map[string]time.Time{"image": start}}
	j.CapabilityID, j.CapabilityVersion, j.CapabilityDeleted, j.Intents["capability"] = "ocid1.computeimgcapschema.oc1..fixture", "fixture-version", true, start
	j.ConsoleHistories, j.ConsoleDeleted, j.HostKeys, j.ConsoleDigests, j.HostConsoleHistory = map[string]string{}, map[string]bool{}, map[string]string{}, map[string]string{}, map[string]string{}
	var cloud []hostObservation
	var ids []string
	for index, spec := range a.Hosts {
		id, address := fmt.Sprintf("ocid1.instance.oc1..fixture%d", index), fmt.Sprintf("10.8.0.%d", index+2)
		role := spec.Role
		if role == "worker" {
			role = "container"
		}
		r.Hosts = append(r.Hosts, host.HostReport{Role: role, WorkerSourceRevision: a.Candidate.SourceRevision, OCID: id, Address: address, WorkerSHA256: a.RunnerSHA256, NodeID: fmt.Sprintf("native-node-%d", index), Observed: host.Identity{Architecture: a.Candidate.Architecture, KernelRelease: "6.12.fixture", KernelSHA256: a.KernelSHA256, BinarySHA256: a.BinarySHA256, ContainerdSHA256: a.ContainerdSHA256, RuncSHA256: a.RuncSHA256, InstanceID: id, ImageOCID: r.ImageOCID}})
		key := publicSSHKey(t)
		_, markerDigest, err := parseConsoleKey(a.RunID, "TSQUAL_HOSTKEY "+a.RunID+" "+key+"\n")
		if err != nil {
			t.Fatal(err)
		}
		history, operation := fmt.Sprintf("ocid1.consolehistory.oc1..fixture%d", index), "console/"+spec.Name+"/0"
		j.HostKeys[spec.Name], j.ConsoleDigests[spec.Name], j.HostConsoleHistory[spec.Name] = key, markerDigest, history
		j.ConsoleHistories[operation], j.ConsoleDeleted[operation], j.Intents[operation] = history, true, start
		cloud = append(cloud, hostObservation{Name: spec.Name, InstanceID: id, ImageID: r.ImageOCID, PrivateIP: address, HostKeySHA256: hashBytes([]byte(key)), ConsoleSHA256: markerDigest, ConsoleHistoryID: history})
		j.Hosts[spec.Name], j.Terminated[spec.Name], j.Intents[spec.Name] = id, true, start
		ids = append(ids, id)
	}
	for _, item := range []struct{ name, gate string }{{"native-three-manager-formation", "runtime-ha"}, {"manager-loss", "runtime-ha"}, {"manager-partition", "runtime-ha"}, {"agent-restart", "runtime-ha"}, {"unavailable-agent-replacement", "runtime-ha"}, {"container-isolation", "workload-safety"}, {"readiness-rejection", "workload-safety"}, {"rollback", "workload-safety"}, {"cleanup", "runtime-ha"}} {
		wire := []byte("retained fixture transcript: " + item.name)
		r.Scenarios = append(r.Scenarios, host.Scenario{Name: item.name, Gate: item.gate, StartedAt: start, CompletedAt: r.CompletedAt, HostIDs: ids, Transcript: wire, TranscriptSHA256: hashBytes(wire)})
	}
	return r, j, cloud
}

func TestRetainedUnsignedProofBindsObjectsAndExistingQualifier(t *testing.T) {
	f := fixture(t)
	wireWithWhitespace := append([]byte(" \n"), f.wire...)
	var err error
	f.prepared, err = Prepare(wireWithWhitespace, nil, f.roots, f.prepared.approval.Candidate, f.prepared.approval.RunID, f.disk, f.qualification, f.now)
	if err != nil {
		t.Fatal(err)
	}
	r, j, hosts := reportFixture(t, f)
	directory := t.TempDir()
	now := r.CompletedAt.Add(time.Second)
	proof, err := retainProof(f.prepared, r, j, hosts, []byte("{ \n \"observations\": \"controlled SDK fixture\" }"), directory, now)
	if err != nil {
		t.Fatal(err)
	}
	for _, evidence := range proof.Evidence {
		wire, err := os.ReadFile(filepath.Join(directory, "objects", evidence.SHA256))
		if err != nil || hashBytes(wire) != evidence.SHA256 || int64(len(wire)) != evidence.Bytes {
			t.Fatalf("retained object identity: %v", err)
		}
		var record gateRecord
		if err := json.Unmarshal(wire, &record); err != nil {
			t.Fatal(err)
		}
		if hashBytes(record.ApprovalEnvelope) != f.prepared.approvalSHA256 || hashBytes(record.Confinement) != record.ConfinementSHA256 {
			t.Fatal("retained authority/observation binding differs")
		}
	}
	wire, err := os.ReadFile(filepath.Join(directory, "production.unsigned.json"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := release.VerifyProductionCurrent(wire, nil, f.roots, proof.Candidate, now); err == nil {
		t.Fatal("unsigned proof admitted production")
	}
	envelope, err := trust.Sign(wire, release.ProductionQualificationScope(proof.Candidate), now, now.Add(time.Hour), f.private)
	if err != nil {
		t.Fatal(err)
	}
	signed, err := json.Marshal(envelope)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := release.VerifyProductionCurrent(signed, nil, f.roots, proof.Candidate, now); err != nil {
		t.Fatal(err)
	}
}

func TestReportRejectsChangedIdentityMissingScenariosAndIncompleteCleanup(t *testing.T) {
	f := fixture(t)
	cases := []struct {
		name   string
		change func(*host.Report, *journal, []hostObservation)
	}{
		{"component", func(r *host.Report, _ *journal, _ []hostObservation) {
			r.Hosts[0].Observed.ContainerdSHA256 = hashBytes([]byte("other"))
		}},
		{"source", func(r *host.Report, _ *journal, _ []hostObservation) {
			r.Hosts[0].WorkerSourceRevision = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
		}},
		{"duplicate-host", func(r *host.Report, _ *journal, _ []hostObservation) { r.Hosts[1] = r.Hosts[0] }},
		{"missing-scenario", func(r *host.Report, _ *journal, _ []hostObservation) { r.Scenarios = r.Scenarios[1:] }},
		{"changed-transcript", func(r *host.Report, _ *journal, _ []hostObservation) { r.Scenarios[0].Transcript = []byte("changed") }},
		{"incomplete-cleanup", func(_ *host.Report, j *journal, _ []hostObservation) { j.ImageDeleted = false }},
		{"unresolved-intent", func(_ *host.Report, j *journal, _ []hostObservation) { j.Intents["unknown"] = f.now }},
		{"cloud-image", func(_ *host.Report, _ *journal, h []hostObservation) { h[0].ImageID = "ocid1.image.oc1..other" }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r, j, h := reportFixture(t, f)
			tc.change(&r, &j, h)
			if err := validateReport(f.prepared, r, j, h, r.CompletedAt); err == nil {
				t.Fatal("changed native report accepted")
			}
		})
	}
}
