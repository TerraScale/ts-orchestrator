package imagequalification

import (
	"encoding/json/v2"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/tests/imagequalification/confinement"
	"github.com/TerraScale/ts-orchestrator/tests/imagequalification/host"
	"github.com/TerraScale/ts-orchestrator/tests/imagequalification/netbird/protocol"
)

func TestNetBirdSealedSDKConsumerRetainsFixtureObservationsWithoutProductionProof(t *testing.T) {
	f, _ := netBirdFixture(t)
	exercisePublicConfinement(t, f, func(p Prepared, verified confinement.Verified, cleaned journal) {
		f.prepared = p
		// These guest/console observations are explicitly constructed consumer
		// input. Only confinement and Compute resource cleanup crossed real SDK
		// boundaries; this test establishes no native execution or image gate.
		r, constructed, cloudHosts := reportFixture(t, f)
		r.ImageOCID = cleaned.ImageID
		r.StartedAt, r.CompletedAt = time.Now().UTC(), time.Now().UTC()
		cleaned.HostKeys, cleaned.ConsoleDigests, cleaned.HostConsoleHistory = constructed.HostKeys, constructed.ConsoleDigests, constructed.HostConsoleHistory
		cleaned.ConsoleHistories, cleaned.ConsoleDeleted = constructed.ConsoleHistories, constructed.ConsoleDeleted
		var ids []string
		for i, spec := range p.approval.Hosts {
			id := cleaned.Hosts[spec.Name]
			r.Hosts[i].OCID, r.Hosts[i].Observed.InstanceID, r.Hosts[i].Observed.ImageOCID, r.Hosts[i].NodeID = id, id, cleaned.ImageID, ""
			cloudHosts[i].InstanceID, cloudHosts[i].ImageID = id, cleaned.ImageID
			ids = append(ids, id)
		}
		r.Scenarios = nil
		for _, item := range []struct{ name, gate, operation string }{{"netbird-foundation", "netbird-foundation", "foundation"}, {"netbird-recovery", "", "restore"}, {"cleanup", "", "cleanup"}} {
			wire, err := json.Marshal([]netBirdEvent{{Host: ids[0], Operation: item.operation, Observation: protocol.Observation{TLSAuthority: "fixture-internal", BackupStorage: "signed-sdk-fixture"}}})
			if err != nil {
				t.Fatal(err)
			}
			r.Scenarios = append(r.Scenarios, host.Scenario{Name: item.name, Gate: item.gate, StartedAt: r.StartedAt, CompletedAt: r.CompletedAt, HostIDs: ids, Transcript: wire, TranscriptSHA256: hashBytes(wire)})
		}
		directory := t.TempDir()
		proof, path, err := retainNetBirdProof(t.Context(), p, verified, r, cleaned, cloudHosts, directory, r.CompletedAt.Add(time.Millisecond))
		if err == nil || !strings.Contains(err.Error(), "required netbird-recovery gate is absent") || path == "" || proof.Schema != "" || len(proof.Evidence) != 0 {
			t.Fatalf("fixture observations became production proof: path=%s proof=%+v err=%v", path, proof, err)
		}
		wire, err := os.ReadFile(path)
		if err != nil || hashBytes(wire) != filepath.Base(path) {
			t.Fatalf("retained NET object differs: %v", err)
		}
		var record netBirdObservationRecord
		if err := json.Unmarshal(wire, &record); err != nil || record.Approval.Candidate != p.approval.Candidate || record.ConfinementSHA256 != verified.EvidenceSHA256() || len(record.Scenarios) != 3 {
			t.Fatalf("retained NET authority/observations differ: %v", err)
		}
		if _, err := os.Stat(filepath.Join(directory, "production.unsigned.json")); !os.IsNotExist(err) {
			t.Fatal("fixture recovery wrote an unsigned production proof")
		}
		// A failed run still retains its redacted observations and cleanup state.
		r.CompletedAt = time.Time{}
		if _, path, err := retainNetBirdProof(t.Context(), p, verified, r, cleaned, cloudHosts, t.TempDir(), time.Now().UTC()); err == nil || path == "" {
			t.Fatal("failed NET run lost public diagnostics or qualified")
		}
		// Private carriers cannot enter retained transcript objects.
		r.Scenarios[0].Transcript = []byte(`[{"host":"` + ids[0] + `","operation":"foundation","observation":{},"private":"fixture-sensitive-token"}]`)
		r.Scenarios[0].TranscriptSHA256 = hashBytes(r.Scenarios[0].Transcript)
		if _, path, err := retainNetBirdProof(t.Context(), p, verified, r, cleaned, cloudHosts, t.TempDir(), time.Now().UTC()); err == nil || path != "" {
			t.Fatal("private worker carrier entered retained evidence")
		}
	})
}
