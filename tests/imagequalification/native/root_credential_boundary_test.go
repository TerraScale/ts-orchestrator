package native

import (
	"context"
	"strings"
	"testing"
	"time"

	"encoding/json/v2"
	"github.com/TerraScale/ts-orchestrator/internal/app"
	"github.com/TerraScale/ts-orchestrator/internal/bootstrapstart"
	"github.com/TerraScale/ts-orchestrator/internal/release"
)

type credentialResultPeer struct {
	result *release.RootCredentialBoundaryHost
}

func (p credentialResultPeer) call(_ context.Context, c command) (response, error) {
	if c.Operation == "credential-identity" {
		return response{Role: c.Mode, Identity: c.Host.ExpectedIdentity, WorkerSourceRevision: c.SourceRevision}, nil
	}
	return response{RootCredentialBoundary: p.result}, nil
}
func (credentialResultPeer) probeHTTP(context.Context) error { return nil }
func (credentialResultPeer) close() error                    { return nil }

func TestRootCredentialCollectorRefusesMissingOrForeignResult(t *testing.T) {
	req := Request{Hosts: []Host{{OCID: "ocid1.instance.expected"}}, RootCredentialProofs: map[string][]byte{"ocid1.instance.expected": []byte("not-used-by-fixture")}}
	for _, test := range []struct {
		name    string
		result  *release.RootCredentialBoundaryHost
		message string
	}{
		{name: "missing", message: "returned no root credential boundary evidence"},
		{name: "foreign-host", result: &release.RootCredentialBoundaryHost{Role: "manager", InstanceID: "ocid1.instance.foreign"}, message: "differs from approved host"},
		{name: "empty-outcomes", result: &release.RootCredentialBoundaryHost{Role: "manager", InstanceID: "ocid1.instance.expected"}, message: "did not prove authenticated reads"},
	} {
		t.Run(test.name, func(t *testing.T) {
			report, evidence, err := runRootCredentialBoundary(t.Context(), req, Report{StartedAt: time.Now().UTC()}, release.RootCredentialBoundaryEvidence{}, func(context.Context, Host) (peer, error) { return credentialResultPeer{result: test.result}, nil })
			if err == nil || !strings.Contains(err.Error(), test.message) {
				t.Fatalf("unexpected credential gate result: %v", err)
			}
			if !report.CompletedAt.IsZero() || !evidence.CompletedAt.IsZero() || len(evidence.Hosts) != 0 {
				t.Fatal("failed probe produced successful retained evidence")
			}
			if len(report.Scenarios) != 1 || report.Scenarios[0].Gate != "" || len(report.Scenarios[0].Transcript) == 0 {
				t.Fatal("failed probe lost its failure transcript")
			}
		})
	}
}

func TestRootCredentialResultRequiresSixReadersAndLiveRefusals(t *testing.T) {
	hash := strings.Repeat("a", 64)
	w := &worker{binaryHash: hash, identity: Identity{InstanceID: "instance", ImageOCID: "image"}}
	observation := app.RootOCIQualificationObservation{SHA256: hash, Bytes: 2}
	valid := app.RootOCIQualificationResult{SchemaVersion: 1, InstanceID: "instance", ImageID: "image", BinarySHA256: hash, NamespaceSHA256: hash, SourceSHA256: hash, PeerUID: 999, Socket: rootCredentialSocket, Readers: app.RootOCIQualificationReaders{Inventory: observation, LocalInstance: observation, Fleet: observation, Costs: observation, Image: observation, ReleaseChannel: observation}, Negative: app.RootOCIQualificationDenials{SameUIDProcessDenied: true, ProtectedWriteDenied: true, RawSignDenied: true, IMDSDenied: true}}
	localWire, err := json.Marshal(bootstrapstart.InstanceObservation{InstanceOCID: "instance", ImageOCID: "image"})
	if err != nil {
		t.Fatal(err)
	}
	valid.Readers.LocalInstance = app.RootOCIQualificationObservation{SHA256: digest(localWire), Bytes: int64(len(localWire)), Response: localWire}
	if err := verifyRootCredentialResult(valid, w, 999); err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name   string
		change func(*app.RootOCIQualificationResult)
	}{
		{"retained-local-response", func(r *app.RootOCIQualificationResult) { r.Readers.LocalInstance.Response = []byte("{}") }},
		{"workload-uid", func(r *app.RootOCIQualificationResult) { r.PeerUID = 65532 }},
		{"inventory", func(r *app.RootOCIQualificationResult) { r.Readers.Inventory.Bytes = 0 }},
		{"local-instance", func(r *app.RootOCIQualificationResult) { r.Readers.LocalInstance.SHA256 = "" }},
		{"fleet", func(r *app.RootOCIQualificationResult) { r.Readers.Fleet.Bytes = 0 }},
		{"costs", func(r *app.RootOCIQualificationResult) { r.Readers.Costs.Bytes = 0 }},
		{"image", func(r *app.RootOCIQualificationResult) { r.Readers.Image.Bytes = 0 }},
		{"release", func(r *app.RootOCIQualificationResult) { r.Readers.ReleaseChannel.Bytes = 0 }},
		{"imds", func(r *app.RootOCIQualificationResult) { r.Negative.IMDSDenied = false }},
		{"signing", func(r *app.RootOCIQualificationResult) { r.Negative.RawSignDenied = false }},
		{"same-uid-ipc", func(r *app.RootOCIQualificationResult) { r.Negative.SameUIDProcessDenied = false }},
		{"protected-write", func(r *app.RootOCIQualificationResult) { r.Negative.ProtectedWriteDenied = false }},
		{"foreign-binary", func(r *app.RootOCIQualificationResult) { r.BinarySHA256 = strings.Repeat("b", 64) }},
		{"wrong-uid", func(r *app.RootOCIQualificationResult) { r.PeerUID = 0 }},
		{"wrong-socket", func(r *app.RootOCIQualificationResult) { r.Socket = "/missing/socket" }},
	} {
		t.Run(test.name, func(t *testing.T) {
			r := valid
			test.change(&r)
			if err := verifyRootCredentialResult(r, w, 999); err == nil {
				t.Fatal("incomplete or foreign credential result accepted")
			}
		})
	}
}

func TestRootCredentialOutputRejectsOversize(t *testing.T) {
	output := new(rootCredentialOutput)
	if _, err := output.Write(make([]byte, maxRootCredentialResultBytes+1)); err == nil || output.Len() != 0 {
		t.Fatal("oversized installed result retained")
	}
}
