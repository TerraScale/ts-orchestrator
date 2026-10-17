package native

import (
	"context"
	"strings"
	"testing"
	"time"

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
