package release

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/trust"
)

func TestNetBirdProductionQualificationPurpose(t *testing.T) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	roots, err := trust.ParseKeyring(public)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	candidate := ProductionExpectation{SourceRevision: testSourceRevision, ArtifactSHA256: strings.Repeat("a", 64),
		QualificationSHA256: strings.Repeat("b", 64), Cell: "GRU", Environment: "production",
		Runtime: NetBirdProductionRuntime, Architecture: "arm64", Role: "netbird-manager"}
	for _, scenario := range []struct {
		name   string
		alter  func(*ProductionExpectation)
		gates  [2]string
		accept bool
	}{
		{name: "dedicated foundation and recovery", accept: true},
		{name: "ordinary gates cannot qualify NetBird", gates: [2]string{"runtime-ha", "workload-safety"}},
		{name: "gate order is fixed", gates: [2]string{"netbird-recovery", "netbird-foundation"}},
		{name: "duplicate foundation gate", gates: [2]string{"netbird-foundation", "netbird-foundation"}},
		{name: "NetBird role cannot use Swarm runtime", alter: func(c *ProductionExpectation) { c.Runtime = ProductionRuntime }},
		{name: "NetBird runtime cannot qualify ordinary role", alter: func(c *ProductionExpectation) { c.Role = "orchestrator" }},
		{name: "dedicated cell is fixed", alter: func(c *ProductionExpectation) { c.Cell = "SFO" }},
		{name: "dedicated native architecture is fixed", alter: func(c *ProductionExpectation) { c.Architecture = "amd64" }},
		{name: "ordinary proof retains ordinary gates", alter: func(c *ProductionExpectation) {
			c.Runtime, c.Role, c.Architecture = ProductionRuntime, "orchestrator", "amd64"
		}, gates: [2]string{"runtime-ha", "workload-safety"}, accept: true},
		{name: "ordinary proof cannot substitute NetBird gates", alter: func(c *ProductionExpectation) { c.Runtime, c.Role = ProductionRuntime, "orchestrator" }},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			expected := candidate
			if scenario.alter != nil {
				scenario.alter(&expected)
			}
			gates := scenario.gates
			if gates == ([2]string{}) {
				gates = [2]string{"netbird-foundation", "netbird-recovery"}
			}
			qualification := ProductionQualification{Schema: ProductionQualificationSchema, Candidate: expected}
			for _, gate := range gates {
				data := []byte("retained test evidence for " + gate)
				qualification.Evidence = append(qualification.Evidence, ProductionGateEvidence{Gate: gate,
					SHA256: fingerprintWire(t, data), Bytes: int64(len(data)), CompletedAt: now.Add(-time.Second)})
			}
			envelope := signDirect(t, qualification, ProductionQualificationScope(expected), private, now, now.Add(time.Hour))
			_, err := VerifyProductionCurrent(encodeEnvelope(t, envelope), nil, roots, expected, now)
			if scenario.accept {
				if err != nil {
					t.Fatal(err)
				}
			} else if !errors.Is(err, ErrProductionQualification) {
				t.Fatalf("qualification error = %v; want invalid production purpose or gates", err)
			}
		})
	}
}
