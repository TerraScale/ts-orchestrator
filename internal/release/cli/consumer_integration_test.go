package cli

import (
	"encoding/json/v2"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/protocol"
	"github.com/TerraScale/ts-orchestrator/internal/release"
	"github.com/TerraScale/ts-orchestrator/internal/releasechannel"
	"github.com/TerraScale/ts-orchestrator/internal/selfupdate"
	"github.com/TerraScale/ts-orchestrator/internal/trust"
)

func TestProductionChannelAndSelfUpdateRequireIndependentQualification(t *testing.T) {
	fixture := newApplyHTTPFixture(t)
	directory := filepath.Dir(filepath.Dir(fixture.binaryPath))
	data, err := os.ReadFile(filepath.Join(directory, "GRU", "channel.json"))
	if err != nil {
		t.Fatal(err)
	}
	var channel releasechannel.Channel
	if err := json.Unmarshal(data, &channel); err != nil {
		t.Fatal(err)
	}
	private, err := readDelegatedPrivateKey(fixture.leafPath)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(private)
	policy := selfupdate.ReceiptPolicy{Roots: fixture.roots, Environment: "production", Cell: "GRU", Architecture: "amd64"}
	for _, failure := range []string{"", "missing proof", "ordinary release signer", "wrong candidate", "future proof"} {
		t.Run(failure, func(t *testing.T) {
			envelope, err := trust.DecodeEnvelope(channel.Receipts[0])
			if err != nil {
				t.Fatal(err)
			}
			var receipt release.BinaryUpdateReceipt
			if err := protocol.DecodeStrict(envelope.Payload, &receipt, trust.MaxPayloadBytes); err != nil {
				t.Fatal(err)
			}
			if failure == "missing proof" {
				receipt.Production = nil
			} else if failure != "" {
				record := writeProductionEvidence(t, t.TempDir(), productionCandidate(fixture.binary, "GRU"))
				if failure == "wrong candidate" {
					record.Candidate.ArtifactSHA256 = record.Evidence[0].SHA256
				}
				signer := fixture.rootPrivate
				if failure == "ordinary release signer" {
					signer = private
				}
				issued := time.Now().UTC().Add(-time.Minute)
				if failure == "future proof" {
					issued = time.Now().UTC().Add(5 * time.Minute)
				}
				payload, err := trust.EncodePayload(record)
				if err != nil {
					t.Fatal(err)
				}
				qualification, err := trust.Sign(payload, release.ProductionQualificationScope(record.Candidate), issued, time.Now().UTC().Add(time.Hour), signer)
				if err != nil {
					t.Fatal(err)
				}
				proofWire, err := trust.EncodeEnvelope(qualification)
				if err != nil {
					t.Fatal(err)
				}
				receipt.Production = &release.ProductionProof{Qualification: proofWire}
			}
			payload, err := trust.EncodePayload(receipt)
			if err != nil {
				t.Fatal(err)
			}
			envelope, err = trust.Sign(payload, envelope.Scope, envelope.IssuedAt, envelope.ExpiresAt, private)
			if err != nil {
				t.Fatal(err)
			}
			wire, err := trust.EncodeEnvelope(envelope)
			if err != nil {
				t.Fatal(err)
			}
			candidate := channel
			candidate.Receipts = append(candidate.Receipts[:0:0], wire)
			_, channelErr := candidate.Verify(fixture.roots, "GRU", "production", time.Now().UTC())
			_, policyErr := policy.Verify(wire, channel.Delegation, time.Now().UTC())
			if failure == "" {
				if channelErr != nil || policyErr != nil {
					t.Fatalf("qualified consumer rejected: channel=%v selfupdate=%v", channelErr, policyErr)
				}
				return
			}
			if !errors.Is(channelErr, release.ErrProductionQualification) || !errors.Is(policyErr, release.ErrProductionQualification) {
				t.Fatalf("ordinary signer bypassed consumer qualification: channel=%v selfupdate=%v", channelErr, policyErr)
			}
			layout := selfupdate.Layout{Root: t.TempDir(), Owner: os.Getuid()}
			file, err := os.Open(fixture.binaryPath)
			if err != nil {
				t.Fatal(err)
			}
			defer file.Close()
			if _, err := selfupdate.Stage(layout, file, wire, channel.Delegation, policy, time.Now().UTC()); !errors.Is(err, release.ErrProductionQualification) {
				t.Fatalf("unqualified bytes reached staging: %v", err)
			}
			entries, err := os.ReadDir(layout.Root)
			if err != nil {
				t.Fatal(err)
			}
			if len(entries) != 0 {
				t.Fatal("refused update wrote staged files")
			}
		})
	}
}
