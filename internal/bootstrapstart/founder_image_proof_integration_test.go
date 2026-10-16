package bootstrapstart

import (
	"context"
	"crypto/ed25519"
	"encoding/json/v2"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/bootstrap"
	"github.com/TerraScale/ts-orchestrator/internal/entityid"
	"github.com/TerraScale/ts-orchestrator/internal/protocol"
	"github.com/TerraScale/ts-orchestrator/internal/release"
	"github.com/TerraScale/ts-orchestrator/internal/trust"
	"github.com/oracle/oci-go-sdk/v65/core"
)

func qualifyFounderRuntimeFixture(t *testing.T, fixture *founderSignerFixture) {
	t.Helper()
	image, delegation := founderRuntimeImageWires(t, fixture)
	for slot, wire := range fixture.manifests {
		envelope, err := trust.DecodeEnvelope(wire)
		if err != nil {
			t.Fatal(err)
		}
		manifest, err := bootstrap.ManifestPayload(envelope.Payload)
		if err != nil {
			t.Fatal(err)
		}
		manifest.ReleaseImageReceiptWire, manifest.ReleaseDelegationWire = image, delegation
		manifest.ReleaseReceiptSHA256 = digestWire(image)
		signed, err := bootstrap.SignManifest(manifest, envelope.IssuedAt, envelope.ExpiresAt, fixture.root)
		if err != nil {
			t.Fatal(err)
		}
		fixture.manifests[slot] = envelopeWire(t, signed)
	}
	publishFounderRuntimeImages(t, fixture)
}

func publishFounderRuntimeImages(t *testing.T, fixture *founderSignerFixture) {
	t.Helper()
	fixture.accepted.ManifestSHA256 = digestWire(fixture.manifests[fixture.accepted.Slot])
	fixture.plan.SeedManifestSHA256 = fixture.accepted.ManifestSHA256
	for i := range fixture.plan.Peers {
		fixture.plan.Peers[i].ManifestSHA256 = digestWire(fixture.manifests[fixture.plan.Peers[i].Slot])
	}
	for i := range fixture.selection.Manifests {
		fixture.selection.Manifests[i].SHA256 = digestWire(fixture.manifests[fixture.selection.Manifests[i].Slot])
	}
	payload, err := trust.EncodePayload(fixture.plan)
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := trust.Sign(payload, trust.Scope{Domain: bootstrap.FounderPlanDomain,
		DeploymentID: fixture.plan.DeploymentID, Cell: string(fixture.plan.Cell), Environment: fixture.plan.Environment,
		Role: "controller", Slot: fixture.plan.SeedSlot}, fixture.now.Add(-time.Minute), fixture.now.Add(22*time.Hour), fixture.root)
	if err != nil {
		t.Fatal(err)
	}
	fixture.planWire = envelopeWire(t, envelope)
	fixture.selection.PlanSHA256 = digestWire(fixture.planWire)
	// Fixture construction starts a fresh floor; no runtime rollback is allowed.
	fixture.floor = testFounderFloor(t)
	selected := fixture.publish(t, fixture.selection)
	if err := fixture.floor.Initialize(fixture.selection.Generation, digestWire(selected)); err != nil {
		t.Fatal(err)
	}
	fixture.current, err = fixture.reader(t).ReadCurrent(t.Context(), fixture.now)
	if err != nil {
		t.Fatal(err)
	}
}

// Retained manifests remain root-authorized while their independent image
// proof can expire or be invalid. Exercise the real SDK HTTP boundary.
func TestFounderImageProofBeforeSDKLaunch(t *testing.T) {
	for _, scenario := range []string{"qualified", "missing", "expired", "expires-before-launch", "wrong-environment", "wrong-cell", "wrong-image", "wrong-architecture", "wrong-final-digest"} {
		t.Run(scenario, func(t *testing.T) {
			fixture, caller, objects, fake := newFounderRuntimeFixtureWithSetup(t, func(fixture *founderSignerFixture) {
				mutateFounderImageProof(t, fixture, scenario)
			})
			slot := fixture.plan.Peers[0].Slot
			snapshot, err := caller.fresh(t.Context(), slot)
			if err != nil {
				t.Fatalf("retained signed authority failed before image gate: %v", err)
			}
			attempt, err := NewFounderOCIAttempt(snapshot.peer, snapshot.now)
			if err != nil {
				t.Fatal(err)
			}
			if scenario == "expires-before-launch" {
				effectCtx, cancel, err := caller.adapter.beforeEffect(t.Context(), attempt, caller.peerRefresh(slot))
				if err != nil {
					t.Fatal(err)
				}
				deadline, ok := effectCtx.Deadline()
				cancel()
				if remaining := time.Until(deadline); !ok || remaining > 2*time.Minute || remaining < 110*time.Second {
					t.Fatalf("SDK context exceeded independent image proof lifetime: %v", remaining)
				}
			}
			var launches, reads atomic.Int64
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				switch {
				case r.Method == http.MethodGet && strings.Contains(r.URL.Path, "/images/"):
					reads.Add(1)
					row := fake.rows[slot]
					body, _ := json.Marshal(map[string]string{"id": row.ImageOCID, "compartmentId": row.ImageCompartmentOCID, "lifecycleState": "AVAILABLE"})
					_, _ = w.Write(body)
				case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/instances"):
					launches.Add(1)
					w.WriteHeader(http.StatusOK)
					row := fake.rows[slot]
					body, _ := json.Marshal(map[string]string{"id": founderTestInstanceID, "compartmentId": row.CompartmentOCID, "imageId": row.ImageOCID})
					_, _ = w.Write(body)
				default:
					w.WriteHeader(http.StatusBadRequest)
				}
			}))
			defer server.Close()
			caller.adapter.compute = founderImageProofSDK{ComputeClient: &core.ComputeClient{Host: server.URL,
				BasePath: "20160918", UserAgent: "founder-image-proof-test", Signer: founderImageSDKSigner{}, HTTPClient: server.Client()},
				afterImage: func() {
					if scenario == "expires-before-launch" {
						objects.now = fixture.now.Add(3 * time.Minute)
					}
				}}
			_, err = caller.adapter.Launch(t.Context(), attempt, caller.peerRefresh(slot))
			if scenario == "qualified" {
				if err != nil || launches.Load() != 1 || reads.Load() != 1 {
					t.Fatalf("qualified exact image: launches=%d reads=%d err=%v", launches.Load(), reads.Load(), err)
				}
			} else {
				wantReads := int64(0)
				if scenario == "expires-before-launch" {
					wantReads = 1
				}
				if err == nil || launches.Load() != 0 || reads.Load() != wantReads {
					t.Fatalf("invalid image proof reached launch: launches=%d reads=%d err=%v", launches.Load(), reads.Load(), err)
				}
			}
		})
	}
}

type founderImageSDKSigner struct{}

func (founderImageSDKSigner) Sign(*http.Request) error { return nil }

type founderImageProofSDK struct {
	*core.ComputeClient
	afterImage func()
}

func (client founderImageProofSDK) GetImage(ctx context.Context, request core.GetImageRequest) (core.GetImageResponse, error) {
	response, err := client.ComputeClient.GetImage(ctx, request)
	if err == nil {
		client.afterImage()
	}
	return response, err
}

func mutateFounderImageProof(t *testing.T, fixture *founderSignerFixture, scenario string) {
	t.Helper()
	for slot, wire := range fixture.manifests {
		envelope, err := trust.DecodeEnvelope(wire)
		if err != nil {
			t.Fatal(err)
		}
		manifest, err := bootstrap.ManifestPayload(envelope.Payload)
		if err != nil {
			t.Fatal(err)
		}
		imageEnvelope, err := trust.DecodeEnvelope(manifest.ReleaseImageReceiptWire)
		if err != nil {
			t.Fatal(err)
		}
		var image release.ImageReceipt
		if err := protocol.DecodeStrict(imageEnvelope.Payload, &image, bootstrap.MaxManifestBytes); err != nil {
			t.Fatal(err)
		}
		switch scenario {
		case "missing":
			image.Production = nil
		case "expired", "expires-before-launch", "wrong-environment", "wrong-cell", "wrong-architecture", "wrong-final-digest":
			proof, err := trust.DecodeEnvelope(image.Production.Qualification)
			if err != nil {
				t.Fatal(err)
			}
			var record release.ProductionQualification
			if err := protocol.DecodeStrict(proof.Payload, &record, bootstrap.MaxManifestBytes); err != nil {
				t.Fatal(err)
			}
			switch scenario {
			case "expired":
				proof.IssuedAt, proof.ExpiresAt = fixture.now.Add(-2*time.Hour), fixture.now.Add(-time.Hour)
				for i := range record.Evidence {
					record.Evidence[i].CompletedAt = proof.IssuedAt.Add(-time.Second)
				}
			case "expires-before-launch":
				proof.ExpiresAt = fixture.now.Add(2 * time.Minute)
			case "wrong-environment":
				record.Candidate.Environment = "canary"
			case "wrong-cell":
				record.Candidate.Cell = "VCP"
			case "wrong-architecture":
				record.Candidate.Architecture = "arm64"
			case "wrong-final-digest":
				record.Candidate.ArtifactSHA256 = strings.Repeat("f", 64)
			}
			payload, err := trust.EncodePayload(record)
			if err != nil {
				t.Fatal(err)
			}
			proof, err = trust.Sign(payload, release.ProductionQualificationScope(record.Candidate), proof.IssuedAt, proof.ExpiresAt, fixture.root)
			if err != nil {
				t.Fatal(err)
			}
			image.Production.Qualification = envelopeWire(t, proof)
		case "wrong-image":
			image.OCIImageOCID += "other"
		}
		public := fixture.root.Public().(ed25519.PublicKey)
		keyID, _ := trust.KeyID(public)
		publicWire, _ := trust.EncodeDelegatedPublicKey(public)
		grant, err := trust.SignDelegation(trust.Delegation{SchemaVersion: trust.SchemaVersion, SubjectKeyID: keyID,
			SubjectPublicKey: publicWire, Capabilities: []trust.Capability{{Domain: release.ImageDomain,
				DeploymentID: entityid.Derive("build", image.SourceRevision), Cell: image.OCIRegion, Environment: manifest.Environment,
				Role: "oci-image", Slots: []string{image.OCIImageOCID}, Actions: []string{"sign"}}}}, fixture.now.Add(-time.Hour), fixture.now.Add(2*time.Hour), fixture.root)
		if err != nil {
			t.Fatal(err)
		}
		payload, err := trust.EncodePayload(image)
		if err != nil {
			t.Fatal(err)
		}
		imageEnvelope, err = trust.Sign(payload, release.ImageScope(image, manifest.Environment), fixture.now.Add(-time.Minute), fixture.now.Add(time.Hour), fixture.root)
		if err != nil {
			t.Fatal(err)
		}
		manifest.ReleaseImageReceiptWire = envelopeWire(t, imageEnvelope)
		manifest.ReleaseDelegationWire = envelopeWire(t, grant)
		manifest.ReleaseReceiptSHA256 = digestWire(manifest.ReleaseImageReceiptWire)
		envelope, err = bootstrap.SignManifest(manifest, envelope.IssuedAt, envelope.ExpiresAt, fixture.root)
		if err != nil {
			t.Fatal(err)
		}
		fixture.manifests[slot] = envelopeWire(t, envelope)
	}
	publishFounderRuntimeImages(t, fixture)
}
