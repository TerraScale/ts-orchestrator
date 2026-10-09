package bootstrapstart

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/bootstrap"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/protocol"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/trust"
	"github.com/oracle/oci-go-sdk/v65/objectstorage"
)

func TestFounderContinuitySelectionIsReadOnlyAndUsesDurableFloor(t *testing.T) {
	fixture := newFounderSelectionFixture(t)
	firstWire := fixture.publish(t, fixture.selection)
	if err := fixture.floor.Initialize(1, digestWire(firstWire)); err != nil {
		t.Fatal(err)
	}
	pins := []FounderContinuityPin{}
	for _, slot := range []string{"controller-a", "controller-b", "seed-a"} {
		wire := []byte("read-only proof for " + slot)
		digest := digestWire(wire)
		pins = append(pins, FounderContinuityPin{Slot: slot, SHA256: digest})
		key := fixture.domain.LedgerBucket + "/" + FounderImmutableObjectName(fixture.domain,
			"0000000000F9PR1WNVDTEXS31Z", "GRU", "production", digest)
		fixture.objects.items[key] = wire
	}
	continuation := FounderSelection{SchemaVersion: 2, DeploymentID: "0000000000F9PR1WNVDTEXS31Z", Cell: "GRU",
		Environment: "production", Generation: 2, Continuities: pins}
	currentWire := fixture.signSelection(t, continuation, fixture.now.Add(time.Hour))
	selectorKey := fixture.domain.HeadBucket + "/" + FounderSelectionObjectName(fixture.domain,
		"0000000000F9PR1WNVDTEXS31Z", "GRU", "production")
	fixture.objects.items[selectorKey] = currentWire
	reader := fixture.reader(t)
	if _, err := reader.ReadCurrent(t.Context(), fixture.now); !errors.Is(err, ErrFounderSelection) {
		t.Fatalf("read-only selector reached launch-capable reader: %v", err)
	}
	selected, err := reader.readCurrentInstallContinuation(t.Context(), fixture.now)
	if err != nil || selected.proofSHA256 != pins[2].SHA256 ||
		!bytes.Equal(selected.proofWire, []byte("read-only proof for seed-a")) {
		t.Fatalf("read-only selected seed proof = %+v, %v", selected, err)
	}
	if err := fixture.floor.Observe(2, digestWire(currentWire)); err != nil {
		t.Fatal(err)
	}
	fixture.objects.items[selectorKey] = firstWire
	if err := fixture.floor.Check(1, digestWire(firstWire)); !errors.Is(err, ErrFounderSelectionFloor) {
		t.Fatalf("selector rollback passed durable floor: %v", err)
	}
}

type ambiguousFounderPublisher struct {
	store *founderLedgerObjects
}

func (publisher ambiguousFounderPublisher) GetObject(ctx context.Context,
	request objectstorage.GetObjectRequest,
) (objectstorage.GetObjectResponse, error) {
	return publisher.store.GetObject(ctx, request)
}

func (publisher ambiguousFounderPublisher) PutObject(ctx context.Context,
	request objectstorage.PutObjectRequest,
) (objectstorage.PutObjectResponse, error) {
	response, err := publisher.store.PutObject(ctx, request)
	if err == nil && strings.HasSuffix(*request.ObjectName, "/current.json") {
		return response, errors.New("response lost after selector CAS")
	}
	return response, err
}

func TestPublishFounderContinuityProofsBeforeAmbiguousSelectorCAS(t *testing.T) {
	fixture := newFounderSelectionFixture(t)
	firstWire := fixture.signSelection(t, fixture.selection, fixture.now.Add(-time.Second))
	proofs := make(map[string][]byte)
	pins := make([]FounderContinuityPin, 0, 3)
	for _, slot := range []string{"controller-a", "controller-b", "seed-a"} {
		marker := fixture.accepted
		marker.Slot = slot
		marker.ManifestSHA256 = digestWire(fixture.manifests[slot])
		markerWire, err := protocol.EncodeJSON(marker)
		if err != nil {
			t.Fatal(err)
		}
		credentialDigest, err := bootstrap.InstallContinuityCredentialDigest(marker.MaterialSHA256)
		if err != nil {
			t.Fatal(err)
		}
		claim := bootstrap.InstallContinuity{SchemaVersion: bootstrap.InstallContinuitySchemaVersion,
			DeploymentID: marker.DeploymentID, Environment: "production", ClusterID: "0000000000RMSAJ9B0JFV7ESHN",
			Cell: fixture.baked.Identity.Cell, OCIRegion: "sa-saopaulo-1", Slot: slot,
			GenesisAnchorSHA256: marker.AnchorSHA256, AcceptedMarkerSHA256: digestWire(markerWire),
			ManifestSHA256: marker.ManifestSHA256, ResultSHA256: marker.ResultSHA256,
			ReceiptSHA256: marker.ReceiptSHA256, ImageReceiptSHA256: marker.ImageReceiptSHA256,
			ImageOCID: marker.ImageOCID, InstanceOCID: marker.InstanceOCID,
			PrimaryVNICOCID: marker.PrimaryVNICOCID, PrimaryPrivateIP: marker.PrimaryPrivateIP,
			LedgerAttempt: marker.HeadAttempt, LedgerGeneration: marker.HeadGeneration,
			AcceptedAt: marker.AcceptedAt, BinarySHA256: marker.BinarySHA256,
			MaterialSHA256: marker.MaterialSHA256, CredentialSHA256: credentialDigest,
			CredentialValidUntil: fixture.now.Add(2 * time.Hour), SelectorGeneration: 2}
		envelope, err := bootstrap.SignInstallContinuity(claim, fixture.now, fixture.now.Add(time.Hour), fixture.root)
		if err != nil {
			t.Fatal(err)
		}
		wire, err := trust.EncodeEnvelope(envelope)
		if err != nil {
			t.Fatal(err)
		}
		proofs[slot] = wire
		pins = append(pins, FounderContinuityPin{Slot: slot, SHA256: digestWire(wire)})
	}
	selection := FounderSelection{SchemaVersion: 2, DeploymentID: "0000000000F9PR1WNVDTEXS31Z", Cell: "GRU",
		Environment: "production", Generation: 2, Continuities: pins}
	selectionWire := fixture.signSelection(t, selection, fixture.now.Add(time.Hour))
	key := fixture.domain.HeadBucket + "/" + FounderSelectionObjectName(fixture.domain,
		"0000000000F9PR1WNVDTEXS31Z", "GRU", "production")
	store := &founderLedgerObjects{objects: map[string]founderStoredObject{
		key: {wire: firstWire, etag: "old-etag", modified: fixture.now},
	}, now: fixture.now}
	publisher := ambiguousFounderPublisher{store: store}
	anchorEnvelope, err := trust.DecodeEnvelope(fixture.anchorWire)
	if err != nil {
		t.Fatal(err)
	}
	historicalAnchor, err := bootstrap.VerifyHistoricalBootstrapAnchor(anchorEnvelope, fixture.baked.Roots,
		fixture.baked.Identity.AnchorExpectation(), fixture.accepted.AcceptedAt, bootstrap.BootstrapAnchorTrustPolicy())
	if err != nil {
		t.Fatal(err)
	}
	if err := PublishFounderContinuities(t.Context(), historicalAnchor, fixture.baked.Identity,
		fixture.baked.Roots, selectionWire, proofs, publisher, fixture.now); err != nil {
		t.Fatal(err)
	}
	if store.writes != 4 || !bytes.Equal(store.objects[key].wire, selectionWire) {
		t.Fatalf("immutable proofs and selector CAS were not fully published: writes=%d", store.writes)
	}
	for _, pin := range pins {
		immutable := fixture.domain.LedgerBucket + "/" + FounderImmutableObjectName(fixture.domain,
			"0000000000F9PR1WNVDTEXS31Z", "GRU", "production", pin.SHA256)
		if !bytes.Equal(store.objects[immutable].wire, proofs[pin.Slot]) {
			t.Fatalf("missing immutable continuity proof for %s", pin.Slot)
		}
	}
}

func TestFounderInstallContinuationChecksSeedAndPeerAgainstCurrentSelection(t *testing.T) {
	for _, slot := range []string{"seed-a", "controller-a"} {
		t.Run(slot, func(t *testing.T) {
			fixture := newFounderSelectionFixture(t)
			marker := fixture.accepted
			marker.Slot = slot
			marker.ManifestSHA256 = digestWire(fixture.manifests[slot])
			reader, err := NewCurrentFounderAuthorityReader(fixture.baked, marker, fixture.objects, fixture.floor)
			if err != nil {
				t.Fatal(err)
			}
			firstWire := fixture.publish(t, fixture.selection)
			if err := fixture.floor.Initialize(1, digestWire(firstWire)); err != nil {
				t.Fatal(err)
			}
			markerWire, err := protocol.EncodeJSON(marker)
			if err != nil {
				t.Fatal(err)
			}
			credentialDigest, err := bootstrap.InstallContinuityCredentialDigest(marker.MaterialSHA256)
			if err != nil {
				t.Fatal(err)
			}
			bound := CredentialBound{SHA256: credentialDigest, ValidUntil: fixture.now.Add(2 * time.Hour)}
			claim := bootstrap.InstallContinuity{SchemaVersion: bootstrap.InstallContinuitySchemaVersion,
				DeploymentID: marker.DeploymentID, Environment: "production", ClusterID: "0000000000RMSAJ9B0JFV7ESHN",
				Cell: fixture.baked.Identity.Cell, OCIRegion: "sa-saopaulo-1", Slot: slot,
				GenesisAnchorSHA256: marker.AnchorSHA256, AcceptedMarkerSHA256: digestWire(markerWire),
				ManifestSHA256: marker.ManifestSHA256, ResultSHA256: marker.ResultSHA256,
				ReceiptSHA256: marker.ReceiptSHA256, ImageReceiptSHA256: marker.ImageReceiptSHA256,
				ImageOCID: marker.ImageOCID, InstanceOCID: marker.InstanceOCID,
				PrimaryVNICOCID: marker.PrimaryVNICOCID, PrimaryPrivateIP: marker.PrimaryPrivateIP,
				LedgerAttempt: marker.HeadAttempt, LedgerGeneration: marker.HeadGeneration,
				AcceptedAt: marker.AcceptedAt, BinarySHA256: marker.BinarySHA256,
				MaterialSHA256: marker.MaterialSHA256, CredentialSHA256: credentialDigest,
				CredentialValidUntil: bound.ValidUntil, SelectorGeneration: 2}
			envelope, err := bootstrap.SignInstallContinuity(claim, fixture.now, fixture.now.Add(time.Hour), fixture.root)
			if err != nil {
				t.Fatal(err)
			}
			proofWire, err := trust.EncodeEnvelope(envelope)
			if err != nil {
				t.Fatal(err)
			}
			pins := make([]FounderContinuityPin, 0, 3)
			for _, name := range []string{"controller-a", "controller-b", "seed-a"} {
				wire := []byte("other slot " + name)
				if name == slot {
					wire = proofWire
				}
				digest := digestWire(wire)
				pins = append(pins, FounderContinuityPin{Slot: name, SHA256: digest})
				key := fixture.domain.LedgerBucket + "/" + FounderImmutableObjectName(fixture.domain,
					"0000000000F9PR1WNVDTEXS31Z", "GRU", "production", digest)
				fixture.objects.items[key] = wire
			}
			selection := FounderSelection{SchemaVersion: 2, DeploymentID: "0000000000F9PR1WNVDTEXS31Z", Cell: "GRU",
				Environment: "production", Generation: 2, Continuities: pins}
			selectorKey := fixture.domain.HeadBucket + "/" + FounderSelectionObjectName(fixture.domain,
				"0000000000F9PR1WNVDTEXS31Z", "GRU", "production")
			fixture.objects.items[selectorKey] = fixture.signSelection(t, selection, fixture.now.Add(time.Hour))
			mode := bootstrap.IntentModeManaged
			if slot == marker.SeedSlot {
				mode = bootstrap.IntentModeExternalSeed
			}
			state := bootstrap.SlotState{Head: bootstrap.SlotHead{Attempt: marker.HeadAttempt,
				Generation: marker.HeadGeneration, ResultDigest: marker.ResultSHA256},
				ResultRecord:   &bootstrap.StoredRecord{SHA256: marker.ResultSHA256},
				ManifestRecord: &bootstrap.StoredRecord{SHA256: marker.ManifestSHA256},
				Intent: bootstrap.Intent{Mode: mode, DeploymentID: marker.DeploymentID, Cell: marker.Cell,
					Slot: marker.Slot, ImageOCID: marker.ImageOCID, ManifestDigest: marker.ManifestSHA256,
					ReleaseReceiptDigest: marker.ImageReceiptSHA256},
				Result: &bootstrap.Result{InstanceOCID: marker.InstanceOCID}}
			if mode == bootstrap.IntentModeExternalSeed {
				state.SeedReceiptRecord = &bootstrap.StoredRecord{SHA256: marker.ReceiptSHA256}
			} else {
				state.PeerReceiptRecord = &bootstrap.StoredRecord{SHA256: marker.ReceiptSHA256}
			}
			observed := InstanceObservation{InstanceOCID: marker.InstanceOCID, ImageOCID: marker.ImageOCID,
				PrimaryVNICOCID: marker.PrimaryVNICOCID, PrimaryPrivateIP: marker.PrimaryPrivateIP}
			checker := &FounderInstallContinuation{reader: reader,
				credentialBound: func(AcceptedInstall, bootstrap.SlotState) (CredentialBound, error) { return bound, nil },
				now:             func() time.Time { return fixture.now }}
			if err := checker.VerifyCurrentContinuation(t.Context(), marker, observed, state); err != nil {
				t.Fatalf("marked %s restart: %v", slot, err)
			}
			changed := observed
			changed.PrimaryVNICOCID = "ocid1.vnic.oc1.sa-saopaulo-1.changed"
			if err := checker.VerifyCurrentContinuation(t.Context(), marker, changed, state); !errors.Is(err, ErrFounderInstallContinuation) {
				t.Fatalf("changed primary VNIC admitted: %v", err)
			}
			fixture.objects.items[selectorKey] = firstWire
			if err := checker.VerifyCurrentContinuation(t.Context(), marker, observed, state); err == nil {
				t.Fatal("selector rollback admitted marked restart")
			}
		})
	}
}
