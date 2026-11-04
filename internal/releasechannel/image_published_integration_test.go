package releasechannel

import (
	"bytes"

	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/release"
	"github.com/TerraScale/ts-orchestrator/internal/trust"
)

func TestPublishedImageSDKReplaysExactManifestAfterExpiry(t *testing.T) {
	location, backend := functionObjectEndpoint(t)
	f := newWriterImageFixture(t, "amd64")
	wire, delegation := f.wires(t)
	f.retain(backend)
	expected := CurrentImageExpectation{Cell: "GRU", Environment: "production", Architecture: "amd64", Role: release.FoundationWriterRole}
	publishedAt := f.now.Add(time.Second)
	backend.modifiedAt = publishedAt
	if err := PublishCurrentImage(t.Context(), location, wire, delegation, f.roots, expected, publishedAt); err != nil {
		t.Fatal(err)
	}
	current, found, err := ReadPublishedImage(t.Context(), location, f.roots, expected, "", publishedAt.Add(time.Second))
	if err != nil || !found {
		t.Fatalf("discover publication: found=%v err=%v", found, err)
	}
	if current.ManifestSHA256 == "" || !current.ManifestLastModified.Equal(publishedAt) || !bytes.Equal(current.ReceiptWire, wire) || !current.ExpiresAt.Equal(f.qualificationExpiry) {
		t.Fatal("publication lost its exact bytes, provider timestamp, or original authority expiry")
	}
	ordinary, found, err := ReadCurrentImage(t.Context(), location, f.roots, expected, publishedAt.Add(time.Second))
	if err != nil || !found || ordinary.ManifestSHA256 != current.ManifestSHA256 {
		t.Fatalf("ordinary locator selected another manifest: found=%v err=%v", found, err)
	}

	// Advance discovery with a separately qualified image, retaining the first bytes.
	f.receipt.OCIImageOCID += "NEXT"
	f.qualification.Candidate.ImageOCID = f.receipt.OCIImageOCID
	f.boundary.Candidate.ImageOCID = f.receipt.OCIImageOCID
	for index := range f.boundary.Hosts {
		f.boundary.Hosts[index].ImageOCID = f.receipt.OCIImageOCID
	}
	nextWire, nextDelegation := f.wires(t)
	backend.mu.Lock()
	for digest, data := range f.objects {
		backend.objects[ImageProductionEvidenceObject(digest)] = functionObject{data: bytes.Clone(data), version: 1}
	}
	backend.modifiedAt = publishedAt.Add(time.Second)
	backend.mu.Unlock()
	if err := PublishCurrentImage(t.Context(), location, nextWire, nextDelegation, f.roots, expected, publishedAt.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	next, found, err := ReadPublishedImage(t.Context(), location, f.roots, expected, "", publishedAt.Add(2*time.Second))
	if err != nil || !found || next.ManifestSHA256 == current.ManifestSHA256 || !bytes.Equal(next.ReceiptWire, nextWire) {
		t.Fatalf("discovery did not advance independently: found=%v err=%v", found, err)
	}
	afterExpiry := current.ExpiresAt.Add(time.Second)
	replayed, found, err := ReadPublishedImage(t.Context(), location, f.roots, expected, current.ManifestSHA256, afterExpiry)
	if err != nil || !found || replayed.ManifestSHA256 != current.ManifestSHA256 || !bytes.Equal(replayed.ReceiptWire, wire) || !replayed.ExpiresAt.Equal(current.ExpiresAt) || !replayed.ManifestLastModified.Equal(publishedAt) {
		t.Fatalf("exact historical replay: found=%v err=%v", found, err)
	}
	original := f.expected()
	original.OCIImageOCID = current.Image.Receipt().OCIImageOCID
	if err := replayed.FoundationWriter.ValidFor(original, afterExpiry); err == nil {
		t.Fatal("historical publication renewed current writer authority")
	}
	if _, _, err := ReadCurrentImage(t.Context(), location, f.roots, expected, afterExpiry); err == nil {
		t.Fatal("ordinary reader admitted expired current authority")
	}
	backend.mu.Lock()
	delete(backend.objects, CurrentImageObject(expected.Role, expected.Architecture, expected.Environment))
	backend.mu.Unlock()
	if replayed, found, err := ReadPublishedImage(t.Context(), location, f.roots, expected, current.ManifestSHA256, afterExpiry); err != nil || !found || !bytes.Equal(replayed.ReceiptWire, wire) {
		t.Fatalf("retained digest depended on missing discovery: found=%v err=%v", found, err)
	}
	if _, _, err := ReadPublishedImage(t.Context(), location, trust.Keyring{}, expected, current.ManifestSHA256, afterExpiry); err == nil {
		t.Fatal("historical replay trusted a signer removed from current roots")
	}
}
