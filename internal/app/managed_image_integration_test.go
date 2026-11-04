package app

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json/v2"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/cellspec"
	"github.com/TerraScale/ts-orchestrator/internal/oci"
	"github.com/TerraScale/ts-orchestrator/internal/trust"

	"github.com/oracle/oci-go-sdk/v65/common"
	"github.com/oracle/oci-go-sdk/v65/core"
)

type managedImageProtocol struct {
	mu            sync.Mutex
	image         core.Image
	compatibility core.ImageShapeCompatibilityEntry
	pages         [][]core.Shape
	repeatPage    bool
	shapeOutage   bool
	requests      []string
}

func managedImageSDK(t *testing.T, verifier *managedImageVerifier, processor string) *managedImageProtocol {
	t.Helper()
	region := verifier.region
	observed := &managedImageProtocol{
		image: core.Image{Id: new(managedImageTestOCID), CompartmentId: new(region.ImageCompartmentID),
			LifecycleState: core.ImageLifecycleStateAvailable},
		compatibility: core.ImageShapeCompatibilityEntry{ImageId: new(managedImageTestOCID), Shape: new(region.Shape)},
		pages:         [][]core.Shape{{{Shape: new(region.Shape), ProcessorDescription: new(processor)}}},
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		observed.mu.Lock()
		defer observed.mu.Unlock()
		observed.requests = append(observed.requests, r.URL.Path)
		if r.Method != http.MethodGet || r.Header.Get("Authorization") == "" {
			t.Error("OCI SDK request lacks GET method or authentication")
			http.Error(w, "invalid request", http.StatusBadRequest)
			return
		}
		var body any
		switch r.URL.Path {
		case "/20160918/shapes":
			if observed.shapeOutage {
				http.Error(w, "provider unavailable", http.StatusServiceUnavailable)
				return
			}
			query := r.URL.Query()
			if query.Get("compartmentId") != region.CompartmentID || query.Get("availabilityDomain") != region.AvailabilityDomain ||
				query.Get("imageId") != managedImageTestOCID || query.Get("shape") != region.Shape {
				t.Errorf("shape request lost trusted regional image/placement scope: %s", r.URL.RawQuery)
				http.Error(w, "wrong scope", http.StatusBadRequest)
				return
			}
			page := 0
			if query.Get("page") != "" {
				if query.Get("page") != "next" || len(observed.pages) < 2 {
					t.Error("unexpected shape pagination token")
					http.Error(w, "wrong page", http.StatusBadRequest)
					return
				}
				page = 1
			}
			if page+1 < len(observed.pages) || observed.repeatPage {
				w.Header().Set("opc-next-page", "next")
			}
			body = observed.pages[page]
		case "/20160918/images/" + managedImageTestOCID:
			body = observed.image
		case "/20160918/images/" + managedImageTestOCID + "/shapes/" + region.Shape:
			body = observed.compatibility
		default:
			t.Errorf("unexpected OCI readback: %s", r.URL.Path)
			http.NotFound(w, r)
			return
		}
		wire, err := json.Marshal(body)
		if err != nil {
			t.Error(err)
			http.Error(w, "encode response", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(wire)
	}))
	t.Cleanup(server.Close)
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	provider := common.NewRawConfigurationProvider("ocid1.tenancy.oc1..integration", "ocid1.user.oc1..integration",
		"sa-saopaulo-1", "integration", string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})), nil)
	client, err := core.NewComputeClientWithConfigurationProvider(provider)
	if err != nil {
		t.Fatal(err)
	}
	client.Host, client.HTTPClient = server.URL, server.Client()
	client.Configuration.RetryPolicy = new(common.NoRetryPolicy())
	verifier.images = &client
	return observed
}

func TestManagedImageSignedSnapshotLaunchIntegration(t *testing.T) {
	fixture, now := managedImageVerifierFixture(t, "arm64")
	proof, err := independentManagedImageProof(fixture.region, oci.RegionGRU, "production", fixture.roots,
		fixture.receiptWire, fixture.delegationWire, now)
	if err != nil {
		t.Fatal(err)
	}
	proof.now = fixture.now
	managedImageSDK(t, proof, "Ampere Altra")
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	if err := proof.VerifyImageQualified(ctx, oci.RegionGRU, managedImageTestOCID); err != nil {
		t.Fatal(err)
	}
	accepted, _, _ := identityRekeyConfigFixture(t)
	accepted.Cell, accepted.Environment, accepted.ImageOCID, accepted.AcceptedAt = "GRU", "production", "ocid1.image.oc1.sa-saopaulo-1.controller", now
	accepted.Binary.Architecture = "amd64"
	accepted.ControllerBindings[0].ImageOCID, accepted.ControllerBindings[0].Binary = accepted.ImageOCID, accepted.Binary
	historical, err := acceptedManagedImageProof(fixture.region, accepted, fixture.roots, fixture.receiptWire, fixture.delegationWire)
	if err != nil {
		t.Fatalf("accepted initialization lost historical qualification: %v", err)
	}
	historical.images, historical.now = proof.images, func() time.Time { return now.Add(2 * time.Hour) }
	if err := historical.VerifyImageQualified(ctx, oci.RegionGRU, managedImageTestOCID); err == nil {
		t.Fatal("historical acceptance authorized a launch after expiry")
	}
	image := cellspec.HostImage{ImageID: managedImageTestOCID, Receipt: bytes.Clone(proof.receiptWire), Delegation: proof.delegationWire}
	proof.region.ImageID += "PINNED"
	proof.receiptWire, proof.delegationWire = nil, nil
	if err := proof.VerifyImageQualified(ctx, oci.RegionGRU, managedImageTestOCID); err == nil {
		t.Fatal("image outside the signed snapshot qualified")
	}
	snapshot := hostImageSnapshot{images: []cellspec.HostImage{image}, launch: image.ImageID, roots: proof.roots, version: "1"}
	reads := 0
	proof.hostImages = func() hostImageSnapshot { reads++; return snapshot }
	if images, launch := proof.HostImages(); !slices.Equal(images, []string{image.ImageID}) || launch != image.ImageID {
		t.Fatalf("signed host images = %v, launch = %q", images, launch)
	}
	reads = 0
	got, version, err := proof.QualifiedLaunchImage(ctx, oci.RegionGRU, proof.region.ImageID)
	if err != nil || got != image.ImageID || version != snapshot.version || reads != 1 {
		t.Fatalf("qualified launch = %q, %q after %d snapshots: %v", got, version, reads, err)
	}
	holds := 0
	proof.holdLaunch = func() func() { holds++; return func() { holds-- } }
	snapshot.version = "2"
	if _, err := proof.AdmitLaunch(ctx, oci.RegionGRU, got, version); err == nil || holds != 0 {
		t.Fatalf("changed snapshot passed launch fence: holds=%d err=%v", holds, err)
	}
	snapshot.version = version
	release, err := proof.AdmitLaunch(ctx, oci.RegionGRU, got, version)
	if err != nil || holds != 1 {
		t.Fatalf("current snapshot refused: holds=%d err=%v", holds, err)
	}
	release()
	if holds != 0 {
		t.Fatal("launch fence was not released")
	}
	snapshot.roots = trust.Keyring{}
	if _, err := proof.AdmitLaunch(ctx, oci.RegionGRU, got, version); err == nil || holds != 0 {
		t.Fatalf("retired snapshot root passed launch fence: holds=%d err=%v", holds, err)
	}
	proof.roots, snapshot.roots = nil, fixture.roots
	if err := proof.VerifyImageQualified(ctx, oci.RegionGRU, got); err != nil {
		t.Fatalf("adopted snapshot root did not qualify its own image: %v", err)
	}
	snapshot.images[0].Receipt[len(snapshot.images[0].Receipt)-3] ^= 1
	if err := proof.VerifyImageQualified(ctx, oci.RegionGRU, got); err == nil {
		t.Fatal("tampered snapshot image qualified")
	}
	snapshot.images = nil
	if err := proof.VerifyImageQualified(ctx, oci.RegionGRU, got); err == nil {
		t.Fatal("removed snapshot image qualified")
	}
}
