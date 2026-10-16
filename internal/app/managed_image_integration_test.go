package app

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json/v2"
	"encoding/pem"
	"errors"
	"net/http"
	"net/http/httptest"
	goruntime "runtime"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/cellspec"
	"github.com/TerraScale/ts-orchestrator/internal/natscell"
	"github.com/TerraScale/ts-orchestrator/internal/oci"
	"github.com/TerraScale/ts-orchestrator/internal/releasechannel"
	"github.com/TerraScale/ts-orchestrator/internal/trust"
	"github.com/nats-io/nats.go/jetstream"
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

func TestManagedImageObservedArchitectureIntegration(t *testing.T) {
	for _, test := range []struct{ architecture, processor string }{
		{"arm64", "AmpereOne ARM"}, {"amd64", "AMD EPYC"}, {"amd64", "Intel Xeon"},
	} {
		t.Run(test.processor, func(t *testing.T) {
			verifier, _ := managedImageVerifierFixture(t, test.architecture)
			observed := managedImageSDK(t, verifier, test.processor)
			// A later page and a new shape family must use provider facts, not a name map.
			observed.mu.Lock()
			observed.pages = [][]core.Shape{{{Shape: new("unrelated"), ProcessorDescription: new("unknown")}}, observed.pages[0]}
			observed.mu.Unlock()
			ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
			defer cancel()
			if err := verifier.VerifyImageQualified(ctx, oci.RegionGRU, managedImageTestOCID); err != nil {
				t.Fatal(err)
			}
			observed.mu.Lock()
			defer observed.mu.Unlock()
			if len(observed.requests) != 4 {
				t.Fatalf("qualified image did not cross shape, image and compatibility boundaries: %v", observed.requests)
			}
		})
	}
	for _, test := range []struct {
		name   string
		mutate func(*managedImageVerifier, *managedImageProtocol, time.Time)
	}{
		{"wrong architecture", func(_ *managedImageVerifier, p *managedImageProtocol, _ time.Time) {
			p.pages[0][0].ProcessorDescription = new("Intel Xeon")
		}},
		{"unknown processor", func(_ *managedImageVerifier, p *managedImageProtocol, _ time.Time) {
			p.pages[0][0].ProcessorDescription = new("unknown")
		}},
		{"contradictory processor", func(_ *managedImageVerifier, p *managedImageProtocol, _ time.Time) {
			p.pages[0][0].ProcessorDescription = new("Ampere AMD")
		}},
		{"missing processor", func(_ *managedImageVerifier, p *managedImageProtocol, _ time.Time) {
			p.pages[0][0].ProcessorDescription = nil
		}},
		{"unavailable shape", func(_ *managedImageVerifier, p *managedImageProtocol, _ time.Time) { p.pages = [][]core.Shape{{}} }},
		{"duplicate shape", func(_ *managedImageVerifier, p *managedImageProtocol, _ time.Time) {
			p.pages[0] = append(p.pages[0], p.pages[0][0])
		}},
		{"repeated page", func(_ *managedImageVerifier, p *managedImageProtocol, _ time.Time) {
			p.pages = append(p.pages, []core.Shape{})
			p.repeatPage = true
		}},
		{"expired receipt", func(v *managedImageVerifier, _ *managedImageProtocol, now time.Time) {
			v.now = func() time.Time { return now.Add(2 * time.Hour) }
		}},
		{"retired root", func(v *managedImageVerifier, _ *managedImageProtocol, _ time.Time) { v.roots = trust.Keyring{} }},
		{"tampered receipt", func(v *managedImageVerifier, _ *managedImageProtocol, _ time.Time) {
			v.receiptWire[len(v.receiptWire)-3] ^= 1
		}},
		{"wrong fleet pin", func(v *managedImageVerifier, _ *managedImageProtocol, _ time.Time) { v.region.ImageID += "OTHER" }},
		{"wrong OCI image", func(_ *managedImageVerifier, p *managedImageProtocol, _ time.Time) {
			p.image.Id = new(managedImageTestOCID + "OTHER")
		}},
		{"wrong OCI compartment", func(_ *managedImageVerifier, p *managedImageProtocol, _ time.Time) {
			p.image.CompartmentId = new("ocid1.compartment.oc1..other")
		}},
		{"unavailable image", func(_ *managedImageVerifier, p *managedImageProtocol, _ time.Time) {
			p.image.LifecycleState = core.ImageLifecycleStateDisabled
		}},
		{"wrong compatibility shape", func(_ *managedImageVerifier, p *managedImageProtocol, _ time.Time) {
			p.compatibility.Shape = new("other-shape")
		}},
		{"wrong compatibility image", func(_ *managedImageVerifier, p *managedImageProtocol, _ time.Time) {
			p.compatibility.ImageId = new(managedImageTestOCID + "OTHER")
		}},
		{"missing placement scope", func(v *managedImageVerifier, _ *managedImageProtocol, _ time.Time) { v.region.AvailabilityDomain = "" }},
	} {
		t.Run(test.name, func(t *testing.T) {
			verifier, now := managedImageVerifierFixture(t, "arm64")
			observed := managedImageSDK(t, verifier, "Ampere Altra")
			observed.mu.Lock()
			test.mutate(verifier, observed, now)
			observed.mu.Unlock()
			ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
			defer cancel()
			if err := verifier.VerifyImageQualified(ctx, oci.RegionGRU, managedImageTestOCID); err == nil {
				t.Fatal("invalid image crossed managed fleet admission")
			}
		})
	}
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

func TestManagedImageReleaseScopeIntegration(t *testing.T) {
	fixture := newChannelFixture(t)
	architecture, processor := "arm64", "Ampere Altra"
	if goruntime.GOARCH == "arm64" {
		architecture, processor = "amd64", "AMD EPYC"
	}
	verifier, _ := managedImageVerifierFixture(t, architecture)
	services := fixture.signer.services(t)
	services.ociRegion = &verifier.region
	control, err := newRolloutControl(Config{NATS: natscell.Config{Cell: "gru", Lab: true}}, services, "")
	if err != nil || control.managedArchitecture == nil {
		t.Fatalf("managed controller construction requires OCI or lost its observer: %v", err)
	}
	observed := managedImageSDK(t, verifier, processor)
	control.managedArchitecture = func(ctx context.Context) (string, error) {
		return observedManagedImageArchitecture(ctx, verifier.images, verifier.region, verifier.region.ImageID)
	}
	fixture.control.managedArchitecture = control.managedArchitecture
	fixture.setChannel(t, fixture.signer.channel(t, "GRU", 620, []byte("qualified binary")))
	entry, err := fixture.kv.Get(t.Context(), releasechannel.ChannelKey("GRU"))
	if err != nil {
		t.Fatal(err)
	}
	observed.mu.Lock()
	observed.shapeOutage = true
	observed.mu.Unlock()
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	if err := fixture.control.consumeChannel(ctx, fixture.store, fixture.kv, 7, entry.Value(), time.Now().UTC()); err == nil {
		t.Fatal("unobserved architecture authorized a release")
	}
	if len(fixture.generations(t)) != 0 {
		t.Fatal("provider outage published a release generation")
	}
	if _, err := fixture.kv.Get(ctx, releasechannel.StatusKey("GRU")); !errors.Is(err, jetstream.ErrKeyNotFound) {
		t.Fatalf("provider outage published incomplete architecture status: %v", err)
	}
	observed.mu.Lock()
	observed.shapeOutage = false
	observed.mu.Unlock()
	status := fixture.consume(t)
	if !slices.Equal(status.Architectures, []string{"amd64", "arm64"}) || len(fixture.generations(t)) != 1 {
		t.Fatalf("provider recovery did not publish the observed release scope: %+v", status)
	}
}
