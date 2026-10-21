package region

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/json/v2"
	"encoding/pem"
	"maps"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/TerraScale/ts-orchestrator/internal/oci"
	"github.com/TerraScale/ts-orchestrator/internal/ociclient"
	"github.com/oracle/oci-go-sdk/v65/common"
)

// The actual SDK crosses signed TLS requests to independently persisted provider
// observations. These observations never manufacture a protected pool proof.
func TestWorkerInstanceSDKObservationsRequireProtectedCreation(t *testing.T) {
	const instanceID = "ocid1.instance.oc1.sa-saopaulo-1.worker"
	const configID = "ocid1.instanceconfiguration.oc1.sa-saopaulo-1.worker"
	const compartment = "ocid1.compartment.oc1..workload"
	const imageID = "ocid1.image.oc1.sa-saopaulo-1.worker"
	const bootID = "ocid1.bootvolume.oc1.sa-saopaulo-1.worker"
	const vnicID = "ocid1.vnic.oc1.sa-saopaulo-1.worker"
	const subnetID = "ocid1.subnet.oc1.sa-saopaulo-1.workload"
	dir := t.TempDir()
	instance := map[string]any{"id": instanceID, "compartmentId": compartment, "instanceConfigurationId": configID, "lifecycleState": "RUNNING", "availabilityDomain": "AD-1", "shape": "VM.Standard.A1.Flex", "shapeConfig": map[string]any{"ocpus": 2, "memoryInGBs": 12, "processorDescription": "Ampere Altra"}, "instanceOptions": map[string]any{"areLegacyImdsEndpointsDisabled": true}, "sourceDetails": map[string]any{"sourceType": "image", "imageId": imageID}, "metadata": map[string]string{"public": "source-derived"}}
	boot := map[string]any{"id": bootID, "compartmentId": compartment, "availabilityDomain": "AD-1", "imageId": imageID, "sizeInGBs": 50, "lifecycleState": "AVAILABLE"}
	bootAttachment := map[string]any{"id": "ocid1.bootvolumeattachment.oc1.sa-saopaulo-1.worker", "instanceId": instanceID, "compartmentId": compartment, "availabilityDomain": "AD-1", "bootVolumeId": bootID, "lifecycleState": "ATTACHED"}
	vnic := map[string]any{"id": vnicID, "availabilityDomain": "AD-1", "subnetId": subnetID, "lifecycleState": "AVAILABLE", "isPrimary": true, "skipSourceDestCheck": false, "privateIp": "10.251.0.4", "nsgIds": []string{"ocid1.networksecuritygroup.oc1.sa-saopaulo-1.workload"}}
	vnicAttachment := map[string]any{"id": "ocid1.vnicattachment.oc1.sa-saopaulo-1.worker", "instanceId": instanceID, "compartmentId": compartment, "subnetId": subnetID, "vnicId": vnicID, "lifecycleState": "ATTACHED"}
	write := func(name string, value any) {
		t.Helper()
		wire, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, name), wire, 0600); err != nil {
			t.Fatal(err)
		}
	}
	reset := func() {
		write("instance", instance)
		write("boot", boot)
		write("bootAttachments", []any{bootAttachment})
		write("volumeAttachments", []any{})
		write("vnic", vnic)
		write("vnicAttachments", []any{vnicAttachment})
	}
	reset()
	var requests atomic.Int64
	var repeatedPage atomic.Bool
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		if r.Method != http.MethodGet || !strings.HasPrefix(r.Header.Get("Authorization"), "Signature ") {
			t.Errorf("unsigned or mutating worker SDK request: %s %s", r.Method, r.URL.Path)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		name := ""
		switch r.URL.Path {
		case "/20160918/instances/" + instanceID:
			name = "instance"
		case "/20160918/bootVolumeAttachments":
			name = "bootAttachments"
		case "/20160918/bootVolumes/" + bootID:
			name = "boot"
		case "/20160918/volumeAttachments":
			name = "volumeAttachments"
		case "/20160918/vnicAttachments":
			name = "vnicAttachments"
		case "/20160918/vnics/" + vnicID:
			name = "vnic"
		default:
			t.Errorf("worker SDK escaped exact observation resources: %s", r.URL)
			w.WriteHeader(http.StatusNotFound)
			return
		}
		if strings.HasSuffix(name, "Attachments") && (r.URL.Query().Get("instanceId") != instanceID || r.URL.Query().Get("compartmentId") != compartment) {
			t.Error("worker attachment request omitted exact recipient and compartment")
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		if name == "bootAttachments" && repeatedPage.Load() {
			w.Header().Set("opc-next-page", "again")
			w.Write([]byte("[]"))
			return
		}
		wire, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			t.Error(err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.Write(wire)
	}))
	t.Cleanup(server.Close)
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	address := strings.TrimPrefix(server.URL, "https://")
	transport.DialContext = func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, address)
	}
	transport.DialTLSContext = func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&tls.Dialer{Config: server.Client().Transport.(*http.Transport).TLSClientConfig}).DialContext(ctx, network, address)
	}
	original := http.DefaultTransport
	http.DefaultTransport = transport
	t.Cleanup(func() { http.DefaultTransport = original; transport.CloseIdleConnections() })
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	provider := common.NewRawConfigurationProvider("ocid1.tenancy.oc1..test", "ocid1.user.oc1..test", foundationHomeRegion, "fixture", string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})), nil)
	factory, err := ociclient.New(provider, ociclient.Options{Region: foundationHomeRegion, Retry: ociclient.RetryOptions{MaxAttempts: 1}, Limits: map[ociclient.Service]ociclient.Limit{ociclient.ServiceCompute: {PerSecond: 10000, Burst: 10000}, ociclient.ServiceBlockstorage: {PerSecond: 10000, Burst: 10000}, ociclient.ServiceNetwork: {PerSecond: 10000, Burst: 10000}}})
	if err != nil {
		t.Fatal(err)
	}
	read := func(t *testing.T) (WorkerRecipe, error) {
		t.Helper()
		candidate, ip, vnic, boot, err := readWorkerInstance(t.Context(), factory, instanceID, configID, "GRU", "container", "arm64")
		if err == nil && (ip != "10.251.0.4" || vnic != vnicID || boot != bootID) {
			t.Fatalf("actual attachment observations changed: %s %s %s", ip, vnic, boot)
		}
		return candidate, err
	}
	candidate, err := read(t)
	if err != nil {
		t.Fatal(err)
	}
	if candidate.ImageID != imageID || candidate.OCPUs != 2 || candidate.MemoryGB != 12 || candidate.BootGB != 50 || candidate.SubnetID != subnetID || candidate.Metadata["public"] != "source-derived" {
		t.Fatalf("actual SDK launch facts lost: %+v", candidate)
	}
	before := requests.Load()
	resolver := FoundationResolver{Footprint: &SignedFootprint{factory: factory}}
	if admitted, err := resolver.AuthorizeWorkerInstance(t.Context(), oci.VerifiedPoolInstance{}); err == nil || admitted.IsVerified() {
		t.Fatal("actual SDK facts manufactured original creation authority")
	}
	if requests.Load() != before {
		t.Fatal("unprotected instance reached live SDK observations")
	}
	for _, scenario := range []struct {
		name  string
		alter func()
	}{
		{"legacy metadata endpoints", func() {
			changed := maps.Clone(instance)
			changed["instanceOptions"] = map[string]any{"areLegacyImdsEndpointsDisabled": false}
			write("instance", changed)
		}},
		{"different native processor", func() {
			changed := maps.Clone(instance)
			changed["shapeConfig"] = map[string]any{"ocpus": 2, "memoryInGBs": 12, "processorDescription": "AMD EPYC"}
			write("instance", changed)
		}},
		{"different configuration", func() {
			changed := maps.Clone(instance)
			changed["instanceConfigurationId"] = "ocid1.instanceconfiguration.oc1.sa-saopaulo-1.other"
			write("instance", changed)
		}},
		{"public primary address", func() {
			changed := maps.Clone(vnic)
			changed["publicIp"] = "203.0.113.5"
			write("vnic", changed)
		}},
		{"additional VNIC", func() { write("vnicAttachments", []any{vnicAttachment, vnicAttachment}) }},
		{"different boot image", func() {
			changed := maps.Clone(boot)
			changed["imageId"] = "ocid1.image.oc1.sa-saopaulo-1.other"
			write("boot", changed)
		}},
		{"unapproved data attachment", func() {
			write("volumeAttachments", []any{map[string]any{"attachmentType": "paravirtualized", "instanceId": instanceID, "lifecycleState": "ATTACHED"}})
		}},
		{"repeated inventory page", func() { repeatedPage.Store(true) }},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			reset()
			repeatedPage.Store(false)
			scenario.alter()
			if _, err := read(t); err == nil {
				t.Fatal("drifted actual worker SDK observations were accepted")
			}
		})
	}
}
