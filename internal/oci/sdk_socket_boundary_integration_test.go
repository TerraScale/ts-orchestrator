package oci

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json/v2"
	"encoding/pem"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/hostboot"
	"github.com/oracle/oci-go-sdk/v65/common"
	"github.com/oracle/oci-go-sdk/v65/core"
)

func sdkSocketProvider(t *testing.T, config RegionConfig, handler http.Handler) (*sdkProvider, context.Context) {
	t.Helper()
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer r.Body.Close()
		if r.TLS == nil || !strings.HasPrefix(r.Header.Get("Authorization"), "Signature ") {
			t.Error("SDK request lacks TLS or its signing header")
			http.Error(w, "unsigned request", http.StatusBadRequest)
			return
		}
		handler.ServeHTTP(w, r)
	}))
	t.Cleanup(server.Close)
	client := server.Client()
	t.Cleanup(client.CloseIdleConnections)
	client.Timeout = 5 * time.Second
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	client.Transport.(*http.Transport).DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		if address != server.Listener.Addr().String() {
			return nil, errors.New("SDK fixture refuses endpoints outside its TLS listener")
		}
		return (&net.Dialer{Timeout: time.Second}).DialContext(ctx, network, address)
	}
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	credentials := common.NewRawConfigurationProvider("ocid1.tenancy.oc1..test", "ocid1.user.oc1..test", "sa-saopaulo-1", "test",
		string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})), nil)
	compute, err := core.NewComputeClientWithConfigurationProvider(credentials)
	if err != nil {
		t.Fatal(err)
	}
	storage, err := core.NewBlockstorageClientWithConfigurationProvider(credentials)
	if err != nil {
		t.Fatal(err)
	}
	network, err := core.NewVirtualNetworkClientWithConfigurationProvider(credentials)
	if err != nil {
		t.Fatal(err)
	}
	provider := &sdkProvider{config: config, compute: compute, storage: storage, network: network, verified: newVerificationCache()}
	for _, service := range []*common.BaseClient{&provider.compute.BaseClient, &provider.storage.BaseClient, &provider.network.BaseClient} {
		service.Host, service.HTTPClient = server.URL, client
	}
	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
	t.Cleanup(cancel)
	return provider, ctx
}

func sdkSocketJSON(t *testing.T, w http.ResponseWriter, value any) {
	t.Helper()
	wire, err := json.Marshal(value)
	if err != nil {
		t.Error(err)
		http.Error(w, "fixture encoding failed", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	if _, err := w.Write(wire); err != nil {
		t.Error(err)
	}
}

func sdkSocketLaunchRequest(t *testing.T, config RegionConfig) LaunchRequest {
	t.Helper()
	request := LaunchRequest{
		DisplayName: "gru-1-db-1", CreateKey: "00000000002W8M515D00HW6ZEG", PrivateIP: "10.251.0.21", Node: hostNode(config, "00000000002W8M515D00HW6ZEG"), RetryToken: "retry-token-sdk-shape-config",
		FaultDomain: "FAULT-DOMAIN-1", Shape: config.Shape, WholeOCPUs: 2, MemoryInGBs: 12,
		PlacementProfileDigest: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		PlacementGeneration:    9,
		BootVolumeGB:           config.BootVolumeGB, BootVolumeVPUsPerGB: config.BootVolumeVPUsPerGB,
		FreeformTags: map[string]string{
			tagManagedBy: managedByValue, tagPlacementProfileDigest: "caller-value-must-not-win",
		},
	}
	bootRequest := testEnsureRequest(request.CreateKey)
	bootRequest.PlacementProfileDigest = request.PlacementProfileDigest
	bootRequest.PlacementGeneration = request.PlacementGeneration
	descriptor, err := (&fleet{config: config}).hostBootDescriptor(bootRequest, config.ImageID)
	if err != nil {
		t.Fatal(err)
	}
	wire, err := descriptor.CanonicalBytes()
	if err != nil {
		t.Fatal(err)
	}
	request.ImageID, request.BootDescriptor = config.ImageID, string(wire)
	return request
}

func TestSDKSocketLaunchPreservesSignedProfileAndResponse(t *testing.T) {
	config, _ := testRegionConfig()
	request := sdkSocketLaunchRequest(t, config)
	var captured atomic.Pointer[core.LaunchInstanceRequest]
	var calls atomic.Int32
	provider, ctx := sdkSocketProvider(t, config, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.Method != http.MethodPost || r.URL.Path != "/20160918/instances" || r.URL.RawQuery != "" {
			t.Errorf("unexpected launch request: %s %s", r.Method, r.URL)
			http.Error(w, "unexpected launch", http.StatusBadRequest)
			return
		}
		wire, err := io.ReadAll(r.Body)
		if err != nil {
			t.Error(err)
			http.Error(w, "unreadable launch", http.StatusBadRequest)
			return
		}
		var details core.LaunchInstanceDetails
		if err := json.Unmarshal(wire, &details); err != nil {
			t.Error(err)
			http.Error(w, "invalid launch", http.StatusBadRequest)
			return
		}
		captured.Store(&core.LaunchInstanceRequest{LaunchInstanceDetails: details, OpcRetryToken: new(r.Header.Get("opc-retry-token"))})
		w.Header().Set("etag", "sdk-etag")
		sdkSocketJSON(t, w, core.Instance{Id: new("ocid1.instance.sdk-shape-config"), Shape: new(config.Shape),
			ShapeConfig: &core.InstanceShapeConfig{Ocpus: new(float32(2)), MemoryInGBs: new(float32(12))},
			ImageId:     new(config.ImageID), Metadata: map[string]string{hostboot.MetadataKey: request.BootDescriptor}})
	}))

	enrollment := `{"schema_version":1}`
	cloud, err := launchInstance(ctx, provider.compute, config, request,
		map[string]string{hostboot.EnrollmentMetadataKey: enrollment})
	if err != nil {
		t.Fatalf("launchInstance: %v", err)
	}
	received := captured.Load()
	if received == nil {
		t.Fatal("SDK launch returned without reaching its socket")
	}
	if got := received.LaunchInstanceDetails.Metadata; got[hostboot.EnrollmentMetadataKey] != enrollment ||
		got[hostboot.MetadataKey] != request.BootDescriptor || got["terrascale_host_node"] != request.Node {
		t.Fatalf("host launch metadata lost its enrollment bundle or boot binding: %v", got)
	}
	if _, err := launchInstance(ctx, provider.compute, config, request,
		map[string]string{hostboot.MetadataKey: "{}"}); !errors.Is(err, ErrHostBootBindingMismatch) {
		t.Fatalf("launch material replaced the fleet-bound boot descriptor: %v", err)
	}
	if calls.Load() != 1 || captured.Load() == nil {
		t.Fatalf("OCI SDK client did not receive a launch request: calls=%d request=%+v", calls.Load(), captured.Load())
	}
	details := received.LaunchInstanceDetails
	if details.Shape == nil || *details.Shape != request.Shape || details.ShapeConfig == nil ||
		details.ShapeConfig.Ocpus == nil || *details.ShapeConfig.Ocpus != 2 ||
		details.ShapeConfig.MemoryInGBs == nil || *details.ShapeConfig.MemoryInGBs != 12 {
		t.Fatalf("signed shape sizing was omitted or changed: %+v", details)
	}
	if received.OpcRetryToken == nil || *received.OpcRetryToken != request.RetryToken ||
		details.FreeformTags[tagPlacementProfileDigest] != request.PlacementProfileDigest ||
		details.FreeformTags[tagPlacementGeneration] != "9" {
		t.Fatalf("retry/profile identity did not reach OCI: retryToken=%v tags=%v", received.OpcRetryToken, details.FreeformTags)
	}
	if details.FreeformTags[tagManagedBy] != managedByValue {
		t.Fatalf("launch lost the caller's non-profile resource tags: %v", details.FreeformTags)
	}
	if details.DisplayName == nil || *details.DisplayName != request.DisplayName ||
		details.CreateVnicDetails == nil || details.CreateVnicDetails.AssignPublicIp == nil ||
		*details.CreateVnicDetails.AssignPublicIp || details.CreateVnicDetails.PrivateIp == nil ||
		*details.CreateVnicDetails.PrivateIp != request.PrivateIP ||
		details.CreateVnicDetails.SkipSourceDestCheck == nil || *details.CreateVnicDetails.SkipSourceDestCheck {
		t.Fatalf("launch lost the bounded display name or private-only VNIC: %+v", details)
	}
	imageDetails, ok := details.SourceDetails.(core.InstanceSourceViaImageDetails)
	if !ok || imageDetails.ImageId == nil || *imageDetails.ImageId != config.ImageID ||
		imageDetails.BootVolumeSizeInGBs == nil || *imageDetails.BootVolumeSizeInGBs != 50 ||
		imageDetails.BootVolumeVpusPerGB == nil || *imageDetails.BootVolumeVpusPerGB != 10 ||
		details.Metadata[hostboot.MetadataKey] != request.BootDescriptor || details.Metadata["terrascale_host_node"] != request.Node {
		t.Fatalf("public image/descriptor binding did not reach OCI: image=%+v metadata=%v", details.SourceDetails, details.Metadata)
	}
	if cloud.Shape != request.Shape || cloud.Ocpus == nil || *cloud.Ocpus != 2 ||
		cloud.MemoryInGBs == nil || *cloud.MemoryInGBs != 12 || cloud.ETag != "sdk-etag" ||
		cloud.ImageID != config.ImageID || cloud.Metadata[hostboot.MetadataKey] != request.BootDescriptor {
		t.Fatalf("SDK response dimensions were not normalized: %+v", cloud)
	}
}
