package oci

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json/v2"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"slices"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/hostboot"
	"github.com/oracle/oci-go-sdk/v65/common"
	"github.com/oracle/oci-go-sdk/v65/core"
)

// Each service uses its real SDK signer and verified TLS, with dialing confined
// to this listener. Signature cryptographic verification is outside this fixture.
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

func TestSDKSocketLaunchRejectsInexactSizingBeforeAnyRequest(t *testing.T) {
	config, _ := testRegionConfig()
	var calls atomic.Int32
	provider, ctx := sdkSocketProvider(t, config, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		t.Errorf("inexact sizing reached the SDK socket: %s %s", r.Method, r.URL)
		http.Error(w, "unexpected launch", http.StatusBadRequest)
	}))
	request := sdkSocketLaunchRequest(t, config)
	request.WholeOCPUs = 1<<24 + 1
	if _, err := launchInstance(ctx, provider.compute, config, request, nil); !errors.Is(err, ErrPlacementProfileMismatch) {
		t.Fatalf("non-exact float32 sizing was not rejected: %v", err)
	}
	if calls.Load() != 0 {
		t.Fatalf("invalid sizing reached OCI SDK: calls=%d", calls.Load())
	}
}

// These values are HTTP response payloads, never injected SDK implementations.
type sdkSocketReadback struct {
	t                          *testing.T
	config                     RegionConfig
	instanceID, bootID, vnicID string
	boots                      core.ListBootVolumeAttachmentsResponse
	boot                       core.BootVolume
	attachments                core.ListVnicAttachmentsResponse
	vnic                       core.Vnic
	bootGets, vnicGets         atomic.Int32
}

func (wire *sdkSocketReadback) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		wire.t.Errorf("readback issued a mutation: %s %s", r.Method, r.URL)
		http.Error(w, "unexpected mutation", http.StatusBadRequest)
		return
	}
	var value any
	switch r.URL.Path {
	case "/20160918/bootVolumeAttachments":
		if q := r.URL.Query(); q.Get("compartmentId") != wire.config.CompartmentID || q.Get("availabilityDomain") != wire.config.AvailabilityDomain || q.Get("instanceId") != wire.instanceID {
			wire.t.Errorf("boot attachment query widened its exact instance: %s", r.URL)
		}
		if wire.boots.OpcNextPage != nil {
			w.Header().Set("opc-next-page", *wire.boots.OpcNextPage)
		}
		value = wire.boots.Items
	case "/20160918/bootVolumes/" + wire.bootID:
		wire.bootGets.Add(1)
		value = wire.boot
	case "/20160918/vnicAttachments":
		if q := r.URL.Query(); q.Get("compartmentId") != wire.config.CompartmentID || q.Get("instanceId") != wire.instanceID {
			wire.t.Errorf("VNIC attachment query widened its exact instance: %s", r.URL)
		}
		if wire.attachments.OpcNextPage != nil {
			w.Header().Set("opc-next-page", *wire.attachments.OpcNextPage)
		}
		value = wire.attachments.Items
	case "/20160918/vnics/" + wire.vnicID:
		wire.vnicGets.Add(1)
		value = wire.vnic
	default:
		wire.t.Errorf("unexpected SDK readback: %s", r.URL)
		http.Error(w, "unexpected readback", http.StatusBadRequest)
		return
	}
	sdkSocketJSON(wire.t, w, value)
}

func TestSDKSocketManagedReadbackPreservesBootAndPrivateVNICClassifications(t *testing.T) {
	config, _ := testRegionConfig()
	instanceID := "ocid1.instance.managed-readback"
	bootID := "ocid1.bootvolume.managed-readback"
	vnicID := "ocid1.vnic.managed-readback"
	instance := CloudInstance{ID: instanceID, CompartmentID: config.CompartmentID,
		AvailabilityDomain: config.AvailabilityDomain, ImageID: config.ImageID, LifecycleState: "RUNNING"}
	reader := &sdkSocketReadback{t: t, config: config, instanceID: instanceID, bootID: bootID, vnicID: vnicID,
		boots: core.ListBootVolumeAttachmentsResponse{Items: []core.BootVolumeAttachment{{
			BootVolumeId: new(bootID), InstanceId: new(instanceID),
			LifecycleState: core.BootVolumeAttachmentLifecycleStateAttached,
		}}},
		boot: core.BootVolume{
			Id: new(bootID), CompartmentId: new(config.CompartmentID), ImageId: new(config.ImageID),
			SizeInGBs: new(int64(50)), VpusPerGB: new(int64(10)),
		},
		attachments: core.ListVnicAttachmentsResponse{Items: []core.VnicAttachment{{
			VnicId: new(vnicID), InstanceId: new(instanceID),
			LifecycleState: core.VnicAttachmentLifecycleStateAttached,
		}}},
		vnic: core.Vnic{
			Id: new(vnicID), SubnetId: new(config.SubnetID), PrivateIp: new("10.251.0.21"),
			NsgIds:         slices.Clone(config.NetworkSecurityGroupIDs),
			LifecycleState: core.VnicLifecycleStateAvailable,
		},
	}
	provider, ctx := sdkSocketProvider(t, config, reader)
	if ip, err := verifyInstanceStorageAndNetwork(ctx, config, instance, provider.compute, provider.storage, provider.network); err != nil || ip != "10.251.0.21" {
		t.Fatalf("exact boot and private VNIC refused: %v", err)
	}
	// The boot volume binds the instance's own image; the fleet decides
	// whether that image is allowed, so a host launched from an earlier
	// image reads back here too.
	earlier := instance
	earlier.ImageID = "ocid1.image.oc1.sa-saopaulo-1.earlier"
	reader.boot.ImageId = new(earlier.ImageID)
	if _, err := verifyInstanceStorageAndNetwork(ctx, config, earlier, provider.compute, provider.storage, provider.network); err != nil {
		t.Fatalf("boot volume of the instance's own image refused: %v", err)
	}
	reader.boot.ImageId = new(config.ImageID)
	for _, state := range []core.BootVolumeAttachmentLifecycleStateEnum{
		core.BootVolumeAttachmentLifecycleStateAttaching, core.BootVolumeAttachmentLifecycleStateDetaching,
	} {
		reader.boots.Items[0].LifecycleState = state
		_, err := verifyInstanceStorageAndNetwork(ctx, config, instance, provider.compute, provider.storage, provider.network)
		if !errors.Is(err, ErrOutcomeUnknown) || errors.Is(err, ErrForeignResource) {
			t.Fatalf("transient boot attachment %s classified as foreign: %v", state, err)
		}
		reader.boots.OpcNextPage = new("extra")
		if _, err := verifyInstanceStorageAndNetwork(ctx, config, instance, provider.compute, provider.storage, provider.network); !errors.Is(err, ErrForeignResource) {
			t.Fatalf("paginated transient boot attachment was not foreign: %v", err)
		}
		reader.boots.OpcNextPage = nil
	}
	reader.boots.Items[0].LifecycleState = core.BootVolumeAttachmentLifecycleStateAttached
	for _, state := range []core.VnicAttachmentLifecycleStateEnum{
		core.VnicAttachmentLifecycleStateAttaching, core.VnicAttachmentLifecycleStateDetaching,
	} {
		reader.attachments.Items[0].LifecycleState = state
		_, err := verifyInstanceStorageAndNetwork(ctx, config, instance, provider.compute, provider.storage, provider.network)
		if !errors.Is(err, ErrOutcomeUnknown) || errors.Is(err, ErrForeignResource) {
			t.Fatalf("transient VNIC attachment %s classified as foreign: %v", state, err)
		}
		reader.attachments.OpcNextPage = new("extra")
		if _, err := verifyInstanceStorageAndNetwork(ctx, config, instance, provider.compute, provider.storage, provider.network); !errors.Is(err, ErrForeignResource) {
			t.Fatalf("paginated transient VNIC attachment was not foreign: %v", err)
		}
		reader.attachments.OpcNextPage = nil
	}
	reader.attachments.Items[0].LifecycleState = core.VnicAttachmentLifecycleStateAttached
	boots := reader.boots.Items
	reader.boots.Items = nil
	if _, err := verifyInstanceStorageAndNetwork(ctx, config, instance, provider.compute, provider.storage, provider.network); !errors.Is(err, ErrOutcomeUnknown) {
		t.Fatalf("not-yet-visible boot attachment was not retryable: %v", err)
	}
	reader.boots.Items = boots
	vnics := reader.attachments.Items
	reader.attachments.Items = nil
	if _, err := verifyInstanceStorageAndNetwork(ctx, config, instance, provider.compute, provider.storage, provider.network); !errors.Is(err, ErrOutcomeUnknown) {
		t.Fatalf("not-yet-visible VNIC attachment was not retryable: %v", err)
	}
	reader.attachments.Items = vnics
	for _, test := range []struct {
		name    string
		mutate  func()
		restore func()
	}{
		{"image", func() { reader.boot.ImageId = new("ocid1.image.other") },
			func() { reader.boot.ImageId = new(config.ImageID) }},
		{"instance without image", func() { instance.ImageID, reader.boot.ImageId = "", new("") },
			func() { instance.ImageID, reader.boot.ImageId = config.ImageID, new(config.ImageID) }},
		{"size", func() { reader.boot.SizeInGBs = new(int64(100)) },
			func() { reader.boot.SizeInGBs = new(int64(50)) }},
		{"tier", func() { reader.boot.VpusPerGB = new(int64(20)) },
			func() { reader.boot.VpusPerGB = new(int64(10)) }},
	} {
		t.Run(test.name, func(t *testing.T) {
			test.mutate()
			defer test.restore()
			_, err := verifyInstanceStorageAndNetwork(ctx, config, instance, provider.compute, provider.storage, provider.network)
			if !errors.Is(err, ErrImageNotQualified) || !errors.Is(err, ErrForeignResource) {
				t.Fatalf("instance boot drift did not carry both classifications: %v", err)
			}
		})
	}
	bootGets := reader.bootGets.Load()
	reader.boots.Items[0].BootVolumeId = nil
	if _, err := verifyInstanceStorageAndNetwork(ctx, config, instance, provider.compute, provider.storage, provider.network); !errors.Is(err, ErrForeignResource) || reader.bootGets.Load() != bootGets {
		t.Fatalf("missing boot ID reached GetBootVolume or was not foreign: err=%v calls=%d", err, reader.bootGets.Load())
	}
	reader.boots.Items[0].BootVolumeId = new(bootID)
	vnicGets := reader.vnicGets.Load()
	reader.attachments.Items[0].VnicId = nil
	if _, err := verifyInstanceStorageAndNetwork(ctx, config, instance, provider.compute, provider.storage, provider.network); !errors.Is(err, ErrForeignResource) || reader.vnicGets.Load() != vnicGets {
		t.Fatalf("missing VNIC ID reached GetVnic or was not foreign: err=%v calls=%d", err, reader.vnicGets.Load())
	}
	reader.attachments.Items[0].VnicId = new(vnicID)
	reader.vnic.SkipSourceDestCheck = new(true)
	if _, err := verifyInstanceStorageAndNetwork(ctx, config, instance, provider.compute, provider.storage, provider.network); !errors.Is(err, ErrForeignResource) {
		t.Fatalf("VNIC without source/destination checks was accepted: %v", err)
	}
	reader.vnic.SkipSourceDestCheck = new(false)
	reader.vnic.PublicIp = new("203.0.113.5")
	if _, err := verifyInstanceStorageAndNetwork(ctx, config, instance, provider.compute, provider.storage, provider.network); !errors.Is(err, ErrForeignResource) {
		t.Fatalf("public VNIC was accepted: %v", err)
	}
}

func TestSDKSocketNamedHostRequiresExactRunningPrivateInstance(t *testing.T) {
	instanceID, vnicID := "ocid1.instance.controller", "ocid1.vnic.controller"
	instance := CloudInstance{ID: instanceID, DisplayName: "gru-1-ctl-1", CompartmentID: "ocid1.compartment.control",
		LifecycleState: "RUNNING"}
	config, _ := testRegionConfig()
	config.CompartmentID = instance.CompartmentID
	reader := &sdkSocketReadback{t: t, config: config, instanceID: instanceID, vnicID: vnicID,
		attachments: core.ListVnicAttachmentsResponse{Items: []core.VnicAttachment{{
			VnicId: new(vnicID), InstanceId: new(instanceID), LifecycleState: core.VnicAttachmentLifecycleStateAttached,
		}}},
		vnic: core.Vnic{Id: new(vnicID), PrivateIp: new("10.251.0.11"),
			LifecycleState: core.VnicLifecycleStateAvailable},
	}
	provider, ctx := sdkSocketProvider(t, config, reader)
	observed, err := observeNamedHost(ctx, instance, instanceID, "gru-1-ctl-1", provider.compute, provider.network)
	if err != nil || observed.PrivateIP != "10.251.0.11" {
		t.Fatalf("controller refused: %+v %v", observed, err)
	}
	stopped := instance
	stopped.LifecycleState = "STOPPED"
	for name, check := range map[string]func() error{
		"another name": func() error {
			_, err := observeNamedHost(ctx, instance, instanceID, "gru-1-ctl-2", provider.compute, provider.network)
			return err
		},
		"another instance": func() error {
			_, err := observeNamedHost(ctx, instance, "ocid1.instance.other", "gru-1-ctl-1", provider.compute, provider.network)
			return err
		},
		"stopped": func() error {
			_, err := observeNamedHost(ctx, stopped, instanceID, "gru-1-ctl-1", provider.compute, provider.network)
			return err
		},
		"public VNIC": func() error {
			reader.vnic.PublicIp = new("203.0.113.5")
			defer func() { reader.vnic.PublicIp = nil }()
			_, err := observeNamedHost(ctx, instance, instanceID, "gru-1-ctl-1", provider.compute, provider.network)
			return err
		},
		"second VNIC": func() error {
			reader.attachments.Items = append(reader.attachments.Items, reader.attachments.Items[0])
			defer func() { reader.attachments.Items = reader.attachments.Items[:1] }()
			_, err := observeNamedHost(ctx, instance, instanceID, "gru-1-ctl-1", provider.compute, provider.network)
			return err
		},
	} {
		if err := check(); !errors.Is(err, ErrForeignResource) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestSDKSocketVolumeAttachmentLookupKeepsExactFilter(t *testing.T) {
	config, _ := testRegionConfig()
	const volumeID = "ocid1.volume.exact"
	var calls atomic.Int32
	provider, ctx := sdkSocketProvider(t, config, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		q := r.URL.Query()
		if r.Method != http.MethodGet || r.URL.Path != "/20160918/volumeAttachments" ||
			q.Get("volumeId") != volumeID || q.Get("compartmentId") != config.CompartmentID ||
			q.Get("availabilityDomain") != config.AvailabilityDomain || q.Get("instanceId") != "" || q.Get("page") != "" {
			t.Errorf("lookup scanned outside the exact volume: %s %s", r.Method, r.URL)
			http.Error(w, "unexpected list", http.StatusBadRequest)
			return
		}
		sdkSocketJSON(t, w, []map[string]any{
			{"id": "attachment-x", "volumeId": volumeID, "instanceId": "ocid1.instance.x", "attachmentType": "paravirtualized"},
			{"id": "foreign", "volumeId": "ocid1.volume.other", "instanceId": "ocid1.instance.other", "attachmentType": "paravirtualized"},
		})
	}))
	f := &fleet{config: config, provider: provider}
	found, err := f.findVolumeAttachments(ctx, volumeID)
	if err != nil || len(found) != 1 || found[0].ID != "attachment-x" {
		t.Fatalf("filtered attachments = %+v, %v", found, err)
	}
	if calls.Load() != 1 {
		t.Fatalf("lookup made %d requests, want one exact filtered list and no compartment scan", calls.Load())
	}
}

func TestSDKSocketVolumeBackupPaginationKeepsNewestBoundedHistory(t *testing.T) {
	config, _ := testRegionConfig()
	const total = maxProviderItems + 150
	var calls atomic.Int32
	provider, ctx := sdkSocketProvider(t, config, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		call := int(calls.Add(1))
		q := r.URL.Query()
		start, pageErr := strconv.Atoi(q.Get("page"))
		if q.Get("page") == "" {
			start, pageErr = 0, nil
		}
		limit, limitErr := strconv.Atoi(q.Get("limit"))
		if r.Method != http.MethodGet || r.URL.Path != "/20160918/volumeBackups" ||
			q.Get("compartmentId") != config.CompartmentID || q.Get("volumeId") != "ocid1.volume.exact" ||
			q.Get("sortBy") != "TIMECREATED" || q.Get("sortOrder") != "DESC" ||
			pageErr != nil || limitErr != nil || limit != 100 || start != (call-1)*100 || call > 6 {
			t.Errorf("backup listing widened, reordered or exceeded its bound: %s %s", r.Method, r.URL)
			http.Error(w, "unexpected backup page", http.StatusBadRequest)
			return
		}
		base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
		var items []map[string]any
		for i := start; i < min(start+limit, total); i++ {
			items = append(items, map[string]any{"id": fmt.Sprintf("ocid1.volumebackup.%d", i), "volumeId": "ocid1.volume.exact",
				"compartmentId": config.CompartmentID, "displayName": "b", "type": "INCREMENTAL", "lifecycleState": "AVAILABLE",
				"freeformTags": map[string]string{}, "timeCreated": base.Add(time.Duration(total-i) * time.Hour).Format(time.RFC3339)})
		}
		if start+limit < total {
			w.Header().Set("opc-next-page", strconv.Itoa(start+limit))
		}
		sdkSocketJSON(t, w, items)
	}))
	backups, err := provider.ListVolumeBackups(ctx, "ocid1.volume.exact")
	if err != nil {
		t.Fatalf("long backup history = %v", err)
	}
	if len(backups) != maxProviderItems || backups[0].ID != "ocid1.volumebackup.0" ||
		backups[len(backups)-1].ID != "ocid1.volumebackup.511" || !backups[0].CreatedAt.After(backups[len(backups)-1].CreatedAt) {
		t.Fatalf("listing = %d backups, want the exact newest %d", len(backups), maxProviderItems)
	}
	if calls.Load() != 6 {
		t.Fatalf("backup listing made %d pages, want six bounded SDK requests", calls.Load())
	}
}
