package oci

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json/v2"
	"encoding/pem"
	"errors"
	"maps"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/oracle/oci-go-sdk/v65/common"

	"github.com/TerraScale/ts-orchestrator/internal/entityid"
	"github.com/TerraScale/ts-orchestrator/internal/hostboot"
	"github.com/TerraScale/ts-orchestrator/internal/ociclient"
)

func TestVolumeMountObserverUsesSignedSDKAndDurableOwnershipWithoutEffects(t *testing.T) {
	intent := RegionIntent{SchemaVersion: 1, Generation: 7, BootstrapRegion: RegionGRU, Regions: []RegionMapping{{Cell: RegionGRU, OCIRegion: "sa-saopaulo-1"}}}
	config := RegionConfig{Region: RegionGRU, Generation: 7, Endpoint: "https://iaas.sa-saopaulo-1.oraclecloud.com",
		CompartmentID: "ocid1.compartment.oc1..aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", ImageCompartmentID: "ocid1.compartment.oc1..bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
		AvailabilityDomain: "sa-saopaulo-1-AD-1", FaultDomains: []string{"FAULT-DOMAIN-1"}, SubnetID: "ocid1.subnet.oc1.sa-saopaulo-1.aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		NetworkSecurityGroupIDs: []string{"ocid1.networksecuritygroup.oc1.sa-saopaulo-1.aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},
		ImageID:                 "ocid1.image.oc1.sa-saopaulo-1.aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", BootVolumeGB: 50, BootVolumeVPUsPerGB: 10, DataVolumeVPUsPerGB: 10, MaxDataVolumeGB: 32768,
		Shape: "VM.Standard.E5.Flex", Owner: "orchestrator"}
	runtime, err := startAuthenticatedJournal(t.Context(), authenticatedJournalConfig(t, "volume-observer"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { runtime.Close() })
	if _, err := OpenJournalReader(t.Context(), runtime.JetStream(), 1); err == nil {
		t.Fatal("journal reader opened an absent bucket")
	}
	if _, err := runtime.JetStream().KeyValue(t.Context(), journalBucket); err == nil {
		t.Fatal("journal reader created an absent bucket")
	}
	journal, err := OpenJournal(t.Context(), runtime.JetStream(), 1)
	if err != nil {
		t.Fatal(err)
	}
	reader, err := OpenJournalReader(t.Context(), runtime.JetStream(), 1)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := OpenJournalReader(t.Context(), runtime.JetStream(), 2); err == nil {
		t.Fatal("journal reader ignored the required regional replicas")
	}
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	provider := common.NewRawConfigurationProvider("ocid1.tenancy.oc1..test", "ocid1.user.oc1..test", "sa-saopaulo-1", "test", string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})), nil)
	factory, err := ociclient.New(provider, ociclient.Options{Region: "sa-saopaulo-1", Retry: ociclient.RetryOptions{MaxAttempts: 2, BaseDelay: time.Millisecond}})
	if err != nil {
		t.Fatal(err)
	}
	observer, err := NewVolumeMountObserver(factory, config, intent, journal)
	if err != nil {
		t.Fatal(err)
	}
	// The running host uses a signed allow-list image rather than the new pin.
	fleetConfig := config
	fleetConfig.ImageID = "ocid1.image.oc1.sa-saopaulo-1.bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	images := &allowListImageVerifier{allowed: []string{config.ImageID}}
	fleetReader, err := NewFleetObserver(fleetConfig, intent, factory, reader, images)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := fleetReader.(Fleet); ok {
		t.Fatal("read-only observer exposed fleet mutations")
	}
	if _, ok := any(reader).(Journal); ok {
		t.Fatal("opaque reader exposed journal mutations")
	}
	if _, err := NewFleetObserver(config, intent, factory, reader, nil); err == nil {
		t.Fatal("fleet observer accepted a missing image verifier")
	}
	if _, err := NewFleetObserver(config, intent, factory, JournalReader{}, images); err == nil {
		t.Fatal("fleet observer accepted a zero journal reader")
	}
	instanceID, oldID := "ocid1.instance.oc1.sa-saopaulo-1.recipient", "ocid1.instance.oc1.sa-saopaulo-1.predecessor"
	volumeID, attachmentID := "ocid1.volume.oc1.sa-saopaulo-1.retained", "ocid1.volumeattachment.oc1.sa-saopaulo-1.current"
	database, partition := entityid.New(), entityid.New()
	now := time.Now().UTC()
	record := func(operation OperationIntent, id, etag string) {
		t.Helper()
		if err := journal.RecordIntent(t.Context(), operation); err != nil {
			t.Fatal(err)
		}
		if err := journal.RecordResult(t.Context(), OperationResult{Intent: operation, ResourceID: id, ETag: etag, RecordedAt: now}); err != nil {
			t.Fatal(err)
		}
	}
	var hostKey, descriptorDigest string
	instances := map[string]map[string]any{}
	for _, id := range []string{instanceID, oldID} {
		createKey := entityid.New()
		request := EnsureRequest{CreateKey: createKey, PlacementGeneration: 3, PlacementProfileDigest: strings.Repeat("a", 64),
			BootPins: HostBootPins{DatabaseID: database, PartitionID: partition, SeatID: entityid.New(), HostAttempt: 1, IntentPayloadDigest: strings.Repeat("b", 64), CanonicalRosterDigest: strings.Repeat("c", 64), RuntimeManifestDigest: strings.Repeat("d", 64)}}
		descriptor, err := (&fleet{config: config}).hostBootDescriptor(request, config.ImageID)
		if err != nil {
			t.Fatal(err)
		}
		wire, err := descriptor.CanonicalBytes()
		if err != nil {
			t.Fatal(err)
		}
		digest, err := descriptor.Digest()
		if err != nil {
			t.Fatal(err)
		}
		op := OperationIntent{Action: actionLaunch, Key: createKey, CreateKey: createKey, Region: config.Region, Generation: config.Generation, Owner: config.Owner,
			CreatedAt: now, FaultDomain: "FAULT-DOMAIN-1", PrivateIP: "10.251.0.21", Shape: config.Shape, WholeOCPUs: 1, MemoryInGBs: 6,
			PlacementProfileDigest: request.PlacementProfileDigest, PlacementGeneration: request.PlacementGeneration, ImageID: config.ImageID, BootDescriptor: string(wire), BootDescriptorSHA256: digest}
		record(op, id, "instance-v1")
		state := "TERMINATED"
		if id == instanceID {
			state, hostKey, descriptorDigest = "RUNNING", createKey, digest
		}
		instances[id] = map[string]any{"id": id, "compartmentId": config.CompartmentID, "availabilityDomain": config.AvailabilityDomain, "faultDomain": "FAULT-DOMAIN-1", "lifecycleState": state,
			"shape": config.Shape, "shapeConfig": map[string]any{"ocpus": 1, "memoryInGBs": 6}, "imageId": config.ImageID,
			"metadata": map[string]string{hostboot.MetadataKey: string(wire)}, "freeformTags": placementProfileTags(hostTags(config, createKey), request.PlacementProfileDigest, request.PlacementGeneration)}
	}
	volumeKey := entityid.New()
	record(OperationIntent{Action: actionVolumeCreate, Key: volumeKey, CreateKey: volumeKey, Region: config.Region, Generation: config.Generation, Owner: config.Owner, CreatedAt: now, AvailabilityDomain: config.AvailabilityDomain, SizeGB: 50}, volumeID, "volume-v1")
	device := "/dev/oracleoci/oraclevdb"
	record(OperationIntent{Action: actionVolumeAttach, Key: entityid.New(), CreateKey: hostKey, ResourceID: instanceID, VolumeID: volumeID, Region: config.Region,
		Generation: config.Generation, Owner: config.Owner, CreatedAt: now, Device: device, IsPvEncryptionInTransitEnabled: true}, attachmentID, "attachment-v1")
	attachment := map[string]any{"id": attachmentID, "instanceId": instanceID, "volumeId": volumeID, "device": device, "lifecycleState": "ATTACHED", "attachmentType": "paravirtualized",
		"isReadOnly": false, "isShareable": false, "isPvEncryptionInTransitEnabled": true,
		"compartmentId": config.CompartmentID, "availabilityDomain": config.AvailabilityDomain, "timeCreated": now.Add(-time.Minute)}
	history := maps.Clone(attachment)
	history["id"], history["instanceId"], history["lifecycleState"] = "ocid1.volumeattachment.oc1.sa-saopaulo-1.history", oldID, "DETACHED"
	var mode, writes, calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.Method != http.MethodGet || r.Header.Get("Authorization") == "" {
			writes.Add(1)
			w.WriteHeader(403)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("etag", "instance-v1")
		var value any
		switch {
		case strings.HasSuffix(r.URL.Path, "/instances"):
			if r.URL.Query().Get("compartmentId") != config.CompartmentID {
				t.Error("fleet observer widened its regional compartment query")
			}
			value = []map[string]any{instances[instanceID]}
		case strings.Contains(r.URL.Path, "/instances/"):
			_, id, _ := strings.CutLast(r.URL.Path, "/")
			if mode.Load() == 9 {
				<-r.Context().Done()
				return
			}
			if id == oldID && mode.Load() == 6 {
				w.WriteHeader(404)
				w.Write([]byte(`{"code":"NotAuthorizedOrNotFound","message":"absent"}`))
				return
			}
			cloud := maps.Clone(instances[id])
			if id == oldID && mode.Load() == 5 {
				cloud["lifecycleState"] = "STOPPED"
			}
			if id == instanceID && mode.Load() == 7 {
				cloud["compartmentId"] = "ocid1.compartment.oc1..foreign"
			}
			value = cloud
		case strings.HasSuffix(r.URL.Path, "/bootVolumeAttachments"):
			value = []map[string]any{{"instanceId": instanceID, "bootVolumeId": "ocid1.bootvolume.oc1.sa-saopaulo-1.boot", "lifecycleState": "ATTACHED"}}
		case strings.Contains(r.URL.Path, "/bootVolumes/"):
			value = map[string]any{"id": "ocid1.bootvolume.oc1.sa-saopaulo-1.boot", "compartmentId": config.CompartmentID, "imageId": config.ImageID, "sizeInGBs": 50, "vpusPerGB": 10}
		case strings.HasSuffix(r.URL.Path, "/vnicAttachments"):
			value = []map[string]any{{"instanceId": r.URL.Query().Get("instanceId"), "vnicId": "ocid1.vnic.oc1.sa-saopaulo-1.private", "lifecycleState": "ATTACHED"}}
		case strings.Contains(r.URL.Path, "/vnics/"):
			subnet := config.SubnetID
			if mode.Load() == 8 {
				subnet = "ocid1.subnet.oc1.sa-saopaulo-1.foreign"
			}
			value = map[string]any{"id": "ocid1.vnic.oc1.sa-saopaulo-1.private", "subnetId": subnet, "privateIp": "10.251.0.21", "lifecycleState": "AVAILABLE", "nsgIds": config.NetworkSecurityGroupIDs}
		case strings.Contains(r.URL.Path, "/volumes/"):
			value = map[string]any{"id": volumeID, "compartmentId": config.CompartmentID, "availabilityDomain": config.AvailabilityDomain, "lifecycleState": "AVAILABLE", "sizeInGBs": 50, "vpusPerGB": 10,
				"freeformTags": volumeTags(config, VolumeCreateRequest{CreateKey: volumeKey, SizeGB: 50})}
		case strings.Contains(r.URL.Path, "/volumeAttachments/"):
			if mode.Load() == 16 {
				w.WriteHeader(404)
				w.Write([]byte(`{"code":"NotAuthorizedOrNotFound","message":"absent"}`))
				return
			}
			w.Header().Set("etag", "attachment-v1")
			current := maps.Clone(attachment)
			switch mode.Load() {
			case 1:
				w.Header().Set("etag", "changed")
			case 2:
				current["volumeId"] = "ocid1.volume.oc1.sa-saopaulo-1.foreign"
			case 3:
				current["isShareable"] = true
			case 10, 15:
				current["timeCreated"] = now.Add(-time.Second)
			case 11:
				current["compartmentId"] = "ocid1.compartment.oc1..foreign"
			case 12:
				current["availabilityDomain"] = "foreign-AD-1"
			case 13:
				current["attachmentType"] = "iscsi"
			case 14:
				current["id"] = "ocid1.volumeattachment.oc1.sa-saopaulo-1.replacement"
			case 19:
				current["instanceId"] = oldID
			}
			value = current
		case strings.HasSuffix(r.URL.Path, "/volumeAttachments"):
			listed := []map[string]any{attachment}
			if mode.Load() == 14 {
				replacement := maps.Clone(attachment)
				replacement["id"] = "ocid1.volumeattachment.oc1.sa-saopaulo-1.replacement"
				listed = []map[string]any{replacement}
			}
			if mode.Load() == 15 {
				replacement := maps.Clone(attachment)
				replacement["timeCreated"] = now.Add(-time.Second)
				listed = []map[string]any{replacement}
			}
			if mode.Load() == 17 {
				listed = nil
			}
			if mode.Load() == 18 {
				listed = append(listed, attachment)
			}
			if mode.Load() == 20 {
				conflict := maps.Clone(attachment)
				conflict["volumeId"] = "ocid1.volume.oc1.sa-saopaulo-1.foreign"
				listed = []map[string]any{conflict}
			}
			if r.URL.Query().Get("volumeId") != "" {
				if r.URL.Query().Get("volumeId") != volumeID {
					t.Error("observer widened exact volume query")
				}
				listed = append(listed, history)
				if mode.Load() == 4 {
					other := maps.Clone(history)
					other["lifecycleState"] = "ATTACHED"
					listed = append(listed, other)
				}
			}
			value = listed
		default:
			t.Errorf("unexpected OCI read: %s", r.URL.Path)
			w.WriteHeader(404)
			return
		}
		wire, err := json.Marshal(value)
		if err != nil {
			t.Error(err)
		}
		w.Write(wire)
	}))
	t.Cleanup(server.Close)
	sdk := observer.reader.provider.(volumeObservationProvider).Provider.(*sdkProvider)
	for _, client := range []*common.BaseClient{&sdk.compute.BaseClient, &sdk.storage.BaseClient, &sdk.network.BaseClient} {
		ociclient.PinHost(client, server.URL)
	}
	fleetSDK := fleetReader.(*fleetObserver).reader.provider.(fleetObservationProvider).Provider.(*sdkProvider)
	for _, client := range []*common.BaseClient{&fleetSDK.compute.BaseClient, &fleetSDK.storage.BaseClient, &fleetSDK.network.BaseClient} {
		ociclient.PinHost(client, server.URL)
	}
	pins := VolumeInitializationPins{DatabaseID: database, PartitionID: partition, InstanceID: instanceID, HostCreateKey: hostKey, VolumeID: volumeID,
		AttachmentID: attachmentID, AttachmentETag: "attachment-v1", Device: device, FileSystemUUID: "12345678-1234-1234-1234-123456789abc", FileSystemType: "ext4"}
	before, err := journal.kv.Status(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	stream, err := runtime.JetStream().Stream(t.Context(), "KV_"+journalBucket)
	if err != nil {
		t.Fatal(err)
	}
	lastSequence := func() uint64 {
		t.Helper()
		info, err := stream.Info(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		return info.State.LastSeq
	}
	sequence := lastSequence()
	cachedContext := WithCachedVerification(t.Context())
	selected := func(id, node string) bool { return id == instanceID && node == hostNode(config, hostKey) }
	if hosts, err := fleetReader.ObserveSelected(cachedContext, selected); err != nil || len(hosts) != 1 || hosts[0].ID != instanceID || hosts[0].BootDescriptorSHA256 != descriptorDigest {
		t.Fatalf("read-only fleet did not preserve allow-listed host verification: hosts=%+v err=%v", hosts, err)
	}
	if hosts, err := fleetReader.Observe(t.Context()); err != nil || len(hosts) != 1 {
		t.Fatalf("read-only fleet sweep failed: hosts=%+v err=%v", hosts, err)
	}
	if _, err := fleetReader.ObserveSelected(t.Context(), nil); err == nil {
		t.Fatal("read-only fleet accepted a nil selector")
	}
	if hosts, err := fleetReader.ObserveSelected(t.Context(), func(string, string) bool { return false }); err != nil || len(hosts) != 0 {
		t.Fatalf("read-only fleet ignored its selector: hosts=%+v err=%v", hosts, err)
	}
	images.allowed = nil
	if hosts, err := fleetReader.ObserveSelected(t.Context(), selected); err != nil || len(hosts) != 0 {
		t.Fatalf("read-only fleet admitted an image removed from the allow-list: hosts=%+v err=%v", hosts, err)
	}
	images.allowed = []string{config.ImageID}
	mode.Store(8)
	if hosts, err := fleetReader.ObserveSelected(cachedContext, selected); err == nil && len(hosts) != 0 {
		t.Fatal("read-only fleet reused cached network verification during registration")
	}
	mode.Store(0)
	terminalTarget := TerminalAttachmentTarget{DatabaseID: database, PartitionID: partition, InstanceID: instanceID,
		VolumeID: volumeID, HostCreateKey: hostKey, DataCreateKey: volumeKey}
	var terminalGuards atomic.Int32
	terminalAdmission := ociclient.WithRequestGuard(t.Context(), func(context.Context) error {
		terminalGuards.Add(1)
		return nil
	})
	attachmentObservation, err := observer.ObserveTerminalAttachment(terminalAdmission, terminalTarget)
	if err != nil || !attachmentObservation.IsVerified() || attachmentObservation.Pins().Target != terminalTarget ||
		attachmentObservation.Pins().AttachmentID != attachmentID || attachmentObservation.Pins().CompartmentID != config.CompartmentID ||
		attachmentObservation.Pins().AvailabilityDomain != config.AvailabilityDomain || attachmentObservation.Pins().Type != "paravirtualized" ||
		!attachmentObservation.Pins().CreatedAt.Equal(now.Add(-time.Minute)) || attachmentObservation.ETag() != "attachment-v1" ||
		attachmentObservation.BootDescriptorSHA256() != descriptorDigest {
		t.Fatalf("terminal attachment did not retain exact native SDK identity: %v", err)
	}
	guards := terminalGuards.Load()
	if err := attachmentObservation.Revalidate(t.Context()); err != nil || terminalGuards.Load() <= guards {
		t.Fatalf("original native attachment failed revalidation: %v", err)
	}
	originalContext, cancelOriginal := context.WithCancel(terminalAdmission)
	cancelableObservation, err := observer.ObserveTerminalAttachment(originalContext, terminalTarget)
	cancelOriginal()
	if err != nil || cancelableObservation.IsVerified() || cancelableObservation.Revalidate(t.Context()) == nil {
		t.Fatalf("terminal observation replaced the canceled original caller lifetime: %v", err)
	}
	canceledContext, cancelCurrent := context.WithCancel(t.Context())
	cancelCurrent()
	if err := attachmentObservation.Revalidate(canceledContext); !errors.Is(err, context.Canceled) {
		t.Fatalf("terminal revalidation ignored current caller cancellation: %v", err)
	}
	for _, scenario := range []int32{2, 3, 4, 5, 6, 7, 10, 11, 12, 13, 16, 17, 18, 19, 20} {
		mode.Store(scenario)
		if observed, err := observer.ObserveTerminalAttachment(t.Context(), terminalTarget); err == nil || observed.IsVerified() {
			t.Fatalf("terminal SDK observation admitted conflicting/absent identity scenario %d", scenario)
		}
	}
	for _, scenario := range []int32{14, 15} {
		mode.Store(scenario)
		if err := attachmentObservation.Revalidate(t.Context()); err == nil {
			t.Fatalf("terminal revalidation followed replacement attachment scenario %d", scenario)
		}
	}
	mode.Store(1)
	if err := attachmentObservation.Revalidate(t.Context()); err != nil {
		t.Fatalf("mutable ETag replaced immutable native incarnation: %v", err)
	}
	mode.Store(8)
	if _, err := observer.ObserveTerminalAttachment(cachedContext, terminalTarget); err == nil {
		t.Fatal("terminal attachment reused the placement sweep's cached native checks")
	}
	mode.Store(0)
	observation, err := observer.InspectVolumeMount(t.Context(), pins, oldID)
	if err != nil || !observation.IsVerified() || observation.Pins() != pins || observation.PredecessorID() != oldID || observation.BootDescriptorSHA256() != descriptorDigest {
		t.Fatalf("existing retained mount did not verify: %v", err)
	}
	if observation, err := observer.InspectVolumeMount(t.Context(), pins, ""); err != nil || !observation.IsVerified() || observation.PredecessorID() != "" {
		t.Fatalf("current mount with terminated historical attachments did not verify: %v", err)
	}
	terminal, err := observer.ObserveTerminatedInstance(t.Context(), oldID)
	if err != nil || !terminal.IsVerified() || terminal.InstanceID() != oldID || terminal.Region() != config.Region || terminal.Generation() != config.Generation || terminal.Owner() != config.Owner {
		t.Fatalf("exact terminated predecessor did not verify: %v", err)
	}
	for scenario := int32(1); scenario <= 7; scenario++ {
		mode.Store(scenario)
		if _, err := observer.InspectVolumeMount(t.Context(), pins, oldID); err == nil {
			t.Fatalf("unsafe OCI observation scenario %d admitted", scenario)
		}
	}
	mode.Store(5)
	if _, err := observer.InspectVolumeMount(t.Context(), pins, ""); err == nil {
		t.Fatal("omitted predecessor skipped nonterminal attachment history")
	}
	mode.Store(0)
	if _, err := observer.ObserveTerminatedInstance(t.Context(), instanceID); err == nil {
		t.Fatal("running recipient proved terminated")
	}
	after, err := journal.kv.Status(t.Context())
	if err != nil || before.Values() != after.Values() || sequence != lastSequence() || writes.Load() != 0 {
		t.Fatal("observer mutated OCI or journal records")
	}
	mode.Store(9)
	count := calls.Load()
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	started := time.Now()
	_, err = observer.InspectVolumeMount(ctx, pins, oldID)
	cancel()
	if !errors.Is(err, context.DeadlineExceeded) || time.Since(started) > 2*time.Second || calls.Load() <= count {
		t.Fatalf("actual SDK read did not honor cancellation: %v", err)
	}
	terminalContext, cancelTerminal := context.WithTimeout(t.Context(), 100*time.Millisecond)
	_, err = observer.ObserveTerminalAttachment(terminalContext, terminalTarget)
	cancelTerminal()
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("terminal SDK read lost original caller deadline: %v", err)
	}
	mode.Store(0)
	if err := journal.kv.Delete(t.Context(), ownershipKey("instance", instanceID)); err != nil {
		t.Fatal(err)
	}
	sequence = lastSequence()
	if hosts, err := fleetReader.ObserveSelected(t.Context(), selected); err != nil || len(hosts) != 0 {
		t.Fatalf("read-only fleet admitted or repaired missing durable ownership: hosts=%+v err=%v", hosts, err)
	}
	if _, err := observer.InspectVolumeMount(t.Context(), pins, oldID); err == nil {
		t.Fatal("missing ownership projection was repaired by a read-only observer")
	}
	if observed, err := observer.ObserveTerminalAttachment(t.Context(), terminalTarget); err == nil || observed.IsVerified() {
		t.Fatal("terminal attachment admitted or repaired missing original durable ownership")
	}
	entry, err := journal.kv.Get(t.Context(), ownershipKey("instance", instanceID))
	if err == nil || entry != nil {
		t.Fatal("read-only observer recreated missing ownership projection")
	}
	if sequence != lastSequence() || writes.Load() != 0 {
		t.Fatal("read-only observers changed the journal or OCI after missing ownership")
	}
	if (VerifiedVolumeObservation{}).IsVerified() || (VerifiedTerminatedInstance{}).IsVerified() || (TerminalAttachmentObservation{}).IsVerified() || !errors.Is(ctx.Err(), context.DeadlineExceeded) {
		t.Fatal("zero or canceled observation acquired authority")
	}
}
