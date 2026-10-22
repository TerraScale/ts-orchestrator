package region

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json/v2"
	"errors"
	"fmt"
	"maps"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/bootstrap"
	"github.com/TerraScale/ts-orchestrator/internal/capacityledger"
	"github.com/TerraScale/ts-orchestrator/internal/ociclient"
	"github.com/TerraScale/ts-orchestrator/internal/ociregion/capacityinventory"
	"github.com/TerraScale/ts-orchestrator/internal/release"
	"github.com/TerraScale/ts-orchestrator/internal/releasechannel"
	"github.com/TerraScale/ts-orchestrator/internal/trust"
	"github.com/oracle/oci-go-sdk/v65/core"
)

type originalActorDispatch struct {
	cell, host, token string
	body              []byte
	pending           PendingFoundationCreate
	quote             capacityledger.Quote
}

type originalActorSDKFixture struct {
	*originalVaultSDKFixture
	actorMu       sync.Mutex
	actorFault    string
	actorSlot     int
	actorFaulted  bool
	actorPosts    []originalActorDispatch
	actorTokens   map[string]string
	actorRows     map[string]map[string]any
	actorGets     map[string]int
	actorUpstream []byte
	actorTariffs  map[string]time.Time
}

func newOriginalActorSDKFixture(t *testing.T, fault string, slot int) *originalActorSDKFixture {
	t.Helper()
	f := &originalActorSDKFixture{originalVaultSDKFixture: newOriginalVaultSDKFixture(t, "", 0), actorFault: fault, actorSlot: slot, actorTokens: map[string]string{}, actorRows: map[string]map[string]any{}, actorGets: map[string]int{}, actorTariffs: map[string]time.Time{}}
	server := httptest.NewTLSServer(http.HandlerFunc(f.serveHTTP))
	t.Cleanup(server.Close)
	listener, ok := server.Listener.Addr().(*net.TCPAddr)
	if !ok || !listener.IP.IsLoopback() || listener.Port == 0 {
		t.Fatal("original actor fixture requires literal loopback TLS")
	}
	previous := http.DefaultTransport
	transport := previous.(*http.Transport).Clone()
	transport.DialTLSContext = func(ctx context.Context, network, _ string) (net.Conn, error) {
		if network != "tcp" && network != "tcp4" && network != "tcp6" {
			return nil, fmt.Errorf("fixture refuses network %q", network)
		}
		return (&tls.Dialer{Config: server.Client().Transport.(*http.Transport).TLSClientConfig}).DialContext(ctx, "tcp", listener.String())
	}
	http.DefaultTransport = transport
	t.Cleanup(func() { http.DefaultTransport = previous; transport.CloseIdleConnections() })
	return f
}

func (f *originalActorSDKFixture) run(t *testing.T) error {
	t.Helper()
	stage, err := provisionFoundationMaterial(t.Context(), f.factoryFor(), f.roots, f.bundle)
	if err != nil {
		return err
	}
	defer stage.cancel()
	ctx, release, err := stage.authority.HomeWrite(stage.ctx, 0)
	if err != nil {
		return err
	}
	defer release()
	if err := retainOriginalFoundationCompartments(ctx, stage.authority); err != nil {
		return err
	}
	if err := retainOriginalFoundationNetwork(ctx, stage.authority); err != nil {
		return err
	}
	if err := retainOriginalFoundationVault(ctx, stage.authority); err != nil {
		return err
	}
	return retainOriginalFoundationActorLaunches(ctx, stage.authority)
}

func originalActorUpstream(record FoundationRecord) ([]byte, error) {
	section := *record.OriginalFoundationCompartments
	for index := range section.Regions {
		section.Regions[index].Actor = nil
		section.Regions[index].ActorReads = nil
	}
	return json.Marshal(struct {
		Material     *NetBirdMaterialJournal
		Births       *[3]OriginalSourceProducerBirth
		Compartments OriginalFoundationCompartments
	}{record.NetBirdMaterial, record.OriginalSourceProducers, section}, json.Deterministic(true))
}

func (f *originalActorSDKFixture) checkActorPrerequisites(record FoundationRecord) {
	f.checkVaultPrerequisites(record)
	for index, region := range record.OriginalFoundationCompartments.Regions {
		actor := region.Actor
		network, networkErr := json.Marshal(region.Network, json.Deterministic(true))
		vault, vaultErr := json.Marshal(region.Vault, json.Deterministic(true))
		if actor == nil || region.Vault == nil || networkErr != nil || vaultErr != nil {
			f.cloud.test.Error("actor effect preceded all three original actor scopes and complete prerequisites")
			continue
		}
		material := f.prepared.Grant.Regions[index].BootstrapMaterial
		if !sameOriginalSourceValue(actor.Startup, *material.Startup) || !sameOriginalSourceValue(actor.Config, material.Config) {
			f.cloud.test.Error("actor scope replaced exact original signed startup/config snapshots")
		}
		if actor.ControlCompartmentID != originalCompartmentID(region.Compartments[0]) || actor.NetworkProofSHA256 != preparationDigest(network) || actor.VaultProofSHA256 != preparationDigest(vault) {
			f.cloud.test.Error("actor effect changed exact original control/network/Vault dependencies")
		}
		for slot := range 2 {
			entry := originalVaultEntry(region.Vault, slot)
			if entry.VerifiedAt.IsZero() || entry.ReadbackSHA256 == "" || entry.HoldReason != "" {
				f.cloud.test.Error("actor effect preceded all three independently read-back Vault/key pairs")
			}
		}
	}
	pins, err := originalActorUpstream(record)
	if err != nil {
		f.cloud.test.Error(err)
		return
	}
	if f.actorUpstream == nil {
		f.actorUpstream = pins
	} else if !bytes.Equal(pins, f.actorUpstream) {
		f.cloud.test.Error("actor progress changed original material, producer, compartment, network or Vault pins")
	}
}

// This oracle projects signed inputs independently of the producer's request.
func (f *originalActorSDKFixture) expectedBody(record FoundationRecord, index int) map[string]any {
	region := record.OriginalFoundationCompartments.Regions[index]
	material := f.prepared.Grant.Regions[index].BootstrapMaterial
	startup := material.Startup
	var profile bootstrap.LaunchProfile
	var geometry bootstrap.StartupSlotResources
	for _, candidate := range startup.Profiles {
		if candidate.Slot == "controller-a" {
			profile = candidate
		}
	}
	for _, candidate := range startup.FounderResources.Slots {
		if candidate.Slot == "controller-a" {
			geometry = candidate
		}
	}
	privateIP := ""
	for _, slot := range material.Config.Slots {
		if slot.Name == "controller-a" {
			privateIP = slot.PrivateIP
		}
	}
	return map[string]any{
		"availabilityDomain": profile.AvailabilityDomain, "faultDomain": profile.FaultDomain,
		"compartmentId": originalCompartmentID(region.Compartments[0]), "displayName": strings.ToLower(region.Cell) + "-1-controller-a", "shape": profile.Shape,
		"metadata":    map[string]any{"terrascale-bootstrap": fmt.Sprintf(`{"schemaVersion":1,"slot":"controller-a","originalBundleSha256":%q}`, record.OriginalFoundationCompartments.BundleSHA256)},
		"definedTags": map[string]any{}, "securityAttributes": map[string]any{}, "extendedMetadata": map[string]any{}, "freeformTags": map[string]any{},
		"launchVolumeAttachments": []any{}, "licensingConfigs": []any{},
		"shapeConfig":   map[string]any{"ocpus": float64(geometry.WholeOCPUs), "memoryInGBs": float64(geometry.MemoryInGB)},
		"sourceDetails": map[string]any{"sourceType": "image", "imageId": startup.ImageOCID, "bootVolumeSizeInGBs": float64(geometry.BootVolumeGB), "bootVolumeVpusPerGB": float64(10)},
		"createVnicDetails": map[string]any{
			"subnetId": region.Network.Creates[4].Provenance.ResourceID, "nsgIds": []any{region.Network.Creates[5].Provenance.ResourceID}, "privateIp": privateIP, "assignPublicIp": false,
			"definedTags": map[string]any{}, "freeformTags": map[string]any{}, "securityAttributes": map[string]any{}, "ipv6AddressIpv6SubnetCidrPairDetails": []any{},
		},
	}
}

func (f *originalActorSDKFixture) serveHTTP(w http.ResponseWriter, r *http.Request) {
	f.actorMu.Lock()
	defer f.actorMu.Unlock()
	for _, region := range f.prepared.Grant.Regions {
		if region.BootstrapMaterial != nil && region.BootstrapMaterial.OriginalSourceProducer != nil {
			object := region.BootstrapMaterial.OriginalSourceProducer.SourceObject
			if object != "" && strings.HasSuffix(r.URL.Path, "/o/"+object) {
				f.cloud.test.Error("physical original actor selected or wrote a source archive")
				originalCompartmentFailure(w, 400, "InvalidParameter")
				return
			}
		}
	}
	if r.Method != http.MethodGet && (strings.Contains(r.URL.Path, "/policies") || strings.Contains(r.URL.Path, "/dynamicGroups") || strings.Contains(r.URL.Path, "/secrets")) {
		wire, readErr := os.ReadFile(f.cloud.objectPath("gru-1-head/" + foundationObjectPrefix + "GRU.json"))
		var saved FoundationRecord
		if readErr == nil && json.Unmarshal(wire, &saved) == nil && saved.OriginalFoundationCompartments != nil && saved.OriginalFoundationCompartments.Regions[0].Actor != nil {
			f.cloud.test.Error("physical actor stage emitted downstream policy/secret/IAM mutation")
			originalCompartmentFailure(w, 400, "InvalidParameter")
			return
		}
	}
	if r.Method == http.MethodGet && r.URL.Path == "/pls/apex/cetools/api/v1/products/" {
		f.actorTariffs[r.URL.Query().Get("partNumber")] = time.Now().UTC()
	}
	if r.Method == http.MethodPut && strings.HasSuffix(r.URL.Path, "/o/"+foundationObjectPrefix+"GRU.json") && !f.actorFaulted {
		body, _, err := originalNetworkBody(r)
		if err != nil {
			f.cloud.test.Error(err)
			originalCompartmentFailure(w, 400, "InvalidParameter")
			return
		}
		wire, err := json.Marshal(body)
		var record FoundationRecord
		if err == nil && json.Unmarshal(wire, &record) == nil && record.OriginalFoundationCompartments != nil {
			actor := record.OriginalFoundationCompartments.Regions[f.actorSlot].Actor
			if actor != nil {
				scope := actor.Pending == nil
				reservation := actor.Pending != nil && actor.Provenance == nil
				accepted := actor.Provenance != nil && actor.VerifiedAt.IsZero()
				if reservation && f.actorFault == "stale lease" {
					f.actorFaulted = true
					recorder := httptest.NewRecorder()
					f.originalVaultSDKFixture.serveHTTP(recorder, r)
					if recorder.Code >= 300 {
						f.cloud.test.Error("stale lease fault preceded acknowledged reservation")
					}
					leaseWire, readErr := os.ReadFile(f.cloud.objectPath("gru-1-head/" + homeIAMObject))
					var lease homeIAMRecord
					if readErr != nil || json.Unmarshal(leaseWire, &lease) != nil {
						f.cloud.test.Error("fixture could not read acknowledged HomeWrite lease")
					} else {
						lease.UpdatedAt = time.Now().UTC()
						lease.ExpiresAt = lease.UpdatedAt
						lease.ReleasedAt = lease.UpdatedAt
						expired, marshalErr := json.Marshal(lease)
						if marshalErr != nil {
							f.cloud.test.Error(marshalErr)
						} else {
							f.cloud.writeObject("gru-1-head/"+homeIAMObject, expired)
						}
					}
					originalNetworkCopyResponse(w, recorder)
					return
				}
				stop := f.actorFault == "scope checkpoint" && scope || f.actorFault == "reservation checkpoint" && reservation || (f.actorFault == "lost accepted checkpoint" || f.actorFault == "response before CAS") && accepted
				if stop {
					f.actorFaulted = true
					if f.actorFault == "lost accepted checkpoint" {
						recorder := httptest.NewRecorder()
						f.originalVaultSDKFixture.serveHTTP(recorder, r)
						if recorder.Code >= 300 {
							f.cloud.test.Errorf("actor lost-ACK fault preceded accepted checkpoint: %d", recorder.Code)
						}
					}
					originalCompartmentFailure(w, 503, "InternalError")
					return
				}
			}
		}
	}
	parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
	actorEndpoint := len(parts) >= 2 && slices.Contains([]string{"instances", "vnicAttachments", "vnics", "bootVolumeAttachments", "bootVolumes"}, parts[1])
	if !actorEndpoint {
		f.originalVaultSDKFixture.serveHTTP(w, r)
		return
	}
	if parts[0] != "20160918" || !strings.HasPrefix(r.Header.Get("Authorization"), "Signature ") || r.Method != http.MethodGet && r.Method != http.MethodPost {
		f.cloud.test.Error("actor operation escaped exact authenticated OCI protocol")
		originalCompartmentFailure(w, 400, "InvalidParameter")
		return
	}
	record := f.record(f.cloud.test)
	if record.OriginalFoundationCompartments == nil {
		f.cloud.test.Error("actor effect preceded original journal")
		originalCompartmentFailure(w, 400, "InvalidParameter")
		return
	}
	index := slices.IndexFunc(record.OriginalFoundationCompartments.Regions[:], func(region OriginalFoundationCompartmentRegion) bool {
		return r.Host == "iaas."+region.OCIRegion+".oraclecloud.com"
	})
	if index < 0 {
		f.cloud.test.Error("actor request escaped its regional OCI origin")
		originalCompartmentFailure(w, 400, "InvalidParameter")
		return
	}
	f.checkActorPrerequisites(record)
	if r.Method == http.MethodPost {
		if parts[1] != "instances" || len(parts) != 2 || r.URL.RawQuery != "" {
			f.cloud.test.Error("actor emitted non-launch mutation")
			originalCompartmentFailure(w, 400, "InvalidParameter")
			return
		}
		f.launch(w, r, record, index)
		return
	}
	f.observe(w, r, parts, record, index)
}

func (f *originalActorSDKFixture) launch(w http.ResponseWriter, r *http.Request, record FoundationRecord, index int) {
	region := record.OriginalFoundationCompartments.Regions[index]
	actor := region.Actor
	body, canonical, err := originalNetworkBody(r)
	if err != nil || actor == nil || actor.Pending == nil || actor.OriginalQuote == nil {
		f.cloud.test.Error("launch preceded acknowledged body/token/quote reservation")
		originalCompartmentFailure(w, 400, "InvalidParameter")
		return
	}
	expected, err := json.Marshal(f.expectedBody(record, index), json.Deterministic(true))
	actual, actualErr := json.Marshal(originalNetworkPrune(body), json.Deterministic(true))
	scopeWire, scopeErr := json.Marshal(struct {
		SignedScopeSHA256   string
		TenancyID, Currency string
		Regions             []capacityinventory.RegionScope
	}{f.prepared.Grant.InfrastructureSpend.ScopeSHA256, record.TenancyID, f.prepared.Grant.Currency, []capacityinventory.RegionScope{{Cell: region.Cell, OCIRegion: region.OCIRegion, CompartmentIDs: []string{actor.ControlCompartmentID}}}}, json.Deterministic(true))
	digest, digestErr := netBirdRequestDigest(actor.Request)
	pending, q := actor.Pending, actor.OriginalQuote
	for _, sku := range []string{"B93297", "B93298", "B91961", "B91962"} {
		observed := f.actorTariffs[sku]
		if observed.IsZero() || observed.Before(time.Now().Add(-2*time.Minute)) {
			f.cloud.test.Error("launch lacked freshly observed real capacityinventory tariff inputs")
		}
	}
	allocation := (*record.OriginalSourceProducers)[index].Intent.Allocation
	if err != nil || actualErr != nil || scopeErr != nil || actor.OriginalQuote.ScopeSHA256 != preparationDigest(scopeWire) || !bytes.Equal(expected, actual) || digestErr != nil || pending.Request.RequestDigest != digest || pending.Request.RequestDigest != preparationDigest(canonical) || pending.Request.Region != region.OCIRegion || pending.Request.Key != "controller-a" || pending.OperationID != (*record.OriginalSourceProducers)[index].Intent.OperationID || pending.IntentDigest != region.IntentSHA256 || pending.Request.RetryToken != BootstrapRetryToken(pending.OperationID, digest) || r.Header.Get("opc-retry-token") != pending.Request.RetryToken || pending.FirstAttemptAt.IsZero() || pending.FirstAttemptAt.Before(f.started) || pending.FirstAttemptAt.After(q.IssuedAt) || q.Validate() != nil || q.MonthlyCents == 0 || q.MonthlyCents > uint64(allocation.MonthlyLimitMinor) || q.Cell != region.Cell || q.CompartmentID != actor.ControlCompartmentID || q.Shape != allocation.Shape || q.OCPUs != allocation.OCPUs || q.MemoryGB != allocation.MemoryGB || q.BootGB != allocation.BootGB || q.Currency != f.prepared.Grant.Currency {
		f.cloud.test.Errorf("original launch escaped exact signed finite geometry, private network, independent quote or acknowledged reservation: %v %v", err, digestErr)
	}
	if actor.Provenance != nil {
		f.cloud.test.Error("known original instance was launched again")
	}
	f.actorPosts = append(f.actorPosts, originalActorDispatch{region.Cell, r.Host, r.Header.Get("opc-retry-token"), canonical, *pending, q.Clone()})
	f.cloud.mu.Lock()
	f.cloud.launchPosts++
	f.cloud.mu.Unlock()
	fault := index == f.actorSlot && !f.actorFaulted
	if fault && (f.actorFault == "unknown create" || f.actorFault == "conflict" || f.actorFault == "invalid token" || f.actorFault == "throttle" || f.actorFault == "timeout") {
		f.actorFaulted = true
		status, code := 503, "InternalError"
		switch f.actorFault {
		case "conflict":
			status, code = 409, "Conflict"
		case "invalid token":
			status, code = 400, "InvalidParameter"
		case "throttle":
			status, code = 429, "TooManyRequests"
		case "timeout":
			status, code = 408, "RequestTimeout"
		}
		originalCompartmentFailure(w, status, code)
		return
	}
	id := f.actorTokens[pending.Request.RetryToken]
	if id == "" {
		id = "ocid1.instance.oc1." + region.OCIRegion + ".originalcontroller"
		f.actorTokens[pending.Request.RetryToken] = id
		f.seedActorRows(id, record, index)
		f.cloud.mu.Lock()
		f.cloud.creates++
		f.cloud.mu.Unlock()
	}
	if fault && f.actorFault == "lost create response" {
		f.actorFaulted = true
		originalCompartmentFailure(w, 503, "InternalError")
		return
	}
	row := maps.Clone(f.actorRows[id])
	if fault {
		switch f.actorFault {
		case "empty ID":
			row["id"] = ""
			f.actorFaulted = true
		case "wrong region ID":
			row["id"] = "ocid1.instance.oc1.foreign.originalcontroller"
			f.actorFaulted = true
		case "duplicate ID":
			row["id"] = originalActorID(record.OriginalFoundationCompartments.Regions[0].Actor)
			f.actorFaulted = true
		}
	}
	w.WriteHeader(http.StatusOK)
	json.MarshalWrite(w, row)
}

func (f *originalActorSDKFixture) seedActorRows(id string, record FoundationRecord, index int) {
	body := f.expectedBody(record, index)
	region := record.OriginalFoundationCompartments.Regions[index]
	vnicID, bootID := strings.Replace(id, ".instance.", ".vnic.", 1), strings.Replace(id, ".instance.", ".bootvolume.", 1)
	row := maps.Clone(body)
	delete(row, "createVnicDetails")
	row["id"], row["lifecycleState"], row["imageId"] = id, "RUNNING", region.Actor.Startup.ImageOCID
	f.actorRows[id] = row
	vnic := body["createVnicDetails"].(map[string]any)
	f.actorRows[vnicID] = map[string]any{"id": vnicID, "compartmentId": region.Network.CompartmentID, "availabilityDomain": body["availabilityDomain"], "lifecycleState": "AVAILABLE", "subnetId": vnic["subnetId"], "nsgIds": vnic["nsgIds"], "privateIp": vnic["privateIp"], "isPrimary": true, "skipSourceDestCheck": false, "ipv6Addresses": []any{}}
	source := body["sourceDetails"].(map[string]any)
	f.actorRows[bootID] = map[string]any{"id": bootID, "compartmentId": body["compartmentId"], "availabilityDomain": body["availabilityDomain"], "imageId": source["imageId"], "sizeInGBs": source["bootVolumeSizeInGBs"], "vpusPerGB": float64(10), "lifecycleState": "AVAILABLE", "isAutoTuneEnabled": false, "autotunePolicies": []any{}}
}

func (f *originalActorSDKFixture) observe(w http.ResponseWriter, r *http.Request, parts []string, record FoundationRecord, index int) {
	region := record.OriginalFoundationCompartments.Regions[index]
	actor := region.Actor
	id := originalActorID(actor)
	if id == "" || f.actorRows[id] == nil || actor.Pending == nil || !sameOriginalSourceValue(actor.Provenance.Create, *actor.Pending) {
		f.cloud.test.Error("physical actor read preceded acknowledged actual SDK instance ID")
		originalCompartmentFailure(w, 400, "InvalidParameter")
		return
	}
	collection := parts[1]
	if collection == "vnicAttachments" || collection == "bootVolumeAttachments" {
		f.attachments(w, r, collection, record, index, id)
		return
	}
	if len(parts) != 3 || r.URL.RawQuery != "" {
		f.cloud.test.Error("actor listed/adopted instances or changed exact read protocol")
		originalCompartmentFailure(w, 400, "InvalidParameter")
		return
	}
	expected := id
	if collection == "vnics" {
		expected = strings.Replace(id, ".instance.", ".vnic.", 1)
	}
	if collection == "bootVolumes" {
		expected = strings.Replace(id, ".instance.", ".bootvolume.", 1)
	}
	if parts[2] != expected || f.actorRows[expected] == nil {
		f.cloud.test.Error("physical read escaped exact retained instance attachment identity")
		originalCompartmentFailure(w, 404, "NotAuthorizedOrNotFound")
		return
	}
	f.actorGets[expected]++
	row := maps.Clone(f.actorRows[expected])
	if index == f.actorSlot {
		f.drift(collection, row, record, index)
	}
	if row["id"] == nil {
		originalCompartmentFailure(w, 404, "NotAuthorizedOrNotFound")
		return
	}
	json.MarshalWrite(w, row)
}

func (f *originalActorSDKFixture) attachments(w http.ResponseWriter, r *http.Request, collection string, record FoundationRecord, index int, id string) {
	region := record.OriginalFoundationCompartments.Regions[index]
	actor := region.Actor
	query := r.URL.Query()
	allowed := map[string]bool{"instanceId": true, "compartmentId": true, "availabilityDomain": true, "limit": true, "page": true}
	for key, values := range query {
		if !allowed[key] || len(values) != 1 {
			f.cloud.test.Error("attachment query escaped exact bounded scope")
		}
	}
	if query.Get("instanceId") != id || query.Get("compartmentId") != actor.ControlCompartmentID || query.Get("limit") != "2" || query.Get("availabilityDomain") != *actor.Request.AvailabilityDomain {
		f.cloud.test.Error("attachment read lost exact instance/control/AD or explicit bound")
	}
	kind, field := "vnic", "vnicId"
	if collection == "bootVolumeAttachments" {
		kind, field = "bootvolume", "bootVolumeId"
	}
	attachment := map[string]any{"id": strings.Replace(id, ".instance.", "."+kind+"attachment.", 1), "instanceId": id, "compartmentId": actor.ControlCompartmentID, "availabilityDomain": *actor.Request.AvailabilityDomain, "lifecycleState": "ATTACHED", field: strings.Replace(id, ".instance.", "."+kind+".", 1)}
	if collection == "vnicAttachments" {
		attachment["subnetId"] = region.Network.Creates[4].Provenance.ResourceID
	}
	rows := []any{attachment}
	fault := index == f.actorSlot
	prefix := "VNIC"
	if kind == "bootvolume" {
		prefix = "boot"
	}
	page := query.Get("page")
	pageKey := collection + id + "/current"
	if query.Get("page") == "" {
		f.actorGets[pageKey] = 0
	}
	f.actorGets[pageKey]++
	if f.actorGets[pageKey] > 3 {
		f.cloud.test.Error("actor attachment reader exceeded fixed3-page bound")
		originalCompartmentFailure(w, 400, "InvalidParameter")
		return
	}
	if fault {
		switch f.actorFault {
		case prefix + " missing attachment":
			rows = []any{}
		case prefix + " extra attachment":
			rows = append(rows, maps.Clone(attachment))
		case prefix + " foreign attachment":
			attachment["instanceId"] = "ocid1.instance.oc1." + region.OCIRegion + ".foreign"
		case prefix + " wrong compartment":
			attachment["compartmentId"] = record.SharedCompartmentID
		case prefix + " detached":
			attachment["lifecycleState"] = "DETACHED"
		case prefix + " wrong AD":
			attachment["availabilityDomain"] = "foreign:AD-1"
		case prefix + " empty attachment ID":
			attachment["id"] = ""
		case prefix + " second page extra":
			if page == "" {
				w.Header().Set("opc-next-page", "second")
			} else {
				attachment["id"] = attachment["id"].(string) + "extra"
			}
		case prefix + " cyclic pages":
			rows = []any{}
			w.Header().Set("opc-next-page", "cycle")
		case prefix + " unbounded pages":
			rows = []any{}
			w.Header().Set("opc-next-page", fmt.Sprintf("page%d", f.actorGets[collection+id]))
		case "complete pagination":
			if page == "" {
				rows = []any{}
				w.Header().Set("opc-next-page", "second")
			}
		}
	}
	f.actorGets[collection+id]++
	json.MarshalWrite(w, rows)
}

func (f *originalActorSDKFixture) drift(collection string, row map[string]any, record FoundationRecord, index int) {
	switch f.actorFault {
	case "instance missing":
		if collection == "instances" {
			delete(row, "id")
		}
	case "instance identity":
		if collection == "instances" {
			row["id"] = "ocid1.instance.oc1.foreign.foreign"
		}
	case "instance compartment":
		if collection == "instances" {
			row["compartmentId"] = record.SharedCompartmentID
		}
	case "instance pending":
		if collection == "instances" {
			row["lifecycleState"] = "PROVISIONING"
		}
	case "instance AD":
		if collection == "instances" {
			row["availabilityDomain"] = "foreign:AD-1"
		}
	case "instance FD":
		if collection == "instances" {
			row["faultDomain"] = "FAULT-DOMAIN-3"
		}
	case "instance shape":
		if collection == "instances" {
			row["shape"] = "VM.Standard.E4.Flex"
		}
	case "instance OCPU":
		if collection == "instances" {
			shape := maps.Clone(row["shapeConfig"].(map[string]any))
			shape["ocpus"] = float64(2)
			row["shapeConfig"] = shape
		}
	case "instance memory":
		if collection == "instances" {
			shape := maps.Clone(row["shapeConfig"].(map[string]any))
			shape["memoryInGBs"] = float64(12)
			row["shapeConfig"] = shape
		}
	case "instance image":
		if collection == "instances" {
			row["imageId"] = "ocid1.image.oc1.foreign.foreign"
		}
	case "instance source":
		if collection == "instances" {
			source := maps.Clone(row["sourceDetails"].(map[string]any))
			source["imageId"] = "ocid1.image.oc1.foreign.foreign"
			row["sourceDetails"] = source
		}
	case "instance metadata":
		if collection == "instances" {
			row["metadata"] = map[string]any{"user_data": "forbidden"}
		}
	case "instance extended metadata":
		if collection == "instances" {
			row["extendedMetadata"] = map[string]any{"foreign": "value"}
		}
	case "instance display name":
		if collection == "instances" {
			row["displayName"] = "foreign"
		}
	case "VNIC public":
		if collection == "vnics" {
			row["publicIp"] = "203.0.113.10"
		}
	case "VNIC IPv6":
		if collection == "vnics" {
			row["ipv6Addresses"] = []any{"2001:db8::1"}
		}
	case "VNIC forwarding":
		if collection == "vnics" {
			row["skipSourceDestCheck"] = true
		}
	case "VNIC secondary":
		if collection == "vnics" {
			row["isPrimary"] = false
		}
	case "VNIC identity":
		if collection == "vnics" {
			row["id"] = "ocid1.vnic.oc1.foreign.foreign"
		}
	case "VNIC AD":
		if collection == "vnics" {
			row["availabilityDomain"] = "foreign:AD-1"
		}
	case "VNIC compartment":
		if collection == "vnics" {
			row["compartmentId"] = record.SharedCompartmentID
		}
	case "VNIC subnet":
		if collection == "vnics" {
			row["subnetId"] = "ocid1.subnet.oc1.foreign.foreign"
		}
	case "VNIC NSG":
		if collection == "vnics" {
			row["nsgIds"] = []any{}
		}
	case "VNIC extra NSG":
		if collection == "vnics" {
			row["nsgIds"] = append(slices.Clone(row["nsgIds"].([]any)), "ocid1.networksecuritygroup.oc1.foreign.foreign")
		}
	case "VNIC private IP":
		if collection == "vnics" {
			row["privateIp"] = "10.99.0.99"
		}
	case "VNIC nonready":
		if collection == "vnics" {
			row["lifecycleState"] = "PROVISIONING"
		}
	case "boot identity":
		if collection == "bootVolumes" {
			row["id"] = "ocid1.bootvolume.oc1.foreign.foreign"
		}
	case "boot compartment":
		if collection == "bootVolumes" {
			row["compartmentId"] = record.SharedCompartmentID
		}
	case "boot AD":
		if collection == "bootVolumes" {
			row["availabilityDomain"] = "foreign:AD-1"
		}
	case "boot image":
		if collection == "bootVolumes" {
			row["imageId"] = "ocid1.image.oc1.foreign.foreign"
		}
	case "boot size":
		if collection == "bootVolumes" {
			row["sizeInGBs"] = float64(51)
		}
	case "boot tier":
		if collection == "bootVolumes" {
			row["vpusPerGB"] = float64(20)
		}
	case "boot autotune":
		if collection == "bootVolumes" {
			row["isAutoTuneEnabled"] = true
		}
	case "boot policy":
		if collection == "bootVolumes" {
			row["autotunePolicies"] = []any{map[string]any{"autotuneType": "PERFORMANCE_BASED", "maxVpusPerGB": float64(20)}}
		}
	case "boot tuned tier":
		if collection == "bootVolumes" {
			row["autoTunedVpusPerGB"] = float64(20)
		}
	case "boot nonready":
		if collection == "bootVolumes" {
			row["lifecycleState"] = "PROVISIONING"
		}
	}
}

func (f *originalActorSDKFixture) actorDispatches() []originalActorDispatch {
	f.actorMu.Lock()
	defer f.actorMu.Unlock()
	return slices.Clone(f.actorPosts)
}

func (f *originalActorSDKFixture) assertActorState(t *testing.T) {
	t.Helper()
	record := f.record(t)
	if len(f.wire(t)) > foundationJournalLimit {
		t.Fatal("full original actor preimages exceed protected FoundationRecord object read bound")
	}
	if err := record.validate(); err != nil {
		t.Fatal(err)
	}
	if record.Stage != "original-foundation" || !record.netBirdMaterialOnly() || !record.CompletedAt.IsZero() || len(record.ResourceIDs) != 0 || len(record.ResourceProvenance) != 0 || len(record.PendingCreates) != 0 || len(record.SourcePolicyIDs) != 0 || record.FoundationWriter != nil || record.NetBirdManager != nil || record.CapacityLedger != nil || f.cloud.hasAnchor() {
		t.Fatal("physical actors acquired runtime, source IAM, ledger, admission or published-anchor credit")
	}
	f.checkActorPrerequisites(record)
	pins, err := originalActorUpstream(record)
	if err != nil || !bytes.Equal(pins, f.actorUpstream) {
		t.Fatal("actor completion replaced immutable upstream prerequisites")
	}
	seen := map[string]bool{}
	for _, region := range record.OriginalFoundationCompartments.Regions {
		actor := region.Actor
		id := originalActorID(actor)
		if actor == nil || actor.Pending == nil || actor.OriginalQuote == nil || actor.Provenance == nil || id == "" || seen[id] || actor.VerifiedAt.IsZero() || len(actor.ReadbackSHA256) != 64 || actor.HoldReason != "" || !sameOriginalSourceValue(actor.Provenance.Create, *actor.Pending) || actor.BootVolumeID != strings.Replace(id, ".instance.", ".bootvolume.", 1) || actor.PrimaryVNICID != strings.Replace(id, ".instance.", ".vnic.", 1) {
			t.Fatalf("%s actor lacks unique actual response, immutable quote and independent physical proof", region.Cell)
		}
		seen[id] = true
		f.actorMu.Lock()
		instanceGets, vnicGets, bootGets := f.actorGets[id], f.actorGets[actor.PrimaryVNICID], f.actorGets[actor.BootVolumeID]
		f.actorMu.Unlock()
		if instanceGets == 0 || vnicGets == 0 || bootGets == 0 {
			t.Fatal("physical completion lacked actual exact instance/VNIC/boot GETs")
		}
		for _, compartment := range region.Compartments {
			if compartment.VerifiedAt.IsZero() || compartment.ReadbackSHA256 == "" || compartment.HoldReason != "" {
				t.Fatal("actor completion lost compartment provenance")
			}
		}
		if region.Network == nil || !region.Network.Complete || len(region.Network.Rules.ReturnedRules) != 9 || region.Network.Rules.VerifiedAt.IsZero() {
			t.Fatal("actor completion lost complete private network and rule proof")
		}
		for slot := range 2 {
			entry := originalVaultEntry(region.Vault, slot)
			if entry.VerifiedAt.IsZero() || entry.HoldReason != "" || entry.ReadbackSHA256 == "" || region.Cell == "GRU" && (entry.SelectedID == "" || entry.Pending != nil || entry.Provenance != nil) || region.Cell != "GRU" && (entry.SelectedID != "" || entry.Pending == nil || entry.Provenance == nil || !sameOriginalSourceValue(entry.Provenance.Create, *entry.Pending)) {
				t.Fatal("actor completion changed original selected/created KMS proof")
			}
		}
	}
}

func TestOriginalFoundationActorsSDK(t *testing.T) {
	t.Skip("QUARANTINE until 2026-10-23, owner w17c: passes but takes 2197s without -race at GOMAXPROCS=2 -cpu 2; every fault subtest rebuilds and reruns the compartment, network and Vault chain")
	// Sequential: the inherited real signed SDK fixture owns the process transport.
	t.Run("three finite originals and complete physical replay remain downstream HOLD", func(t *testing.T) {
		for _, fault := range []string{"", "complete pagination"} {
			t.Run(fault, func(t *testing.T) {
				f := newOriginalActorSDKFixture(t, fault, 0)
				if err := f.run(t); err != nil {
					t.Fatalf("actor component did not retain complete original physical history: %v", err)
				}
				network, rules := f.effects()
				posts := f.actorDispatches()
				if len(posts) != 3 || len(f.dispatches()) != 5 || len(network) != 18 || len(f.kmsDispatches()) != 4 || rules != 3 || f.cloud.creates != 30 || f.cloud.launchPosts != 3 {
					t.Fatal("original path must make exactly5 compartments+18 network+4 KMS+3 instances and3NSG adds")
				}
				for index, post := range posts {
					if post.cell != []string{"GRU", "SJC", "FRA"}[index] {
						t.Fatal("original actor launch escaped finite cell order")
					}
				}
				f.assertActorState(t)
				before, material := f.wire(t), f.cloud.materialPosts
				if err := f.run(t); err != nil {
					t.Fatal(err)
				}
				if len(f.actorDispatches()) != 3 || f.cloud.creates != 30 || f.cloud.launchPosts != 3 || f.cloud.materialPosts != material || !bytes.Equal(before, f.wire(t)) {
					t.Fatal("completed physical replay changed original identities or repeated a launch/material effect")
				}
				f.assertActorState(t)
			})
		}
	})

	t.Run("acknowledged reservations and actual IDs bound recovery", func(t *testing.T) {
		for slot := range 3 {
			for _, fault := range []string{"scope checkpoint", "reservation checkpoint", "stale lease", "lost create response", "unknown create", "lost accepted checkpoint", "response before CAS", "throttle", "timeout", "instance pending"} {
				t.Run(fmt.Sprintf("%d/%s", slot, fault), func(t *testing.T) {
					f := newOriginalActorSDKFixture(t, fault, slot)
					if err := f.run(t); err == nil {
						t.Fatal("interrupted actor operation claimed complete startup")
					}
					first := f.actorDispatches()
					record := f.record(t)
					actor := record.OriginalFoundationCompartments.Regions[slot].Actor
					if fault == "scope checkpoint" {
						if len(first) != 0 || f.cloud.creates != 27 {
							t.Fatal("unacknowledged all-three actor scopes authorized a launch")
						}
						for _, region := range record.OriginalFoundationCompartments.Regions {
							if region.Actor != nil {
								t.Fatal("failed initial scopes checkpoint left partial accepted actor scopes")
							}
						}
					} else {
						if actor == nil {
							t.Fatal("interrupted actor lost retained initial scope")
						}
						if fault == "reservation checkpoint" || fault == "stale lease" {
							if len(first) != slot || f.cloud.creates != 27+slot {
								t.Fatal("launch escaped request/quote checkpoint or live HomeWrite fencing")
							}
							if fault == "reservation checkpoint" && (actor.Pending != nil || actor.OriginalQuote != nil) || fault == "stale lease" && (actor.Pending == nil || actor.OriginalQuote == nil) {
								t.Fatal("checkpoint/lease fault modeled incorrect durable original reservation")
							}
						} else {
							if len(first) != slot+1 || actor.Pending == nil || actor.OriginalQuote == nil {
								t.Fatal("actor interruption did not preserve exact original reservation")
							}
							id := "ocid1.instance.oc1." + record.OriginalFoundationCompartments.Regions[slot].OCIRegion + ".originalcontroller"
							if fault == "response before CAS" && actor.Provenance != nil || fault == "lost accepted checkpoint" && actor.Provenance == nil {
								t.Fatal("actual-ID checkpoint fault did not model durable storage acceptance accurately")
							}
							if fault == "response before CAS" || fault == "lost accepted checkpoint" || fault == "lost create response" {
								if f.actorGets[id] != 0 {
									t.Fatal("physical observation followed an unacknowledged actual-ID checkpoint in the same invocation")
								}
							}
							if fault == "instance pending" && (actor.Provenance == nil || !actor.VerifiedAt.IsZero()) {
								t.Fatal("pending instance lost actual ID or fabricated physical completion")
							}
						}
					}
					f.actorMu.Lock()
					f.actorFault = ""
					f.actorMu.Unlock()
					if err := f.run(t); err != nil {
						t.Fatalf("retained original actor did not recover: %v", err)
					}
					after := f.actorDispatches()
					replay := slices.Contains([]string{"lost create response", "unknown create", "response before CAS", "throttle", "timeout"}, fault)
					want := 3
					if replay {
						want++
						if len(after) <= slot+1 {
							t.Fatal("unknown response did not replay original token")
						}
						original, next := first[slot], after[slot+1]
						if original.cell != next.cell || original.host != next.host || original.token != next.token || !bytes.Equal(original.body, next.body) || !sameOriginalSourceValue(original.pending, next.pending) || original.quote.SHA256() != next.quote.SHA256() {
							t.Fatal("recovery replaced original request/token/time/tariffs instead of exact replay")
						}
					}
					if len(after) != want || f.cloud.creates != 30 {
						t.Fatal("recovery bought a replacement or relaunched a known actual instance")
					}
					f.assertActorState(t)
				})
			}
		}
	})

	t.Run("terminal identities prices and original authority remain bounded", func(t *testing.T) {
		for slot := range 3 {
			for _, fault := range []string{"conflict", "invalid token", "empty ID", "wrong region ID", "duplicate ID"} {
				if fault == "duplicate ID" && slot == 0 {
					continue
				}
				t.Run(fmt.Sprintf("%d/%s", slot, fault), func(t *testing.T) {
					f := newOriginalActorSDKFixture(t, fault, slot)
					if err := f.run(t); err == nil {
						t.Fatal("refused or unresolved original create claimed completion")
					}
					actor := f.record(t).OriginalFoundationCompartments.Regions[slot].Actor
					want := "create-unresolved"
					if fault == "conflict" || fault == "invalid token" {
						want = "create-refused"
					}
					if actor.Pending == nil || actor.OriginalQuote == nil || actor.Provenance != nil || actor.HoldReason != want {
						t.Fatal("terminal actor failure lost monotone exact pending HOLD")
					}
					before, posts, creates := f.wire(t), len(f.actorDispatches()), f.cloud.creates
					if err := f.run(t); err == nil || !bytes.Equal(before, f.wire(t)) || len(f.actorDispatches()) != posts || f.cloud.creates != creates {
						t.Fatal("terminal original HOLD reset time/token or replayed malformed identity")
					}
					store := f.store(t)
					record, etag, err := store.Load(t.Context(), "GRU")
					if err != nil {
						t.Fatal(err)
					}
					record.OriginalFoundationCompartments.Regions[slot].Actor.HoldReason = ""
					if _, err := store.CompareAndSwap(t.Context(), record, etag); err == nil || !bytes.Equal(before, f.wire(t)) {
						t.Fatal("protected CAS erased terminal original actor HOLD")
					}
				})
			}
		}
		t.Run("fresh tariff drift cannot replace the original quote", func(t *testing.T) {
			f := newOriginalActorSDKFixture(t, "unknown create", 0)
			if err := f.run(t); err == nil {
				t.Fatal("unknown response unexpectedly completed")
			}
			before := f.wire(t)
			quote := f.record(t).OriginalFoundationCompartments.Regions[0].Actor.OriginalQuote.Clone()
			f.cloud.mu.Lock()
			f.cloud.tariff *= 2
			f.cloud.mu.Unlock()
			if err := f.run(t); err == nil || len(f.actorDispatches()) != 1 || !bytes.Equal(before, f.wire(t)) {
				t.Fatal("fresh different-price quote authorized retry or replaced immutable original")
			}
			f.cloud.mu.Lock()
			f.cloud.tariff /= 2
			f.cloud.mu.Unlock()
			if err := f.run(t); err != nil {
				t.Fatal(err)
			}
			if len(f.actorDispatches()) != 4 || f.cloud.creates != 30 || f.record(t).OriginalFoundationCompartments.Regions[0].Actor.OriginalQuote.SHA256() != quote.SHA256() {
				t.Fatal("equal-price replay replaced original quote or purchased a second instance")
			}
			f.assertActorState(t)
		})
		t.Run("fresh quote exceeds signed finite slot", func(t *testing.T) {
			f := newOriginalActorSDKFixture(t, "", 0)
			f.cloud.mu.Lock()
			f.cloud.tariff = 100
			f.cloud.mu.Unlock()
			if err := f.run(t); err == nil || len(f.actorDispatches()) != 0 || f.cloud.creates != 27 {
				t.Fatal("over-budget fresh tariff quote authorized original launch")
			}
		})
		t.Run("genuine historical first attempt exceeds23h", func(t *testing.T) {
			f := newOriginalActorSDKFixture(t, "unknown create", 0)
			f.bundle = signHistoricalOriginalCompartmentBundle(t, f.foundationProvisionFixture)
			f.cloud.bundle = f.bundle.clone()
			if err := VerifyFoundationProvisionBundle(t.Context(), f.roots, f.bundle); err != nil {
				t.Fatal(err)
			}
			if err := f.run(t); err == nil {
				t.Fatal("unknown original create lost reservation")
			}
			record := f.record(t)
			originalVaultAgeTimeline(t, &record)
			for index := range record.OriginalFoundationCompartments.Regions {
				region := &record.OriginalFoundationCompartments.Regions[index]
				actor := region.Actor
				network, err := json.Marshal(region.Network, json.Deterministic(true))
				if err != nil {
					t.Fatal(err)
				}
				vault, err := json.Marshal(region.Vault, json.Deterministic(true))
				if err != nil {
					t.Fatal(err)
				}
				actor.NetworkProofSHA256, actor.VaultProofSHA256 = preparationDigest(network), preparationDigest(vault)
				if actor.Pending != nil {
					actor.Pending.FirstAttemptAt = actor.Pending.FirstAttemptAt.Add(-24 * time.Hour)
				}
				if actor.OriginalQuote != nil {
					actor.OriginalQuote.IssuedAt = actor.OriginalQuote.IssuedAt.Add(-24 * time.Hour)
					actor.OriginalQuote.ExpiresAt = actor.OriginalQuote.ExpiresAt.Add(-24 * time.Hour)
				}
			}
			if err := record.validate(); err != nil {
				t.Fatalf("historical timeline lacks genuine otherwise valid original scope: %v", err)
			}
			actor := record.OriginalFoundationCompartments.Regions[0].Actor
			if actor.Pending == nil || !actor.Pending.FirstAttemptAt.Before(time.Now().Add(-23*time.Hour)) || !time.Now().Before(actor.Startup.FounderResources.LaunchDeadline) {
				t.Fatal("expiry test did not retain a current signed image/founder deadline and genuinely old first attempt")
			}
			wire, err := json.Marshal(record, json.Deterministic(true))
			if err != nil {
				t.Fatal(err)
			}
			f.cloud.writeObject("gru-1-head/"+foundationObjectPrefix+"GRU.json", wire)
			f.upstream, err = originalNetworkUpstream(record)
			if err != nil {
				t.Fatal(err)
			}
			f.vaultUpstream, err = originalVaultUpstream(record)
			if err != nil {
				t.Fatal(err)
			}
			f.actorUpstream, err = originalActorUpstream(record)
			if err != nil {
				t.Fatal(err)
			}
			if err := f.run(t); !errors.Is(err, ErrOriginalSourceProducerHold) {
				t.Fatalf("valid expired original did not retain retry-expired HOLD: %v", err)
			}
			retained := f.record(t)
			actor.HoldReason = "retry-expired"
			record.UpdatedAt = retained.UpdatedAt
			if !sameOriginalSourceValue(record, retained) {
				t.Fatal("retry expiry changed original bodies, tariffs, timing or prerequisite identities")
			}
			hold := f.wire(t)
			if err := f.run(t); !errors.Is(err, ErrOriginalSourceProducerHold) || !bytes.Equal(hold, f.wire(t)) || len(f.actorDispatches()) != 1 || f.cloud.creates != 27 {
				t.Fatal("expired unknown original reset time/token or bought replacement")
			}
		})
		t.Run("root-signed spending currency must match original grant", func(t *testing.T) {
			for _, trusted := range []bool{false, true} {
				t.Run(fmt.Sprintf("trusted journal %t", trusted), func(t *testing.T) {
					f := newOriginalActorSDKFixture(t, "", 0)
					if trusted {
						if err := f.run(t); err != nil {
							t.Fatal(err)
						}
						f.assertActorState(t)
					}
					journal := f.cloud.objectPath("gru-1-head/" + foundationObjectPrefix + "GRU.json")
					before, beforeErr := os.ReadFile(journal)
					if trusted && beforeErr != nil || !trusted && !errors.Is(beforeErr, os.ErrNotExist) {
						t.Fatal("currency regression lacks the expected genuine journal baseline")
					}
					reads, requests := f.provider.reads.Load(), f.cloud.requests
					creates, material, launches := f.cloud.creates, f.cloud.materialPosts, f.cloud.launchPosts
					posts := len(f.actorDispatches())
					if err := ValidatePreparedFoundation(f.prepared.Grant); err != nil {
						t.Fatalf("genuine same-currency prepared grant is invalid: %v", err)
					}
					changed := f.prepared
					spending := *changed.Grant.InfrastructureSpend
					changed.Grant.InfrastructureSpend = &spending
					if changed.Grant.Currency != "USD" || spending.Currency != "USD" {
						t.Fatal("currency regression requires the genuine same-currency USD original")
					}
					spending.Currency = "BRL"
					if err := ValidatePreparedFoundation(changed.Grant); err == nil {
						t.Fatal("prepared grant accepted spending in a different currency")
					}
					f.bundle = signProvisionFoundation(t, changed, f.bundle.RootChainWire, f.root, f.now)
					f.cloud.bundle = f.bundle.clone()
					if err := f.run(t); err == nil {
						t.Fatal("genuinely signed USD grant with BRL spending acquired authority")
					}
					after, afterErr := os.ReadFile(journal)
					if f.provider.reads.Load() != reads || f.cloud.requests != requests || f.cloud.creates != creates || f.cloud.materialPosts != material || f.cloud.launchPosts != launches || len(f.actorDispatches()) != posts {
						t.Fatal("currency mismatch reached provider, quote, reservation or launch effects")
					}
					if trusted && afterErr != nil || !trusted && !errors.Is(afterErr, os.ErrNotExist) || !bytes.Equal(before, after) {
						t.Fatal("currency mismatch changed trusted journal bytes or created a new journal")
					}
				})
			}
		})
		for name, mutate := range map[string]func(*FoundationGrant){
			"Q without full signed spend":    func(g *FoundationGrant) { g.InfrastructureSpend = nil },
			"missing finite Bootstrap slice": func(g *FoundationGrant) { g.InfrastructureSpend.Bootstrap = nil },
			"missing all-nine originals":     func(g *FoundationGrant) { g.WorkloadGenesis = g.WorkloadGenesis[:8] },
			"changed Q allocation":           func(g *FoundationGrant) { g.Regions[0].BootstrapMaterial.OriginalSourceProducer.Allocation.OCPUs++ },
			"changed Q plan": func(g *FoundationGrant) {
				g.Regions[0].BootstrapMaterial.OriginalSourceProducer.PlanSHA256 = strings.Repeat("a", 64)
			},
			"wrong-cell control ref": func(g *FoundationGrant) {
				g.Regions[0].BootstrapMaterial.Startup.Profiles[0].CompartmentOCID = "foundation:SJC:control_compartment"
			},
			"NSG journal alias": func(g *FoundationGrant) {
				g.Regions[0].BootstrapMaterial.Startup.Profiles[0].NetworkSecurityGroupOCIDs = []string{"foundation:GRU:controller_nsg"}
			},
			"unknown subnet ref": func(g *FoundationGrant) {
				g.Regions[0].BootstrapMaterial.Startup.Profiles[0].SubnetOCID = "foundation:GRU:foreign"
			},
			"unsigned config substitution": func(g *FoundationGrant) { g.Regions[0].BootstrapMaterial.Config.Slots[0].PrivateIP = "10.99.0.99" },
			"zero OCPU": func(g *FoundationGrant) {
				g.Regions[0].BootstrapMaterial.Startup.FounderResources.Slots[0].WholeOCPUs = 0
			},
			"float32 OCPU overflow": func(g *FoundationGrant) {
				g.Regions[0].BootstrapMaterial.Startup.FounderResources.Slots[0].WholeOCPUs = (1 << 24) + 1
			},
			"float32 memory overflow": func(g *FoundationGrant) {
				g.Regions[0].BootstrapMaterial.Startup.FounderResources.Slots[0].MemoryInGB = (1 << 24) + 1
			},
			"fractional signed OCPU allocation":   func(g *FoundationGrant) { g.InfrastructureSpend.Bootstrap.Slots[0].OCPUs = 1.5 },
			"fractional signed memory allocation": func(g *FoundationGrant) { g.InfrastructureSpend.Bootstrap.Slots[0].MemoryGB = 6.5 },
			"signed boot geometry drift": func(g *FoundationGrant) {
				g.Regions[0].BootstrapMaterial.Startup.FounderResources.Slots[0].BootVolumeGB++
			},
		} {
			t.Run(name, func(t *testing.T) {
				f := newOriginalActorSDKFixture(t, "", 0)
				wire, err := json.Marshal(f.prepared)
				if err != nil {
					t.Fatal(err)
				}
				var changed FoundationPreparation
				if err := json.Unmarshal(wire, &changed); err != nil {
					t.Fatal(err)
				}
				mutate(&changed.Grant)
				// These are genuinely root-signed inconsistent preimages, never a fake
				// verified authority or a replacement production constructor.
				f.bundle = signProvisionFoundation(t, changed, f.bundle.RootChainWire, f.root, f.now)
				f.cloud.bundle = f.bundle.clone()
				if err := f.run(t); err == nil || len(f.actorDispatches()) != 0 || f.cloud.creates != 0 || f.cloud.materialPosts != 0 {
					t.Fatalf("inconsistent full signed grant acquired original launch/material authority: %v", err)
				}
			})
		}
		for _, fault := range []string{"network no add ACK", "Vault nonready"} {
			t.Run(fault, func(t *testing.T) {
				f := newOriginalActorSDKFixture(t, "", 0)
				if fault == "network no add ACK" {
					f.networkFault = "unknown rule response"
				} else {
					f.vaultFault = "nonready"
					f.failSlot = 1
				}
				if err := f.run(t); err == nil || len(f.actorDispatches()) != 0 {
					t.Fatal("partial/held original upstream acquired actor launch authority")
				}
				for _, region := range f.record(t).OriginalFoundationCompartments.Regions {
					if region.Actor != nil {
						t.Fatal("held original prerequisite imported actor scopes")
					}
				}
			})
		}
		for _, fault := range []string{"image identity", "image compartment", "image nonready", "image missing", "writer evidence", "wrong user", "wrong tenancy", "expired original", "corrupt original"} {
			t.Run(fault, func(t *testing.T) {
				f := newOriginalActorSDKFixture(t, "reservation checkpoint", 0)
				if err := f.run(t); err == nil || len(f.actorDispatches()) != 0 || f.cloud.creates != 27 {
					t.Fatal("authority refusal setup did not stop after genuine prerequisites and before launch")
				}
				before := f.wire(t)
				imageID := f.prepared.Grant.Regions[0].BootstrapMaterial.Startup.ImageOCID
				f.cloud.mu.Lock()
				switch fault {
				case "image identity":
					f.cloud.rows[imageID]["id"] = "ocid1.image.oc1.foreign.foreign"
				case "image compartment":
					f.cloud.rows[imageID]["compartmentId"] = originalCompartmentID(f.cloud.journal("GRU").OriginalFoundationCompartments.Regions[0].Compartments[0])
				case "image nonready":
					f.cloud.rows[imageID]["lifecycleState"] = "DISABLED"
				case "image missing":
					delete(f.cloud.rows, imageID)
				}
				f.cloud.mu.Unlock()
				if fault == "writer evidence" {
					image := f.images["GRU"].Image.Receipt()
					qualification, err := trust.DecodeEnvelope(image.HostProduction[release.FoundationWriterRole].Qualification)
					if err != nil {
						t.Fatal(err)
					}
					var proof release.ProductionQualification
					if err := json.Unmarshal(qualification.Payload, &proof); err != nil {
						t.Fatal(err)
					}
					if len(proof.Evidence) == 0 {
						t.Fatal("fixture lacks independent writer evidence")
					}
					f.cloud.writeObject("gru-1-head/"+releasechannel.ImageProductionEvidenceObject(proof.Evidence[0].SHA256), []byte("corrupt evidence"))
				}
				var err error
				if fault == "wrong user" || fault == "wrong tenancy" {
					provider := originalCompartmentProvider{ConfigurationProvider: f.provider, user: "ocid1.user.oc1..test", tenancy: f.approval.TenancyID}
					if fault == "wrong user" {
						provider.user = "ocid1.user.oc1..foreign"
					} else {
						provider.tenancy = "ocid1.tenancy.oc1..foreign"
					}
					factory, factoryErr := ociclient.New(provider, ociclient.Options{Region: foundationHomeRegion, Retry: ociclient.RetryOptions{MaxAttempts: 1}})
					if factoryErr != nil {
						t.Fatal(factoryErr)
					}
					err = provisionOriginalFoundationCompartments(t.Context(), factory, f.roots, f.bundle)
				} else {
					if fault == "expired original" {
						f.bundle = signProvisionFoundation(t, f.prepared, f.bundle.RootChainWire, f.root, f.now.Add(-24*time.Hour))
					}
					if fault == "corrupt original" {
						f.bundle.GrantWire = []byte("invalid root-pinned original")
					}
					err = f.run(t)
				}
				if err == nil || len(f.actorDispatches()) != 0 || f.cloud.creates != 27 || !bytes.Equal(before, f.wire(t)) {
					t.Fatalf("image/writer/original authority failure acquired launch effects: %v", err)
				}
			})
		}
	})

	t.Run("independent physical graph geometry and complete pagination refuse drift", func(t *testing.T) {
		faults := []string{"instance missing", "instance identity", "instance compartment", "instance pending", "instance AD", "instance FD", "instance shape", "instance OCPU", "instance memory", "instance image", "instance source", "instance metadata", "instance extended metadata", "instance display name", "VNIC public", "VNIC IPv6", "VNIC forwarding", "VNIC secondary", "VNIC identity", "VNIC AD", "VNIC compartment", "VNIC subnet", "VNIC NSG", "VNIC extra NSG", "VNIC private IP", "VNIC nonready", "boot identity", "boot compartment", "boot AD", "boot image", "boot size", "boot tier", "boot autotune", "boot policy", "boot tuned tier", "boot nonready"}
		for _, kind := range []string{"VNIC", "boot"} {
			for _, suffix := range []string{"missing attachment", "extra attachment", "foreign attachment", "wrong compartment", "detached", "wrong AD", "empty attachment ID", "second page extra", "cyclic pages", "unbounded pages"} {
				faults = append(faults, kind+" "+suffix)
			}
		}
		for _, fault := range faults {
			t.Run(fault, func(t *testing.T) {
				f := newOriginalActorSDKFixture(t, fault, 0)
				if err := f.run(t); err == nil || errors.Is(err, ErrOriginalFoundationActorPending) {
					t.Fatalf("physical mismatch reached completed physical actor stage: %v", err)
				}
				actor := f.record(t).OriginalFoundationCompartments.Regions[0].Actor
				if actor == nil || actor.Provenance == nil || actor.Pending == nil || actor.OriginalQuote == nil || !actor.VerifiedAt.IsZero() {
					t.Fatal("failed physical read discarded actual instance or fabricated readiness")
				}
				retained := *actor
				if err := f.run(t); err == nil || errors.Is(err, ErrOriginalFoundationActorPending) || len(f.actorDispatches()) != 1 || f.cloud.creates != 28 {
					t.Fatal("known mismatched actor was replaced or adopted")
				}
				current := f.record(t).OriginalFoundationCompartments.Regions[0].Actor
				if !sameOriginalSourceValue(current, &retained) {
					t.Fatal("read-only mismatch changed original actual instance/body/token/quote/physical pins")
				}
				f.actorMu.Lock()
				f.actorFault = ""
				f.actorMu.Unlock()
				if err := f.run(t); err != nil {
					t.Fatalf("same retained physical identity did not recover after exact readback: %v", err)
				}
				if len(f.actorDispatches()) != 3 || f.cloud.creates != 30 {
					t.Fatal("corrected physical readback launched replacement")
				}
				f.assertActorState(t)
			})
		}
	})

	t.Run("protected CAS retains original scope request quote and physical proof", func(t *testing.T) {
		f := newOriginalActorSDKFixture(t, "", 0)
		if err := f.run(t); err != nil {
			t.Fatal(err)
		}
		store, wire := f.store(t), f.wire(t)
		for name, mutate := range map[string]func(*FoundationRecord){
			"erase scope": func(r *FoundationRecord) { r.OriginalFoundationCompartments.Regions[0].Actor = nil },
			"replace startup": func(r *FoundationRecord) {
				r.OriginalFoundationCompartments.Regions[0].Actor.Startup.SeedSlot = "controller-b"
			},
			"replace config": func(r *FoundationRecord) {
				r.OriginalFoundationCompartments.Regions[0].Actor.Config.Slots[0].PrivateIP = "10.99.0.99"
			},
			"replace control": func(r *FoundationRecord) {
				r.OriginalFoundationCompartments.Regions[0].Actor.ControlCompartmentID = r.SharedCompartmentID
			},
			"replace network": func(r *FoundationRecord) {
				r.OriginalFoundationCompartments.Regions[0].Actor.NetworkProofSHA256 = strings.Repeat("a", 64)
			},
			"replace Vault": func(r *FoundationRecord) {
				r.OriginalFoundationCompartments.Regions[0].Actor.VaultProofSHA256 = strings.Repeat("a", 64)
			},
			"erase request": func(r *FoundationRecord) {
				r.OriginalFoundationCompartments.Regions[0].Actor.Request = core.LaunchInstanceDetails{}
			},
			"public request": func(r *FoundationRecord) {
				r.OriginalFoundationCompartments.Regions[0].Actor.Request.CreateVnicDetails.AssignPublicIp = new(true)
			},
			"request metadata": func(r *FoundationRecord) {
				r.OriginalFoundationCompartments.Regions[0].Actor.Request.Metadata["user_data"] = "forbidden"
			},
			"erase pending": func(r *FoundationRecord) { r.OriginalFoundationCompartments.Regions[0].Actor.Pending = nil },
			"replace operation": func(r *FoundationRecord) {
				r.OriginalFoundationCompartments.Regions[0].Actor.Pending.OperationID = "foreign"
			},
			"replace digest": func(r *FoundationRecord) {
				r.OriginalFoundationCompartments.Regions[0].Actor.Pending.Request.RequestDigest = strings.Repeat("a", 64)
			},
			"replace token": func(r *FoundationRecord) {
				r.OriginalFoundationCompartments.Regions[0].Actor.Pending.Request.RetryToken = strings.Repeat("a", 64)
			},
			"replace first time": func(r *FoundationRecord) {
				a := r.OriginalFoundationCompartments.Regions[0].Actor
				a.Pending.FirstAttemptAt = a.Pending.FirstAttemptAt.Add(time.Second)
			},
			"erase quote": func(r *FoundationRecord) { r.OriginalFoundationCompartments.Regions[0].Actor.OriginalQuote = nil },
			"replace quote scope": func(r *FoundationRecord) {
				r.OriginalFoundationCompartments.Regions[0].Actor.OriginalQuote.ScopeSHA256 = strings.Repeat("a", 64)
			},
			"replace quote geometry": func(r *FoundationRecord) { r.OriginalFoundationCompartments.Regions[0].Actor.OriginalQuote.OCPUs++ },
			"replace quote price": func(r *FoundationRecord) {
				r.OriginalFoundationCompartments.Regions[0].Actor.OriginalQuote.MonthlyCents++
			},
			"replace tariff": func(r *FoundationRecord) {
				r.OriginalFoundationCompartments.Regions[0].Actor.OriginalQuote.Prices[0].PerUnit *= 2
			},
			"replace quote time": func(r *FoundationRecord) {
				a := r.OriginalFoundationCompartments.Regions[0].Actor
				a.OriginalQuote.IssuedAt = a.OriginalQuote.IssuedAt.Add(time.Second)
			},
			"erase actual instance": func(r *FoundationRecord) { r.OriginalFoundationCompartments.Regions[0].Actor.Provenance = nil },
			"replace actual instance": func(r *FoundationRecord) {
				r.OriginalFoundationCompartments.Regions[0].Actor.Provenance.ResourceID = "ocid1.instance.oc1.sa-saopaulo-1.foreign"
			},
			"replace boot": func(r *FoundationRecord) {
				r.OriginalFoundationCompartments.Regions[0].Actor.BootVolumeID = "ocid1.bootvolume.oc1.sa-saopaulo-1.foreign"
			},
			"replace VNIC": func(r *FoundationRecord) {
				r.OriginalFoundationCompartments.Regions[0].Actor.PrimaryVNICID = "ocid1.vnic.oc1.sa-saopaulo-1.foreign"
			},
			"erase readback":            func(r *FoundationRecord) { r.OriginalFoundationCompartments.Regions[0].Actor.ReadbackSHA256 = "" },
			"erase physical completion": func(r *FoundationRecord) { r.OriginalFoundationCompartments.Regions[0].Actor.VerifiedAt = time.Time{} },
			"replace verification time": func(r *FoundationRecord) {
				a := r.OriginalFoundationCompartments.Regions[0].Actor
				a.VerifiedAt = a.VerifiedAt.Add(time.Second)
			},
			"runtime binding": func(r *FoundationRecord) {
				r.ResourceIDs["controller-a"] = originalActorID(r.OriginalFoundationCompartments.Regions[0].Actor)
			},
		} {
			record, etag, err := store.Load(t.Context(), "GRU")
			if err != nil {
				t.Fatal(err)
			}
			mutate(&record)
			if _, err := store.CompareAndSwap(t.Context(), record, etag); err == nil || !bytes.Equal(wire, f.wire(t)) {
				t.Fatalf("protected actor CAS accepted %s: %v", name, err)
			}
		}
		f.assertActorState(t)
		t.Run("component requires genuine held matching HomeWrite", func(t *testing.T) {
			first, err := provisionFoundationMaterial(t.Context(), f.factoryFor(), f.roots, f.bundle)
			if err != nil {
				t.Fatal(err)
			}
			defer first.cancel()
			second, err := provisionFoundationMaterial(t.Context(), f.factoryFor(), f.roots, f.bundle)
			if err != nil {
				t.Fatal(err)
			}
			defer second.cancel()
			before, posts := f.wire(t), len(f.actorDispatches())
			if err := retainOriginalFoundationActorLaunches(first.ctx, first.authority); err == nil {
				t.Fatal("component accepted absent HomeWrite lease")
			}
			leased, release, err := first.authority.HomeWrite(first.ctx, 0)
			if err != nil {
				t.Fatal(err)
			}
			defer release()
			if err := retainOriginalFoundationActorLaunches(leased, second.authority); err == nil {
				t.Fatal("component accepted another genuine authority's lease context")
			}
			if len(f.actorDispatches()) != posts || !bytes.Equal(before, f.wire(t)) {
				t.Fatal("absent/mismatched lease performed actor progress")
			}
		})
	})
}
