package oci

import (
	"context"
	"encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"maps"
	"net/http"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"
)

// These records belong to the HTTPS service, never to the Provider interface.
type memberSDKVolume struct {
	ID, CompartmentID, AvailabilityDomain, LifecycleState, ETag string
	SizeGB, VPUsPerGB int64
	FreeformTags map[string]string
}

type memberSDKInstance struct {
	ID, DisplayName, CompartmentID, AvailabilityDomain, LifecycleState, ETag string
	ConsistentVolumeNamingEnabled *bool
}

type memberSDKAttachment struct {
	ID, VolumeID, InstanceID, LifecycleState, ETag, Device string
	IsReadOnly, IsShareable, IsPvEncryptionInTransitEnabled *bool
}

type memberSDKDevice struct { Name string; IsAvailable *bool }
type memberSDKBackup struct {
	ID, VolumeID, LifecycleState string
	SizeGB int64
	CreatedAt time.Time
}
type memberSDKPolicy struct {
	ID, DisplayName string
	Schedules []BackupSchedule
	FreeformTags map[string]string
}

type memberSDKLedger struct {
	mu sync.Mutex
	t *testing.T
	config RegionConfig
	instances map[string]memberSDKInstance
	volumes map[string]memberSDKVolume
	attachments map[string]memberSDKAttachment
	devices map[string][]memberSDKDevice
	volumeBackups []memberSDKBackup
	backupPolicies []memberSDKPolicy
	backupPolicyAssignments map[string]string
	volumeRetryTokens, attachmentRetryTokens, backupPolicyRetryTokens map[string]string
	volumeCreateRequests []VolumeCreateRequest
	volumeCreateCalls, volumeCreates, attachCalls, deviceListCalls int
	backupPolicyCreates, updates, detaches, deletes, writes int
	afterVolumeCreate func()
	volumeCreateErrorAfterCreate, updateErr, detachErr error
	updateApplies, stayBusy bool
}

// The transport only synchronizes test edits with the real HTTPS handler.
type memberSDKTransport struct { ledger *memberSDKLedger; next http.RoundTripper }

func (transport memberSDKTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	transport.ledger.mu.Lock()
	transport.ledger.mu.Unlock()
	response, err := transport.next.RoundTrip(request)
	transport.ledger.mu.Lock()
	transport.ledger.mu.Unlock()
	return response, err
}

func memberSDKFixture(t *testing.T) (*MemberVolumes, *memberSDKLedger) {
	t.Helper()
	config := testMemberVolumeConfig()
	region, err := config.regionConfig()
	if err != nil { t.Fatal(err) }
	ledger := &memberSDKLedger{t: t, config: region,
		instances: make(map[string]memberSDKInstance), volumes: make(map[string]memberSDKVolume),
		attachments: make(map[string]memberSDKAttachment), devices: make(map[string][]memberSDKDevice),
		backupPolicyAssignments: make(map[string]string), volumeRetryTokens: make(map[string]string),
		attachmentRetryTokens: make(map[string]string), backupPolicyRetryTokens: make(map[string]string)}
	provider, _ := sdkSocketProvider(t, region, ledger)
	client := provider.storage.HTTPClient.(*http.Client)
	client.Transport = memberSDKTransport{ledger: ledger, next: client.Transport}
	volumes, err := newMemberVolumes(config, memberVolumeProvider{provider})
	if err != nil { t.Fatal(err) }
	volumes.fleet.attachmentSettle = 50 * time.Millisecond
	volumes.restoreSettle = 50 * time.Millisecond
	return volumes, ledger
}

func memberSDKAddInstance(p *memberSDKLedger, id, name string) memberSDKInstance {
	instance := memberSDKInstance{ID: id, DisplayName: name, CompartmentID: p.config.CompartmentID,
		AvailabilityDomain: p.config.AvailabilityDomain, LifecycleState: "RUNNING", ETag: "instance-etag",
		ConsistentVolumeNamingEnabled: new(true)}
	p.instances[id] = instance
	return instance
}

func memberSDKOnlyVolume(t *testing.T, p *memberSDKLedger) memberSDKVolume {
	t.Helper()
	if len(p.volumes) != 1 { t.Fatalf("volumes = %d, want 1", len(p.volumes)) }
	for volume := range maps.Values(p.volumes) { return volume }
	return memberSDKVolume{}
}

func memberSDKSetVolumeStates(p *memberSDKLedger, from, to string) {
	for id, volume := range p.volumes {
		if volume.LifecycleState == from { volume.LifecycleState = to; p.volumes[id] = volume }
	}
}

func memberSDKSetAttachmentState(p *memberSDKLedger, id, state string) {
	attachment := p.attachments[id]
	attachment.LifecycleState = state
	p.attachments[id] = attachment
}

func memberSDKRetireFixture(t *testing.T) (*MemberVolumes, *memberSDKLedger, MemberVolumeRequest, Attachment) {
	t.Helper()
	volumes, ledger := memberSDKFixture(t)
	memberSDKAddInstance(ledger, "ocid1.instance.old", testMember)
	request := MemberVolumeRequest{Member: testMember, InstanceID: "ocid1.instance.old", SizeGB: 50}
	attachment, err := volumes.Ensure(t.Context(), request)
	if err != nil { t.Fatal(err) }
	request.VolumeID = attachment.VolumeID
	return volumes, ledger, request, attachment
}

func memberSDKRestoreFixture(t *testing.T) (*MemberVolumes, *memberSDKLedger, RestoredVolume) {
	t.Helper()
	volumes, ledger, member, _ := memberSDKRetireFixture(t)
	scratch := memberSDKAddInstance(ledger, "ocid1.instance.scratch", "gru-1-restore-drill")
	ledger.devices[scratch.ID] = []memberSDKDevice{{Name: RestoreVolumeDevice, IsAvailable: new(true)}}
	ledger.volumeBackups = []memberSDKBackup{{ID: "ocid1.volumebackup.daily", VolumeID: member.VolumeID,
		LifecycleState: "AVAILABLE", SizeGB: 50, CreatedAt: time.Now()}}
	restored, err := volumes.Restore(t.Context(), RestoreRequest{Member: testMember, ScratchInstanceID: scratch.ID, SourceVolumeID: member.VolumeID})
	if err != nil { t.Fatal(err) }
	return volumes, ledger, restored
}

func (p *memberSDKLedger) volumeWire(volume memberSDKVolume) map[string]any {
	return map[string]any{"id": volume.ID, "compartmentId": volume.CompartmentID,
		"availabilityDomain": volume.AvailabilityDomain, "sizeInGBs": volume.SizeGB,
		"vpusPerGB": volume.VPUsPerGB, "lifecycleState": volume.LifecycleState, "freeformTags": volume.FreeformTags}
}

func (p *memberSDKLedger) attachmentWire(attachment memberSDKAttachment) map[string]any {
	return map[string]any{"id": attachment.ID, "volumeId": attachment.VolumeID, "instanceId": attachment.InstanceID,
		"lifecycleState": attachment.LifecycleState, "attachmentType": "paravirtualized", "device": attachment.Device,
		"isReadOnly": attachment.IsReadOnly, "isShareable": attachment.IsShareable,
		"isPvEncryptionInTransitEnabled": attachment.IsPvEncryptionInTransitEnabled}
}

func (p *memberSDKLedger) policyWire(policy memberSDKPolicy) map[string]any {
	schedules := make([]map[string]any, 0, len(policy.Schedules))
	for _, schedule := range policy.Schedules {
		schedules = append(schedules, map[string]any{"backupType": schedule.Type, "period": schedule.Period,
			"retentionSeconds": schedule.RetentionSeconds, "offsetType": schedule.OffsetType, "hourOfDay": schedule.HourOfDay,
			"dayOfWeek": schedule.DayOfWeek, "timeZone": schedule.TimeZone})
	}
	return map[string]any{"id": policy.ID, "displayName": policy.DisplayName, "schedules": schedules, "freeformTags": policy.FreeformTags}
}

func (p *memberSDKLedger) backupWire(backup memberSDKBackup) map[string]any {
	return map[string]any{"id": backup.ID, "volumeId": backup.VolumeID, "lifecycleState": backup.LifecycleState,
		"sizeInGBs": backup.SizeGB, "timeCreated": backup.CreatedAt.UTC().Format(time.RFC3339Nano)}
}

func (p *memberSDKLedger) ServeHTTP(w http.ResponseWriter, request *http.Request) {
	p.mu.Lock()
	value, status, drop := p.exchange(request, w.Header())
	wire, err := json.Marshal(value)
	p.mu.Unlock()
	if err != nil { p.t.Error(err); http.Error(w, "encoding failed", 500); return }
	if drop {
		connection, _, err := http.NewResponseController(w).Hijack()
		if err != nil { p.t.Error(err); return }
		_ = connection.Close()
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if status != http.StatusNoContent { if _, err := w.Write(wire); err != nil { p.t.Error(err) } }
}

func (p *memberSDKLedger) exchange(r *http.Request, header http.Header) (any, int, bool) {
	if r.Method != http.MethodGet { p.writes++ }
	path := strings.TrimPrefix(r.URL.Path, "/20160918")
	query := r.URL.Query()
	fail := func(status int, code string) (any, int, bool) {
		return map[string]string{"code": code, "message": code}, status, false
	}
	decode := func(value any) bool {
		wire, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
		if err == nil { err = json.Unmarshal(wire, value) }
		if err != nil { p.t.Error(err); return false }
		return true
	}
	if r.Method == http.MethodGet {
		switch {
		case strings.HasPrefix(path, "/instances/") && strings.HasSuffix(path, "/devices"):
			id := strings.TrimSuffix(strings.TrimPrefix(path, "/instances/"), "/devices")
			p.deviceListCalls++
			if query.Get("isAvailable") != "true" { p.t.Error("device read lost availability filter") }
			devices, exists := p.devices[id]
			if !exists { devices = []memberSDKDevice{{Name: MemberVolumeDevice, IsAvailable: new(true)}} }
			wire := make([]map[string]any, 0, len(devices))
			for _, device := range devices { wire = append(wire, map[string]any{"name": device.Name, "isAvailable": device.IsAvailable}) }
			return wire, 200, false
		case strings.HasPrefix(path, "/instances/"):
			instance, exists := p.instances[strings.TrimPrefix(path, "/instances/")]
			if !exists { return fail(404, "NotAuthorizedOrNotFound") }
			header.Set("etag", instance.ETag)
			return map[string]any{"id": instance.ID, "displayName": instance.DisplayName, "compartmentId": instance.CompartmentID,
				"availabilityDomain": instance.AvailabilityDomain, "lifecycleState": instance.LifecycleState,
				"launchOptions": map[string]any{"isConsistentVolumeNamingEnabled": instance.ConsistentVolumeNamingEnabled}}, 200, false
		case path == "/volumes":
			if query.Get("compartmentId") != p.config.CompartmentID || query.Get("availabilityDomain") != p.config.AvailabilityDomain { p.t.Error("volume read widened scope") }
			wire := make([]map[string]any, 0, len(p.volumes))
			for volume := range maps.Values(p.volumes) { wire = append(wire, p.volumeWire(volume)) }
			return wire, 200, false
		case strings.HasPrefix(path, "/volumes/"):
			volume, exists := p.volumes[strings.TrimPrefix(path, "/volumes/")]
			if !exists { return fail(404, "NotAuthorizedOrNotFound") }
			header.Set("etag", volume.ETag)
			return p.volumeWire(volume), 200, false
		case path == "/volumeAttachments":
			if query.Get("compartmentId") != p.config.CompartmentID { p.t.Error("attachment read widened compartment") }
			if query.Get("volumeId") == "" && query.Get("instanceId") == "" { p.t.Error("attachment read lost exact filter") }
			if query.Get("volumeId") != "" && query.Get("availabilityDomain") != p.config.AvailabilityDomain { p.t.Error("attachment read widened domain") }
			wire := make([]map[string]any, 0, len(p.attachments))
			for attachment := range maps.Values(p.attachments) {
				if query.Get("volumeId") != "" && query.Get("volumeId") != attachment.VolumeID { continue }
				if query.Get("instanceId") != "" && query.Get("instanceId") != attachment.InstanceID { continue }
				wire = append(wire, p.attachmentWire(attachment))
			}
			return wire, 200, false
		case strings.HasPrefix(path, "/volumeAttachments/"):
			attachment, exists := p.attachments[strings.TrimPrefix(path, "/volumeAttachments/")]
			if !exists { return fail(404, "NotAuthorizedOrNotFound") }
			header.Set("etag", attachment.ETag)
			return p.attachmentWire(attachment), 200, false
		case path == "/volumeBackupPolicies":
			if query.Get("compartmentId") != p.config.CompartmentID { p.t.Error("policy read widened scope") }
			wire := make([]map[string]any, 0, len(p.backupPolicies))
			for _, policy := range p.backupPolicies { wire = append(wire, p.policyWire(policy)) }
			return wire, 200, false
		case path == "/volumeBackupPolicyAssignments":
			wire := make([]map[string]any, 0, 1)
			if id := p.backupPolicyAssignments[query.Get("assetId")]; id != "" { wire = append(wire, map[string]any{"id": "assignment", "policyId": id}) }
			return wire, 200, false
		case path == "/volumeBackups":
			if query.Get("compartmentId") != p.config.CompartmentID || query.Get("volumeId") == "" || query.Get("sortBy") != "TIMECREATED" || query.Get("sortOrder") != "DESC" { p.t.Error("backup read lost bounded source ordering") }
			wire := make([]map[string]any, 0, len(p.volumeBackups))
			for _, backup := range p.volumeBackups { if backup.VolumeID == query.Get("volumeId") { wire = append(wire, p.backupWire(backup)) } }
			return wire, 200, false
		case strings.HasPrefix(path, "/volumeBackups/"):
			for _, backup := range p.volumeBackups { if backup.ID == strings.TrimPrefix(path, "/volumeBackups/") { return p.backupWire(backup), 200, false } }
			return fail(404, "NotAuthorizedOrNotFound")
		}
	}
	if r.Method == http.MethodPost {
		token := r.Header.Get("opc-retry-token")
		switch path {
		case "/volumes":
			p.volumeCreateCalls++
			var details struct {
				Name string `json:"displayName"`
				Compartment string `json:"compartmentId"`
				Domain string `json:"availabilityDomain"`
				Size int64 `json:"sizeInGBs"`
				Tier int64 `json:"vpusPerGB"`
				Tags map[string]string `json:"freeformTags"`
				Source struct { ID string `json:"id"`; Type string `json:"type"` } `json:"sourceDetails"`
			}
			if !decode(&details) { return fail(400, "BadRequest") }
			if token == "" || details.Compartment != p.config.CompartmentID || details.Domain != p.config.AvailabilityDomain || details.Tier != 10 { p.t.Error("create lost retry identity, scope or performance tier") }
			if details.Source.ID != "" && details.Source.Type != "volumeBackup" { p.t.Error("restore lost source backup discriminator") }
			id, replay := p.volumeRetryTokens[token]
			if !replay {
				p.volumeCreates++
				id = fmt.Sprintf("ocid1.volume.created-%d", p.volumeCreates)
				p.volumeRetryTokens[token] = id
				p.volumes[id] = memberSDKVolume{ID: id, CompartmentID: details.Compartment, AvailabilityDomain: details.Domain,
					SizeGB: details.Size, VPUsPerGB: details.Tier, LifecycleState: "AVAILABLE", ETag: "volume-etag", FreeformTags: maps.Clone(details.Tags)}
				p.volumeCreateRequests = append(p.volumeCreateRequests, VolumeCreateRequest{Name: details.Name, SizeGB: details.Size, SourceBackupID: details.Source.ID})
				if p.afterVolumeCreate != nil { p.afterVolumeCreate() }
			}
			if p.volumeCreateErrorAfterCreate != nil { return nil, 200, true }
			header.Set("etag", p.volumes[id].ETag)
			return p.volumeWire(p.volumes[id]), 200, false
		case "/volumeAttachments":
			p.attachCalls++
			var details struct {
				InstanceID string `json:"instanceId"`; VolumeID string `json:"volumeId"`; Device string `json:"device"`; Type string `json:"type"`
				ReadOnly *bool `json:"isReadOnly"`; Shareable *bool `json:"isShareable"`; Encrypted *bool `json:"isPvEncryptionInTransitEnabled"`
			}
			if !decode(&details) { return fail(400, "BadRequest") }
			if token == "" || details.Type != "paravirtualized" || details.ReadOnly == nil || *details.ReadOnly || details.Shareable == nil || *details.Shareable || details.Encrypted == nil || !*details.Encrypted { p.t.Error("attachment lost retry identity or exclusive encrypted flags") }
			if volume := p.volumes[details.VolumeID]; volume.FreeformTags[tagResource] == resourceMemberData && p.backupPolicyAssignments[details.VolumeID] == "" { p.t.Error("attachment preceded the member backup policy") }
			id, replay := p.attachmentRetryTokens[token]
			if !replay {
				id = fmt.Sprintf("attachment-%d", len(p.attachmentRetryTokens)+1)
				p.attachmentRetryTokens[token] = id
				p.attachments[id] = memberSDKAttachment{ID: id, VolumeID: details.VolumeID, InstanceID: details.InstanceID,
					Device: details.Device, LifecycleState: "ATTACHED", ETag: "attachment-etag",
					IsReadOnly: details.ReadOnly, IsShareable: details.Shareable, IsPvEncryptionInTransitEnabled: details.Encrypted}
			}
			header.Set("etag", p.attachments[id].ETag)
			return p.attachmentWire(p.attachments[id]), 200, false
		case "/volumeBackupPolicies":
			var details struct {
				Name string `json:"displayName"`; Compartment string `json:"compartmentId"`; Tags map[string]string `json:"freeformTags"`
				Schedules []struct {
					Type string `json:"backupType"`; Period string `json:"period"`; Retention int `json:"retentionSeconds"`
					Offset string `json:"offsetType"`; Hour int `json:"hourOfDay"`; Day string `json:"dayOfWeek"`; Zone string `json:"timeZone"`
				} `json:"schedules"`
			}
			if !decode(&details) { return fail(400, "BadRequest") }
			if token == "" || details.Compartment != p.config.CompartmentID { p.t.Error("policy create lost scope or retry token") }
			if id := p.backupPolicyRetryTokens[token]; id != "" {
				for _, policy := range p.backupPolicies { if policy.ID == id { return p.policyWire(policy), 200, false } }
			}
			p.backupPolicyCreates++
			policy := memberSDKPolicy{ID: fmt.Sprintf("ocid1.volumebackuppolicy.created-%d", p.backupPolicyCreates), DisplayName: details.Name, FreeformTags: details.Tags}
			for _, schedule := range details.Schedules { policy.Schedules = append(policy.Schedules, BackupSchedule{Type: schedule.Type, Period: schedule.Period,
				RetentionSeconds: schedule.Retention, OffsetType: schedule.Offset, HourOfDay: schedule.Hour, DayOfWeek: schedule.Day, TimeZone: schedule.Zone}) }
			p.backupPolicies = append(p.backupPolicies, policy)
			p.backupPolicyRetryTokens[token] = policy.ID
			return p.policyWire(policy), 200, false
		case "/volumeBackupPolicyAssignments":
			var details struct { Asset string `json:"assetId"`; Policy string `json:"policyId"` }
			if !decode(&details) { return fail(400, "BadRequest") }
			p.backupPolicyAssignments[details.Asset] = details.Policy
			return map[string]string{"id": "assignment", "assetId": details.Asset, "policyId": details.Policy}, 200, false
		}
	}
	if r.Method == http.MethodPut && strings.HasPrefix(path, "/volumes/") {
		p.updates++
		id := strings.TrimPrefix(path, "/volumes/")
		volume, exists := p.volumes[id]
		if !exists { return fail(404, "NotAuthorizedOrNotFound") }
		if r.Header.Get("If-Match") == "" || r.Header.Get("If-Match") != volume.ETag { p.t.Error("volume update lost exact If-Match"); return fail(412, "PreconditionFailed") }
		if errors.Is(p.updateErr, ErrStaleETag) { return fail(412, "PreconditionFailed") }
		var details struct { Size int64 `json:"sizeInGBs"`; Tags map[string]string `json:"freeformTags"` }
		if !decode(&details) { return fail(400, "BadRequest") }
		if p.updateErr == nil || p.updateApplies {
			volume.SizeGB, volume.FreeformTags, volume.ETag = details.Size, details.Tags, fmt.Sprintf("updated-%d", p.updates)
			p.volumes[id] = volume
		}
		if p.updateErr != nil { return nil, 200, true }
		header.Set("etag", volume.ETag)
		return p.volumeWire(volume), 200, false
	}
	if r.Method == http.MethodDelete && strings.HasPrefix(path, "/volumeAttachments/") {
		p.detaches++
		id := strings.TrimPrefix(path, "/volumeAttachments/")
		attachment, exists := p.attachments[id]
		if !exists { return fail(404, "NotAuthorizedOrNotFound") }
		if r.Header.Get("If-Match") == "" || r.Header.Get("If-Match") != attachment.ETag { p.t.Error("detach lost exact If-Match"); return fail(412, "PreconditionFailed") }
		attachment.LifecycleState = attachmentStateDetached
		if p.stayBusy { attachment.LifecycleState = attachmentStateDetaching }
		p.attachments[id] = attachment
		if p.detachErr != nil { return nil, 204, true }
		return nil, 204, false
	}
	if r.Method == http.MethodDelete && strings.HasPrefix(path, "/volumes/") { p.deletes++ }
	p.t.Errorf("unexpected member-volume SDK request: %s %s", r.Method, r.URL.RequestURI())
	return fail(400, "UnexpectedRequest")
}

func TestMemberVolumeSocketCreateAttachReplayAndAdmission(t *testing.T) {
	t.Run("MemberVolumeCreatesAndAttachesOnceIdempotently", memberSDKMemberVolumeCreatesAndAttachesOnceIdempotently)
	t.Run("MemberVolumeLostCreateResponseReplaysOneVolume", memberSDKMemberVolumeLostCreateResponseReplaysOneVolume)
	t.Run("MemberVolumeRejectsInstancesAndNamesOutsideTheMember", memberSDKMemberVolumeRejectsInstancesAndNamesOutsideTheMember)
	t.Run("MemberVolumeHoldsWhenDeviceIsBusy", memberSDKMemberVolumeHoldsWhenDeviceIsBusy)
	t.Run("MemberVolumeDuplicateCreateKeyHolds", memberSDKMemberVolumeDuplicateCreateKeyHolds)
	t.Run("MemberVolumeRecordedVolumeIsNeverRecreated", memberSDKMemberVolumeRecordedVolumeIsNeverRecreated)
}

func TestMemberVolumeSocketReplacementPreservesRecordedData(t *testing.T) {
	t.Run("MemberVolumeReattachesSameVolumeAfterHostReplacement", memberSDKMemberVolumeReattachesSameVolumeAfterHostReplacement)
	t.Run("MemberVolumeRefusesToStealLiveAttachment", memberSDKMemberVolumeRefusesToStealLiveAttachment)
	t.Run("MemberVolumeFailsClosedOnTerminatedVolume", memberSDKMemberVolumeFailsClosedOnTerminatedVolume)
}

func TestMemberVolumeSocketRetirementRetainsDataAndSeparatesIncarnations(t *testing.T) {
	t.Run("MemberVolumeResizeChecksRecordedIDBeforeAnyUpdate", memberSDKMemberVolumeResizeChecksRecordedIDBeforeAnyUpdate)
	t.Run("MemberVolumeRetireRetainsAndNameReuseCreatesFreshVolume", memberSDKMemberVolumeRetireRetainsAndNameReuseCreatesFreshVolume)
	t.Run("MemberVolumeRetirementRetriesUnknownOutcomes", memberSDKMemberVolumeRetirementRetriesUnknownOutcomes)
	t.Run("MemberNameReuseLostCreateResponseReplaysFreshIncarnation", memberSDKMemberNameReuseLostCreateResponseReplaysFreshIncarnation)
	t.Run("MemberVolumeRetireRefusesOtherLiveAttachmentAndWrongRecordedData", memberSDKMemberVolumeRetireRefusesOtherLiveAttachmentAndWrongRecordedData)
}

func TestMemberVolumeSocketBackupPolicyPrecedesAttachment(t *testing.T) {
	t.Run("MemberVolumeCarriesTheCellBackupPolicy", memberSDKMemberVolumeCarriesTheCellBackupPolicy)
}

func TestMemberVolumeSocketScratchRestoreAndReadOnlyVerification(t *testing.T) {
	t.Run("VerifyRestoredAttachmentReadsExactScratchCopyWithoutMutatingOCI", memberSDKVerifyRestoredAttachmentReadsExactScratchCopyWithoutMutatingOCI)
	t.Run("VerifyRestoredAttachmentFailsClosedOnWrongVolumeScopeStateAndAttachments", memberSDKVerifyRestoredAttachmentFailsClosedOnWrongVolumeScopeStateAndAttachments)
	t.Run("MemberVolumeRestoreDrill", memberSDKMemberVolumeRestoreDrill)
}

func memberSDKVerifyRestoredAttachmentReadsExactScratchCopyWithoutMutatingOCI(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
	defer cancel()
	volumes, ledger, restored := memberSDKRestoreFixture(t)
	// Detached history does not turn an exclusive current attachment into
	// another live attachment.
	history := ledger.attachments[restored.ID]
	history.ID, history.InstanceID, history.LifecycleState = "detached-history", "ocid1.instance.old-scratch", attachmentStateDetached
	ledger.attachments[history.ID] = history
	creates, attaches, writes := ledger.volumeCreateCalls, ledger.attachCalls, ledger.writes
	verified, err := volumes.VerifyRestoredAttachment(ctx, restored.InstanceID, restored.VolumeID)
	if err != nil || verified != restored.Attachment || ledger.volumeCreateCalls != creates || ledger.attachCalls != attaches ||
		ledger.updates != 0 || ledger.detaches != 0 || ledger.deletes != 0 || ledger.writes != writes {
		t.Fatalf("read-only verification = %+v, %v; want exact %+v without OCI writes", verified, err, restored.Attachment)
	}
}

func memberSDKVerifyRestoredAttachmentFailsClosedOnWrongVolumeScopeStateAndAttachments(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
	defer cancel()
	for _, scenario := range []string{
		"member data volume", "missing volume", "wrong returned volume ID", "wrong compartment", "wrong domain", "wrong tier", "wrong size tag",
		"wrong resource tag", "wrong owner tag", "wrong region tag", "wrong generation tag", "wrong managed tag", "wrong create key", "unfinished restore",
		"wrong device", "wrong returned attachment ID", "wrong instance", "read-only", "shareable", "unencrypted", "detaching", "missing attachment",
		"second scratch volume", "duplicate scratch attachment", "second volume attachment", "member instance", "foreign scratch", "stopped scratch",
	} {
		t.Run(scenario, func(t *testing.T) {
			volumes, ledger, restored := memberSDKRestoreFixture(t)
			volume := ledger.volumes[restored.VolumeID]
			attachment := ledger.attachments[restored.ID]
			switch scenario {
			case "member data volume":
				restored.VolumeID = "ocid1.volume.created-1"
			case "missing volume":
				delete(ledger.volumes, restored.VolumeID)
			case "wrong returned volume ID":
				volume.ID = "ocid1.volume.other"
			case "wrong compartment":
				volume.CompartmentID = "0000000000V4MRM46HP1SNGDYW"
			case "wrong domain":
				volume.AvailabilityDomain = "0000000000V4MRM46HP1SNGDYW"
			case "wrong tier":
				volume.VPUsPerGB = 20
			case "wrong size tag":
				volume.FreeformTags[tagVolumeSize] = "100"
			case "wrong resource tag":
				volume.FreeformTags[tagResource] = resourceMemberData
			case "wrong owner tag":
				volume.FreeformTags[tagOwner] = "0000000000V4MRM46HP1SNGDYW"
			case "wrong region tag":
				volume.FreeformTags[tagRegion] = "SFO"
			case "wrong generation tag":
				volume.FreeformTags[tagGeneration] = "2"
			case "wrong managed tag":
				volume.FreeformTags[tagManagedBy] = "0000000000V4MRM46HP1SNGDYW"
			case "wrong create key":
				volume.FreeformTags[tagCreateKey] = memberVolumeCreateKey(testMemberVolume)
			case "unfinished restore":
				volume.LifecycleState = "RESTORING"
			case "wrong device":
				attachment.Device = MemberVolumeDevice
			case "wrong returned attachment ID":
				attachment.ID = "0000000000V4MRM46HP1SNGDYW"
			case "wrong instance":
				attachment.InstanceID = "0000000000V4MRM46HP1SNGDYW"
			case "read-only":
				attachment.IsReadOnly = new(true)
			case "shareable":
				attachment.IsShareable = new(true)
			case "unencrypted":
				attachment.IsPvEncryptionInTransitEnabled = new(false)
			case "detaching":
				attachment.LifecycleState = attachmentStateDetaching
			case "missing attachment":
				delete(ledger.attachments, restored.ID)
			case "second scratch volume", "duplicate scratch attachment", "second volume attachment":
				other := attachment
				other.ID = "extra"
				if scenario == "second scratch volume" {
					other.VolumeID = "ocid1.volume.other"
				}
				if scenario == "second volume attachment" {
					other.InstanceID = "ocid1.instance.other"
				}
				ledger.attachments[other.ID] = other
			case "member instance", "foreign scratch", "stopped scratch":
				instance := ledger.instances[restored.InstanceID]
				if scenario == "member instance" {
					instance.DisplayName = testMember
				}
				if scenario == "foreign scratch" {
					instance.CompartmentID = "0000000000V4MRM46HP1SNGDYW"
				}
				if scenario == "stopped scratch" {
					instance.LifecycleState = "STOPPED"
				}
				ledger.instances[restored.InstanceID] = instance
			}
			if scenario != "missing volume" && scenario != "member data volume" {
				ledger.volumes[restored.VolumeID] = volume
			}
			if scenario != "missing attachment" {
				ledger.attachments[restored.ID] = attachment
			}
			creates, attaches, writes := ledger.volumeCreateCalls, ledger.attachCalls, ledger.writes
			if verified, err := volumes.VerifyRestoredAttachment(ctx, restored.InstanceID, restored.VolumeID); err == nil ||
				ledger.volumeCreateCalls != creates || ledger.attachCalls != attaches || ledger.updates != 0 || ledger.detaches != 0 || ledger.deletes != 0 || ledger.writes != writes {
				t.Fatalf("%s passed verification or mutated OCI: %+v, %v", scenario, verified, err)
			}
		})
	}
}

func memberSDKMemberVolumeResizeChecksRecordedIDBeforeAnyUpdate(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
	defer cancel()
	volumes, ledger, request, _ := memberSDKRetireFixture(t)
	for _, recorded := range []string{"", "ocid1.volume.some-other-recorded-volume"} {
		for _, size := range []int64{50, 100} {
			if _, err := volumes.Resize(ctx, testMember, recorded, size); err == nil {
				t.Fatalf("Resize accepted recorded ID %q at %d GB", recorded, size)
			}
		}
	}
	if ledger.updates != 0 || ledger.volumes[request.VolumeID].SizeGB != 50 {
		t.Fatal("recorded ID rejection happened after a volume update")
	}
	delete(ledger.volumes, request.VolumeID)
	if _, err := volumes.Resize(ctx, testMember, request.VolumeID, 100); err == nil || ledger.updates != 0 {
		t.Fatalf("missing recorded data was updated: %v (updates %d)", err, ledger.updates)
	}
}

func memberSDKMemberVolumeRetireRetainsAndNameReuseCreatesFreshVolume(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
	defer cancel()
	volumes, ledger, request, first := memberSDKRetireFixture(t)
	now := time.Date(2026, 10, 5, 12, 0, 0, 0, time.UTC)
	volumes.fleet.now = func() time.Time { return now }
	retired, err := volumes.Retire(ctx, request)
	if err != nil {
		t.Fatal(err)
	}
	old := ledger.volumes[first.VolumeID]
	if retired.ID != first.VolumeID || retired.State != "AVAILABLE" || old.SizeGB != 50 ||
		old.FreeformTags[tagResource] != resourceMemberRetiredData || old.FreeformTags[tagRetiredNode] != testMember ||
		old.FreeformTags[tagRetiredInstance] != request.InstanceID || old.FreeformTags[tagRetiredAt] != now.Format(time.RFC3339Nano) ||
		old.FreeformTags[tagCreateKey] == memberVolumeCreateKey(testMemberVolume) || ledger.detaches != 1 || ledger.updates != 1 || ledger.deletes != 0 {
		t.Fatalf("retirement did not detach/tag/retain the recorded volume: %+v, ledger %+v", old, ledger)
	}
	if _, _, err := volumes.fleet.reobserveVolume(ctx, retired.ID); !errors.Is(err, ErrForeignResource) {
		t.Fatalf("normal fleet adopted a retired volume: %v", err)
	}
	now = now.Add(time.Hour)
	delete(ledger.instances, request.InstanceID)
	if again, err := volumes.Retire(ctx, request); err != nil || again.ID != retired.ID || ledger.updates != 1 || ledger.detaches != 1 ||
		ledger.volumes[retired.ID].FreeformTags[tagRetiredAt] != old.FreeformTags[tagRetiredAt] {
		t.Fatalf("retirement retry changed its volume/time or repeated effects: %+v, %v", again, err)
	}

	// Reuse even the same instance ID: attachment tokens bind the new exact
	// volume too, so the old attachment token cannot replay detached data.
	memberSDKAddInstance(ledger, request.InstanceID, testMember)
	if _, err := volumes.Ensure(ctx, request); err == nil {
		t.Fatal("Ensure adopted the recorded retired volume")
	}
	fresh := request
	fresh.VolumeID = ""
	second, err := volumes.Ensure(ctx, fresh)
	if err != nil {
		t.Fatal(err)
	}
	if second.VolumeID != "ocid1.volume.created-2" || second.VolumeID == first.VolumeID || second.InstanceID != request.InstanceID ||
		ledger.volumeCreates != 2 || len(ledger.volumeRetryTokens) != 2 || len(ledger.volumes) != 2 || ledger.attachCalls != 2 || ledger.deletes != 0 {
		t.Fatalf("name reuse did not return the exact fresh VolumeID: %+v, retired %+v", second, retired)
	}
	if again, err := volumes.Ensure(ctx, fresh); err != nil || again.VolumeID != second.VolumeID || ledger.volumeCreates != 2 {
		t.Fatalf("fresh incarnation was not idempotent: %+v, %v", again, err)
	}
	// A second retirement changes the stable history and therefore the token.
	fresh.VolumeID = second.VolumeID
	if _, err := volumes.Retire(ctx, fresh); err != nil {
		t.Fatal(err)
	}
	fresh.VolumeID = ""
	third, err := volumes.Ensure(ctx, fresh)
	if err != nil || third.VolumeID != "ocid1.volume.created-3" || len(ledger.volumeRetryTokens) != 3 || len(ledger.volumes) != 3 {
		t.Fatalf("second name reuse replayed old data: %+v, %v", third, err)
	}
}

func memberSDKMemberVolumeRetirementRetriesUnknownOutcomes(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
	defer cancel()
	for _, scenario := range []string{"lost detach response", "lost tag response", "rejected tags", "pending detach"} {
		t.Run(scenario, func(t *testing.T) {
			volumes, ledger, request, attachment := memberSDKRetireFixture(t)
			switch scenario {
			case "lost detach response":
				ledger.detachErr = errors.New("response lost")
			case "lost tag response":
				ledger.updateErr, ledger.updateApplies = errors.New("response lost"), true
			case "rejected tags":
				ledger.updateErr = ErrStaleETag
			case "pending detach":
				ledger.stayBusy = true
			}
			_, err := volumes.Retire(ctx, request)
			unknown := scenario == "rejected tags" || scenario == "pending detach"
			if unknown && !errors.Is(err, ErrOutcomeUnknown) || !unknown && err != nil {
				t.Fatalf("Retire under %s = %v", scenario, err)
			}
			if scenario == "pending detach" {
				if ledger.updates != 0 {
					t.Fatal("tagged retirement before detach was confirmed")
				}
				memberSDKSetAttachmentState(ledger, attachment.ID, attachmentStateDetached)
			}
			ledger.updateErr, ledger.detachErr, ledger.stayBusy = nil, nil, false
			if retired, err := volumes.Retire(ctx, request); err != nil || retired.ID != request.VolumeID || ledger.detaches != 1 ||
				ledger.deletes != 0 || len(ledger.volumes) != 1 {
				t.Fatalf("retirement retry failed or repeated detach/deleted data: %+v, %v", retired, err)
			}
		})
	}
}

func memberSDKMemberNameReuseLostCreateResponseReplaysFreshIncarnation(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
	defer cancel()
	volumes, ledger, request, first := memberSDKRetireFixture(t)
	if _, err := volumes.Retire(ctx, request); err != nil {
		t.Fatal(err)
	}
	request.VolumeID = ""
	hidden := map[string]memberSDKVolume{}
	ledger.afterVolumeCreate = func() {
		for id, volume := range ledger.volumes {
			if volume.FreeformTags[tagResource] == resourceMemberData {
				volume.LifecycleState = "AVAILABLE"
				hidden[id] = volume
				delete(ledger.volumes, id)
			}
		}
	}
	ledger.volumeCreateErrorAfterCreate = errors.New("response lost")
	for range 2 {
		if _, err := volumes.Ensure(ctx, request); !errors.Is(err, ErrOutcomeUnknown) {
			t.Fatalf("hidden fresh incarnation = %v; want ErrOutcomeUnknown", err)
		}
	}
	if ledger.volumeCreates != 2 || ledger.volumeCreateCalls != 3 || len(ledger.volumeRetryTokens) != 2 || ledger.attachCalls != 1 {
		t.Fatal("fresh incarnation retries changed tokens or attached retired data")
	}
	for id, volume := range hidden {
		ledger.volumes[id] = volume
	}
	fresh, err := volumes.Ensure(ctx, request)
	if err != nil || fresh.VolumeID != "ocid1.volume.created-2" || fresh.VolumeID == first.VolumeID || ledger.volumeCreates != 2 {
		t.Fatalf("fresh incarnation recovery = %+v, %v", fresh, err)
	}
}

func memberSDKMemberVolumeRetireRefusesOtherLiveAttachmentAndWrongRecordedData(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
	defer cancel()
	for _, scenario := range []string{"other instance", "multiple attachments", "wrong recorded ID", "wrong member", "missing recorded ID", "missing recorded data", "foreign instance"} {
		t.Run(scenario, func(t *testing.T) {
			volumes, ledger, request, attachment := memberSDKRetireFixture(t)
			switch scenario {
			case "other instance":
				request.InstanceID = "ocid1.instance.new"
				memberSDKAddInstance(ledger, request.InstanceID, testMember)
			case "multiple attachments":
				other := ledger.attachments[attachment.ID]
				other.ID, other.InstanceID = "second", "ocid1.instance.other"
				ledger.attachments[other.ID] = other
			case "wrong recorded ID":
				request.VolumeID = "ocid1.volume.other"
			case "wrong member":
				request.Member = "gru-1-db-2"
			case "missing recorded ID":
				request.VolumeID = ""
			case "missing recorded data":
				delete(ledger.volumes, request.VolumeID)
			case "foreign instance":
				instance := ledger.instances[request.InstanceID]
				instance.CompartmentID = "0000000000V4MRM46HP1SNGDYW"
				ledger.instances[instance.ID] = instance
			}
			if _, err := volumes.Retire(ctx, request); err == nil || ledger.detaches != 0 || ledger.updates != 0 || ledger.deletes != 0 {
				t.Fatalf("unsafe retirement reached a mutation: %v, ledger %+v", err, ledger)
			}
		})
	}
}

func memberSDKMemberVolumeCreatesAndAttachesOnceIdempotently(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
	defer cancel()
	volumes, p := memberSDKFixture(t)
	memberSDKAddInstance(p, "ocid1.instance.host-1", testMember)

	attachment, err := volumes.Ensure(ctx, MemberVolumeRequest{Member: testMember, InstanceID: "ocid1.instance.host-1", SizeGB: 50})
	if err != nil {
		t.Fatal(err)
	}
	volume := memberSDKOnlyVolume(t, p)
	if p.volumeCreates != 1 || volume.SizeGB != 50 || volume.VPUsPerGB != 10 || volume.LifecycleState != "AVAILABLE" ||
		volume.CompartmentID != p.config.CompartmentID || volume.AvailabilityDomain != p.config.AvailabilityDomain {
		t.Fatalf("created volume = %+v (creates %d)", volume, p.volumeCreates)
	}
	for key, want := range map[string]string{
		tagCreateKey: memberVolumeCreateKey(testMemberVolume), tagOwner: "gru-1", tagResource: resourceMemberData, tagVolumeSize: "50",
		tagRegion: "GRU", tagGeneration: "1", tagManagedBy: managedByValue,
	} {
		if got := volume.FreeformTags[key]; got != want {
			t.Fatalf("tag %s = %q, want %q", key, got, want)
		}
	}
	if attachment.VolumeID != volume.ID || attachment.InstanceID != "ocid1.instance.host-1" || attachment.State != "ATTACHED" ||
		attachment.Device != "/dev/oracleoci/oraclevdb" ||
		attachment.IsReadOnly || attachment.IsShareable || !attachment.IsPvEncryptionInTransitEnabled || p.attachCalls != 1 {
		t.Fatalf("attachment = %+v (attach calls %d)", attachment, p.attachCalls)
	}

	again, err := volumes.Ensure(ctx, MemberVolumeRequest{Member: testMember, InstanceID: "ocid1.instance.host-1", SizeGB: 50})
	if err != nil {
		t.Fatal(err)
	}
	if again.ID != attachment.ID || again.VolumeID != volume.ID || p.volumeCreateCalls != 1 || p.attachCalls != 1 || len(p.volumes) != 1 {
		t.Fatalf("second Ensure = %+v (create calls %d, attach calls %d, volumes %d)", again, p.volumeCreateCalls, p.attachCalls, len(p.volumes))
	}
}

func memberSDKMemberVolumeLostCreateResponseReplaysOneVolume(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
	defer cancel()
	volumes, p := memberSDKFixture(t)
	memberSDKAddInstance(p, "ocid1.instance.host-1", testMember)

	// The create succeeds but its response is lost: the fleet sees it anyway.
	p.volumeCreateErrorAfterCreate = errors.New("response lost")
	if _, err := volumes.Ensure(ctx, MemberVolumeRequest{Member: testMember, InstanceID: "ocid1.instance.host-1", SizeGB: 50}); err != nil {
		t.Fatalf("Ensure after a lost create response: %v", err)
	}
	if p.volumeCreates != 1 || len(p.volumes) != 1 {
		t.Fatalf("creates = %d, volumes = %d", p.volumeCreates, len(p.volumes))
	}

	// The create is not yet listed: Ensure fails with an unknown outcome and a
	// retry replays the same token instead of creating a second volume.
	volumes, p = memberSDKFixture(t)
	memberSDKAddInstance(p, "ocid1.instance.host-1", testMember)
	hidden := map[string]memberSDKVolume{}
	p.afterVolumeCreate = func() {
		for id, volume := range p.volumes {
			volume.LifecycleState = "AVAILABLE"
			hidden[id] = volume
			delete(p.volumes, id)
		}
	}
	p.volumeCreateErrorAfterCreate = errors.New("response lost")
	for attempt := range 2 {
		if _, err := volumes.Ensure(ctx, MemberVolumeRequest{Member: testMember, InstanceID: "ocid1.instance.host-1", SizeGB: 50}); !errors.Is(err, ErrOutcomeUnknown) {
			t.Fatalf("attempt %d: Ensure = %v, want ErrOutcomeUnknown", attempt, err)
		}
	}
	if p.volumeCreateCalls != 2 || p.volumeCreates != 1 || len(p.volumeRetryTokens) != 1 || p.attachCalls != 0 {
		t.Fatalf("create calls %d, creates %d, tokens %d, attach calls %d", p.volumeCreateCalls, p.volumeCreates, len(p.volumeRetryTokens), p.attachCalls)
	}
	for id, volume := range hidden {
		p.volumes[id] = volume
	}
	attachment, err := volumes.Ensure(ctx, MemberVolumeRequest{Member: testMember, InstanceID: "ocid1.instance.host-1", SizeGB: 50})
	if err != nil {
		t.Fatal(err)
	}
	if volume := memberSDKOnlyVolume(t, p); attachment.VolumeID != volume.ID || p.volumeCreates != 1 || p.volumeCreateCalls != 2 {
		t.Fatalf("attachment %+v to %s (creates %d, create calls %d)", attachment, volume.ID, p.volumeCreates, p.volumeCreateCalls)
	}
}

func memberSDKMemberVolumeReattachesSameVolumeAfterHostReplacement(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
	defer cancel()
	volumes, p := memberSDKFixture(t)
	old := memberSDKAddInstance(p, "ocid1.instance.old", testMember)
	first, err := volumes.Ensure(ctx, MemberVolumeRequest{Member: testMember, InstanceID: old.ID, SizeGB: 50})
	if err != nil {
		t.Fatal(err)
	}
	old.LifecycleState = "TERMINATED"
	p.instances[old.ID] = old
	memberSDKSetAttachmentState(p, first.ID, attachmentStateDetached)

	memberSDKAddInstance(p, "ocid1.instance.new", testMember)
	second, err := volumes.Ensure(ctx, MemberVolumeRequest{Member: testMember, InstanceID: "ocid1.instance.new", SizeGB: 100, VolumeID: first.VolumeID})
	if err != nil {
		t.Fatal(err)
	}
	volume := memberSDKOnlyVolume(t, p)
	if second.VolumeID != first.VolumeID || second.VolumeID != volume.ID || second.InstanceID != "ocid1.instance.new" ||
		second.ID == first.ID || second.Device != MemberVolumeDevice || p.volumeCreateCalls != 1 || p.attachCalls != 2 {
		t.Fatalf("reattach = %+v from %+v (create calls %d, attach calls %d)", second, first, p.volumeCreateCalls, p.attachCalls)
	}
	// An existing volume is reused at its size: a larger request does not grow it.
	if volume.SizeGB != 50 {
		t.Fatalf("reattached volume size = %d, want 50", volume.SizeGB)
	}
}

func memberSDKMemberVolumeRefusesToStealLiveAttachment(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
	defer cancel()
	for _, state := range []string{"ATTACHED", "DETACHING", "ATTACHING"} {
		t.Run(state, func(t *testing.T) {
			volumes, p := memberSDKFixture(t)
			memberSDKAddInstance(p, "ocid1.instance.old", testMember)
			first, err := volumes.Ensure(ctx, MemberVolumeRequest{Member: testMember, InstanceID: "ocid1.instance.old", SizeGB: 50})
			if err != nil {
				t.Fatal(err)
			}
			memberSDKSetAttachmentState(p, first.ID, state)
			memberSDKAddInstance(p, "ocid1.instance.new", testMember)

			_, err = volumes.Ensure(ctx, MemberVolumeRequest{Member: testMember, InstanceID: "ocid1.instance.new", SizeGB: 50})
			if !errors.Is(err, ErrRetainedVolumeInUse) {
				t.Fatalf("Ensure = %v, want ErrRetainedVolumeInUse", err)
			}
			held, ok := p.attachments[first.ID]
			if p.attachCalls != 1 || len(p.attachments) != 1 || !ok || held.LifecycleState != state || held.InstanceID != "ocid1.instance.old" {
				t.Fatalf("attachments = %+v (attach calls %d)", p.attachments, p.attachCalls)
			}
		})
	}
}

func memberSDKMemberVolumeFailsClosedOnTerminatedVolume(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
	defer cancel()
	volumes, p := memberSDKFixture(t)
	memberSDKAddInstance(p, "ocid1.instance.host-1", testMember)
	if _, err := volumes.Ensure(ctx, MemberVolumeRequest{Member: testMember, InstanceID: "ocid1.instance.host-1", SizeGB: 50}); err != nil {
		t.Fatal(err)
	}
	clear(p.attachments)
	memberSDKSetVolumeStates(p, "AVAILABLE", "TERMINATED")
	memberSDKAddInstance(p, "ocid1.instance.host-2", testMember)

	if _, err := volumes.Ensure(ctx, MemberVolumeRequest{Member: testMember, InstanceID: "ocid1.instance.host-2", SizeGB: 50}); err == nil {
		t.Fatal("Ensure replaced a terminated data volume")
	}
	if p.volumeCreateCalls != 1 || len(p.volumes) != 1 || p.attachCalls != 1 {
		t.Fatalf("create calls %d, volumes %d, attach calls %d", p.volumeCreateCalls, len(p.volumes), p.attachCalls)
	}
}

func memberSDKMemberVolumeRejectsInstancesAndNamesOutsideTheMember(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
	defer cancel()
	volumes, p := memberSDKFixture(t)
	mutate := func(id string, change func(*memberSDKInstance)) {
		instance := memberSDKAddInstance(p, id, testMember)
		change(&instance)
		p.instances[id] = instance
	}
	mutate("ocid1.instance.renamed", func(i *memberSDKInstance) { i.DisplayName = "gru-1-db-2" })
	mutate("ocid1.instance.compartment", func(i *memberSDKInstance) { i.CompartmentID = "ocid1.compartment.other" })
	mutate("ocid1.instance.domain", func(i *memberSDKInstance) { i.AvailabilityDomain = "AD-2" })
	mutate("ocid1.instance.stopped", func(i *memberSDKInstance) { i.LifecycleState = "STOPPED" })
	mutate("ocid1.instance.provisioning", func(i *memberSDKInstance) { i.LifecycleState = "PROVISIONING" })
	mutate("ocid1.instance.naming-off", func(i *memberSDKInstance) { i.ConsistentVolumeNamingEnabled = new(false) })
	mutate("ocid1.instance.naming-unset", func(i *memberSDKInstance) { i.ConsistentVolumeNamingEnabled = nil })
	for _, id := range []string{
		"ocid1.instance.renamed", "ocid1.instance.compartment", "ocid1.instance.domain", "ocid1.instance.stopped",
		"ocid1.instance.provisioning", "ocid1.instance.naming-off", "ocid1.instance.naming-unset", "ocid1.instance.missing",
	} {
		if _, err := volumes.Ensure(ctx, MemberVolumeRequest{Member: testMember, InstanceID: id, SizeGB: 50}); err == nil {
			t.Fatalf("Ensure on %s succeeded", id)
		}
	}
	for _, name := range []string{"gru-1-gw-1", "gru-2-db-1", "gru-1-db-1-data", "postgres", ""} {
		memberSDKAddInstance(p, "ocid1.instance."+name, name)
		if _, err := volumes.Ensure(ctx, MemberVolumeRequest{Member: name, InstanceID: "ocid1.instance." + name, SizeGB: 50}); err == nil {
			t.Fatalf("Ensure for non-member %q succeeded", name)
		}
	}
	memberSDKAddInstance(p, "ocid1.instance.host-1", testMember)
	for _, size := range []int64{0, 49, maxMemberVolumeGB + 1} {
		if _, err := volumes.Ensure(ctx, MemberVolumeRequest{Member: testMember, InstanceID: "ocid1.instance.host-1", SizeGB: size}); err == nil {
			t.Fatalf("Ensure with %d GB succeeded", size)
		}
	}
	if p.volumeCreateCalls != 0 || len(p.volumes) != 0 || p.attachCalls != 0 || p.writes != 0 {
		t.Fatalf("create calls %d, volumes %d, attach calls %d", p.volumeCreateCalls, len(p.volumes), p.attachCalls)
	}
}

func memberSDKMemberVolumeHoldsWhenDeviceIsBusy(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
	defer cancel()
	for name, devices := range map[string][]memberSDKDevice{
		"taken":   {{Name: MemberVolumeDevice, IsAvailable: new(false)}, {Name: "/dev/oracleoci/oraclevdc", IsAvailable: new(true)}},
		"unknown": {{Name: MemberVolumeDevice}, {Name: "/dev/oracleoci/oraclevdc", IsAvailable: new(true)}},
		"missing": {{Name: "/dev/oracleoci/oraclevdc", IsAvailable: new(true)}},
	} {
		t.Run(name, func(t *testing.T) {
			volumes, p := memberSDKFixture(t)
			memberSDKAddInstance(p, "ocid1.instance.host-1", testMember)
			p.devices["ocid1.instance.host-1"] = devices
			if _, err := volumes.Ensure(ctx, MemberVolumeRequest{Member: testMember, InstanceID: "ocid1.instance.host-1", SizeGB: 50}); err == nil {
				t.Fatal("Ensure attached to a busy device")
			}
			if p.deviceListCalls != 1 || p.attachCalls != 0 || len(p.attachments) != 0 {
				t.Fatalf("device lists %d, attach calls %d, attachments %d", p.deviceListCalls, p.attachCalls, len(p.attachments))
			}
		})
	}
}

func memberSDKMemberVolumeDuplicateCreateKeyHolds(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
	defer cancel()
	volumes, p := memberSDKFixture(t)
	memberSDKAddInstance(p, "ocid1.instance.host-1", testMember)
	tags := volumeTags(p.config, VolumeCreateRequest{CreateKey: memberVolumeCreateKey(testMemberVolume), SizeGB: 50})
	for _, id := range []string{"ocid1.volume.a", "ocid1.volume.b"} {
		p.volumes[id] = memberSDKVolume{
			ID: id, CompartmentID: p.config.CompartmentID, AvailabilityDomain: p.config.AvailabilityDomain,
			SizeGB: 50, VPUsPerGB: 10, LifecycleState: "AVAILABLE", ETag: "volume-etag", FreeformTags: cloneStringMap(tags),
		}
	}
	if _, err := volumes.Ensure(ctx, MemberVolumeRequest{Member: testMember, InstanceID: "ocid1.instance.host-1", SizeGB: 50}); !errors.Is(err, ErrDuplicateCreateKey) {
		t.Fatalf("Ensure = %v, want ErrDuplicateCreateKey", err)
	}
	if p.volumeCreateCalls != 0 || p.attachCalls != 0 || len(p.volumes) != 2 || p.writes != 0 {
		t.Fatalf("create calls %d, attach calls %d, volumes %d", p.volumeCreateCalls, p.attachCalls, len(p.volumes))
	}
}

func memberSDKMemberVolumeRecordedVolumeIsNeverRecreated(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
	defer cancel()
	volumes, ledger := memberSDKFixture(t)
	memberSDKAddInstance(ledger, "ocid1.instance.host-1", testMember)
	first, err := volumes.Ensure(ctx, MemberVolumeRequest{Member: testMember, InstanceID: "ocid1.instance.host-1", SizeGB: 50})
	if err != nil {
		t.Fatal(err)
	}
	recorded := MemberVolumeRequest{Member: testMember, InstanceID: "ocid1.instance.host-1", SizeGB: 50, VolumeID: first.VolumeID}
	if again, err := volumes.Ensure(ctx, recorded); err != nil || again.ID != first.ID {
		t.Fatalf("recorded volume = %+v, %v; want the same attachment", again, err)
	}
	if _, err := volumes.Ensure(ctx, MemberVolumeRequest{Member: testMember, InstanceID: "ocid1.instance.host-1", SizeGB: 50,
		VolumeID: "ocid1.volume.other"}); !errors.Is(err, ErrForeignResource) {
		t.Fatalf("a different recorded volume = %v, want ErrForeignResource", err)
	}
	// OCI purged the volume and its attachments: nothing is listed any more.
	clear(ledger.volumes)
	clear(ledger.attachments)
	memberSDKAddInstance(ledger, "ocid1.instance.host-2", testMember)
	recorded.InstanceID = "ocid1.instance.host-2"
	if _, err := volumes.Ensure(ctx, recorded); err == nil {
		t.Fatal("recreated a purged recorded volume")
	}
	if ledger.volumeCreates != 1 || len(ledger.volumes) != 0 {
		t.Fatalf("creates = %d, volumes = %d; want no new volume", ledger.volumeCreates, len(ledger.volumes))
	}
}

func memberSDKMemberVolumeCarriesTheCellBackupPolicy(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
	defer cancel()
	volumes, ledger := memberSDKFixture(t)
	for _, member := range []string{"gru-1-db-1", "gru-1-db-2"} {
		memberSDKAddInstance(ledger, "ocid1.instance."+member, member)
		attachment, err := volumes.Ensure(ctx, MemberVolumeRequest{Member: member, InstanceID: "ocid1.instance." + member, SizeGB: 50})
		if err != nil {
			t.Fatal(err)
		}
		if ledger.backupPolicyAssignments[attachment.VolumeID] != "ocid1.volumebackuppolicy.created-1" {
			t.Fatalf("%s volume policy = %q", member, ledger.backupPolicyAssignments[attachment.VolumeID])
		}
	}
	if ledger.backupPolicyCreates != 1 || len(ledger.backupPolicies) != 1 {
		t.Fatalf("policies created = %d, want one for the cell", ledger.backupPolicyCreates)
	}
	policy := ledger.backupPolicies[0]
	daily := BackupSchedule{Type: "INCREMENTAL", Period: "ONE_DAY", RetentionSeconds: 7 * 86400, OffsetType: "STRUCTURED", HourOfDay: 3, TimeZone: "UTC"}
	weekly := BackupSchedule{Type: "FULL", Period: "ONE_WEEK", RetentionSeconds: 4 * 7 * 86400, OffsetType: "STRUCTURED", HourOfDay: 4,
		DayOfWeek: "SUNDAY", TimeZone: "UTC"}
	if policy.DisplayName != "gru-1-db-data" || !slices.Equal(policy.Schedules, []BackupSchedule{daily, weekly}) ||
		policy.FreeformTags[tagOwner] != "gru-1" || policy.FreeformTags[tagResource] != resourceMemberBackupPolicy {
		t.Fatalf("policy = %+v", policy)
	}

	// A volume carrying another policy, or a policy of that name with other
	// schedules, holds the attach instead of being changed.
	held, heldLedger := memberSDKFixture(t)
	memberSDKAddInstance(heldLedger, "ocid1.instance.host-1", testMember)
	heldLedger.afterVolumeCreate = func() {
		memberSDKSetVolumeStates(heldLedger, "PROVISIONING", "AVAILABLE")
		for id := range heldLedger.volumes {
			heldLedger.backupPolicyAssignments = map[string]string{id: "ocid1.volumebackuppolicy.bronze"}
		}
	}
	if _, err := held.Ensure(ctx, MemberVolumeRequest{Member: testMember, InstanceID: "ocid1.instance.host-1", SizeGB: 50}); !errors.Is(err, ErrForeignResource) {
		t.Fatalf("volume with another policy = %v, want ErrForeignResource", err)
	}
	if heldLedger.attachCalls != 0 {
		t.Fatal("attached a volume without the member backup policy")
	}
	drifted, driftedLedger := memberSDKFixture(t)
	memberSDKAddInstance(driftedLedger, "ocid1.instance.host-1", testMember)
	driftedLedger.backupPolicies = []memberSDKPolicy{{ID: "ocid1.volumebackuppolicy.old", DisplayName: "gru-1-db-data",
		Schedules: []BackupSchedule{daily}, FreeformTags: policy.FreeformTags}}
	if _, err := drifted.Ensure(ctx, MemberVolumeRequest{Member: testMember, InstanceID: "ocid1.instance.host-1", SizeGB: 50}); !errors.Is(err, ErrForeignResource) {
		t.Fatalf("drifted policy = %v, want ErrForeignResource", err)
	}
	if driftedLedger.attachCalls != 0 || driftedLedger.backupPolicyCreates != 0 {
		t.Fatal("changed or bypassed a drifted backup policy")
	}
	regional := daily
	regional.TimeZone = "REGIONAL_DATA_CENTER_TIME"
	driftedLedger.backupPolicies[0].Schedules = []BackupSchedule{regional, weekly}
	if _, err := drifted.Ensure(ctx, MemberVolumeRequest{Member: testMember, InstanceID: "ocid1.instance.host-1", SizeGB: 50}); !errors.Is(err, ErrForeignResource) {
		t.Fatalf("policy in another time zone = %v, want ErrForeignResource", err)
	}
}

func memberSDKMemberVolumeRestoreDrill(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
	defer cancel()
	volumes, ledger := memberSDKFixture(t)
	volumes.restoreSettle = 50 * time.Millisecond
	memberSDKAddInstance(ledger, "ocid1.instance.member", testMember)
	member, err := volumes.Ensure(ctx, MemberVolumeRequest{Member: testMember, InstanceID: "ocid1.instance.member", SizeGB: 50})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	ledger.volumeBackups = []memberSDKBackup{
		{ID: "ocid1.volumebackup.old", VolumeID: member.VolumeID, LifecycleState: "AVAILABLE", SizeGB: 50, CreatedAt: now.Add(-48 * time.Hour)},
		{ID: "ocid1.volumebackup.daily", VolumeID: member.VolumeID, LifecycleState: "AVAILABLE", SizeGB: 50, CreatedAt: now.Add(-24 * time.Hour)},
		{ID: "ocid1.volumebackup.running", VolumeID: member.VolumeID, LifecycleState: "CREATING", SizeGB: 50, CreatedAt: now},
		{ID: "ocid1.volumebackup.foreign", VolumeID: "ocid1.volume.other", LifecycleState: "AVAILABLE", SizeGB: 50, CreatedAt: now},
	}
	scratch := memberSDKAddInstance(ledger, "ocid1.instance.scratch", "gru-1-restore-drill")
	ledger.devices[scratch.ID] = []memberSDKDevice{{Name: RestoreVolumeDevice, IsAvailable: new(true)}}
	ledger.afterVolumeCreate = func() { memberSDKSetVolumeStates(ledger, "PROVISIONING", "AVAILABLE") }
	request := RestoreRequest{Member: testMember, ScratchInstanceID: scratch.ID}
	restored, err := volumes.Restore(ctx, request)
	if err != nil {
		t.Fatal(err)
	}
	created := ledger.volumeCreateRequests[len(ledger.volumeCreateRequests)-1]
	if restored.BackupID != "ocid1.volumebackup.daily" || created.SourceBackupID != "ocid1.volumebackup.daily" ||
		created.Name != "restore-"+testMemberVolume || created.SizeGB != 50 {
		t.Fatalf("restored %+v from create %+v; want the newest AVAILABLE backup", restored, created)
	}
	volume := ledger.volumes[restored.VolumeID]
	if restored.InstanceID != scratch.ID || restored.Device != RestoreVolumeDevice || volume.FreeformTags[tagResource] != resourceMemberRestore ||
		ledger.backupPolicyAssignments[restored.VolumeID] != "" {
		t.Fatalf("restored volume %+v attached %+v; want a scratch-only copy without a backup policy", volume, restored.Attachment)
	}
	if again, err := volumes.Restore(ctx, request); err != nil || again.VolumeID != restored.VolumeID || ledger.volumeCreates != 2 {
		t.Fatalf("rerun = %+v, %v (creates %d); want the same restored volume", again, err, ledger.volumeCreates)
	}
	if again, err := volumes.Ensure(ctx, MemberVolumeRequest{Member: testMember, InstanceID: "ocid1.instance.member", SizeGB: 50}); err != nil ||
		again.VolumeID != member.VolumeID {
		t.Fatalf("member volume after the drill = %+v, %v", again, err)
	}

	for name, bad := range map[string]RestoreRequest{
		"member host":         {Member: testMember, ScratchInstanceID: "ocid1.instance.member"},
		"other volume backup": {Member: testMember, BackupID: "ocid1.volumebackup.foreign", ScratchInstanceID: scratch.ID},
		"unfinished backup":   {Member: testMember, BackupID: "ocid1.volumebackup.running", ScratchInstanceID: scratch.ID},
		"not a member":        {Member: "gru-1-gw-1", ScratchInstanceID: scratch.ID},
	} {
		if _, err := volumes.Restore(ctx, bad); err == nil {
			t.Fatalf("%s restore was accepted", name)
		}
	}
	if ledger.volumeCreates != 2 {
		t.Fatalf("refused restores created volumes: %d", ledger.volumeCreates)
	}

	// A scratch instance holding any other volume is refused before the
	// restored volume is created, so restore-check can only mount the copy.
	busy := memberSDKAddInstance(ledger, "ocid1.instance.busy", "gru-1-restore-busy")
	readOnly, shareable, encrypted := false, false, true
	ledger.attachments["attachment-busy"] = memberSDKAttachment{ID: "attachment-busy", VolumeID: "ocid1.volume.other", InstanceID: busy.ID,
		LifecycleState: "ATTACHED", ETag: "e", Device: MemberVolumeDevice, IsReadOnly: &readOnly, IsShareable: &shareable,
		IsPvEncryptionInTransitEnabled: &encrypted}
	creates := ledger.volumeCreates
	if _, err := volumes.Restore(ctx, RestoreRequest{Member: testMember, BackupID: "ocid1.volumebackup.old", ScratchInstanceID: busy.ID}); err == nil ||
		!strings.Contains(err.Error(), "only the restored volume") || ledger.volumeCreates != creates {
		t.Fatalf("scratch instance with another volume = %v, creates %d -> %d", err, creates, ledger.volumeCreates)
	}
	delete(ledger.attachments, "attachment-busy")

	// The member volume is gone: its backups are found through the recorded
	// volume ID only, and no other volume's backup is accepted.
	delete(ledger.volumes, member.VolumeID)
	memberSDKAddInstance(ledger, "ocid1.instance.second", "gru-1-restore-drill-2")
	ledger.devices["ocid1.instance.second"] = []memberSDKDevice{{Name: RestoreVolumeDevice, IsAvailable: new(true)}}
	if _, err := volumes.Restore(ctx, RestoreRequest{Member: testMember, BackupID: "ocid1.volumebackup.old", ScratchInstanceID: "ocid1.instance.second"}); err == nil ||
		!strings.Contains(err.Error(), "no recorded volume ID") {
		t.Fatalf("restore of a gone volume without its recorded ID = %v", err)
	}
	gone := RestoreRequest{Member: testMember, ScratchInstanceID: "ocid1.instance.second", SourceVolumeID: member.VolumeID}
	gone.BackupID = "ocid1.volumebackup.foreign"
	if _, err := volumes.Restore(ctx, gone); !errors.Is(err, ErrForeignResource) {
		t.Fatalf("another volume's backup for a gone volume = %v, want ErrForeignResource", err)
	}
	// The drill volume of that backup stays on its first scratch instance.
	gone.BackupID, gone.ScratchInstanceID = "", scratch.ID
	if restored, err := volumes.Restore(ctx, gone); err != nil || restored.BackupID != "ocid1.volumebackup.daily" {
		t.Fatalf("newest backup of the recorded gone volume = %+v, %v", restored, err)
	}
}
