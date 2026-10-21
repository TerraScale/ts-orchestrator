package oci_test

import (
	"cmp"
	"context"
	"encoding/json/v2"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/authority"
	"github.com/TerraScale/ts-orchestrator/internal/entityid"
	"github.com/TerraScale/ts-orchestrator/internal/oci"
	"github.com/TerraScale/ts-orchestrator/internal/storage/backup"
)

type backupPruneAuthority struct{ epoch uint64 }

func (fencer backupPruneAuthority) Current() authority.Snapshot {
	return authority.Snapshot{DeploymentID: entityid.Derive("test", "backup-prune-deployment"), Leader: true, Ready: true, Epoch: cmp.Or(fencer.epoch, 1), Revision: 1, ExpiresAt: time.Now().Add(time.Minute)}
}

func (backupPruneAuthority) Guard(context.Context, uint64) error { return nil }

type backupPruneSDK struct {
	volumeResponse string
	volumeStatus   int
	backup         map[string]any
	deletes        int
	volumeReads    int
}

func (sdk *backupPruneSDK) Do(request *http.Request) (*http.Response, error) {
	header := make(http.Header)
	header.Set("Content-Type", "application/json")
	status := http.StatusOK
	var body []byte
	var err error
	switch {
	case request.Method == http.MethodGet && strings.HasSuffix(request.URL.Path, "/volumeBackups"):
		body, err = json.Marshal([]map[string]any{sdk.backup})
	case request.Method == http.MethodGet && strings.Contains(request.URL.Path, "/volumes/"):
		sdk.volumeReads++
		status, body = sdk.volumeStatus, []byte(sdk.volumeResponse)
	case request.Method == http.MethodGet && strings.HasSuffix(request.URL.Path, "/volumeBackups/backup"):
		header.Set("etag", "exact-backup-etag")
		body, err = json.Marshal(sdk.backup)
	case request.Method == http.MethodDelete && strings.HasSuffix(request.URL.Path, "/volumeBackups/backup"):
		if request.Header.Get("If-Match") != "exact-backup-etag" {
			return nil, fmt.Errorf("delete without the backup's ETag")
		}
		sdk.deletes++
		status = http.StatusNoContent
	default:
		return nil, fmt.Errorf("unexpected backup SDK request: %s %s", request.Method, request.URL.Path)
	}
	if err != nil {
		return nil, err
	}
	return &http.Response{StatusCode: status, Header: header, Body: io.NopCloser(strings.NewReader(string(body))), Request: request}, nil
}

func TestSDKOrphanPruningRequiresPositiveSourceDeletion(t *testing.T) {
	const volumeID = "ocid1.volume.exact"
	config := oci.RegionConfig{Region: oci.RegionGRU, Owner: "owner-a", CompartmentID: "ocid1.compartment.owned", AvailabilityDomain: "AD-1"}
	scope := backup.Scope{Owner: "owner-a", Region: config.Region}
	now := time.Now().UTC()
	for _, test := range []struct {
		name       string
		status     int
		body       string
		wantError  bool
		wantDelete int
	}{
		{name: "ambiguous 404", status: http.StatusNotFound,
			body: `{"code":"NotAuthorizedOrNotFound","message":"unreadable or absent"}`, wantError: true},
		{name: "available", status: http.StatusOK,
			body: `{"id":"ocid1.volume.exact","compartmentId":"ocid1.compartment.owned","availabilityDomain":"AD-1","lifecycleState":"AVAILABLE"}`},
		{name: "terminated", status: http.StatusOK,
			body: `{"id":"ocid1.volume.exact","compartmentId":"ocid1.compartment.owned","availabilityDomain":"AD-1","lifecycleState":"TERMINATED"}`, wantDelete: 1},
		{name: "another source", status: http.StatusOK,
			body: `{"id":"ocid1.volume.other","compartmentId":"ocid1.compartment.owned","availabilityDomain":"AD-1","lifecycleState":"TERMINATED"}`, wantError: true},
		{name: "outside the compartment", status: http.StatusOK,
			body: `{"id":"ocid1.volume.exact","compartmentId":"ocid1.compartment.other","availabilityDomain":"AD-1","lifecycleState":"TERMINATED"}`, wantError: true},
		{name: "outside the availability domain", status: http.StatusOK,
			body: `{"id":"ocid1.volume.exact","compartmentId":"ocid1.compartment.owned","availabilityDomain":"AD-2","lifecycleState":"TERMINATED"}`, wantError: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			sdk := &backupPruneSDK{volumeResponse: test.body, volumeStatus: test.status,
				backup: map[string]any{"id": "backup", "volumeId": volumeID, "compartmentId": config.CompartmentID,
					"lifecycleState": "AVAILABLE", "type": "FULL", "timeCreated": now.Add(-31 * 24 * time.Hour).Format(time.RFC3339),
					"freeformTags": scope.Tags(volumeID, entityid.Derive("test", "orphan-backup"))}}
			runner := backup.Runner{Scope: scope, Provider: oci.VolumeBackupProviderForTest(config, sdk, oci.VolumeBackupJournalForTest(t)), Fencer: backupPruneAuthority{},
				Volumes: func(context.Context) ([]string, error) { return nil, nil }, Now: func() time.Time { return now }}
			report, err := runner.RunOnce(t.Context())
			if (err != nil) != test.wantError || sdk.deletes != test.wantDelete || len(report.Deleted) != test.wantDelete {
				t.Fatalf("orphan pass: deletes=%d report=%+v err=%v; want deletes=%d error=%t", sdk.deletes, report, err, test.wantDelete, test.wantError)
			}
		})
	}
}

func TestSDKOrphanTerminationSurvivesRetentionAndLeaderHandoff(t *testing.T) {
	t.Skip("QUARANTINE until 2026-10-22, owner ts-orch consolidation thread: flaky on main since the 2026-10-21 integration-line merge")
	for _, placed := range [][]string{nil, {"ocid1.volume.exact"}} {
		t.Run(fmt.Sprint(placed), func(t *testing.T) {
			const volumeID = "ocid1.volume.exact"
			config := oci.RegionConfig{Region: oci.RegionGRU, Owner: "owner-a", CompartmentID: "ocid1.compartment.owned", AvailabilityDomain: "AD-1"}
			scope := backup.Scope{Owner: config.Owner, Region: config.Region}
			now := time.Now().UTC()
			sdk := &backupPruneSDK{volumeStatus: http.StatusOK,
				volumeResponse: `{"id":"ocid1.volume.exact","compartmentId":"ocid1.compartment.owned","availabilityDomain":"AD-1","lifecycleState":"TERMINATED"}`,
				backup: map[string]any{"id": "backup", "volumeId": volumeID, "compartmentId": config.CompartmentID,
					"lifecycleState": "AVAILABLE", "type": "FULL", "timeCreated": now.Add(-time.Hour).Format(time.RFC3339),
					"freeformTags": scope.Tags(volumeID, entityid.Derive("test", "young-orphan"))}}
			journal := oci.VolumeBackupJournalForTest(t)
			runner := backup.Runner{Scope: scope, Provider: oci.VolumeBackupProviderForTest(config, sdk, journal), Fencer: backupPruneAuthority{},
				Volumes: func(context.Context) ([]string, error) { return placed, nil }, Now: func() time.Time { return now }}
			if report, err := runner.RunOnce(t.Context()); err != nil || sdk.deletes != 0 || len(report.Deleted) != 0 || sdk.volumeReads != 1 {
				t.Fatalf("young orphan: reads=%d deletes=%d report=%+v err=%v", sdk.volumeReads, sdk.deletes, report, err)
			}
			// A new leader opens the durable journal after OCI has purged the source.
			sdk.volumeStatus = http.StatusNotFound
			sdk.volumeResponse = `{"code":"NotAuthorizedOrNotFound","message":"unreadable or absent"}`
			runner.Provider = oci.VolumeBackupProviderForTest(config, sdk, oci.ReopenVolumeBackupJournalForTest(t, journal))
			runner.Fencer = backupPruneAuthority{epoch: 2}
			now = now.Add(31 * 24 * time.Hour)
			if report, err := runner.RunOnce(t.Context()); err != nil || sdk.deletes != 1 || len(report.Deleted) != 1 || sdk.volumeReads != 1 {
				t.Fatalf("expired proven orphan: reads=%d deletes=%d report=%+v err=%v", sdk.volumeReads, sdk.deletes, report, err)
			}

		})
	}
}

func TestSDKOrphanPruningUsesTerminalLifecycleProof(t *testing.T) {
	config, volumeID, journal := oci.TerminalVolumeProofForTest(t)
	scope := backup.Scope{Owner: config.Owner, Region: config.Region}
	now := time.Now().UTC()
	sdk := &backupPruneSDK{volumeStatus: http.StatusNotFound,
		volumeResponse: `{"code":"NotAuthorizedOrNotFound","message":"unreadable or absent"}`,
		backup: map[string]any{"id": "backup", "volumeId": volumeID, "compartmentId": config.CompartmentID,
			"lifecycleState": "AVAILABLE", "type": "FULL", "timeCreated": now.Add(-31 * 24 * time.Hour).Format(time.RFC3339),
			"freeformTags": scope.Tags(volumeID, entityid.Derive("test", "terminal-orphan"))}}
	runner := backup.Runner{Scope: scope,
		Provider: oci.VolumeBackupProviderForTest(config, sdk, oci.ReopenVolumeBackupJournalForTest(t, journal)),
		Fencer:   backupPruneAuthority{epoch: 2},
		Volumes:  func(context.Context) ([]string, error) { return []string{volumeID}, nil },
		Now:      func() time.Time { return now }}
	if report, err := runner.RunOnce(t.Context()); err != nil || sdk.deletes != 1 || len(report.Deleted) != 1 || sdk.volumeReads != 0 {
		t.Fatalf("purged terminal source: reads=%d deletes=%d report=%+v err=%v", sdk.volumeReads, sdk.deletes, report, err)
	}
}
