package oci

import (
	"encoding/json/v2"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/oracle/oci-go-sdk/v65/common"
	"github.com/oracle/oci-go-sdk/v65/core"
)

// backupHistorySDK serves a volume's backup history newest first in pages
// of the requested size, as OCI does for sortBy=TIMECREATED&sortOrder=DESC.
type backupHistorySDK struct {
	total    int
	requests []*http.Request
}

func (sdk *backupHistorySDK) Do(request *http.Request) (*http.Response, error) {
	sdk.requests = append(sdk.requests, request)
	query := request.URL.Query()
	start, _ := strconv.Atoi(query.Get("page"))
	limit, _ := strconv.Atoi(query.Get("limit"))
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	var items []map[string]any
	for i := start; i < min(start+limit, sdk.total); i++ {
		items = append(items, map[string]any{
			"id": fmt.Sprintf("ocid1.volumebackup.%d", i), "volumeId": "ocid1.volume.exact",
			"compartmentId": "ocid1.compartment.test", "displayName": "b", "type": "INCREMENTAL",
			"lifecycleState": "AVAILABLE", "freeformTags": map[string]string{},
			// Newest first: index 0 is the most recent backup.
			"timeCreated": base.Add(time.Duration(sdk.total-i) * time.Hour).Format(time.RFC3339),
		})
	}
	body, err := json.Marshal(items)
	if err != nil {
		return nil, err
	}
	header := make(http.Header)
	header.Set("Content-Type", "application/json")
	if start+limit < sdk.total {
		header.Set("opc-next-page", strconv.Itoa(start+limit))
	}
	return &http.Response{StatusCode: http.StatusOK, Header: header, Body: io.NopCloser(strings.NewReader(string(body))),
		Request: request}, nil
}

// A volume whose unpruned history outgrew the listing bound still lists its
// newest backups, so scheduling and retention keep working (#127 12050).
func TestVolumeBackupListingKeepsTheNewestBackupsOfALongHistory(t *testing.T) {
	config, _ := testRegionConfig()
	sdk := &backupHistorySDK{total: maxProviderItems + 150}
	base := common.BaseClient{Host: "https://sdk.test.invalid", BasePath: "20160918",
		UserAgent: "oci-backup-test", Signer: observeSDKSigner{}, HTTPClient: sdk}
	provider := &sdkProvider{config: config, storage: core.BlockstorageClient{BaseClient: base}}
	backups, err := provider.ListVolumeBackups(t.Context(), "ocid1.volume.exact")
	if err != nil {
		t.Fatalf("long backup history = %v", err)
	}
	if len(backups) != maxProviderItems || backups[0].ID != "ocid1.volumebackup.0" ||
		!backups[0].CreatedAt.After(backups[len(backups)-1].CreatedAt) {
		t.Fatalf("listing = %d backups, first %q", len(backups), backups[0].ID)
	}
	query := sdk.requests[0].URL.Query()
	if query.Get("sortBy") != "TIMECREATED" || query.Get("sortOrder") != "DESC" || query.Get("volumeId") != "ocid1.volume.exact" {
		t.Fatalf("listing is not newest first for the volume: %v", query)
	}
}
