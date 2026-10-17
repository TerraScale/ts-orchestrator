package oci

import (
	"encoding/json/v2"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"
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
